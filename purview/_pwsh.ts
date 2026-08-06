import { z } from "npm:zod@4.3.6";

/**
 * Global arguments for every Purview model. Authentication deliberately does
 * NOT reuse the active `az login` session: the Security & Compliance PowerShell
 * endpoint (ps.compliance.protection.outlook.com) rejects tokens minted by the
 * Azure CLI's first-party application regardless of which user holds them, so
 * an `az account get-access-token --resource ps.compliance...` bearer always
 * comes back UnAuthorized. Every other `@dougschaefer/azure-*` model can lean
 * on the az session; this one cannot, which is why it carries its own
 * credential surface.
 *
 * Supply appId + certificateThumbprint for unattended (app-only) runs — the
 * only mode suitable for `swamp serve` schedules. Omit both to fall back to the
 * ExchangeOnlineManagement module's own interactive/cached sign-in, which is
 * fine at a workstation but will block a scheduled run waiting for a human.
 */
export const PurviewGlobalArgsSchema = z.object({
  organization: z
    .string()
    .describe(
      "Tenant organization domain, e.g. contoso.onmicrosoft.com",
    ),
  appId: z
    .string()
    .optional()
    .describe(
      "Entra application (client) id for app-only auth. Requires the Exchange.ManageAsApp app role and a directory role such as Compliance Administrator.",
    ),
  certificateThumbprint: z
    .string()
    .optional()
    .describe(
      "Thumbprint of a certificate installed locally, paired with appId for unattended app-only auth.",
    ),
  userPrincipalName: z
    .string()
    .optional()
    .describe(
      "UPN used for interactive sign-in when appId/certificateThumbprint are not supplied.",
    ),
});

export type PurviewGlobalArgs = z.infer<typeof PurviewGlobalArgsSchema>;

const BEGIN = "<<<SWAMP_JSON_BEGIN>>>";
const END = "<<<SWAMP_JSON_END>>>";

/**
 * Build the Connect-* preamble. Certificate app-only auth is preferred; the
 * interactive branch exists so the same model works at a workstation before an
 * app registration is in place.
 */
function connectBlock(g: PurviewGlobalArgs, searchOnly = false): string {
  // Compliance SEARCH execution requires a different session type than
  // everything else. Start-ComplianceSearch refuses to run in an ordinary
  // compliance session with "Please close the current PowerShell session and
  // open a new session using Connect-IPPSSession with the
  // -EnableSearchOnlySession flag" — that flag exists only on
  // Connect-IPPSSession, not Connect-ExchangeOnline. Role-group reads and hold
  // management, conversely, are NOT available in a search-only session, so the
  // two modes cannot be collapsed into one.
  if (searchOnly) {
    const upnS = g.userPrincipalName
      ? `-UserPrincipalName $env:SWAMP_PV_UPN `
      : "";
    if (g.appId && g.certificateThumbprint) {
      return `Connect-IPPSSession -AppId $env:SWAMP_PV_APPID ` +
        `-CertificateThumbprint $env:SWAMP_PV_THUMB ` +
        `-Organization $env:SWAMP_PV_ORG -EnableSearchOnlySession ` +
        `-ShowBanner:$false -ErrorAction Stop`;
    }
    return `Connect-IPPSSession ${upnS}-Organization $env:SWAMP_PV_ORG ` +
      `-EnableSearchOnlySession -ShowBanner:$false -ErrorAction Stop`;
  }

  const common =
    `-ConnectionUri "https://ps.compliance.protection.outlook.com/powershell-liveid/" ` +
    `-AzureADAuthorizationEndpointUri "https://login.microsoftonline.com/organizations" ` +
    `-ShowBanner:$false -ErrorAction Stop`;

  if (g.appId && g.certificateThumbprint) {
    return `Connect-ExchangeOnline -AppId $env:SWAMP_PV_APPID ` +
      `-CertificateThumbprint $env:SWAMP_PV_THUMB ` +
      `-Organization $env:SWAMP_PV_ORG ${common}`;
  }
  const upn = g.userPrincipalName
    ? `-UserPrincipalName $env:SWAMP_PV_UPN `
    : "";
  return `Connect-ExchangeOnline ${upn}-Organization $env:SWAMP_PV_ORG ${common}`;
}

/**
 * Run a PowerShell body against a connected Security & Compliance session and
 * return whatever it emitted between the JSON markers.
 *
 * The body is written to a temp file rather than passed via -Command so that
 * nothing about the query lands in process arguments, and all identity values
 * travel via environment variables for the same reason. Markers are used
 * because the module writes assorted warnings to stdout that would otherwise
 * corrupt the JSON.
 */
export async function pwshJson(
  g: PurviewGlobalArgs,
  body: string,
  params: Record<string, unknown> = {},
  searchOnly = false,
): Promise<unknown> {
  const dir = await Deno.makeTempDir({ prefix: "swamp-purview-" });
  const scriptPath = `${dir}/run.ps1`;
  const paramsPath = `${dir}/params.json`;

  // Parameters travel as a JSON file, never interpolated into the script text,
  // so a principal name containing quotes cannot alter the command.
  await Deno.writeTextFile(paramsPath, JSON.stringify(params));

  const script = `
$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$P = Get-Content -Raw -Path $env:SWAMP_PV_PARAMS | ConvertFrom-Json
${connectBlock(g, searchOnly)}
try {
${body}
} finally {
  try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}
`;
  await Deno.writeTextFile(scriptPath, script);

  const env: Record<string, string> = {
    SWAMP_PV_ORG: g.organization,
    SWAMP_PV_PARAMS: paramsPath,
  };
  if (g.appId) env.SWAMP_PV_APPID = g.appId;
  if (g.certificateThumbprint) env.SWAMP_PV_THUMB = g.certificateThumbprint;
  if (g.userPrincipalName) env.SWAMP_PV_UPN = g.userPrincipalName;

  try {
    const cmd = new Deno.Command("pwsh", {
      args: ["-NoProfile", "-File", scriptPath],
      env,
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr } = await cmd.output();
    const out = new TextDecoder().decode(stdout);
    const err = new TextDecoder().decode(stderr);

    const start = out.indexOf(BEGIN);
    const stop = out.indexOf(END);
    if (start === -1 || stop === -1) {
      throw new Error(
        `Purview PowerShell returned no JSON payload (exit ${code}). ` +
          `stderr: ${err.slice(0, 600) || "(empty)"} stdout: ${
            out.slice(0, 600) || "(empty)"
          }`,
      );
    }
    const payload = out.slice(start + BEGIN.length, stop).trim();
    return payload ? JSON.parse(payload) : null;
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
}

/** Wrap a PowerShell expression so its output is emitted as marked JSON. */
export function emitJson(expr: string, depth = 6): string {
  return `  Write-Output "${BEGIN}"
  ${expr} | ConvertTo-Json -Depth ${depth} -AsArray
  Write-Output "${END}"`;
}

/**
 * The management roles that actually confer eDiscovery capability. Membership
 * in a role group is only meaningful in terms of which of these it carries —
 * notably Export and RMS Decrypt, which decide whether a principal can get
 * evidence out of the tenant rather than merely search for it.
 */
export const EDISCOVERY_ROLES = [
  "Case Management",
  "Compliance Search",
  "Hold",
  "Search And Purge",
  "Preview",
  "Review",
  "Export",
  "RMS Decrypt",
  "Custodian",
  "Communication",
  "Manage Review Set Tags",
] as const;

/** The subset that represents evidence egress rather than search. */
export const EGRESS_ROLES = ["Export", "RMS Decrypt", "Preview"] as const;

export function sanitizeInstanceName(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 120);
}

/**
 * Acquire a Microsoft Graph token from the active `az login` session. Note the
 * asymmetry with the compliance endpoint: az-minted tokens are rejected by
 * ps.compliance.protection.outlook.com but work fine against Graph, so
 * directory *reads* can use the az session even though the Purview session
 * cannot.
 */
async function graphToken(): Promise<string> {
  const cmd = new Deno.Command("az", {
    args: [
      "account",
      "get-access-token",
      "--resource",
      "https://graph.microsoft.com",
      "--output",
      "json",
    ],
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = await cmd.output();
  if (code !== 0) {
    throw new Error(
      `Could not acquire a Graph token from the az session: ${
        new TextDecoder().decode(stderr)
      }`,
    );
  }
  const parsed = JSON.parse(new TextDecoder().decode(stdout)) as {
    accessToken?: string;
  };
  if (!parsed.accessToken) {
    throw new Error("az returned no Graph access token");
  }
  return parsed.accessToken;
}

export interface ResolvedPrincipal {
  input: string;
  id: string;
  displayName: string;
  userPrincipalName: string;
}

/**
 * Resolve a UPN, object id, or display name to a directory principal.
 *
 * This is required rather than optional: Get-RoleGroupMember in a Security &
 * Compliance session returns members with only a display name populated —
 * PrimarySmtpAddress, WindowsLiveID and ExternalDirectoryObjectId all come back
 * empty — so a UPN supplied by a caller can never match role-group membership
 * directly. Without this translation the audit reports "no access" for a
 * principal that in fact holds full export rights, which is a silent false
 * negative and the most dangerous way for a permission audit to be wrong.
 *
 * Throws when a principal cannot be resolved. Refusing to answer is correct
 * here: reporting an unverified principal as having no access would be worse
 * than failing.
 */
export async function resolvePrincipal(
  input: string,
): Promise<ResolvedPrincipal> {
  const token = await graphToken();
  const headers = { Authorization: `Bearer ${token}` };
  const select = "$select=id,displayName,userPrincipalName";

  // Direct lookup handles both UPN and object id.
  const direct = await fetch(
    `https://graph.microsoft.com/v1.0/users/${
      encodeURIComponent(input)
    }?${select}`,
    { headers },
  );
  if (direct.ok) {
    const u = await direct.json() as ResolvedPrincipal & { id: string };
    return {
      input,
      id: u.id,
      displayName: u.displayName ?? input,
      userPrincipalName: u.userPrincipalName ?? "",
    };
  }

  // Fall back to a display-name match so callers may pass either form.
  const filter = encodeURIComponent(
    `displayName eq '${input.replace(/'/g, "''")}'`,
  );
  const byName = await fetch(
    `https://graph.microsoft.com/v1.0/users?$filter=${filter}&${select}`,
    { headers },
  );
  if (byName.ok) {
    const body = await byName.json() as {
      value?: Array<
        { id: string; displayName?: string; userPrincipalName?: string }
      >;
    };
    const hit = body.value?.[0];
    if (hit) {
      return {
        input,
        id: hit.id,
        displayName: hit.displayName ?? input,
        userPrincipalName: hit.userPrincipalName ?? "",
      };
    }
  }

  throw new Error(
    `Could not resolve principal '${input}' to a directory object. ` +
      `Refusing to report eDiscovery access for an unverified principal, ` +
      `because an unresolved name would otherwise be indistinguishable from ` +
      `a principal that genuinely holds no access.`,
  );
}
