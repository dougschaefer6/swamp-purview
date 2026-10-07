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
 * Supply appId + certificateThumbprint for unattended (app-only) runs. The
 * module documents -CertificateThumbprint as Windows-only (the certificate must
 * sit in the Windows user certificate store), so this mode works on a Windows
 * host only. A Linux or macOS host would need certificate-file based auth
 * (-CertificateFilePath / -Certificate), which this model does not implement.
 * Omit both to fall back to the ExchangeOnlineManagement module's own
 * interactive/cached sign-in, which is fine at a workstation but will block a
 * scheduled run waiting for a human. App-only is supported for role-group reads
 * and writes but NOT for the eDiscovery cmdlets; see EdiscoveryAuthSupport.
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
      "Thumbprint of a certificate in the Windows user certificate store, paired with appId for unattended app-only auth. -CertificateThumbprint is Windows-only; this model has no certificate-file option for Linux or macOS hosts.",
    ),
  userPrincipalName: z
    .string()
    .optional()
    .describe(
      "UPN used for interactive sign-in when appId/certificateThumbprint are not supplied.",
    ),
});

export type PurviewGlobalArgs = z.infer<typeof PurviewGlobalArgsSchema>;

/** The slice of the swamp method context the Purview models use. */
export interface PurviewMethodContext {
  globalArgs: PurviewGlobalArgs;
  // Only `info` is declared on purpose: swamp does not render warning-level
  // output without -v, so a safety message logged at warn is invisible in a
  // normal run. Everything that must be seen goes through info.
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
}

/** True when the session will connect app-only (certificate) rather than delegated. */
export function isAppOnly(g: PurviewGlobalArgs): boolean {
  return Boolean(g.appId && g.certificateThumbprint);
}

/**
 * Microsoft support status of the eDiscovery cmdlets for this credential mode.
 *
 * Role-group cmdlets (Get-RoleGroup, Get-RoleGroupMember, Add-/Remove-
 * RoleGroupMember) are ordinary RBAC cmdlets and remain supported app-only. The
 * eDiscovery cmdlets — Get-eDiscoveryCaseAdmin, Get-ComplianceCase, the
 * CaseHold* and ComplianceSearch* families — are not. Microsoft documents
 * app-only auth for eDiscovery cmdlets in Security & Compliance PowerShell as
 * unsupported, and its certificate setup steps as "best-effort guidance for
 * existing automations":
 * https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2
 * https://learn.microsoft.com/purview/edisc-permissions
 * They may keep working, or start failing with an opaque remote error, without
 * notice. Delegated sign-in is the supported path.
 */
export type EdiscoveryAuthSupport = "supported" | "best-effort";

export function ediscoveryAuthSupport(
  g: PurviewGlobalArgs,
): EdiscoveryAuthSupport {
  return isAppOnly(g) ? "best-effort" : "supported";
}

/**
 * Log a notice when an eDiscovery cmdlet is about to run app-only, and return
 * the support status so callers can record it alongside their output. Logged
 * at info, not warn: swamp hides warning-level output unless run with -v.
 */
export function warnIfAppOnlyEdiscovery(
  g: PurviewGlobalArgs,
  logger: { info: (msg: string, props?: Record<string, unknown>) => void },
  cmdlets: string,
): EdiscoveryAuthSupport {
  const support = ediscoveryAuthSupport(g);
  if (support === "best-effort") {
    logger.info(
      "{cmdlets} running with app-only (certificate) auth, which Microsoft documents as unsupported for eDiscovery cmdlets; results are best-effort. Use delegated sign-in (userPrincipalName) for a supported run.",
      { cmdlets },
    );
  }
  return support;
}

/**
 * A failed pwshJson run. `connected` records whether the script got past its
 * Connect-* line, which is what separates "the eDiscovery cmdlet failed" from
 * "pwsh, the module, the certificate or the sign-in failed".
 */
export class PurviewPwshError extends Error {
  constructor(
    message: string,
    readonly connected: boolean,
    readonly exitCode: number,
  ) {
    super(message);
    this.name = "PurviewPwshError";
  }
}

/**
 * Re-express a failure from an eDiscovery cmdlet run app-only so the likely
 * cause is visible, instead of surfacing only the module's raw remote error.
 *
 * The hint is added only when the session actually connected and the failure
 * came afterwards. A missing pwsh, an Import-Module failure, a certificate that
 * is not in the store or a 401 from Connect-* happen before any eDiscovery
 * cmdlet runs, so blaming the app-only support status for them would send the
 * reader the wrong way; those pass through unchanged, as do delegated failures.
 * A string error is treated as post-connect because the only strings passed
 * here are error records captured inside the connected script body.
 */
export function explainEdiscoveryFailure(
  g: PurviewGlobalArgs,
  cmdlets: string,
  err: unknown,
): Error {
  const original = err instanceof Error ? err : new Error(String(err));
  if (!isAppOnly(g)) return original;
  const afterConnect = typeof err === "string" ||
    (err instanceof PurviewPwshError && err.connected);
  if (!afterConnect) return original;
  return new Error(
    `${cmdlets} failed under app-only (certificate) auth after a successful ` +
      `connect. Microsoft documents app-only auth for eDiscovery cmdlets in ` +
      `Security & Compliance PowerShell as unsupported, so this may be the ` +
      `cause rather than a permission gap. Its best-effort setup for existing ` +
      `automations needs the app's service principal registered with ` +
      `New-ServicePrincipal, that service principal made a member of the ` +
      `eDiscoveryManager role group, ExchangeOnlineManagement 3.10.1 or later, ` +
      `and Connect-IPPSSession -EnableSearchOnlySession ` +
      `(https://learn.microsoft.com/purview/edisc-permissions). The supported ` +
      `path is to re-run with userPrincipalName (delegated sign-in) instead of ` +
      `appId + certificateThumbprint. Underlying error: ${original.message}`,
    { cause: original },
  );
}

const BEGIN = "<<<SWAMP_JSON_BEGIN>>>";
const END = "<<<SWAMP_JSON_END>>>";
const CONNECTED = "<<<SWAMP_PV_CONNECTED>>>";

/**
 * Lines on stderr that are error records. pwsh -File sends only the error
 * stream to stderr (warnings, verbose and host output go to stdout), so any
 * non-blank stderr line is an error record unless it carries one of the
 * stream prefixes some hosts redirect there anyway.
 */
function stderrErrorLines(stderr: string): string[] {
  return stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !/^(WARNING|VERBOSE|DEBUG|INFO):/i.test(l));
}

/**
 * Which of the three mutually exclusive PowerShell endpoints a body needs.
 *
 * These are genuinely three separate services that happen to share a module,
 * and a cmdlet available in one is absent from the others:
 *
 * - `compliance` — role groups, cases, hold policies. Connect-ExchangeOnline
 *   pointed at ps.compliance.protection.outlook.com.
 * - `searchOnly` — Start-ComplianceSearch and nothing else, via
 *   Connect-IPPSSession -EnableSearchOnlySession.
 * - `exchange` — the real Exchange Online endpoint. Required for
 *   Search-UnifiedAuditLog, Get-Mailbox and Get-MailboxFolderStatistics, none
 *   of which exist in a compliance session. Omitting -ConnectionUri is what
 *   distinguishes it: passing the compliance URI silently yields a session in
 *   which Search-UnifiedAuditLog is simply not a recognised command.
 */
export type PurviewSession = "compliance" | "searchOnly" | "exchange";

/**
 * Build the Connect-* preamble. Certificate app-only auth is preferred; the
 * interactive branch exists so the same model works at a workstation before an
 * app registration is in place.
 */
function connectBlock(
  g: PurviewGlobalArgs,
  mode: PurviewSession = "compliance",
): string {
  // Compliance SEARCH execution requires a different session type than
  // everything else. Start-ComplianceSearch refuses to run in an ordinary
  // compliance session with "Please close the current PowerShell session and
  // open a new session using Connect-IPPSSession with the
  // -EnableSearchOnlySession flag" — that flag exists only on
  // Connect-IPPSSession, not Connect-ExchangeOnline. Role-group reads and hold
  // management, conversely, are NOT available in a search-only session, so the
  // two modes cannot be collapsed into one.
  if (mode === "searchOnly") {
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

  // The exchange mode deliberately omits -ConnectionUri so the module resolves
  // its own Exchange Online endpoint.
  const common = mode === "exchange"
    ? `-ShowBanner:$false -ErrorAction Stop`
    : `-ConnectionUri "https://ps.compliance.protection.outlook.com/powershell-liveid/" ` +
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
  mode: PurviewSession = "compliance",
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
${connectBlock(g, mode)}
Write-Output "${CONNECTED}"
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

    const connected = out.includes(CONNECTED);

    // A script-level $ErrorActionPreference='Stop' does not reach functions
    // inside the ExchangeOnlineManagement module, so a remote non-terminating
    // error can still let the script print an empty "[]" between the markers
    // and exit. Treat a non-zero exit or any error record on stderr as a
    // failure rather than trusting that payload: an empty list here reads as
    // "no admins" or "no cases", which is the wrong answer stated confidently.
    const errorLines = stderrErrorLines(err);
    if (code !== 0 || errorLines.length > 0) {
      throw new PurviewPwshError(
        `Purview PowerShell failed (exit ${code}${
          errorLines.length ? ", error records on stderr" : ""
        }${connected ? ", after connect" : ", before connect completed"}). ` +
          `stderr: ${err.slice(0, 600) || "(empty)"}`,
        connected,
        code,
      );
    }

    const start = out.indexOf(BEGIN);
    const stop = out.indexOf(END);
    if (start === -1 || stop === -1) {
      throw new PurviewPwshError(
        `Purview PowerShell returned no JSON payload (exit ${code}). ` +
          `stderr: ${err.slice(0, 600) || "(empty)"} stdout: ${
            out.slice(0, 600) || "(empty)"
          }`,
        connected,
        code,
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
