import { z } from "npm:zod@4.3.6";
import {
  EDISCOVERY_ROLES,
  EGRESS_ROLES,
  emitJson,
  PurviewGlobalArgsSchema,
  pwshJson,
  resolvePrincipal,
  sanitizeInstanceName,
} from "./_pwsh.ts";

const RoleGroupSchema = z
  .object({
    name: z.string(),
    roles: z.array(z.string()),
    members: z.array(z.string()),
    grantsEdiscovery: z.boolean(),
    grantsEgress: z.boolean(),
  })
  .passthrough();

const PrincipalAccessSchema = z
  .object({
    principal: z.string(),
    displayName: z.string().nullish(),
    userPrincipalName: z.string().nullish(),
    roleGroups: z.array(z.string()),
    effectiveRoles: z.array(z.string()),
    ediscoveryRoles: z.array(z.string()),
    canSearch: z.boolean(),
    canExport: z.boolean(),
    isCaseAdmin: z.boolean(),
  })
  .passthrough();

const CaseAdminSchema = z
  .object({ name: z.string() })
  .passthrough();

/**
 * `@dougschaefer/purview-rbac` — Microsoft Purview compliance-portal RBAC:
 * role groups, their constituent management roles, their membership, and the
 * eDiscovery Administrator list.
 *
 * This exists because the eDiscovery permission that matters is invisible from
 * Entra. Global Administrator maps to the OrganizationManagement role group,
 * which carries Case Management, Compliance Search, Hold and Search And Purge
 * but NOT Export, Preview, Review, RMS Decrypt or Custodian; Compliance
 * Administrator is missing the same four. Only the eDiscoveryManager role group
 * holds them. So a tenant admin can open a case and run a search yet be unable
 * to preview or export a single item, and an Entra-only audit will report them
 * as fully capable. auditPrincipals is the method that resolves that
 * distinction, separating canSearch from canExport.
 *
 * Authentication does not use the az session — see _pwsh.ts for why. Supply
 * appId + certificateThumbprint for unattended runs.
 */
export const model = {
  type: "@dougschaefer/purview-rbac",
  version: "2026.08.05.1",
  globalArguments: PurviewGlobalArgsSchema,
  resources: {
    roleGroup: {
      description: "Purview role group with its roles and membership",
      schema: RoleGroupSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    principalAccess: {
      description: "Effective Purview eDiscovery capability for one principal",
      schema: PrincipalAccessSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    caseAdmin: {
      description: "eDiscovery Administrator (sees every case in the tenant)",
      schema: CaseAdminSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    syncRoleGroups: {
      description:
        "Sweep every Purview role group with its management roles and membership in one session, flagging which grant eDiscovery capability and which grant evidence egress (Export / RMS Decrypt / Preview). Fan-out by design: one PowerShell connection produces the whole RBAC picture rather than one call per group.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(
            `Get-RoleGroup | ForEach-Object {
    $rg = $_
    $m = @()
    try { $m = Get-RoleGroupMember -Identity $rg.Name -ErrorAction Stop | Select-Object -ExpandProperty Name } catch {}
    [PSCustomObject]@{
      name    = $rg.Name
      roles   = @($rg.Roles | ForEach-Object { ($_ -split '/')[-1] })
      members = @($m)
    }
  }`,
          ),
        )) as Array<{ name: string; roles?: string[]; members?: string[] }>;

        const handles = [];
        for (const rg of raw ?? []) {
          const roles = rg.roles ?? [];
          const record = {
            name: rg.name,
            roles,
            members: rg.members ?? [],
            grantsEdiscovery: roles.some((r) =>
              (EDISCOVERY_ROLES as readonly string[]).includes(r)
            ),
            grantsEgress: roles.some((r) =>
              (EGRESS_ROLES as readonly string[]).includes(r)
            ),
          };
          handles.push(
            await context.writeResource(
              "roleGroup",
              sanitizeInstanceName(rg.name),
              record,
            ),
          );
        }

        context.logger.info(
          "Synced {count} Purview role groups, {egress} of which grant evidence egress",
          {
            count: handles.length,
            egress:
              (raw ?? []).filter((rg) =>
                (rg.roles ?? []).some((r) =>
                  (EGRESS_ROLES as readonly string[]).includes(r)
                )
              ).length,
          },
        );
        return { dataHandles: handles };
      },
    },

    listCaseAdmins: {
      description:
        "List the eDiscovery Administrators — the tier that can open every case in the tenant, including cases they were never assigned to.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(`Get-eDiscoveryCaseAdmin | Select-Object Name`),
        )) as Array<{ Name?: string }>;

        const handles = [];
        for (const a of raw ?? []) {
          if (!a.Name) continue;
          handles.push(
            await context.writeResource(
              "caseAdmin",
              sanitizeInstanceName(a.Name),
              { name: a.Name },
            ),
          );
        }
        context.logger.info("Found {count} eDiscovery Administrators", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    auditPrincipals: {
      description:
        "Resolve what each supplied principal can actually do in eDiscovery: which role groups contain them, the union of management roles that yields, and crucially whether that adds up to search-only or search-plus-export. Distinguishes canSearch (Compliance Search / Case Management) from canExport (Export / RMS Decrypt / Preview), because Global Administrator grants the former and not the latter.",
      arguments: z.object({
        principals: z
          .array(z.string())
          .min(1)
          .describe(
            "Display names or UPNs to evaluate. Role group membership is reported by display name, so either form is accepted and matched case-insensitively.",
          ),
      }),
      execute: async (args, context) => {
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(
            `$groups = Get-RoleGroup | ForEach-Object {
    $rg = $_
    $m = @()
    try { $m = Get-RoleGroupMember -Identity $rg.Name -ErrorAction Stop | ForEach-Object { $_.Name; $_.WindowsLiveID; $_.PrimarySmtpAddress } } catch {}
    [PSCustomObject]@{
      name    = $rg.Name
      roles   = @($rg.Roles | ForEach-Object { ($_ -split '/')[-1] })
      members = @($m | Where-Object { $_ })
    }
  }
  $admins = @()
  try { $admins = Get-eDiscoveryCaseAdmin | Select-Object -ExpandProperty Name } catch {}
  [PSCustomObject]@{ groups = $groups; caseAdmins = @($admins) }`,
          ),
        )) as Array<{
          groups?: Array<
            { name: string; roles?: string[]; members?: string[] }
          >;
          caseAdmins?: string[];
        }>;

        // -AsArray wraps the single object; unwrap it.
        const payload = Array.isArray(raw) ? raw[0] : raw;
        const groups = payload?.groups ?? [];
        const caseAdmins = (payload?.caseAdmins ?? []).map((a) =>
          a.toLowerCase()
        );

        const handles = [];
        for (const principal of args.principals) {
          // Translate to the display name Purview actually reports. Matching
          // the caller's UPN against role-group membership directly would
          // never hit, because the compliance session populates only Name.
          const resolved = await resolvePrincipal(principal);
          const needle = resolved.displayName.toLowerCase();

          const memberOf = groups.filter((g) =>
            (g.members ?? []).some((m) => String(m).toLowerCase() === needle)
          );

          const effectiveRoles = [
            ...new Set(memberOf.flatMap((g) => g.roles ?? [])),
          ].sort();
          const ediscoveryRoles = effectiveRoles.filter((r) =>
            (EDISCOVERY_ROLES as readonly string[]).includes(r)
          );
          const canExport = effectiveRoles.some((r) =>
            (EGRESS_ROLES as readonly string[]).includes(r)
          );
          const canSearch = effectiveRoles.includes("Compliance Search") ||
            effectiveRoles.includes("Case Management");
          // Case-admin entries carry a "(Shared)" suffix for shared mailboxes.
          const isCaseAdmin = caseAdmins.some((a) =>
            a === needle ||
            a.replace(/\s*\(shared\)\s*$/i, "").trim() === needle
          );

          context.logger.info(
            "{principal}: search={search} export={export} caseAdmin={admin} via {groups} role group(s)",
            {
              principal,
              search: canSearch,
              export: canExport,
              admin: isCaseAdmin,
              groups: memberOf.length,
            },
          );

          handles.push(
            await context.writeResource(
              "principalAccess",
              sanitizeInstanceName(resolved.userPrincipalName || principal),
              {
                principal,
                displayName: resolved.displayName,
                userPrincipalName: resolved.userPrincipalName,
                roleGroups: memberOf.map((g) => g.name).sort(),
                effectiveRoles,
                ediscoveryRoles,
                canSearch,
                canExport,
                isCaseAdmin,
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },

    addRoleGroupMember: {
      description:
        "Add a principal to a Purview role group. Use eDiscoveryManager to grant the Export / Preview / Review / RMS Decrypt set that Global Administrator alone does not provide.",
      arguments: z.object({
        roleGroup: z.string().describe(
          "Role group name, e.g. eDiscoveryManager",
        ),
        member: z.string().describe("UPN of the principal to add"),
      }),
      execute: async (args, context) => {
        await pwshJson(
          context.globalArgs,
          emitJson(
            `Add-RoleGroupMember -Identity $P.roleGroup -Member $P.member -Confirm:$false | Out-Null
  Get-RoleGroupMember -Identity $P.roleGroup | Select-Object -ExpandProperty Name`,
          ),
          { roleGroup: args.roleGroup, member: args.member },
        );
        context.logger.info("Added {member} to {group}", {
          member: args.member,
          group: args.roleGroup,
        });
        return { dataHandles: [] };
      },
    },

    removeRoleGroupMember: {
      description:
        "Remove a principal from a Purview role group. Verify current membership with auditPrincipals before running this.",
      arguments: z.object({
        roleGroup: z.string().describe(
          "Role group name, e.g. eDiscoveryManager",
        ),
        member: z.string().describe("UPN of the principal to remove"),
      }),
      execute: async (args, context) => {
        await pwshJson(
          context.globalArgs,
          emitJson(
            `Remove-RoleGroupMember -Identity $P.roleGroup -Member $P.member -Confirm:$false | Out-Null
  Get-RoleGroupMember -Identity $P.roleGroup | Select-Object -ExpandProperty Name`,
          ),
          { roleGroup: args.roleGroup, member: args.member },
        );
        context.logger.info("Removed {member} from {group}", {
          member: args.member,
          group: args.roleGroup,
        });
        return { dataHandles: [] };
      },
    },
  },

  checks: {
    "pwsh-available": {
      description:
        "Verify PowerShell and the ExchangeOnlineManagement module are present before attempting a Purview session.",
      labels: ["live"],
      appliesTo: [
        "syncRoleGroups",
        "auditPrincipals",
        "listCaseAdmins",
        "addRoleGroupMember",
        "removeRoleGroupMember",
      ],
      execute: async (_context) => {
        try {
          const cmd = new Deno.Command("pwsh", {
            args: [
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              "if (Get-Module -ListAvailable ExchangeOnlineManagement) { 'ok' } else { throw 'missing' }",
            ],
            stdout: "piped",
            stderr: "piped",
          });
          const { code } = await cmd.output();
          if (code !== 0) {
            return {
              pass: false,
              errors: [
                "ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser",
              ],
            };
          }
          return { pass: true };
        } catch (err) {
          return {
            pass: false,
            errors: [`PowerShell (pwsh) not available: ${String(err)}`],
          };
        }
      },
    },
  },
};
