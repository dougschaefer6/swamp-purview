import { z } from "npm:zod@4.3.6";
import {
  EDISCOVERY_ROLES,
  EGRESS_ROLES,
  emitJson,
  explainEdiscoveryFailure,
  PurviewGlobalArgsSchema,
  PurviewMethodContext,
  pwshJson,
  resolvePrincipal,
  sanitizeInstanceName,
  transitiveGroupNames,
  warnIfAppOnlyEdiscovery,
} from "./_pwsh.ts";

const AuthSupportSchema = z.enum(["supported", "best-effort"]);

const RoleGroupSchema = z
  .object({
    name: z.string(),
    roles: z.array(z.string()),
    // null when Get-RoleGroupMember could not be read for this group, so a
    // failed read is never recorded as an empty group. membersError says why.
    members: z.array(z.string()).nullable(),
    membersError: z.string().nullish(),
    // Members that are themselves groups (e.g. a mail-enabled security
    // group). Their users hold this group's roles without appearing in
    // members, so auditPrincipals expands them through Graph.
    groupMembers: z.array(z.string()).nullish(),
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
    // canSearch / canExport are null when the answer depends on a role group
    // whose membership could not be read (see membershipErrors), so a failed
    // Get-RoleGroupMember is never recorded as "cannot export".
    canSearch: z.boolean().nullable(),
    canExport: z.boolean().nullable(),
    membershipErrors: z
      .array(z.object({ roleGroup: z.string(), error: z.string() }))
      .optional(),
    // null when Get-eDiscoveryCaseAdmin could not be read, so a failed lookup
    // is never recorded as "not a case admin".
    isCaseAdmin: z.boolean().nullable(),
    caseAdminAuthSupport: AuthSupportSchema.optional(),
  })
  .passthrough();

const CaseAdminSchema = z
  .object({ name: z.string(), authSupport: AuthSupportSchema.optional() })
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
 * appId + certificateThumbprint for unattended runs. That is supported for the
 * role-group methods (syncRoleGroups, add/removeRoleGroupMember) but only
 * best-effort for anything that calls an eDiscovery cmdlet (listCaseAdmins, the
 * case-admin half of auditPrincipals, listCases, placeCustodianHold,
 * runComplianceSearch); those log a notice, tag their output, and explain
 * failures that happen after a successful connect.
 */
export const model = {
  type: "@dougschaefer/purview-rbac",
  version: "2026.10.08.1",
  globalArguments: PurviewGlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.10.07.1",
      description:
        "Flag app-only auth as best-effort for eDiscovery cmdlets (authSupport on caseAdmin, nullable isCaseAdmin on a failed lookup); globalArguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.08.1",
      description:
        "Role-group membership read with -ResultSize Unlimited; access granted through nested groups expanded via Graph (unknown, not false, when that fails); globalArguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
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
      execute: async (_args: unknown, context: PurviewMethodContext) => {
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(
            `Get-RoleGroup -ErrorAction Stop | ForEach-Object {
    $rg = $_
    $m = @()
    $mErr = $null
    # A failed membership read is reported, not swallowed: an empty list would
    # otherwise read as "this group has no members".
    # -ResultSize Unlimited: the default stops at 1000 members, silently.
    $g = @()
    try {
      $raw = @(Get-RoleGroupMember -Identity $rg.Name -ResultSize Unlimited -ErrorAction Stop)
      $m = @($raw | Select-Object -ExpandProperty Name)
      $g = @($raw | Where-Object { [string]$_.RecipientType -like '*Group*' } | Select-Object -ExpandProperty Name)
    } catch { $mErr = [string]$_ }
    [PSCustomObject]@{
      name         = $rg.Name
      roles        = @($rg.Roles | ForEach-Object { ($_ -split '/')[-1] })
      members      = @($m)
      groupMembers = @($g)
      membersError = $mErr
    }
  }`,
          ),
        )) as Array<{
          name: string;
          roles?: string[];
          members?: string[];
          groupMembers?: string[];
          membersError?: string | null;
        }>;

        const handles = [];
        const unreadable: string[] = [];
        for (const rg of raw ?? []) {
          const roles = rg.roles ?? [];
          const membersError = rg.membersError || null;
          if (membersError) unreadable.push(rg.name);
          const record = {
            name: rg.name,
            roles,
            members: membersError ? null : rg.members ?? [],
            membersError,
            groupMembers: membersError ? null : rg.groupMembers ?? [],
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
        if (unreadable.length > 0) {
          context.logger.info(
            "Membership of {count} role group(s) could not be read and is recorded as null with membersError: {groups}",
            { count: unreadable.length, groups: unreadable.join(", ") },
          );
        }
        return { dataHandles: handles };
      },
    },

    listCaseAdmins: {
      description:
        "List the eDiscovery Administrators — the tier that can open every case in the tenant, including cases they were never assigned to.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: PurviewMethodContext) => {
        const authSupport = warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "Get-eDiscoveryCaseAdmin",
        );
        let raw: Array<{ Name?: string }>;
        try {
          raw = (await pwshJson(
            context.globalArgs,
            emitJson(
              `Get-eDiscoveryCaseAdmin -ErrorAction Stop | Select-Object Name`,
            ),
          )) as Array<{ Name?: string }>;
        } catch (err) {
          throw explainEdiscoveryFailure(
            context.globalArgs,
            "Get-eDiscoveryCaseAdmin",
            err,
          );
        }

        const handles = [];
        for (const a of raw ?? []) {
          if (!a.Name) continue;
          handles.push(
            await context.writeResource(
              "caseAdmin",
              sanitizeInstanceName(a.Name),
              { name: a.Name, authSupport },
            ),
          );
        }
        context.logger.info(
          "Found {count} eDiscovery Administrators (auth support: {support})",
          { count: handles.length, support: authSupport },
        );
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
      execute: async (
        args: { principals: string[] },
        context: PurviewMethodContext,
      ) => {
        const caseAdminAuthSupport = warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "Get-eDiscoveryCaseAdmin",
        );
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(
            `$groups = Get-RoleGroup -ErrorAction Stop | ForEach-Object {
    $rg = $_
    $m = @()
    $mErr = $null
    # Reported, not swallowed: a failed read must not look like "not a member".
    # -ResultSize Unlimited: the default stops at 1000 members, silently.
    $g = @()
    try {
      $raw = @(Get-RoleGroupMember -Identity $rg.Name -ResultSize Unlimited -ErrorAction Stop)
      $m = @($raw | ForEach-Object { $_.Name; $_.WindowsLiveID; $_.PrimarySmtpAddress })
      $g = @($raw | Where-Object { [string]$_.RecipientType -like '*Group*' } | Select-Object -ExpandProperty Name)
    } catch { $mErr = [string]$_ }
    [PSCustomObject]@{
      name         = $rg.Name
      roles        = @($rg.Roles | ForEach-Object { ($_ -split '/')[-1] })
      members      = @($m | Where-Object { $_ })
      groupMembers = @($g | Where-Object { $_ })
      membersError = $mErr
    }
  }
  # Get-eDiscoveryCaseAdmin is an eDiscovery cmdlet, unsupported app-only, so
  # its failure is reported rather than swallowed: an empty list would
  # otherwise read as "nobody is a case admin".
  $admins = @()
  $adminError = $null
  try { $admins = Get-eDiscoveryCaseAdmin -ErrorAction Stop | Select-Object -ExpandProperty Name } catch { $adminError = [string]$_ }
  [PSCustomObject]@{ groups = $groups; caseAdmins = @($admins); caseAdminError = $adminError }`,
          ),
        )) as Array<{
          groups?: Array<{
            name: string;
            roles?: string[];
            members?: string[];
            groupMembers?: string[];
            membersError?: string | null;
          }>;
          caseAdmins?: string[];
          caseAdminError?: string | null;
        }>;

        // -AsArray wraps the single object; unwrap it.
        const payload = Array.isArray(raw) ? raw[0] : raw;
        const allGroups = payload?.groups ?? [];
        const groups = allGroups.filter((g) => !g.membersError);
        const unreadableGroups = allGroups.filter((g) => g.membersError);
        if (unreadableGroups.length > 0) {
          context.logger.info(
            "Membership of {count} role group(s) could not be read; canSearch/canExport are recorded as null where they depend on one: {groups}",
            {
              count: unreadableGroups.length,
              groups: unreadableGroups.map((g) => g.name).join(", "),
            },
          );
        }
        const caseAdmins = (payload?.caseAdmins ?? []).map((a) =>
          a.toLowerCase()
        );
        const caseAdminError = payload?.caseAdminError || null;
        if (caseAdminError) {
          context.logger.info(
            "Case-admin lookup failed; isCaseAdmin recorded as null rather than false. {error}",
            {
              error: explainEdiscoveryFailure(
                context.globalArgs,
                "Get-eDiscoveryCaseAdmin",
                caseAdminError,
              ).message,
            },
          );
        }

        const handles = [];
        for (const principal of args.principals) {
          // Translate to the display name Purview actually reports. Matching
          // the caller's UPN against role-group membership directly would
          // never hit, because the compliance session populates only Name.
          const resolved = await resolvePrincipal(principal);
          // Graph and Purview do not always spell a display name the same way:
          // a shared mailbox comes back from Graph as "Alice Example (Shared)"
          // while the role group stores plain "Alice Example". An exact match
          // therefore reports no access for an account that holds export
          // rights — the same false negative as the UPN case, via a different
          // spelling. Normalize the qualifier suffix off both sides.
          const norm = (s: string) =>
            s.toLowerCase().replace(/\s*\((shared|archive|group)\)\s*$/i, "")
              .trim();
          const needle = norm(resolved.displayName);

          const direct = groups.filter((g) =>
            (g.members ?? []).some((m) => norm(String(m)) === needle)
          );
          // Role groups that grant through a nested group the principal is
          // not already a direct member of. Expand them via Graph; if that
          // lookup fails, those groups become unknown for this principal
          // rather than "not a member".
          const viaGroups = groups.filter((g) =>
            !direct.includes(g) && (g.groupMembers ?? []).length > 0
          );
          const nested: typeof groups = [];
          const nestedUnknown: typeof groups = [];
          let nestedError: string | null = null;
          if (viaGroups.length > 0) {
            try {
              const mine = new Set(
                [...await transitiveGroupNames(resolved.id)].map(norm),
              );
              for (const g of viaGroups) {
                if ((g.groupMembers ?? []).some((n) => mine.has(norm(n)))) {
                  nested.push(g);
                }
              }
            } catch (err) {
              nestedError = err instanceof Error ? err.message : String(err);
              nestedUnknown.push(...viaGroups);
              context.logger.info(
                "Nested-group lookup failed for {principal}; role groups granted through a group are recorded as unknown: {error}",
                { principal, error: nestedError },
              );
            }
          }
          const memberOf = [...direct, ...nested];
          const unknownGroups = [...unreadableGroups, ...nestedUnknown];

          const effectiveRoles = [
            ...new Set(memberOf.flatMap((g) => g.roles ?? [])),
          ].sort();
          const ediscoveryRoles = effectiveRoles.filter((r) =>
            (EDISCOVERY_ROLES as readonly string[]).includes(r)
          );
          const isEgress = (r: string) =>
            (EGRESS_ROLES as readonly string[]).includes(r);
          const isSearch = (r: string) =>
            r === "Compliance Search" || r === "Case Management";
          // A capability is known true from any readable group that grants it.
          // Otherwise it is unknown (null) if an unreadable group grants it,
          // because the principal may be a member we could not see.
          const capability = (grants: (r: string) => boolean) =>
            effectiveRoles.some(grants)
              ? true
              : unknownGroups.some((g) => (g.roles ?? []).some(grants))
              ? null
              : false;
          const canExport = capability(isEgress);
          const canSearch = capability(isSearch);
          const membershipErrors = [
            ...unreadableGroups.map((g) => ({
              roleGroup: g.name,
              error: String(g.membersError),
            })),
            ...nestedUnknown.map((g) => ({
              roleGroup: g.name,
              error: `nested group membership unresolved: ${nestedError}`,
            })),
          ];
          // Case-admin entries carry a "(Shared)" suffix for shared mailboxes.
          const isCaseAdmin = caseAdminError
            ? null
            : caseAdmins.some((a) => norm(a) === needle);

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
                ...(membershipErrors.length ? { membershipErrors } : {}),
                isCaseAdmin,
                caseAdminAuthSupport,
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },

    listCases: {
      description:
        "List eDiscovery (compliance) cases with their status, so a search or hold can be attached to the exact case name Purview holds rather than a paraphrase of it.",
      arguments: z.object({}),
      execute: async (_args: unknown, context: PurviewMethodContext) => {
        warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "Get-ComplianceCase",
        );
        let raw: Array<{ Name?: string; Status?: string }>;
        try {
          raw = (await pwshJson(
            context.globalArgs,
            emitJson(
              `Get-ComplianceCase -ErrorAction Stop | Select-Object Name, Status, Identity`,
            ),
          )) as Array<{ Name?: string; Status?: string }>;
        } catch (err) {
          throw explainEdiscoveryFailure(
            context.globalArgs,
            "Get-ComplianceCase",
            err,
          );
        }
        for (const c of raw ?? []) {
          context.logger.info("case: {name} [{status}]", {
            name: c.Name,
            status: c.Status,
          });
        }
        return { dataHandles: [] };
      },
    },

    placeCustodianHold: {
      description:
        "Place a preservation hold on custodian mailboxes within an eDiscovery case (New-CaseHoldPolicy + New-CaseHoldRule). Deliberately preserves the FULL mailbox with no content query by default: a query-scoped hold only preserves what the query happened to match, so any later refinement of the search terms cannot recover what was deleted in the meantime. Holds are preservative and reversible; they never delete. In eDiscovery Standard placing a hold does NOT notify the custodian.",
      arguments: z.object({
        caseName: z
          .string()
          .describe("Exact eDiscovery case name as Purview stores it"),
        holdName: z.string().describe("Name for the hold policy"),
        mailboxes: z
          .array(z.string())
          .min(1)
          .describe("Custodian mailbox UPNs to preserve"),
        contentQuery: z
          .string()
          .optional()
          .describe(
            "Optional KQL to scope the hold. Omit for a full-mailbox hold, which is the defensible default.",
          ),
      }),
      execute: async (
        args: {
          caseName: string;
          holdName: string;
          mailboxes: string[];
          contentQuery?: string;
        },
        context: PurviewMethodContext,
      ) => {
        warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "New-CaseHoldPolicy / New-CaseHoldRule",
        );
        await pwshJson(
          context.globalArgs,
          emitJson(
            `$mb = @($P.mailboxes)
  $policy = New-CaseHoldPolicy -Name $P.holdName -Case $P.caseName -ExchangeLocation $mb -Force -ErrorAction Stop
  if ($P.contentQuery) {
    New-CaseHoldRule -Name ($P.holdName + "-rule") -Policy $policy.Name -ContentMatchQuery $P.contentQuery -ErrorAction Stop | Out-Null
  } else {
    New-CaseHoldRule -Name ($P.holdName + "-rule") -Policy $policy.Name -ErrorAction Stop | Out-Null
  }
  Get-CaseHoldPolicy -Identity $policy.Name -Case $P.caseName |
    Select-Object Name, Enabled, ExchangeLocation, DistributionStatus`,
          ),
          {
            caseName: args.caseName,
            holdName: args.holdName,
            mailboxes: args.mailboxes,
            contentQuery: args.contentQuery ?? "",
          },
        );
        context.logger.info(
          "Hold {hold} placed on {count} mailbox(es) in case {case}",
          {
            hold: args.holdName,
            count: args.mailboxes.length,
            case: args.caseName,
          },
        );
        return { dataHandles: [] };
      },
    },

    runComplianceSearch: {
      description:
        "Create a content search inside an eDiscovery case, start it, and poll until it completes, returning hit counts and size. Read-only against custodian data — it reports what matches and never previews, exports, or alters content. Dates in KQL are evaluated in UTC, so pass boundaries already offset if the intended window is local.",
      arguments: z.object({
        caseName: z
          .string()
          .describe("Exact eDiscovery case name as Purview stores it"),
        searchName: z.string().describe("Name for this search"),
        mailboxes: z
          .array(z.string())
          .min(1)
          .describe("Mailbox UPNs to search"),
        contentQuery: z.string().describe("KQL content query"),
      }),
      execute: async (
        args: {
          caseName: string;
          searchName: string;
          mailboxes: string[];
          contentQuery: string;
        },
        context: PurviewMethodContext,
      ) => {
        warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "New-ComplianceSearch / Start-ComplianceSearch",
        );
        const raw = await pwshJson(
          context.globalArgs,
          emitJson(
            `$mb = @($P.mailboxes)
  # Idempotent: a prior attempt can leave the search created but unstarted,
  # because New-ComplianceSearch succeeds in an ordinary compliance session
  # while Start-ComplianceSearch requires -EnableSearchOnlySession.
  $existing = $null
  try { $existing = Get-ComplianceSearch -Identity $P.searchName -ErrorAction Stop } catch {}
  if (-not $existing) {
    New-ComplianceSearch -Name $P.searchName -Case $P.caseName -ExchangeLocation $mb -ContentMatchQuery $P.contentQuery -ErrorAction Stop | Out-Null
  }
  Start-ComplianceSearch -Identity $P.searchName -ErrorAction Stop | Out-Null
  $deadline = (Get-Date).AddMinutes(25)
  do {
    Start-Sleep -Seconds 15
    $s = Get-ComplianceSearch -Identity $P.searchName
  } while ($s.Status -ne 'Completed' -and (Get-Date) -lt $deadline)
  $s | Select-Object Name, Status, Items, Size, ContentMatchQuery, Errors`,
          ),
          {
            caseName: args.caseName,
            searchName: args.searchName,
            mailboxes: args.mailboxes,
            contentQuery: args.contentQuery,
          },
          "searchOnly",
        );
        const r = (Array.isArray(raw) ? raw[0] : raw) as {
          Status?: string;
          Items?: number;
          Size?: number;
        };
        context.logger.info(
          "Search {name}: status={status} items={items} size={size}",
          {
            name: args.searchName,
            status: r?.Status,
            items: r?.Items,
            size: r?.Size,
          },
        );
        return { dataHandles: [] };
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
      execute: async (
        args: { roleGroup: string; member: string },
        context: PurviewMethodContext,
      ) => {
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
      execute: async (
        args: { roleGroup: string; member: string },
        context: PurviewMethodContext,
      ) => {
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
      execute: async (_context: unknown) => {
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
