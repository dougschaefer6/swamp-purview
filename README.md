# @dougschaefer/purview

Microsoft Purview compliance-portal RBAC for swamp: role groups, the management
roles they carry, their membership, and the eDiscovery Administrator list.

## Why this exists

eDiscovery permission is not visible from Entra, and reading it from Entra alone
produces a confidently wrong answer.

Global Administrator maps to the Purview `OrganizationManagement` role group.
That group carries Case Management, Compliance Search, Hold, and Search And
Purge — but **not** Export, Preview, Review, RMS Decrypt, or Custodian.
`ComplianceAdministrator` is missing the same four. Only the `eDiscoveryManager`
role group holds them.

The practical consequence: a Global Administrator can create a case and run a
search, then discover they cannot preview a single result or export anything. An
access review that stops at directory roles will report that person as fully
capable of running an investigation. They are not.

This model separates the two questions that get conflated:

- `canSearch` — Compliance Search or Case Management
- `canExport` — Export, RMS Decrypt, or Preview, i.e. whether evidence can
  actually leave the tenant

It also reports `isCaseAdmin`, the eDiscovery Administrator tier that can open
every case in the tenant including ones it was never assigned to.

## Authentication

This model does not use the active `az login` session, unlike the rest of my
Azure models. The Security & Compliance PowerShell endpoint
(`ps.compliance.protection.outlook.com`) rejects tokens minted by the Azure
CLI's first-party application regardless of which user holds them — a Global
Administrator gets the same `UnAuthorized` as an unprivileged account. So the
model carries its own credential surface and shells out to
`ExchangeOnlineManagement`.

Directory _reads_ still use the az session: Graph accepts az tokens fine, and
the model needs Graph to translate a UPN into the display name Purview reports
(see below).

```bash
swamp model create @dougschaefer/purview-rbac purview-rbac \
  --global-arg 'organization=contoso.onmicrosoft.com' \
  --global-arg 'appId=<app-id>' \
  --global-arg 'certificateThumbprint=<thumbprint>'
```

Supply `appId` + `certificateThumbprint` for unattended runs. The app
registration needs the `Exchange.ManageAsApp` application permission and a
directory role such as Compliance Administrator. Omit both and pass
`userPrincipalName` instead to use the module's interactive sign-in, which is
fine at a workstation but will block a scheduled run waiting for a human.

Certificate app-only auth here means `-CertificateThumbprint`, and Microsoft
documents that parameter as supported only on Windows, with the certificate
installed in the user certificate store. So app-only works only when the model
runs on a Windows host. A Linux host, which includes a typical `swamp serve`
box, would need certificate-file based auth (`-CertificateFilePath` or
`-Certificate`), and this model does not implement that yet. On Linux today the
only mode is delegated sign-in.

### App-only is not supported for eDiscovery cmdlets

Microsoft documents app-only (certificate) authentication for the **eDiscovery**
cmdlets in Security & Compliance PowerShell as unsupported, and describes its
certificate setup steps as "best-effort guidance for existing automations that
continue to use this unsupported configuration". See
[App-only authentication in Exchange Online PowerShell and Security & Compliance PowerShell](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2)
and
[Assign permissions in eDiscovery](https://learn.microsoft.com/purview/edisc-permissions).
That splits this model's methods into two groups.

**Role-group reads and writes — app-only is fine.** `syncRoleGroups`,
`addRoleGroupMember` and `removeRoleGroupMember` use `Get-RoleGroup`,
`Get-RoleGroupMember`, `Add-RoleGroupMember` and `Remove-RoleGroupMember`. These
are RBAC cmdlets, not eDiscovery cmdlets, and the notice does not cover them.
They run without any notice in app-only mode.

**eDiscovery reads and actions — delegated sign-in, or best-effort app-only.**
`listCaseAdmins` (`Get-eDiscoveryCaseAdmin`), the case-admin half of
`auditPrincipals`, `listCases` (`Get-ComplianceCase`), `placeCustodianHold`
(`New-CaseHoldPolicy` / `New-CaseHoldRule`), `runComplianceSearch` and the audit
model's `previewSearch` (`ComplianceSearch*`) still run app-only, since existing
automations may keep working, but the model handles them as follows:

- Each one logs a notice at info level naming the cmdlet before it runs
  app-only. It is info rather than warn on purpose: swamp does not show
  warning-level output unless you run with `-v`.
- `listCaseAdmins` stamps every `caseAdmin` record with `authSupport`
  (`supported` for delegated, `best-effort` for app-only). If the cmdlet fails
  app-only after the session connected, the error keeps the module's original
  message, says app-only auth is the likely cause, names the documented
  best-effort setup below, and tells you to re-run with `userPrincipalName`.
  Failures before the session connects (pwsh missing, `Import-Module`, a
  certificate not in the store, a 401 from the connect) pass through unchanged,
  because the support status is not their cause.
- `auditPrincipals` records `caseAdminAuthSupport` the same way. If
  `Get-eDiscoveryCaseAdmin` fails in any auth mode, `isCaseAdmin` is recorded as
  `null` and a notice is logged. Earlier versions swallowed that failure and
  reported `false`, so a failed lookup looked the same as "not a case admin".

If you keep an app-only automation for these cmdlets, Microsoft's best-effort
setup (which does not change the unsupported status) is:

- the app's service principal registered in Exchange and Purview with
  `New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id>`,
  using the Object ID from **Enterprise applications**, not App registrations;
- that service principal added as a member of the `eDiscoveryManager` role group
  (not eDiscovery Administrator);
- the **Microsoft Exchange Online Protection** > `Exchange.ManageAsApp`
  application permission with tenant-wide admin consent;
- ExchangeOnlineManagement 3.10.1 or later, connecting with
  `Connect-IPPSSession -EnableSearchOnlySession`.

Note what the code actually does with that last point: only
`runComplianceSearch` connects with
`Connect-IPPSSession
-EnableSearchOnlySession`. Every other method connects with
`Connect-ExchangeOnline` against the compliance endpoint, because role-group
reads and hold management are not available in a search-only session.

For a supported eDiscovery-admin read, run those methods with
`userPrincipalName` (delegated). Microsoft recommends moving automations to the
Microsoft Graph eDiscovery APIs where they exist. This model does not use Graph
for these reads yet.

### Failures are failures, not empty results

A remote non-terminating error from a cmdlet inside the ExchangeOnlineManagement
module is not stopped by a script-level `$ErrorActionPreference = 'Stop'`, so it
could previously produce an empty `[]` that read as "no admins" or "no cases".
The eDiscovery reads now pass `-ErrorAction Stop`, and any run that exits
non-zero or writes an error record to stderr fails the method instead of
returning whatever was printed.

Role-group membership reads behave the same way. If `Get-RoleGroupMember` fails
for a group, `syncRoleGroups` records that group's `members` as `null` with the
error in `membersError`, and `auditPrincipals` records `canSearch` / `canExport`
as `null` (with the failures in `membershipErrors`) whenever the answer depends
on a group it could not read. A capability granted by a group it could read is
still reported as `true`.

Requires PowerShell 7 and `ExchangeOnlineManagement`:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## A sharp edge worth knowing

`Get-RoleGroupMember` in a Security & Compliance session returns members with
**only** the display name populated — `PrimarySmtpAddress`, `WindowsLiveID`, and
`ExternalDirectoryObjectId` all come back as empty strings. A UPN supplied by a
caller therefore never matches role-group membership directly.

`auditPrincipals` resolves each supplied principal through Graph to its display
name before matching. Without that translation the audit reports "no access" for
a principal holding full export rights — a silent false negative, and the most
dangerous way for a permission audit to be wrong. A principal that cannot be
resolved to a directory object fails the run rather than being reported as
having no access.

## Methods

- `syncRoleGroups` — every role group with its roles and membership, flagging
  which grant eDiscovery capability and which grant evidence egress. Fan-out:
  one session produces the whole picture.
- `auditPrincipals` — per-principal capability, separating `canSearch` from
  `canExport` and flagging `isCaseAdmin`. All three are nullable: `null` means
  unknown because a lookup failed, never "no".
- `listCaseAdmins` — the eDiscovery Administrator list, each record tagged with
  `authSupport`.
- `addRoleGroupMember` / `removeRoleGroupMember` — grant or revoke. Use
  `eDiscoveryManager` to grant the Export / Preview / Review / RMS Decrypt set
  that Global Administrator alone does not provide.

## Workflow

`@dougschaefer/ediscovery-access-audit` captures both layers for a set of
principals — directory roles (direct and group-inherited) from an
`@dougschaefer/azure-ad-user` instance, then role groups, per-principal
capability, and case admins from this model:

```bash
swamp workflow run "@dougschaefer/ediscovery-access-audit" \
  --input 'principals=["alice@contoso.com","adm-alice@contoso.com"]'
```

Run unattended with an app-only `purview-rbac` instance (a Windows host, see
[Authentication](#authentication)), the role-group steps are supported. The
`purview-principal-access` step's case-admin flag and the
`ediscovery-case-admins` step are best-effort (see
[App-only is not supported for eDiscovery cmdlets](#app-only-is-not-supported-for-ediscovery-cmdlets)).
Check `authSupport` / `caseAdminAuthSupport`, and any `null` in `isCaseAdmin`,
`canSearch` or `canExport`, before treating an unattended audit as complete. If
`Get-eDiscoveryCaseAdmin` stops working app-only, the `ediscovery-case-admins`
step fails with an explicit message, and the workflow fails because that step
does not allow failure. Run that step at a workstation with a delegated instance
instead.
