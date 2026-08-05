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
search, then discover they cannot preview a single result or export anything.
An access review that stops at directory roles will report that person as fully
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

Directory *reads* still use the az session: Graph accepts az tokens fine, and
the model needs Graph to translate a UPN into the display name Purview reports
(see below).

```bash
swamp model create @dougschaefer/purview-rbac purview-rbac \
  --global-arg 'organization=contoso.onmicrosoft.com' \
  --global-arg 'appId=<app-id>' \
  --global-arg 'certificateThumbprint=<thumbprint>'
```

Supply `appId` + `certificateThumbprint` for unattended runs — the only mode
suitable for a `swamp serve` schedule. The app registration needs the
`Exchange.ManageAsApp` app role and a directory role such as Compliance
Administrator. Omit both and pass `userPrincipalName` instead to use the
module's interactive sign-in, which is fine at a workstation but will block a
scheduled run waiting for a human.

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
  `canExport` and flagging `isCaseAdmin`.
- `listCaseAdmins` — the eDiscovery Administrator list.
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
