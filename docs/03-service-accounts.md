# Windows service accounts and stored service logon secrets

## Why the password must be available

A Windows service configured to run as `DOMAIN\service-user` must start unattended after reboot. The Service Control Manager therefore needs authentication material that allows a service logon without a human entering the password.

Windows protects that material as an LSA secret. It is not stored as a normal readable registry string, but the operating system must be able to recover or use it. A compromise running as `SYSTEM`, code executing inside trusted security components, or offline access to the required system protection material can therefore turn the service configuration into reusable credential access.

Credential Guard is not a substitute for fixing the service identity.

## High-risk design

```text
Service: MSSQL$SQLEXPRESS
Log on as: AD\SQLAdminSVC
Group membership: Domain Admins
Password: static and reused
```

This creates several independent problems:

- a reusable domain password exists on every host running the service
- password rotation can cause outages
- compromise of one service host compromises the identity
- Domain Admin membership converts a local server compromise into a domain compromise
- the same account may have SPNs, interactive logon rights, scheduled tasks, and database permissions

## Safer identity choices

### Built-in service identities

- `LocalSystem`
- `NT AUTHORITY\LocalService`
- `NT AUTHORITY\NetworkService`

These do not require a user-managed password. They have different local and network identities. `LocalSystem` is extremely privileged locally, so use it only when required.

### Virtual service accounts

Format:

```text
NT SERVICE\ServiceName
```

A virtual account has a service-specific local identity and uses the computer account for network authentication. This improves local ACL isolation without managing a password.

### Standalone Managed Service Account

An sMSA provides automatic password management for a service on one host.

### Group Managed Service Account

A gMSA extends managed password retrieval across multiple authorized hosts. Active Directory and the Key Distribution Service manage the password lifecycle. Authorized member hosts retrieve the current managed password when required.

Example identity:

```text
CONTOSO\svc-sql-prod$
```

The trailing dollar sign is a useful heuristic, but not proof that configuration and permissions are correct.

## gMSA does not equal least privilege

A gMSA can still be overprivileged. Do not make it:

- Domain Admin
- Enterprise Admin
- local administrator everywhere
- permitted for interactive logon
- permitted for RDP
- delegated broadly
- authorized on unnecessary hosts

Restrict:

- `PrincipalsAllowedToRetrieveManagedPassword`
- SPNs
- local user rights
- service ACLs
- file and registry ACLs
- SQL/database roles
- network access
- Kerberos delegation

## Inventory logic

The audit module classifies service identities as:

| Identity | Classification | Default risk |
|---|---|---|
| `LocalSystem` | Built-in | Informational |
| `NT AUTHORITY\LocalService` | Built-in | Informational |
| `NT AUTHORITY\NetworkService` | Built-in | Informational |
| `NT SERVICE\Name` | Virtual account | Informational |
| `DOMAIN\name$` | gMSA/sMSA heuristic | Low pending AD validation |
| `DOMAIN\name` | Ordinary domain account | High when automatic/running |
| `.\name` or `HOST\name` | Ordinary local account | Medium/High |
| `name@domain` | Ordinary domain account | High |

Read-only inventory:

```powershell
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName |
    Sort-Object StartName, Name
```

This displays account names, not passwords.

## Active Directory validation

With the ActiveDirectory module:

```powershell
Get-ADServiceAccount -Filter * -Properties `
    PrincipalsAllowedToRetrieveManagedPassword,
    ServicePrincipalNames,
    Enabled
```

Validate a host's ability to use a gMSA:

```powershell
Test-ADServiceAccount -Identity 'svc-sql-prod'
```

Review privileged group membership:

```powershell
Get-ADPrincipalGroupMembership -Identity 'svc-sql-prod$' |
    Select-Object Name, GroupScope, GroupCategory
```

## Migration approach

1. Inventory services, scheduled tasks, IIS app pools, SQL Agent proxies, and application configuration.
2. Identify dependencies, SPNs, network access, and cluster behavior.
3. Create the gMSA and restrict authorized retrieval hosts.
4. Grant only required local user rights, files, registry keys, certificates, and application roles.
5. Configure the service identity without a manually managed password.
6. Restart in a maintenance window.
7. Validate Kerberos and application functionality.
8. remove logon rights and group membership from the legacy account.
9. rotate the legacy password immediately.
10. disable and later delete the legacy identity after dependency monitoring.

## Detection

Alert on:

- new service installation
- service account changes
- services moved from managed identity to ordinary user account
- service accounts added to privileged groups
- interactive or RDP logon by service identities
- logon type 5 from unexpected hosts
- password reset or lockout for service identities
- SPN changes
- changes to `PrincipalsAllowedToRetrieveManagedPassword`

Relevant Windows events can include:

- 4697 — service installed
- 7045 — service installed in System log
- 4624 — successful logon, inspect logon type and account
- 4728/4732/4756 — member added to security-enabled groups
- 4742 — computer account changed
- 5136 — directory object modified, when Directory Service Changes auditing is enabled

## Operational warning

Do not rotate a service account blindly. The same identity may be embedded in scheduled tasks, IIS pools, SQL jobs, application pools, scripts, appliances, and third-party services. Inventory and dependency mapping come first.
