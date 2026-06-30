# Hardening baseline and rollout strategy

## Design order

Apply controls in this order:

1. identity tiering and separate admin accounts
2. PAWs and jump hosts
3. passwordless/managed identities
4. Remote Credential Guard or Restricted Admin
5. disable risky delegation and persistence
6. Credential Guard and LSA protection
7. ASR, EDR, tamper protection, application control
8. registry and policy monitoring
9. continuous service-account review

## Baseline controls

### WDigest

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
UseLogonCredential = 0
```

### Credential Manager domain credential storage

```text
Network access: Do not allow storage of passwords and credentials for network authentication = Enabled
```

Registry:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
DisableDomainCreds = 1
```

A restart is required for the policy to become effective.

### Remote Credential Guard host support

GPO:

```text
Computer Configuration\Administrative Templates\System\Credentials Delegation
Remote host allows delegation of non-exportable credentials = Enabled
```

Registry components:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
DisableRestrictedAdmin = 0

HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
AllowProtectedCreds = 1
```

### Client RDP enforcement

Use Intune Settings Catalog or Group Policy:

```text
Restrict delegation of credentials to remote servers
```

Recommended selections:

- Require Remote Credential Guard for normal server administration
- Restricted Admin for helpdesk access to potentially compromised endpoints

### Credential Guard

Deploy through Intune, Group Policy, or supported configuration management. Validate:

- hardware and firmware requirements
- Secure Boot
- VBS status
- Windows edition/licensing
- smart card and authentication package compatibility
- virtualization platform support
- domain controller exclusions
- Exchange Server support restrictions

Do not enable Credential Guard on domain controllers merely for consistency; Microsoft does not recommend it and states it adds no protection to the AD database.

### LSA protection

Enable LSA protection through supported policy. Test security packages, password filters, smart-card middleware, and authentication plugins. Invalid or unsigned LSA plugins can fail after enforcement.

### Defender ASR

Rule GUID:

```text
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
```

Use Audit or Block according to the rollout stage. Microsoft notes that LSA protection provides similar protection, so avoid treating duplicate controls as independent evidence.

### Service accounts

Target state:

- gMSA for domain services requiring network identity
- virtual service accounts for service-local isolation
- built-in accounts only with justified privilege
- no Domain Admin service accounts
- deny interactive and RDP logon
- AES Kerberos support
- explicit retrieval-host allowlist
- service-specific ACLs and SPNs
- monitored lifecycle

## GPO scoping

Separate policy by device role:

- Domain controllers
- Tier 0 PAWs
- Tier 1 server admin workstations
- jump hosts
- member servers
- RDS hosts
- standard workstations
- legacy exception devices

Do not put every control into Default Domain Policy. Use dedicated, named GPOs with change control and rollback.

Suggested names:

```text
SEC-Windows-CredentialGuard-Workstations
SEC-Windows-LSAProtection-Privileged
SEC-Windows-RDP-RemoteCredentialGuard
SEC-Windows-RDP-RestrictedAdmin-Helpdesk
SEC-Windows-DisableCredentialPersistence-PAW
SEC-Windows-WDigest-Disabled
SEC-Windows-ASR-LSASS
```

## Intune

Prefer:

- Endpoint security > Account protection
- Endpoint security > Attack surface reduction
- Settings Catalog > Credentials Delegation
- Settings Catalog > Device Guard
- Settings Catalog > Local Policies Security Options

Use assignment filters and staged groups:

```text
Ring 0: lab
Ring 1: IT pilot
Ring 2: low-risk business unit
Ring 3: broad production
Ring 4: exception remediation
```

## Rollout gates

Before each ring:

- compatibility test complete
- helpdesk KB prepared
- rollback tested
- monitoring dashboards active
- app owners approve
- break-glass access validated
- restart plan agreed
- policy conflict report clean

## Exception handling

Every exception should include:

- owner
- business justification
- affected devices/users
- exact control disabled
- compensating controls
- expiry date
- remediation plan
- detection coverage
- approval

A permanent wildcard delegation exception is not a valid end state.

## Verification commands

```powershell
# Credential Guard / VBS
Get-CimInstance `
    -Namespace root\Microsoft\Windows\DeviceGuard `
    -ClassName Win32_DeviceGuard

# WDigest
Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    -Name UseLogonCredential `
    -ErrorAction SilentlyContinue

# LSA protection and credential persistence
Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name RunAsPPL, DisableDomainCreds, DisableRestrictedAdmin `
    -ErrorAction SilentlyContinue

# Credentials Delegation
Get-ItemProperty `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
    -ErrorAction SilentlyContinue

# ASR
Get-MpPreference |
    Select-Object AttackSurfaceReductionRules_Ids,
                  AttackSurfaceReductionRules_Actions
```

## Rollback

The hardening script records previous registry values before applying changes. The restore script can restore those registry-backed settings.

ASR and centrally managed settings should be rolled back through the same authority that deployed them. Local changes can be overwritten by GPO or Intune.
