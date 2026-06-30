# Windows Plaintext Credential Exposure Research

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Defensive Research](https://img.shields.io/badge/focus-defensive%20research-2ea44f)](#scope-and-safety-boundary)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Defensive research and validation tooling for common Windows credential-exposure paths involving:

- Remote Desktop and `mstsc.exe`
- Windows services running as reusable user accounts
- WDigest plaintext credential caching
- CredSSP/default credential delegation
- Windows Credential Manager and alternate network credentials
- LSASS, Credential Guard, LSA protection, and Defender ASR controls

The project explains **why plaintext or reusable credential material can still appear even when Credential Guard is enabled**, where each protection boundary begins and ends, how to audit the configuration without extracting secrets, and how to harden endpoints using reversible PowerShell changes.

> **No password dumping, LSASS dumping, memory scraping, credential decryption, or offensive credential-extraction commands are included.** The tooling records configuration metadata only and intentionally excludes passwords, hashes, tickets, DPAPI master keys, and vault contents.

## Why this matters

Credential Guard isolates selected NTLM, Kerberos, and application-stored domain secrets using virtualization-based security. It is a major control, but it is not a universal protection layer around every application buffer, service configuration, credential prompt, or delegation workflow.

A password can still be exposed when an application must receive it in plaintext, when a service is configured with a reusable account, when legacy WDigest behavior is re-enabled, when CredSSP delegation is configured too broadly, or when users persist alternate credentials. The correct defensive approach is layered:

1. Prevent the credential from reaching the endpoint or remote host.
2. Replace reusable passwords with managed or passwordless identities.
3. Reduce credential delegation and persistence.
4. Protect LSASS and enforce application-control boundaries.
5. Detect registry, service, process-access, and policy changes.
6. Separate administrative identities and use privileged access workstations.

## Repository map

| Path | Purpose |
|---|---|
| [`docs/01-threat-model.md`](docs/01-threat-model.md) | Protection boundaries, attacker assumptions, and credential lifecycle |
| [`docs/02-rdp-mstsc.md`](docs/02-rdp-mstsc.md) | RDP, CredSSP, MSTSC process memory, Remote Credential Guard, and Restricted Admin |
| [`docs/03-service-accounts.md`](docs/03-service-accounts.md) | SCM secrets, ordinary service accounts, gMSA, virtual accounts, and least privilege |
| [`docs/04-wdigest.md`](docs/04-wdigest.md) | WDigest history, registry behavior, logon timing, and detection |
| [`docs/05-credential-delegation.md`](docs/05-credential-delegation.md) | Default, saved, and fresh credential delegation policy |
| [`docs/06-credential-manager-network-drives.md`](docs/06-credential-manager-network-drives.md) | Persistent vault entries versus volatile network logon state |
| [`docs/07-detection-engineering.md`](docs/07-detection-engineering.md) | Eventing, Sysmon, Defender, SIEM logic, and triage |
| [`docs/08-hardening-baseline.md`](docs/08-hardening-baseline.md) | GPO, Intune, local policy, tiering, PAW, and rollout guidance |
| [`docs/09-safe-lab-validation.md`](docs/09-safe-lab-validation.md) | Safe validation without harvesting credentials |
| [`docs/10-reference-matrix.md`](docs/10-reference-matrix.md) | Registry, GPO, MDM, ATT&CK, and control mapping |
| [`scripts/Test-WindowsCredentialExposure.ps1`](scripts/Test-WindowsCredentialExposure.ps1) | Read-only audit and JSON/CSV report |
| [`scripts/Set-WindowsCredentialHardening.ps1`](scripts/Set-WindowsCredentialHardening.ps1) | Explicit, reversible hardening switches with `-WhatIf` |
| [`scripts/Restore-WindowsCredentialHardening.ps1`](scripts/Restore-WindowsCredentialHardening.ps1) | Restore registry values from a generated backup |
| [`examples/simulated-findings.json`](examples/simulated-findings.json) | Synthetic findings for SIEM/parser testing |
| [`tests/WindowsCredentialExposure.Tests.ps1`](tests/WindowsCredentialExposure.Tests.ps1) | Pester and defensive-boundary tests |

## Quick start

### 1. Run the read-only audit

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Test-WindowsCredentialExposure.ps1 `
    -OutputDirectory .\CredentialExposureReport `
    -IncludeCompliantServices
```

Generated output:

```text
CredentialExposureReport\
├── findings.csv
├── findings.json
└── system-context.json
```

The report includes:

- Credential Guard configured/running state
- LSA protection state
- WDigest `UseLogonCredential`
- `DisableDomainCreds`
- risky Credentials Delegation policies and wildcard targets
- Remote Credential Guard host support
- Defender ASR state for LSASS credential theft
- Windows services using ordinary local/domain user identities
- severity, evidence, expected state, recommendation, and ATT&CK mapping

The audit does **not** enumerate saved credential contents or access LSASS memory.

### 2. Preview hardening changes

Every setting is opt-in. Start with `-WhatIf`:

```powershell
.\scripts\Set-WindowsCredentialHardening.ps1 `
    -DisableWDigest `
    -PreventDomainCredentialStorage `
    -EnableRemoteCredentialGuardHostSupport `
    -DisableDefaultCredentialDelegation `
    -LsassASRMode Audit `
    -WhatIf
```

### 3. Apply approved controls

```powershell
.\scripts\Set-WindowsCredentialHardening.ps1 `
    -DisableWDigest `
    -PreventDomainCredentialStorage `
    -EnableRemoteCredentialGuardHostSupport `
    -DisableDefaultCredentialDelegation `
    -LsassASRMode Block `
    -Confirm
```

A timestamped JSON backup is created before registry-backed controls are changed. Review compatibility notes in [`docs/08-hardening-baseline.md`](docs/08-hardening-baseline.md) before production rollout.

## Exposure-surface summary

| Surface | Why plaintext/reusable material appears | Credential Guard coverage | Preferred control |
|---|---|---|---|
| MSTSC/RDP credential entry | The client or credential UI must temporarily process supplied credentials | Does not guarantee protection of every application-owned buffer | Remote Credential Guard, Restricted Admin for helpdesk, PAW, passwordless |
| Ordinary service account | SCM must retain material that allows the service to log on after reboot | Not a substitute for managed service identities | gMSA, virtual service account, least privilege |
| WDigest | `UseLogonCredential=1` requests plaintext credential retention for Digest | Do not rely on Credential Guard alone; enforce the secure registry state | `UseLogonCredential=0`, Protected Users, monitor registry changes |
| Default credential delegation | CredSSP may delegate user credentials or derivatives to a remote host | Delegation can create exposure outside the isolated secret set | Disable broad delegation, use Remote Credential Guard |
| Credential Manager/network drive | Saved alternate credentials persist; active network logons can create reusable session state | Credential Guard reduces some LSASS theft paths but does not make saved credentials harmless | `DisableDomainCreds=1` where compatible, avoid alternate admin creds |
| LSASS access | Attackers with high privilege attempt to read credential material | Credential Guard, LSA protection, and ASR reduce access | Enable VBS/CG, LSA protection, ASR, EDR, application control |

## Carousel

The supplied carousel is retained as visual context. The technical documentation corrects several common overgeneralizations and separates persistent credential storage from transient application or logon-session state.

### 1. RDP / MSTSC

![RDP MSTSC plaintext credential exposure](assets/carousel/01-rdp-mstsc.webp)

### 2. Service accounts

![Service account credential exposure](assets/carousel/02-service-accounts.webp)

### 3. WDigest

![WDigest plaintext credential caching](assets/carousel/03-wdigest.webp)

### 4. Default credential delegation

![Default credential delegation](assets/carousel/04-default-credential-delegation.webp)

### 5. Network drive and SSP state

![Network drive alternate credential exposure](assets/carousel/05-network-drive-ssp.webp)

## Key defensive conclusions

### Credential Guard is necessary, not sufficient

Credential Guard protects selected secrets by moving them behind a VBS trust boundary. It does not prevent a user from typing a password into an untrusted endpoint, stop an application from holding plaintext while it performs authentication, fix a service configured with a reusable domain password, or eliminate every saved-credential workflow.

### Service identity design beats password protection

A service running as `DOMAIN\sqlsvc` with a static password creates a reusable identity and a password-rotation problem. A gMSA allows Windows and Active Directory to manage the password lifecycle and limits which hosts may retrieve the managed password. The account must still be least privileged; gMSA does not make Domain Admin membership safe.

### RDP mode must match the operational scenario

- **Remote Credential Guard** keeps credentials off the remote host while retaining SSO through redirected Kerberos.
- **Restricted Admin** keeps credentials off the remote host but prevents the session from using the administrator's identity for outbound access.
- For helpdesk access to potentially compromised endpoints, Restricted Admin is generally safer because an attacker cannot use the live RDP channel to access resources as the helpdesk operator.
- Standard RDP with manually supplied privileged credentials should not be the default administrative path.

### Persistent and volatile credentials are different

Selecting **Remember my credentials** creates a persistence issue. Merely authenticating with alternate credentials can still create volatile authentication state for the session. Detection and mitigation must account for both rather than treating Credential Manager as the only storage location.

## Scope and safety boundary

This repository is intended for:

- authorized security assessments
- defensive validation
- blue-team engineering
- Windows security architecture
- audit and compliance evidence
- isolated lab research using synthetic identities

It is not intended to provide operational credential theft instructions. Do not upload real credentials, screenshots containing production secrets, LSASS dumps, registry hive exports, DPAPI material, or service-account passwords.

See [`SECURITY.md`](SECURITY.md), [`DISCLAIMER.md`](DISCLAIMER.md), and [`NOTICE.md`](NOTICE.md).

## Supported platforms

The audit targets:

- Windows 10 and Windows 11
- Windows Server 2016, 2019, 2022, and 2025
- Windows PowerShell 5.1 or PowerShell 7 on Windows

Some controls depend on edition, licensing, Defender Antivirus availability, hardware, Secure Boot, VBS, domain membership, or application compatibility.

## References

Primary references are listed throughout the documentation. Core sources include:

- Microsoft Learn: Credential Guard overview  
  https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
- Microsoft Learn: Remote Credential Guard  
  https://learn.microsoft.com/windows/security/identity-protection/remote-credential-guard
- Microsoft Learn: Group Managed Service Accounts overview  
  https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview
- Microsoft Support: WDigest `UseLogonCredential` behavior  
  https://support.microsoft.com/en-US/security/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014
- Microsoft Learn: Network access — do not allow storage of passwords and credentials  
  https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
- Microsoft Learn: Defender ASR rule reference  
  https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
- MITRE ATT&CK: LSASS Memory, T1003.001  
  https://attack.mitre.org/techniques/T1003/001/

## License

MIT. See [`LICENSE`](LICENSE).
