# Detection engineering

## Detection objectives

Detect the sequence before and after credential access:

1. security control weakened
2. credential-bearing logon occurs
3. suspicious process accesses LSASS or authentication components
4. reusable credential or session is used for lateral movement
5. persistence or privilege escalation follows

Single events are noisy. Correlation creates useful fidelity.

## Registry changes

High-value paths:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
```

Monitor:

- `UseLogonCredential`
- `RunAsPPL`
- `LsaCfgFlags`
- `DisableRestrictedAdmin`
- `DisableDomainCreds`
- `AllowProtectedCreds`
- all allow/deny delegation values and target lists
- LSA `Security Packages`

Telemetry options:

- Security event 4657 with Audit Registry and SACLs
- Sysmon event 12/13/14
- Microsoft Defender for Endpoint `DeviceRegistryEvents`
- configuration-management drift alerts
- Intune policy reports
- GPO change auditing

## LSASS process access

Sources:

- Sysmon event 10 — Process Access
- Defender ASR events
- Microsoft Defender for Endpoint alerts and `DeviceEvents`
- EDR process-access telemetry
- Windows Code Integrity logs
- vulnerable-driver detections

Do not alert solely because any process opened LSASS. Some legitimate software enumerates or accesses the process. Use:

- requested access mask
- signer and reputation
- parent process
- command line
- process ancestry
- loaded driver
- device role
- user privilege
- subsequent dump-file creation
- credential use after access

## Defender ASR

Rule:

```text
Block credential stealing from the Windows local security authority subsystem
GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
```

Microsoft states that the rule blocks access to LSASS memory. When LSA protection is enabled, the ASR rule may not provide additional protection and can be reported as not applicable.

Deployment pattern:

1. verify EDR and Defender health
2. use a pilot group
3. collect compatibility telemetry
4. move to Block
5. review exclusions critically
6. prefer LSA protection and Credential Guard as primary controls

## Service-account detections

Alert on:

- service installed or modified to use ordinary domain account
- service identity becomes privileged
- service account interactive logon
- service account RDP logon
- gMSA retrieval permission changes
- service account used from an unapproved host
- service-account password reset followed by service failures
- SPN changes
- ticket encryption downgrade or NTLM use

Potential events:

- 4624 — successful logon
- 4625 — failed logon
- 4648 — explicit credentials
- 4672 — special privileges assigned
- 4697 / System 7045 — service installed
- 4728, 4732, 4756 — privileged group membership changes
- 4768/4769 — Kerberos ticket activity
- 4776 — NTLM credential validation
- 5136 — AD object modified

## RDP detections

Correlate:

- 4624 logon type 10
- TerminalServices LocalSessionManager and RemoteConnectionManager logs
- source device identity and network zone
- user tier
- command-line mode for `mstsc.exe`
- Kerberos versus NTLM
- target classification
- session duration
- clipboard/drive redirection policy
- outbound authentication from the target during the session

High fidelity examples:

- Tier 0 account RDPs to a workstation
- PAW launches `mstsc.exe` without protected mode
- Remote Credential Guard workflow falls back to NTLM
- helpdesk account RDPs to endpoint without Restricted Admin
- RDP target immediately authenticates to multiple servers as the operator

## KQL concepts

### WDigest enabled

```kusto
DeviceRegistryEvents
| where RegistryKey endswith @"\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
| where RegistryValueName == "UseLogonCredential"
| where RegistryValueData in ("1", "0x00000001")
```

### Credentials Delegation wildcard

```kusto
DeviceRegistryEvents
| where RegistryKey contains @"\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
| where RegistryValueData contains "*"
```

### LSASS access precursor correlation

```kusto
let ControlChanges =
    DeviceRegistryEvents
    | where RegistryKey contains @"\SecurityProviders\WDigest"
       or RegistryKey contains @"\CredentialsDelegation"
       or RegistryValueName in ("RunAsPPL", "LsaCfgFlags", "DisableRestrictedAdmin");
let LsassActivity =
    DeviceEvents
    | where ActionType contains "Lsass"
       or ActionType contains "CredentialTheft";
ControlChanges
| join kind=innerunique LsassActivity on DeviceId
| where LsassActivity_Timestamp between (Timestamp .. Timestamp + 4h)
```

Adjust action names to the tenant's available schema.

## Triage checklist

- Is the device a PAW, server, workstation, DC, or jump host?
- Was the change delivered by approved GPO/Intune/RMM?
- Which user made the change?
- Was a privileged user logged on afterward?
- Did unsigned or unusual code access LSASS?
- Was a vulnerable driver loaded?
- Were dump files created?
- Did the account authenticate to new hosts?
- Was the account added to groups or delegated?
- Are Defender, EDR, Secure Boot, VBS, and tamper protection healthy?
- Does the timeline indicate testing, misconfiguration, or active intrusion?

## Retention

Keep endpoint security telemetry long enough to correlate policy drift with later privileged logons. A short retention window can miss delayed credential capture.
