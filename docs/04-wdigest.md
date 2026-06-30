# WDigest plaintext credential caching

## Background

WDigest is a Windows Security Support Provider associated with Digest authentication. Legacy Windows versions retained logon credentials in a form that enabled the provider to perform Digest authentication.

Microsoft's credential-protection update introduced the `UseLogonCredential` control:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
  UseLogonCredential (REG_DWORD)
```

Behavior:

- `0` — WDigest does not retain logon credentials for this purpose.
- `1` — WDigest stores credentials in memory.
- missing on Windows 8.1 / Server 2012 R2 and later — secure behavior is the default.

## Why this setting is dangerous

Setting the value to `1` reintroduces plaintext credential retention after a qualifying logon. It does not instantly reveal all prior passwords. An attacker commonly needs:

- permission to change the registry
- a new interactive logon after the change
- sufficient privilege to access the resulting authentication state
- time before the logon session ends and material is cleared

This creates an important detection sequence:

1. WDigest registry value changes to `1`.
2. A privileged user logs on.
3. A suspicious process attempts to access LSASS.
4. The account is used for lateral movement.

Treat step 1 as a high-priority precursor, not a harmless configuration drift event.

## Secure state

Audit:

```powershell
$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
Get-ItemProperty -Path $path -Name UseLogonCredential -ErrorAction SilentlyContinue
```

Enforce:

```powershell
New-Item -Path $path -Force | Out-Null
New-ItemProperty `
    -Path $path `
    -Name UseLogonCredential `
    -PropertyType DWord `
    -Value 0 `
    -Force | Out-Null
```

The repository hardening script performs this change only when `-DisableWDigest` is explicitly supplied.

## Credential Guard and Protected Users

Credential Guard and the Protected Users group add important controls, but the safe baseline is still to explicitly prevent WDigest plaintext caching. Avoid treating any one mitigation as permission to leave a dangerous registry value enabled.

Protected Users imposes authentication restrictions such as reduced credential caching and stronger Kerberos behavior. Test application compatibility before broad deployment.

## Monitoring

### Security event 4657

Enable **Audit Registry** and apply an appropriate SACL to the WDigest key. Event 4657 can record registry value modification.

### Sysmon event 13

Sysmon Registry value set events can record modification of the value when the configuration includes the path.

Conceptual filter:

```xml
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">\Control\SecurityProviders\WDigest\UseLogonCredential</TargetObject>
</RegistryEvent>
```

### Defender advanced hunting

Example concept; adapt schema and environment:

```kusto
DeviceRegistryEvents
| where RegistryKey endswith @"\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
| where RegistryValueName == "UseLogonCredential"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, RegistryValueData, RegistryKey
```

Escalate when `RegistryValueData` indicates `1`.

## Incident response

When WDigest is found enabled unexpectedly:

1. Isolate the endpoint if privilege exposure is plausible.
2. Record the modifying process, account, timestamp, parent process, and deployment source.
3. Set `UseLogonCredential=0`.
4. Identify users who logged on after the value was enabled.
5. Prioritize password reset and session revocation for privileged accounts.
6. Hunt for LSASS access, suspicious dumps, vulnerable-driver loading, and lateral movement.
7. Validate Credential Guard, LSA protection, ASR, EDR health, and tamper protection.
8. Determine whether Group Policy, Intune, a script, malware, or a local administrator caused the change.
9. Rebuild the endpoint when credential-theft tooling or SYSTEM compromise is confirmed.

## Safe lab validation

Do not enable WDigest on a production endpoint to prove that it is dangerous. Use:

- a disposable isolated VM
- synthetic local/domain accounts
- no production network path
- snapshot before testing
- simulated findings included in this repository
- registry auditing and EDR telemetry rather than credential extraction

The repository intentionally does not include a command that enables `UseLogonCredential=1`.
