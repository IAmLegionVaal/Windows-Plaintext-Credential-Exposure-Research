# RDP, MSTSC, CredSSP, and protected administration

## The normal RDP path

The classic Windows RDP client is `mstsc.exe`. With Network Level Authentication, CredSSP authenticates the user before the full desktop session is created. Depending on the selected mode, the client may use signed-in credentials, supplied credentials, or saved credentials.

In a standard RDP session, credentials are sent to and represented on the remote host. Microsoft documents that credentials are stored on the remote host and remain exposed to attackers controlling that host.

## Why MSTSC can still contain plaintext

Credential Guard protects selected secrets after they enter supported authentication packages and the isolated LSA path. It does not wrap every byte in the MSTSC process.

When a user manually types a password:

1. A Windows credential prompt receives the characters.
2. UI and client components must pass the supplied credential into CredSSP.
3. The password can exist transiently in application-owned memory before the buffer is cleared.
4. Endpoint compromise with sufficient rights may inspect those buffers or capture the credential before it reaches a protected authentication boundary.

This is why “Credential Guard is running” does not prove that manually entered credentials never existed in plaintext anywhere on the client.

The defensive answer is not to rely on better buffer clearing as the primary control. Remove manual password entry from the endpoint.

## Remote Credential Guard

Remote Credential Guard redirects Kerberos requests back to the originating client. Credentials and credential derivatives are not passed to the target host.

Security properties:

- the target does not receive the user's reusable credential
- SSO to other systems remains available inside the RDP session
- Kerberos is required; NTLM fallback is not allowed
- a live compromised target may act through the user's open session while the connection exists
- DNS, SPN, domain connectivity, and Kerberos health are prerequisites

One-session invocation:

```powershell
mstsc.exe /remoteGuard
```

Remote host support:

```text
Computer Configuration
└─ Administrative Templates
   └─ System
      └─ Credentials Delegation
         └─ Remote host allows delegation of non-exportable credentials = Enabled
```

Registry representation on the remote host:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  DisableRestrictedAdmin = 0

HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
  AllowProtectedCreds = 1
```

Test this with Kerberos-only connectivity. Connecting by IP address commonly prevents Kerberos because the expected SPN cannot be resolved.

## Restricted Admin

Restricted Admin also prevents credentials from being sent to the remote host, but the remote session cannot authenticate outbound as the signed-in user. Network access from the session uses the remote computer's identity.

Invocation:

```powershell
mstsc.exe /restrictedAdmin
```

This is often the preferred mode for helpdesk staff connecting to a workstation that may already be compromised. The lack of user-identity outbound SSO prevents the target from using the operator's identity to reach additional systems.

Trade-offs:

- local administrator membership is required on the target
- no user SSO to network resources
- workflows that require a second hop need redesign
- shared local admin passwords create a pass-the-hash risk; pair with Windows LAPS

## Standard RDP versus protected modes

| Property | Standard RDP | Remote Credential Guard | Restricted Admin |
|---|---:|---:|---:|
| Credentials sent to target | Yes | No | No |
| Outbound SSO as user | Yes | Yes | No |
| Kerberos required | No | Yes | No |
| Useful for helpdesk to suspect endpoint | Poor | Risk of live-session abuse | Preferred |
| Multi-hop workflows | Yes | Yes | No |
| Protects after disconnect | No | Yes | Yes |

## Tiering and PAW design

A protected RDP mode does not correct tier violations.

Recommended pattern:

- Tier 0 identities only sign in to Tier 0 PAWs and systems.
- Tier 1 server administrators use separate identities and server-admin jump hosts.
- Tier 2 workstation support uses separate identities and Restricted Admin.
- Production admin credentials never enter user workstations.
- RDP is restricted by firewall, identity, source subnet, device compliance, and time-bound access.
- Admin workstations do not browse email or the public web.
- Clipboard, drive, printer, and device redirection are restricted where operationally possible.

## Smart cards and passwordless credentials

Smart cards and certificate-backed authentication remove reusable password entry, but they are not magic. A compromised endpoint can still abuse an authenticated session, capture a PIN before protected UI boundaries, or request operations while the token is available.

Use:

- Windows Hello for Business
- FIDO2 security keys
- smart cards with protected PIN entry
- certificate-based authentication
- short-lived privileged access
- just-in-time group membership

## Detection ideas

Monitor:

- `mstsc.exe` launched without `/remoteGuard` or `/restrictedAdmin` from PAWs
- RDP connections from privileged devices to workstation VLANs
- NTLM authentication during intended Remote Credential Guard workflows
- direct IP-based RDP connections
- unusual process access to `mstsc.exe`, credential UI processes, or LSASS
- changes to `DisableRestrictedAdmin` and `AllowProtectedCreds`
- RDP use by Tier 0 identities outside approved jump hosts

## Validation

Use synthetic accounts and an isolated lab. Validate that:

- `klist` shows Kerberos use
- Remote Credential Guard fails rather than falling back to NTLM
- outbound SSO behaves as expected
- Restricted Admin cannot access shares as the operator
- event logs and EDR identify the selected mode
- business applications do not require unsafe delegation

Do not validate by extracting production credentials.
