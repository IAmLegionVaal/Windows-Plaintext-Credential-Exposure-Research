# Credential Manager, alternate network credentials, and mapped drives

## Two different states

Mapped-drive authentication can create two distinct security conditions:

1. **Persistent saved credential** — a password is stored for later use, commonly through Credential Manager.
2. **Volatile authenticated session** — credentials are used to establish a network logon and protocol/session state exists while the session is active.

These are related but not identical.

Selecting **Remember my credentials** is an obvious persistence action. Selecting **Connect using different credentials** without remembering them may still create active authentication state and expose the supplied credential during entry and protocol processing.

## Credential Manager

Windows Credential Manager can store credentials for domain authentication and applications. Stored secrets are protected with Windows cryptographic mechanisms and user/machine context. They are not equivalent to plaintext in a normal registry value, but malware executing in the correct user or system context can attempt to use or decrypt them.

Safe metadata inventory:

```powershell
cmdkey.exe /list
```

This can display target and account metadata. Do not collect or publish vault databases, DPAPI master keys, or decrypted secrets.

## Network access security option

Policy:

```text
Network access: Do not allow storage of passwords and credentials for network authentication
```

Location:

```text
Computer Configuration
└─ Windows Settings
   └─ Security Settings
      └─ Local Policies
         └─ Security Options
```

Registry representation:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  DisableDomainCreds = 1
```

Microsoft documents that enabling this policy prevents Credential Manager from storing passwords and credentials for later domain authentication. A restart is required when the setting is changed through local or Group Policy.

## Compatibility impact

Enabling `DisableDomainCreds=1` can require users to re-enter passwords and can affect workflows that depend on saved domain credentials.

Test:

- mapped drives using alternate accounts
- scheduled tasks
- run-as workflows
- legacy applications
- disconnected laptops
- RDP saved credentials
- cross-domain resources
- scripts using `cmdkey`
- non-domain NAS appliances

For privileged access workstations and jump hosts, the usability cost is usually justified.

## Better mapped-drive design

Prefer:

- access using the signed-in domain identity
- Kerberos rather than NTLM
- group-based share and NTFS permissions
- DFS namespaces
- managed service identities for unattended access
- no alternate administrator credentials
- no local NAS admin credential reused by multiple users
- no passwords embedded in `net use`, scripts, GPP, or deployment tools

Avoid:

```text
net use Z: \\server\share /user:DOMAIN\AdminUser <password>
```

Even when hidden from command history, embedding credentials in scripts, process command lines, RMM jobs, or tickets creates additional exposure.

## Audit and response

Audit:

- `DisableDomainCreds`
- Credential Manager target metadata
- saved RDP entries
- mapped drives using alternate identities
- scheduled tasks and services with reusable accounts
- SMB authentication protocol
- privileged accounts on user workstations

When an alternate privileged credential may have been exposed:

1. disconnect the affected SMB/RDP sessions
2. remove saved credential entries
3. rotate the password or revoke the credential
4. inspect the endpoint for process access and malware
5. review network logons and lateral movement
6. replace the workflow with SSO, gMSA, certificate, or short-lived access
