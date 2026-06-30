# CredSSP and Windows Credentials Delegation policy

## Purpose of delegation

Credential delegation allows a client to authenticate to a remote service by supplying credentials or credential material through CredSSP. This can enable single sign-on and second-hop access, but it increases the trust placed in the remote host.

The policy area is:

```text
Computer Configuration
└─ Administrative Templates
   └─ System
      └─ Credentials Delegation
```

Common policy names include:

- Allow delegating default credentials
- Allow delegating default credentials with NTLM-only server authentication
- Allow delegating fresh credentials
- Allow delegating fresh credentials with NTLM-only server authentication
- Allow delegating saved credentials
- Allow delegating saved credentials with NTLM-only server authentication
- Deny delegating default credentials
- Deny delegating fresh credentials
- Deny delegating saved credentials
- Remote host allows delegation of non-exportable credentials
- Restrict delegation of credentials to remote servers

## Default, fresh, and saved credentials

- **Default credentials** are associated with the current signed-in session.
- **Fresh credentials** are entered for the current connection.
- **Saved credentials** originate from persistent credential storage.

The exact effect depends on the protocol, server identity, target SPN, authentication method, and client/host policy.

## Registry-backed policy

Primary path:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
```

Examples of control values:

```text
AllowDefaultCredentials
AllowDefCredentialsWhenNTLMOnly
AllowFreshCredentials
AllowFreshCredentialsWhenNTLMOnly
AllowSavedCredentials
AllowSavedCredentialsWhenNTLMOnly
DenyDefaultCredentials
DenyFreshCredentials
DenySavedCredentials
AllowProtectedCreds
```

Target lists may exist in subkeys with entries such as:

```text
TERMSRV/server01.contoso.com
TERMSRV/*.contoso.com
TERMSRV/*
*
```

A broad wildcard dramatically expands the set of hosts trusted to receive delegated credentials.

## Why NTLM-only delegation is higher risk

Kerberos authenticates the server through an SPN and domain trust path. NTLM-only delegation weakens target identity assurance and is vulnerable to relay and name-resolution abuse scenarios.

Risky examples:

```text
Allow delegating default credentials with NTLM-only server authentication
Target: TERMSRV/*
```

Prefer:

- Kerberos
- fully qualified host names
- correct SPNs
- narrow target allowlists
- Remote Credential Guard
- no delegation for privileged identities

## Protected RDP policies

Remote hosts must support delegation of non-exportable credentials:

```text
Remote host allows delegation of non-exportable credentials = Enabled
```

Registry:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
  AllowProtectedCreds = 1
```

Client enforcement can require Remote Credential Guard or Restricted Admin through:

```text
Restrict delegation of credentials to remote servers
```

Microsoft documents the modern MDM-backed setting and values, while the direct registry representation of the client policy is not consistently documented. Prefer Intune Settings Catalog or Group Policy rather than inventing registry values.

## Audit approach

The module enumerates:

- whether each risky allow policy is enabled
- configured target entries
- wildcard targets
- NTLM-only policy usage
- protected credential support
- deny policies

It does not read or expose any credential value.

## Hardening strategy

1. Inventory applications relying on CredSSP and second-hop access.
2. Disable NTLM-only delegation first.
3. Replace wildcard targets with explicit SPNs.
4. remove default and saved credential delegation where possible.
5. enable Remote Credential Guard host support.
6. enforce protected RDP mode from administrative devices.
7. use PowerShell Remoting with Kerberos or constrained delegation for management workflows.
8. redesign applications that require reusable user passwords.
9. block privileged identities from lower-tier systems.

## Compatibility

Disabling delegation can affect:

- RDP SSO
- second-hop management
- WinRM workflows using CredSSP
- applications that authenticate from a remote session to another server
- disconnected or cross-forest scenarios
- connections using IP addresses
- environments with broken SPNs or DNS

A compatibility failure is not a reason to enable `TERMSRV/*` globally. Fix identity and Kerberos design, or scope an exception to the smallest set of systems and users.

## Detection

Alert on:

- creation or modification of Credentials Delegation policy values
- new wildcard targets
- NTLM-only allow policies
- `AllowProtectedCreds` disabled
- `DisableRestrictedAdmin` changed to disable protected mode
- Group Policy changes affecting privileged workstation OUs
- privileged RDP authentication using NTLM
- CredSSP use from non-admin endpoints

## Incident response

If broad delegation is discovered:

- identify which devices received the policy
- determine which users authenticated from those devices
- inspect target hosts for compromise
- review NTLM and RDP event telemetry
- rotate credentials used during the exposure window when compromise is plausible
- remove broad policy and validate protected alternatives
