# Threat model and protection boundaries

## Objective

The objective is to prevent a local compromise from becoming an enterprise credential compromise. The relevant question is not only, “Can an attacker dump LSASS?” It is:

> At what point in the credential lifecycle does plaintext or reusable authentication material exist, which principal can access it, and what architectural control can remove the need for it?

## Assumed attacker

The repository assumes an attacker may have one or more of the following:

- code execution in a standard user context
- local administrator rights
- `SYSTEM` execution through service abuse, EDR tampering, vulnerable drivers, or remote administration tooling
- control of an RDP target
- access to a machine where a privileged operator signs in
- permission to modify local policy or registry values
- time to wait for a new interactive, service, or network logon

It does not assume the attacker already controls a domain controller. Once a domain controller is compromised, endpoint-only controls are insufficient.

## Credential lifecycle

A password commonly passes through these stages:

1. **Entry** — keyboard, Windows credential UI, application prompt, API, unattended configuration.
2. **Application buffer** — the application receives characters or a `SecureString`-like representation.
3. **Authentication package** — CredSSP, Negotiate, Kerberos, NTLM, Digest, or another SSP processes the request.
4. **Logon session** — Windows creates tokens, tickets, hashes, keys, and protocol state.
5. **Persistence** — Credential Manager, LSA secrets, service configuration, scheduled tasks, browser vaults, or application configuration may retain data.
6. **Use and delegation** — credentials or derived material may be sent, redirected, or delegated to another host.
7. **Cleanup** — buffers and logon-session material should be released, but lifetime differs by component and active references.

A control that protects stage 4 does not automatically protect stages 1, 2, 5, or 6.

## What Credential Guard protects

Credential Guard uses virtualization-based security to isolate selected NTLM, Kerberos, and domain credential material. The normal operating system communicates with an isolated LSA component rather than directly reading the protected secrets.

It materially reduces:

- NTLM hash extraction from ordinary LSASS memory
- Kerberos TGT theft
- pass-the-hash and pass-the-ticket opportunities that rely on those protected values
- direct access to selected domain credentials by malware running with administrator rights

It does not claim to protect:

- credentials before they enter the protected authentication path
- plaintext retained by an application in its own process
- passwords configured for services or scheduled tasks
- credentials deliberately delegated to a remote host
- secrets stored in files, scripts, deployment systems, or third-party applications
- the AD database or local SAM
- active abuse of an already authenticated session
- a compromised hypervisor hosting a protected VM
- a domain controller's identity database

Microsoft explicitly recommends combining Credential Guard with other architectural controls.

## Trust boundaries

### Application boundary

`mstsc.exe`, credential UI components, line-of-business applications, installers, and management agents may require a credential value before an authentication package can use it. That creates a transient application-side exposure window.

Mitigation: remove password entry from lower-trust endpoints through smart cards, Windows Hello for Business, FIDO2, Remote Credential Guard, jump hosts, and PAWs.

### LSASS boundary

LSASS contains authentication packages and logon-session state. Credential Guard, LSA protection, Defender ASR, EDR tamper protection, and application control make unauthorized access harder.

Mitigation: enable VBS/Credential Guard, LSA protection, vulnerable-driver controls, ASR, and EDR.

### Service Control Manager boundary

A service configured with an ordinary user account must be able to start after reboot. Windows stores the service logon secret in a protected system store. `SYSTEM`-level compromise can often retrieve or use secrets available to the operating system.

Mitigation: use gMSA, virtual accounts, managed identities where available, or built-in service identities with constrained ACLs.

### Remote-host boundary

Standard CredSSP/RDP authentication can expose credentials or credential derivatives to the remote endpoint. A compromised target is therefore a credential-capture platform.

Mitigation: Remote Credential Guard, Restricted Admin, tiering, no privileged RDP to user workstations, and isolated admin workstations.

### Persistence boundary

Credential Manager and application vaults trade usability for persistent authentication. Encryption at rest does not make the secret harmless if malware executes as the user or obtains the required decryption context.

Mitigation: prevent storage for privileged accounts, use domain SSO instead of alternate credentials, and use short-lived tokens or certificates.

## Risk model

Suggested severity:

| Condition | Severity |
|---|---|
| WDigest explicitly enabled on a privileged workstation/server | Critical |
| Ordinary service account is Domain Admin or equivalent | Critical |
| Privileged RDP from admin workstation to untrusted endpoint without protected mode | Critical |
| Broad `TERMSRV/*` default credential delegation | High |
| Automatic service using ordinary reusable domain account | High |
| `DisableDomainCreds=0` on a PAW or admin jump host | High |
| Credential Guard or LSA protection missing on privileged endpoint | High |
| ASR in Audit mode while LSA protection is absent | Medium |
| Local service account with unique, rotated password and low privilege | Medium |
| Secure policy configured but restart pending | Medium |

## ATT&CK alignment

- T1003.001 — OS Credential Dumping: LSASS Memory
- T1555 — Credentials from Password Stores
- T1021.001 — Remote Services: RDP
- T1552 — Unsecured Credentials
- T1550 — Use Alternate Authentication Material
- T1543.003 — Windows Service

## Defensive principle

The strongest mitigation is to eliminate the password from the workflow. The next best option is to prevent it from reaching the lower-trust host. Memory protection and detection are essential, but they are later layers in the chain.
