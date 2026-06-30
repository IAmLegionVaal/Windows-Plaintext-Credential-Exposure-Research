# Reference matrix

| Area | Setting / artifact | Secure expectation | Notes |
|---|---|---|---|
| Credential Guard | `Win32_DeviceGuard.SecurityServicesRunning` contains `1` | Running on supported privileged endpoints | Validate edition and hardware |
| Credential Guard policy | `LsaCfgFlags` | Configured according to deployment design | Policy and runtime are different |
| LSA protection | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | `1` or supported enforced state | Test LSA plugins |
| WDigest | `...\SecurityProviders\WDigest\UseLogonCredential` | `0` or absent on modern Windows | Alert on value `1` |
| Credential persistence | `...\Control\Lsa\DisableDomainCreds` | `1` on PAWs/admin hosts where compatible | Restart required |
| RCG host support | `...\Control\Lsa\DisableRestrictedAdmin` | `0` | Supports RCG/Restricted Admin |
| RCG policy | `...\CredentialsDelegation\AllowProtectedCreds` | `1` | Remote host allows non-exportable delegation |
| Default delegation | `AllowDefaultCredentials` | disabled unless tightly justified | Inspect target list |
| NTLM-only delegation | `AllowDefCredentialsWhenNTLMOnly` | disabled | High risk |
| Saved credential delegation | `AllowSavedCredentials*` | disabled for privileged devices | Remove wildcard targets |
| ASR | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Block when LSA protection not sufficient/applicable | Audit during pilot |
| Services | `Win32_Service.StartName` | built-in, virtual, or gMSA | Review privileges separately |
| gMSA | `PrincipalsAllowedToRetrieveManagedPassword` | narrow host group | Validate SPNs and AES |
| RDP client | `/remoteGuard` | normal protected admin session | Kerberos only |
| RDP client | `/restrictedAdmin` | helpdesk to suspect endpoint | No outbound user SSO |
| Credential Manager | `cmdkey /list` metadata | no privileged saved creds | Do not export secrets |

## ATT&CK

| Technique | Relevance |
|---|---|
| T1003.001 | LSASS memory credential access |
| T1555 | Credential stores |
| T1021.001 | RDP |
| T1550 | Alternate authentication material |
| T1543.003 | Windows services |
| T1552 | Unsecured credentials |

## Primary Microsoft references

- Credential Guard overview  
  https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
- Remote Credential Guard  
  https://learn.microsoft.com/windows/security/identity-protection/remote-credential-guard
- Group Managed Service Accounts  
  https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview
- WDigest credential protection advisory  
  https://support.microsoft.com/en-US/security/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014
- Credential storage security option  
  https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
- CredentialsDelegation Policy CSP  
  https://learn.microsoft.com/windows/client-management/mdm/policy-csp-credentialsdelegation
- ASR rule reference  
  https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
- Sysmon  
  https://learn.microsoft.com/sysinternals/downloads/sysmon
