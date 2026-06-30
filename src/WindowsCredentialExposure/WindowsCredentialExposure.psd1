@{
    RootModule        = 'WindowsCredentialExposure.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'ed53182c-82dc-4ccc-9ca2-26a264bf9c61'
    Author            = 'Dewald Pretorius'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Dewald Pretorius. MIT License.'
    Description       = 'Defensive Windows credential-exposure configuration audit and hardening helpers.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-WindowsCredentialExposureAudit',
        'Set-WindowsCredentialHardening'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Windows', 'Security', 'CredentialGuard', 'RDP', 'WDigest', 'gMSA', 'BlueTeam')
            LicenseUri = 'https://opensource.org/license/mit'
            ProjectUri = 'https://github.com/IAmLegionVaal/Windows-Plaintext-Credential-Exposure-Research'
        }
    }
}
