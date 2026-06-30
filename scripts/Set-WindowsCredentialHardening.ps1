#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$DisableWDigest,
    [switch]$PreventDomainCredentialStorage,
    [switch]$EnableRemoteCredentialGuardHostSupport,
    [switch]$DisableDefaultCredentialDelegation,

    [ValidateSet('Audit', 'Block')]
    [string]$LsassASRMode,

    [string]$BackupPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $modulePath = Join-Path `
        -Path $PSScriptRoot `
        -ChildPath '..\src\WindowsCredentialExposure\WindowsCredentialExposure.psd1'

    Import-Module -Name $modulePath -Force -ErrorAction Stop

    $parameters = @{
        DisableWDigest                         = $DisableWDigest
        PreventDomainCredentialStorage         = $PreventDomainCredentialStorage
        EnableRemoteCredentialGuardHostSupport = $EnableRemoteCredentialGuardHostSupport
        DisableDefaultCredentialDelegation     = $DisableDefaultCredentialDelegation
        WhatIf                                 = $WhatIfPreference
        Confirm                                = $false
    }

    if (-not [string]::IsNullOrWhiteSpace($LsassASRMode)) {
        $parameters['LsassASRMode'] = $LsassASRMode
    }

    if (-not [string]::IsNullOrWhiteSpace($BackupPath)) {
        $parameters['BackupPath'] = $BackupPath
    }

    $result = Set-WindowsCredentialHardening @parameters
    $result | Format-List
}
catch {
    Write-Error ("Hardening failed: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    Remove-Module -Name WindowsCredentialExposure -ErrorAction SilentlyContinue
}
