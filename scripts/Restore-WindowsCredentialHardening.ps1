#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BackupPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-RegistryKindToPropertyType {
    param([string]$Kind)

    switch ($Kind) {
        'DWord'        { 'DWord' }
        'QWord'        { 'QWord' }
        'String'       { 'String' }
        'ExpandString' { 'ExpandString' }
        'MultiString'  { 'MultiString' }
        'Binary'       { 'Binary' }
        default        { 'String' }
    }
}

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This script must be run on Windows.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated PowerShell session is required.'
    }

    $backup = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    foreach ($entry in @($backup.RegistryValues)) {
        $target = "$($entry.Path)\$($entry.Name)"

        if ([bool]$entry.Existed) {
            if ($PSCmdlet.ShouldProcess($target, "Restore value to '$($entry.OldValue)'")) {
                New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                $propertyType = Convert-RegistryKindToPropertyType -Kind ([string]$entry.OldKind)
                New-ItemProperty `
                    -Path $entry.Path `
                    -Name $entry.Name `
                    -PropertyType $propertyType `
                    -Value $entry.OldValue `
                    -Force `
                    -ErrorAction Stop | Out-Null
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess($target, 'Remove value because it did not exist before hardening')) {
                Remove-ItemProperty `
                    -Path $entry.Path `
                    -Name $entry.Name `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Output 'Registry-backed hardening values restored.'
    if ($backup.AsrChange) {
        Write-Warning 'The backup records an ASR change. Restore centrally managed Defender ASR policy through Intune/GPO/Defender management.'
    }
}
catch {
    Write-Error ("Restore failed: {0}" -f $_.Exception.Message)
    exit 1
}
