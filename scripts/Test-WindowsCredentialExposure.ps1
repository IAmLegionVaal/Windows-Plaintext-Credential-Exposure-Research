#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'CredentialExposureReport'),

    [switch]$IncludeCompliantServices,

    [switch]$FailOnHigh
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This script must be run on Windows.'
    }

    $modulePath = Join-Path `
        -Path $PSScriptRoot `
        -ChildPath '..\src\WindowsCredentialExposure\WindowsCredentialExposure.psd1'

    Import-Module -Name $modulePath -Force -ErrorAction Stop

    New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null
    $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path

    $findings = @(
        Invoke-WindowsCredentialExposureAudit `
            -IncludeCompliantServices:$IncludeCompliantServices
    )

    $jsonPath = Join-Path -Path $resolvedOutput -ChildPath 'findings.json'
    $csvPath = Join-Path -Path $resolvedOutput -ChildPath 'findings.csv'
    $contextPath = Join-Path -Path $resolvedOutput -ChildPath 'system-context.json'

    $findings |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $jsonPath -Encoding UTF8 -ErrorAction Stop

    $findings |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $context = [ordered]@{
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        CollectedAtUtc = [DateTime]::UtcNow.ToString('o')
        PowerShell     = $PSVersionTable.PSVersion.ToString()
        OS             = (Get-CimInstance -ClassName Win32_OperatingSystem |
                          Select-Object Caption, Version, BuildNumber, OSArchitecture)
        Note           = 'No credential values, hashes, tickets, DPAPI keys, or LSASS memory were collected.'
    }

    $context |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $contextPath -Encoding UTF8 -ErrorAction Stop

    $summary = $findings |
        Group-Object -Property Severity |
        Sort-Object -Property Name |
        Select-Object Name, Count

    Write-Output ''
    Write-Output 'Windows credential-exposure audit complete.'
    $summary | Format-Table -AutoSize
    Write-Output "Report: $resolvedOutput"

    if ($FailOnHigh) {
        $blocking = @($findings | Where-Object { $_.Severity -in @('High', 'Critical') -and $_.Status -eq 'NonCompliant' })
        if ($blocking.Count -gt 0) {
            Write-Error "Found $($blocking.Count) High/Critical noncompliant findings."
            exit 2
        }
    }

    exit 0
}
catch {
    Write-Error ("Audit failed: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    Remove-Module -Name WindowsCredentialExposure -ErrorAction SilentlyContinue
}
