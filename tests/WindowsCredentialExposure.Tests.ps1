#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $modulePath = Join-Path `
        -Path $repoRoot `
        -ChildPath 'src\WindowsCredentialExposure\WindowsCredentialExposure.psd1'

    Import-Module -Name $modulePath -Force -ErrorAction Stop
}

Describe 'Module structure' {
    It 'imports the module' {
        Get-Module -Name WindowsCredentialExposure | Should -Not -BeNullOrEmpty
    }

    It 'exports the audit function' {
        Get-Command -Name Invoke-WindowsCredentialExposureAudit -ErrorAction Stop |
            Should -Not -BeNullOrEmpty
    }

    It 'exports the hardening function' {
        Get-Command -Name Set-WindowsCredentialHardening -ErrorAction Stop |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Defensive safety boundary' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $textFiles = Get-ChildItem `
            -Path $repoRoot `
            -Recurse `
            -File |
            Where-Object {
                $_.Extension -in @('.ps1', '.psm1', '.md', '.json', '.yml', '.yaml') -and
                $_.FullName -ne $PSCommandPath
            }

        $combined = ($textFiles | ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Raw
        }) -join "`n"
    }

    It 'does not include Mimikatz execution syntax' {
        $combined | Should -Not -Match '(?i)sekurlsa::|lsadump::|invoke-mimikatz'
    }

    It 'does not include LSASS dump commands' {
        $combined | Should -Not -Match '(?i)comsvcs\.dll\s+MiniDump|procdump(\.exe)?\s+-ma\s+lsass'
    }

    It 'does not include CQSecretsDumper execution' {
        $combined | Should -Not -Match '(?i)CQSecretsDumper\.exe'
    }
}

AfterAll {
    Remove-Module -Name WindowsCredentialExposure -ErrorAction SilentlyContinue
}
