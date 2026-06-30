Set-StrictMode -Version Latest

$script:LsassAsrRuleId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'

function New-CredentialExposureFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Informational','Low','Medium','High','Critical')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('Compliant','NonCompliant','Unknown','NotApplicable')][string]$Status,
        [AllowNull()][object]$CurrentValue,
        [Parameter(Mandatory)][string]$ExpectedValue,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Recommendation,
        [string]$Mitre = ''
    )

    [pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Check          = $Check
        Severity       = $Severity
        Status         = $Status
        CurrentValue   = $CurrentValue
        ExpectedValue  = $ExpectedValue
        Evidence       = $Evidence
        Recommendation = $Recommendation
        MITRE          = $Mitre
        ComputerName   = $env:COMPUTERNAME
        CollectedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
}

function Get-RegistryValueSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null; Error = $null }
        }

        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (@($key.GetValueNames()) -notcontains $Name) {
            return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null; Error = $null }
        }

        [pscustomobject]@{
            Exists = $true
            Value  = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            Kind   = $key.GetValueKind($Name).ToString()
            Error  = $null
        }
    }
    catch {
        [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null; Error = $_.Exception.Message }
    }
}

function Get-CredentialGuardFinding {
    [CmdletBinding()]
    param()

    try {
        $state = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $configured = @($state.SecurityServicesConfigured) -contains 1
        $running = @($state.SecurityServicesRunning) -contains 1

        New-CredentialExposureFinding -Id 'CG-001' -Category 'Credential Guard' `
            -Check 'Credential Guard runtime state' `
            -Severity $(if ($running) { 'Informational' } else { 'High' }) `
            -Status $(if ($running) { 'Compliant' } else { 'NonCompliant' }) `
            -CurrentValue ("Configured={0}; Running={1}; VBSStatus={2}" -f $configured,$running,$state.VirtualizationBasedSecurityStatus) `
            -ExpectedValue 'Credential Guard configured and running on supported privileged endpoints' `
            -Evidence 'Win32_DeviceGuard' `
            -Recommendation 'Enable VBS and Credential Guard through supported GPO or Intune policy after compatibility validation.' `
            -Mitre 'T1003.001'
    }
    catch {
        New-CredentialExposureFinding -Id 'CG-001' -Category 'Credential Guard' `
            -Check 'Credential Guard runtime state' -Severity 'Medium' -Status 'Unknown' `
            -CurrentValue $null -ExpectedValue 'Credential Guard runtime state is measurable' `
            -Evidence $_.Exception.Message `
            -Recommendation 'Verify Windows edition, VBS prerequisites, and the Device Guard WMI provider.' `
            -Mitre 'T1003.001'
    }
}

function Get-RegistrySecurityFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int[]]$CompliantValues,
        [Parameter(Mandatory)][string]$ExpectedValue,
        [Parameter(Mandatory)][string]$Recommendation,
        [Parameter(Mandatory)][string]$Mitre,
        [switch]$MissingIsCompliant,
        [ValidateSet('Medium','High','Critical')][string]$FailureSeverity = 'High'
    )

    $snapshot = Get-RegistryValueSnapshot -Path $Path -Name $Name
    if ($snapshot.Error) {
        return New-CredentialExposureFinding -Id $Id -Category $Category -Check $Check `
            -Severity 'Medium' -Status 'Unknown' -CurrentValue $null -ExpectedValue $ExpectedValue `
            -Evidence $snapshot.Error -Recommendation $Recommendation -Mitre $Mitre
    }

    if (-not $snapshot.Exists) {
        $status = if ($MissingIsCompliant) { 'Compliant' } else { 'NonCompliant' }
        $severity = if ($MissingIsCompliant) { 'Informational' } else { $FailureSeverity }
        return New-CredentialExposureFinding -Id $Id -Category $Category -Check $Check `
            -Severity $severity -Status $status -CurrentValue '<missing>' -ExpectedValue $ExpectedValue `
            -Evidence "$Path\$Name" -Recommendation $Recommendation -Mitre $Mitre
    }

    $compliant = $CompliantValues -contains [int]$snapshot.Value
    New-CredentialExposureFinding -Id $Id -Category $Category -Check $Check `
        -Severity $(if ($compliant) { 'Informational' } else { $FailureSeverity }) `
        -Status $(if ($compliant) { 'Compliant' } else { 'NonCompliant' }) `
        -CurrentValue $snapshot.Value -ExpectedValue $ExpectedValue `
        -Evidence "$Path\$Name" -Recommendation $Recommendation -Mitre $Mitre
}

function Get-CredentialDelegationFinding {
    [CmdletBinding()]
    param()

    $basePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    $policyNames = @(
        'AllowDefaultCredentials',
        'AllowDefCredentialsWhenNTLMOnly',
        'AllowFreshCredentials',
        'AllowFreshCredentialsWhenNTLMOnly',
        'AllowSavedCredentials',
        'AllowSavedCredentialsWhenNTLMOnly'
    )

    foreach ($policyName in $policyNames) {
        $snapshot = Get-RegistryValueSnapshot -Path $basePath -Name $policyName
        $enabled = $snapshot.Exists -and ([int]$snapshot.Value -eq 1)
        $targets = New-Object System.Collections.Generic.List[string]
        $targetPath = Join-Path -Path $basePath -ChildPath $policyName

        if (Test-Path -LiteralPath $targetPath) {
            try {
                $targetKey = Get-Item -LiteralPath $targetPath -ErrorAction Stop
                foreach ($valueName in @($targetKey.GetValueNames())) {
                    $targetValue = [string]$targetKey.GetValue($valueName)
                    if (-not [string]::IsNullOrWhiteSpace($targetValue)) {
                        $targets.Add($targetValue)
                    }
                }
            }
            catch {
                $targets.Add("<enumeration-error: $($_.Exception.Message)>")
            }
        }

        $wildcard = @($targets | Where-Object { $_ -match '\*' }).Count -gt 0
        $severity = if ($enabled -and ($wildcard -or $policyName -like '*NTLMOnly')) {
            'Critical'
        }
        elseif ($enabled) {
            'High'
        }
        else {
            'Informational'
        }

        New-CredentialExposureFinding -Id ("CD-{0}" -f $policyName) `
            -Category 'Credentials Delegation' -Check $policyName -Severity $severity `
            -Status $(if ($enabled) { 'NonCompliant' } else { 'Compliant' }) `
            -CurrentValue ("Enabled={0}; Targets={1}" -f $enabled,(($targets.ToArray() -join ', ') -replace '^$','<none>')) `
            -ExpectedValue 'Disabled unless narrowly justified; no broad wildcards; avoid NTLM-only delegation' `
            -Evidence "$basePath\$policyName" `
            -Recommendation 'Use Kerberos and Remote Credential Guard; remove wildcard and NTLM-only delegation.' `
            -Mitre 'T1021.001'
    }
}

function Get-LsassAsrFinding {
    [CmdletBinding()]
    param()

    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        return New-CredentialExposureFinding -Id 'ASR-001' -Category 'Defender ASR' `
            -Check 'Block credential stealing from LSASS' -Severity 'Medium' -Status 'Unknown' `
            -CurrentValue '<Get-MpPreference unavailable>' `
            -ExpectedValue 'Block, or NotApplicable when LSA protection provides the control' `
            -Evidence $script:LsassAsrRuleId `
            -Recommendation 'Verify Defender health and centrally managed ASR policy.' -Mitre 'T1003.001'
    }

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $ids = @($preference.AttackSurfaceReductionRules_Ids)
        $actions = @($preference.AttackSurfaceReductionRules_Actions)
        $index = [Array]::IndexOf($ids, $script:LsassAsrRuleId)

        if ($index -lt 0) {
            return New-CredentialExposureFinding -Id 'ASR-001' -Category 'Defender ASR' `
                -Check 'Block credential stealing from LSASS' -Severity 'Medium' -Status 'NonCompliant' `
                -CurrentValue '<not configured>' -ExpectedValue 'Block where applicable' `
                -Evidence $script:LsassAsrRuleId `
                -Recommendation 'Pilot and enable the LSASS credential-theft ASR rule where appropriate.' -Mitre 'T1003.001'
        }

        $action = [int]$actions[$index]
        $actionName = switch ($action) { 0 {'Disabled'} 1 {'Block'} 2 {'Audit'} 6 {'Warn'} default {"Unknown($action)"} }
        New-CredentialExposureFinding -Id 'ASR-001' -Category 'Defender ASR' `
            -Check 'Block credential stealing from LSASS' `
            -Severity $(if ($action -eq 1) { 'Informational' } elseif ($action -eq 2) { 'Medium' } else { 'High' }) `
            -Status $(if ($action -eq 1) { 'Compliant' } else { 'NonCompliant' }) `
            -CurrentValue $actionName -ExpectedValue 'Block where applicable' -Evidence $script:LsassAsrRuleId `
            -Recommendation 'Move from Audit/Warn to Block after validation, or verify enforced LSA protection.' -Mitre 'T1003.001'
    }
    catch {
        New-CredentialExposureFinding -Id 'ASR-001' -Category 'Defender ASR' `
            -Check 'Block credential stealing from LSASS' -Severity 'Medium' -Status 'Unknown' `
            -CurrentValue $null -ExpectedValue 'ASR state is measurable' -Evidence $_.Exception.Message `
            -Recommendation 'Review Defender health and policy conflicts.' -Mitre 'T1003.001'
    }
}

function Get-ServiceIdentityClassification {
    [CmdletBinding()]
    param([AllowNull()][string]$Account)

    if ([string]::IsNullOrWhiteSpace($Account)) { return 'Unknown' }
    $normalized = $Account.Trim()

    if ($normalized -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') { return 'BuiltInLocalSystem' }
    if ($normalized -match '^(LocalService|NT AUTHORITY\\LocalService)$') { return 'BuiltInLocalService' }
    if ($normalized -match '^(NetworkService|NT AUTHORITY\\NetworkService)$') { return 'BuiltInNetworkService' }
    if ($normalized -like 'NT SERVICE\*') { return 'VirtualServiceAccount' }
    if ($normalized.EndsWith('$')) { return 'ManagedServiceAccountHeuristic' }

    $escapedComputer = [Regex]::Escape($env:COMPUTERNAME)
    if ($normalized -match '^\.\\' -or $normalized -match "^$escapedComputer\\") { return 'OrdinaryLocalAccount' }
    if ($normalized -match '\\' -or $normalized -match '@') { return 'OrdinaryDomainAccount' }
    'Unknown'
}

function Get-ServiceAccountFinding {
    [CmdletBinding()]
    param([switch]$IncludeCompliantServices)

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    }
    catch {
        return ,(New-CredentialExposureFinding -Id 'SVC-000' -Category 'Service Accounts' `
            -Check 'Service identity inventory' -Severity 'Medium' -Status 'Unknown' `
            -CurrentValue $null -ExpectedValue 'Service identities are enumerable' -Evidence $_.Exception.Message `
            -Recommendation 'Verify CIM/WMI health and local permissions.' -Mitre 'T1543.003')
    }

    foreach ($service in $services) {
        $classification = Get-ServiceIdentityClassification -Account ([string]$service.StartName)
        $risky = $classification -in @('OrdinaryLocalAccount','OrdinaryDomainAccount','Unknown')
        if (-not $risky -and -not $IncludeCompliantServices) { continue }

        $severity = if ($classification -eq 'OrdinaryDomainAccount' -and (($service.StartMode -eq 'Auto') -or ($service.State -eq 'Running'))) {
            'High'
        }
        elseif ($risky) {
            'Medium'
        }
        else {
            'Informational'
        }

        New-CredentialExposureFinding -Id ("SVC-{0}" -f $service.Name) -Category 'Service Accounts' `
            -Check $service.DisplayName -Severity $severity `
            -Status $(if ($risky) { 'NonCompliant' } else { 'Compliant' }) `
            -CurrentValue ("Identity={0}; Classification={1}; State={2}; StartMode={3}" -f $service.StartName,$classification,$service.State,$service.StartMode) `
            -ExpectedValue 'Built-in, virtual, or managed service account with least privilege' `
            -Evidence ("Win32_Service Name={0}" -f $service.Name) `
            -Recommendation $(if ($risky) {'Migrate to gMSA/virtual account where supported; review privilege, SPNs, logon rights, and host scope.'} else {'Validate least privilege, retrieval-host scope, ACLs, and logon restrictions.'}) `
            -Mitre 'T1543.003'
    }
}

function Invoke-WindowsCredentialExposureAudit {
    [CmdletBinding()]
    param([switch]$IncludeCompliantServices)

    if ($env:OS -ne 'Windows_NT') { throw 'This audit module must be run on Windows.' }

    $findings = New-Object System.Collections.Generic.List[object]
    $findings.Add((Get-CredentialGuardFinding))
    $findings.Add((Get-RegistrySecurityFinding -Id 'LSA-001' -Category 'LSA Protection' `
        -Check 'LSASS protected process light configuration' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -CompliantValues @(1,2) -ExpectedValue 'RunAsPPL=1 or supported enforced state' `
        -Recommendation 'Enable LSA protection through supported policy after validating LSA plugins.' -Mitre 'T1003.001'))
    $findings.Add((Get-RegistrySecurityFinding -Id 'WD-001' -Category 'WDigest' `
        -Check 'Plaintext logon credential caching' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -CompliantValues @(0) -ExpectedValue 'UseLogonCredential=0 or absent on modern Windows' `
        -Recommendation 'Set UseLogonCredential to 0 and alert on any change to 1.' -Mitre 'T1003.001' `
        -MissingIsCompliant -FailureSeverity Critical))
    $findings.Add((Get-RegistrySecurityFinding -Id 'CM-001' -Category 'Credential Manager' `
        -Check 'Domain credential persistence policy' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'DisableDomainCreds' -CompliantValues @(1) -ExpectedValue 'DisableDomainCreds=1 on privileged devices where compatible' `
        -Recommendation 'Enable the network credential storage prohibition after compatibility testing.' -Mitre 'T1555'))
    $findings.Add((Get-RegistrySecurityFinding -Id 'RDP-001' -Category 'RDP' `
        -Check 'Restricted Admin/Remote Credential Guard host support' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'DisableRestrictedAdmin' -CompliantValues @(0) -ExpectedValue 'DisableRestrictedAdmin=0 on approved RDP targets' `
        -Recommendation 'Enable protected RDP host support and enforce the appropriate client mode.' -Mitre 'T1021.001'))
    $findings.Add((Get-RegistrySecurityFinding -Id 'RDP-002' -Category 'RDP' `
        -Check 'Delegation of non-exportable credentials' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
        -Name 'AllowProtectedCreds' -CompliantValues @(1) -ExpectedValue 'AllowProtectedCreds=1 on approved RDP targets' `
        -Recommendation 'Enable Remote Credential Guard host support through GPO or Intune.' -Mitre 'T1021.001'))
    $findings.Add((Get-LsassAsrFinding))

    foreach ($finding in @(Get-CredentialDelegationFinding)) { $findings.Add($finding) }
    foreach ($finding in @(Get-ServiceAccountFinding -IncludeCompliantServices:$IncludeCompliantServices)) { $findings.Add($finding) }
    $findings.ToArray()
}

function Set-WindowsCredentialHardening {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$DisableWDigest,
        [switch]$PreventDomainCredentialStorage,
        [switch]$EnableRemoteCredentialGuardHostSupport,
        [switch]$DisableDefaultCredentialDelegation,
        [ValidateSet('Audit','Block')][string]$LsassASRMode,
        [string]$BackupPath
    )

    if ($env:OS -ne 'Windows_NT') { throw 'This hardening function must be run on Windows.' }
    $selected = $DisableWDigest -or $PreventDomainCredentialStorage -or $EnableRemoteCredentialGuardHostSupport -or $DisableDefaultCredentialDelegation -or -not [string]::IsNullOrWhiteSpace($LsassASRMode)
    if (-not $selected) { throw 'No hardening control selected. Supply at least one explicit switch.' }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated PowerShell session is required.' }

    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $BackupPath = Join-Path (Join-Path (Get-Location) 'backups') ("credential-hardening-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    $targets = New-Object System.Collections.Generic.List[object]
    if ($DisableWDigest) { $targets.Add([pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';Name='UseLogonCredential';Value=0}) }
    if ($PreventDomainCredentialStorage) { $targets.Add([pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='DisableDomainCreds';Value=1}) }
    if ($EnableRemoteCredentialGuardHostSupport) {
        $targets.Add([pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='DisableRestrictedAdmin';Value=0})
        $targets.Add([pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation';Name='AllowProtectedCreds';Value=1})
    }
    if ($DisableDefaultCredentialDelegation) {
        foreach ($name in @('AllowDefaultCredentials','AllowDefCredentialsWhenNTLMOnly','AllowSavedCredentials','AllowSavedCredentialsWhenNTLMOnly')) {
            $targets.Add([pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation';Name=$name;Value=0})
        }
    }

    $backup = [ordered]@{
        SchemaVersion = 1
        ComputerName = $env:COMPUTERNAME
        CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
        RegistryValues = @($targets | ForEach-Object {
            $old = Get-RegistryValueSnapshot -Path $_.Path -Name $_.Name
            [pscustomobject]@{Path=$_.Path;Name=$_.Name;Existed=$old.Exists;OldValue=$old.Value;OldKind=$old.Kind;PlannedNew=$_.Value}
        })
        AsrChange = $LsassASRMode
    }

    if ($PSCmdlet.ShouldProcess($BackupPath,'Write configuration backup')) {
        New-Item -ItemType Directory -Path (Split-Path $BackupPath -Parent) -Force -ErrorAction Stop | Out-Null
        $backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BackupPath -Encoding UTF8 -ErrorAction Stop
    }

    foreach ($target in $targets) {
        if ($PSCmdlet.ShouldProcess("$($target.Path)\$($target.Name)","Set DWORD to $($target.Value)")) {
            New-Item -Path $target.Path -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $target.Path -Name $target.Name -PropertyType DWord -Value $target.Value -Force -ErrorAction Stop | Out-Null
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($LsassASRMode)) {
        if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) { throw 'Add-MpPreference is unavailable. Configure ASR centrally.' }
        $action = if ($LsassASRMode -eq 'Block') { 'Enabled' } else { 'AuditMode' }
        if ($PSCmdlet.ShouldProcess($script:LsassAsrRuleId,"Set Defender ASR mode to $LsassASRMode")) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $script:LsassAsrRuleId -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
        }
    }

    [pscustomobject]@{
        BackupPath = $BackupPath
        RegistryChangesRequested = $targets.Count
        AsrModeRequested = $LsassASRMode
        RestartRecommended = [bool]$PreventDomainCredentialStorage
    }
}

Export-ModuleMember -Function @('Invoke-WindowsCredentialExposureAudit','Set-WindowsCredentialHardening')
