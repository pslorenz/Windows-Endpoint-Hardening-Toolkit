#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verify-Hardening.ps1V1
    Checks the current hardening state of an endpoint and reports
    which modules are applied, partially applied, or missing.

    Run this anytime you need to answer: "What is the state of this machine?"

.DESCRIPTION
    Performs read-only checks against every setting in the hardening toolkit.
    Changes nothing. Safe to run at any time, on any machine, repeatedly.

    Output: a scored summary to the console and a detailed CSV report
    saved to C:\ProgramData\EndpointHardening\verify-<timestamp>.csv

    Deploy via NinjaRMM as a scheduled script (weekly) or run ad-hoc.
    The exit code equals the number of failed checks, so NinjaRMM can
    alert on non-zero exits.

.NOTES
    Run As: System | Timeout: 120s
    Read-only. No changes made. No reboot needed.
#>

$LogDir    = "$env:ProgramData\EndpointHardening"
$ReportCSV = "$LogDir\verify-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$results = [System.Collections.ArrayList]::new()

function Test-Check {
    param(
        [string]$Module,
        [string]$Check,
        [string]$Expected,
        [string]$Actual,
        [bool]$Pass
    )
    $status = if ($Pass) { "PASS" } else { "FAIL" }
    $color  = if ($Pass) { "Green" } else { "Red" }

    $obj = [PSCustomObject]@{
        Module   = $Module
        Check    = $Check
        Expected = $Expected
        Actual   = $Actual
        Status   = $status
    }
    $results.Add($obj) | Out-Null

    $icon = if ($Pass) { "[+]" } else { "[-]" }
    Write-Host "  $icon $Check" -ForegroundColor $color -NoNewline
    if (-not $Pass) { Write-Host " (expected: $Expected, got: $Actual)" -ForegroundColor DarkGray }
    else { Write-Host "" }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return $val
    } catch { return $null }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  ENDPOINT HARDENING VERIFICATION" -ForegroundColor Cyan
Write-Host "  $env:COMPUTERNAME | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ============================================================================
# BASE SCRIPT CHECKS
# ============================================================================
Write-Host ""
Write-Host "--- Base Script: Harden-Endpoint-v2 ---" -ForegroundColor Yellow

# WScript/CScript IFEO
$ws = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wscript.exe" "Debugger"
Test-Check "Base" "WScript IFEO block" "nul" "$ws" ($ws -eq "nul")

$cs = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cscript.exe" "Debugger"
Test-Check "Base" "CScript IFEO block" "nul" "$cs" ($cs -eq "nul")

# Constrained Language Mode
$clm = [System.Environment]::GetEnvironmentVariable("__PSLockdownPolicy", "Machine")
Test-Check "Base" "PowerShell Constrained Language Mode" "4" "$clm" ($clm -eq "4")

# Script Block Logging
$sbl = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
Test-Check "Base" "PS Script Block Logging" "1" "$sbl" ($sbl -eq 1)

# Transcription
$tr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
Test-Check "Base" "PS Transcription" "1" "$tr" ($tr -eq 1)

# PS v2
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
$psv2State = if ($psv2) { $psv2.State } else { "NotPresent" }
Test-Check "Base" "PowerShell v2 disabled" "Disabled/NotPresent" "$psv2State" ($psv2State -ne "Enabled")

# ASR rules
$asrIds = (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids
$asrCount = if ($asrIds) { $asrIds.Count } else { 0 }
Test-Check "Base" "ASR rules configured" ">=10" "$asrCount" ($asrCount -ge 10)

# DNS
$dns = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains "9.9.9.9" } | Measure-Object).Count
Test-Check "Base" "Quad9 DNS configured" ">=1 adapter" "$dns adapters" ($dns -ge 1)

# MSI restriction
$msi = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "DisableMSI"
Test-Check "Base" "MSI install restricted" "1" "$msi" ($msi -eq 1)

# Autorun
$ar = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
Test-Check "Base" "Autorun disabled" "255" "$ar" ($ar -eq 255)

# WDigest
$wd = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
Test-Check "Base" "WDigest disabled" "0" "$wd" ($wd -eq 0)

# LSA Protection
$lsa = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
Test-Check "Base" "LSA Protection (RunAsPPL)" "1" "$lsa" ($lsa -eq 1)

# LLMNR
$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
Test-Check "Base" "LLMNR disabled" "0" "$llmnr" ($llmnr -eq 0)

# SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
$smb1State = if ($smb1) { $smb1.State } else { "NotPresent" }
Test-Check "Base" "SMBv1 disabled" "Disabled/NotPresent" "$smb1State" ($smb1State -ne "Enabled")

# Firewall on
$fwProfiles = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }
Test-Check "Base" "Windows Firewall enabled" "3 profiles" "$($fwProfiles.Count) profiles" ($fwProfiles.Count -eq 3)

# LOLBin firewall rules (spot check)
$fwBlock = (Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Block*Outbound*" } | Measure-Object).Count
Test-Check "Base" "LOLBin outbound firewall rules" ">=5" "$fwBlock rules" ($fwBlock -ge 5)

# ============================================================================
# MODULE 1: Local Admin Removal
# ============================================================================
Write-Host ""
Write-Host "--- Module 1: Local Admin Removal ---" -ForegroundColor Yellow

$adminAccount = Get-LocalUser -Name "LocalITAdmin" -ErrorAction SilentlyContinue
Test-Check "Mod1" "LocalITAdmin account exists" "True" "$($null -ne $adminAccount)" ($null -ne $adminAccount)

if ($adminAccount) {
    $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*LocalITAdmin" } | Measure-Object).Count
    Test-Check "Mod1" "LocalITAdmin in Administrators group" "1" "$isAdmin" ($isAdmin -ge 1)
}

# Check if any non-system users are still admins
$adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$systemAccounts = @("Administrator", "LocalITAdmin", "DefaultAccount", "WDAGUtilityAccount")
$dailyAdmins = $adminMembers | Where-Object {
    $_.ObjectClass -eq "User" -and
    $_.PrincipalSource -eq "Local" -and
    $_.Name.Split('\')[-1] -notin $systemAccounts
}
$dailyAdminCount = ($dailyAdmins | Measure-Object).Count
Test-Check "Mod1" "Daily users removed from Administrators" "0" "$dailyAdminCount daily users still admin" ($dailyAdminCount -eq 0)

# ============================================================================
# MODULE 2: Browser Hardening
# ============================================================================
Write-Host ""
Write-Host "--- Module 2: Browser Hardening ---" -ForegroundColor Yellow

$ss = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled"
Test-Check "Mod2" "Edge SmartScreen enforced" "1" "$ss" ($ss -eq 1)

$ssOverride = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "PreventSmartScreenPromptOverride"
Test-Check "Mod2" "Edge SmartScreen bypass blocked" "1" "$ssOverride" ($ssOverride -eq 1)

$extBlock = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist" "1"
Test-Check "Mod2" "Edge extensions blocked by default" "*" "$extBlock" ($extBlock -eq "*")

# ============================================================================
# MODULE 3: RDP Lockdown
# ============================================================================
Write-Host ""
Write-Host "--- Module 3: RDP Lockdown ---" -ForegroundColor Yellow

$nla = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
Test-Check "Mod3" "NLA enforced" "1" "$nla" ($nla -eq 1)

$secLayer = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "SecurityLayer"
Test-Check "Mod3" "RDP security layer (TLS)" "2" "$secLayer" ($secLayer -eq 2)

# ============================================================================
# MODULE 4: Sysmon
# ============================================================================
Write-Host ""
Write-Host "--- Module 4: Sysmon ---" -ForegroundColor Yellow

$sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
$sysmonRunning = $sysmonSvc -and $sysmonSvc.Status -eq "Running"
Test-Check "Mod4" "Sysmon service running" "Running" "$(if ($sysmonSvc) { $sysmonSvc.Status } else { 'Not installed' })" $sysmonRunning

if ($sysmonRunning) {
    $lastEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
    $eventsFlowing = $null -ne $lastEvent
    Test-Check "Mod4" "Sysmon events flowing" "True" "$eventsFlowing" $eventsFlowing
}

# ============================================================================
# MODULE 5: BitLocker
# ============================================================================
Write-Host ""
Write-Host "--- Module 5: BitLocker ---" -ForegroundColor Yellow

$bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
$blOn = $bl -and $bl.ProtectionStatus -eq "On"
Test-Check "Mod5" "BitLocker protection on C:" "On" "$(if ($bl) { $bl.ProtectionStatus } else { 'Not configured' })" $blOn

if ($bl) {
    $recoveryKey = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
    Test-Check "Mod5" "Recovery key protector exists" "True" "$($null -ne $recoveryKey)" ($null -ne $recoveryKey)
}

# ============================================================================
# MODULE 6: USB Control
# ============================================================================
Write-Host ""
Write-Host "--- Module 6: USB Control ---" -ForegroundColor Yellow

$usbWrite = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Write"
Test-Check "Mod6" "USB write blocked" "1" "$usbWrite" ($usbWrite -eq 1)

# ============================================================================
# MODULE 7: WDAC Audit
# ============================================================================
Write-Host ""
Write-Host "--- Module 7: WDAC Audit ---" -ForegroundColor Yellow

$wdacPolicy = Test-Path "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"
Test-Check "Mod7" "WDAC policy deployed" "True" "$wdacPolicy" $wdacPolicy

# ============================================================================
# MODULE 8: Defender Advanced
# ============================================================================
Write-Host ""
Write-Host "--- Module 8: Defender Advanced ---" -ForegroundColor Yellow

$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref) {
    Test-Check "Mod8" "Cloud block level (High)" "2" "$($mpPref.CloudBlockLevel)" ($mpPref.CloudBlockLevel -ge 2)
    Test-Check "Mod8" "Cloud extended timeout" "50" "$($mpPref.CloudExtendedTimeout)" ($mpPref.CloudExtendedTimeout -ge 50)

    $cfaMode = $mpPref.EnableControlledFolderAccess
    $cfaLabel = switch ($cfaMode) { 0 { "Off" } 1 { "Block" } 2 { "Audit" } default { "Unknown" } }
    Test-Check "Mod8" "Controlled Folder Access" "Audit or Block" "$cfaLabel ($cfaMode)" ($cfaMode -ge 1)

    $np = $mpPref.EnableNetworkProtection
    $npLabel = switch ($np) { 0 { "Disabled" } 1 { "Enabled" } 2 { "Audit" } default { "Unknown" } }
    Test-Check "Mod8" "Network Protection" "Enabled" "$npLabel" ($np -ge 1)
}

# ============================================================================
# MODULE 9: Network Protocol Hardening
# ============================================================================
Write-Host ""
Write-Host "--- Module 9: Network Protocol ---" -ForegroundColor Yellow

$nodeType = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType"
Test-Check "Mod9" "NetBIOS NodeType (P-node)" "2" "$nodeType" ($nodeType -eq 2)

$mdns = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
Test-Check "Mod9" "mDNS disabled" "0" "$mdns" ($mdns -eq 0)

$restrictAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
Test-Check "Mod9" "Anonymous enumeration restricted" "1" "$restrictAnon" ($restrictAnon -eq 1)

$smbSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
Test-Check "Mod9" "SMB signing required (server)" "1" "$smbSign" ($smbSign -eq 1)

$ntlm = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
Test-Check "Mod9" "NTLMv2 enforced" "5" "$ntlm" ($ntlm -ge 5)

# ============================================================================
# MODULE 10: Credential Guard
# ============================================================================
Write-Host ""
Write-Host "--- Module 10: Credential Guard ---" -ForegroundColor Yellow

$vbs = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
Test-Check "Mod10" "VBS enabled" "1" "$vbs" ($vbs -eq 1)

$cgFlags = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags"
Test-Check "Mod10" "Credential Guard enabled" "1" "$cgFlags" ($cgFlags -eq 1)

$lockTimeout = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
Test-Check "Mod10" "Screen lock timeout set" ">0" "$lockTimeout" ($lockTimeout -gt 0)

# ============================================================================
# MODULE 11: Print Spooler
# ============================================================================
Write-Host ""
Write-Host "--- Module 11: Print Spooler ---" -ForegroundColor Yellow

$printRestrict = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators"
Test-Check "Mod11" "Printer drivers admin-only" "1" "$printRestrict" ($printRestrict -eq 1)

# ============================================================================
# MODULE 12: LOLBin Expansion
# ============================================================================
Write-Host ""
Write-Host "--- Module 12: LOLBin Expansion ---" -ForegroundColor Yellow

$extFwRules = (Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "rundll32|regsvr32|msbuild|msdt" } | Measure-Object).Count
Test-Check "Mod12" "Extended LOLBin firewall rules" ">=3" "$extFwRules" ($extFwRules -ge 3)

$msdtHandler = Test-Path "HKLM:\SOFTWARE\Classes\ms-msdt"
Test-Check "Mod12" "ms-msdt handler removed (Follina)" "False" "$msdtHandler" (-not $msdtHandler)

$ps7Ifeo = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe" "Debugger"
$ps7Blocked = ($ps7Ifeo -eq "nul") -or (-not (Test-Path "$env:ProgramFiles\PowerShell\7\pwsh.exe"))
Test-Check "Mod12" "PowerShell 7 blocked or absent" "True" "$ps7Blocked" $ps7Blocked

# ============================================================================
# MODULE 13: Windows Sandbox
# ============================================================================
Write-Host ""
Write-Host "--- Module 13: Windows Sandbox ---" -ForegroundColor Yellow

$sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
$sandboxOn = $sandbox -and $sandbox.State -eq "Enabled"
Test-Check "Mod13" "Windows Sandbox enabled" "Enabled" "$(if ($sandbox) { $sandbox.State } else { 'Not available' })" $sandboxOn

$defSandbox = [System.Environment]::GetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "Machine")
Test-Check "Mod13" "Defender Sandbox enabled" "1" "$defSandbox" ($defSandbox -eq "1")

# ============================================================================
# SUMMARY
# ============================================================================
$passed = ($results | Where-Object { $_.Status -eq "PASS" } | Measure-Object).Count
$failed = ($results | Where-Object { $_.Status -eq "FAIL" } | Measure-Object).Count
$total  = $results.Count
$score  = [math]::Round(($passed / $total) * 100, 0)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RESULTS: $passed/$total checks passed ($score%)" -ForegroundColor $(if ($score -ge 90) { "Green" } elseif ($score -ge 70) { "Yellow" } else { "Red" })
Write-Host "  Passed: $passed | Failed: $failed" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
    Write-Host ""
    Write-Host "  FAILED CHECKS:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "    [$($_.Module)] $($_.Check)" -ForegroundColor Red
    }
}

# Export CSV
$results | Export-Csv -Path $ReportCSV -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "  Report saved: $ReportCSV" -ForegroundColor Gray

# NinjaRMM custom fields (uncomment and adjust)
# Ninja-Property-Set hardeningScore $score
# Ninja-Property-Set hardeningPassed $passed
# Ninja-Property-Set hardeningFailed $failed
# Ninja-Property-Set hardeningLastCheck (Get-Date -Format 'yyyy-MM-dd')

# Exit code = number of failed checks (0 = fully hardened)
exit $failed
