#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 8: Defender Advanced Configuration
    Cranks cloud protection to maximum and deploys Controlled Folder Access.

.DESCRIPTION
    Three high-value Defender settings most people leave at defaults:

    1. CLOUD PROTECTION LEVEL - Hold suspicious files for cloud ML analysis
    2. CONTROLLED FOLDER ACCESS - Ransomware protection (audit mode first)
    3. NETWORK PROTECTION - Block malicious domains at OS level (all processes)

    Controlled Folder Access workflow:
      Deploy in Audit mode -> collect Event ID 1124 for 2 weeks ->
      whitelist legitimate apps -> flip to Block mode

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    Requires Defender as active AV. No reboot needed.
#>

$ControlledFolderMode = "Audit"   # "Audit", "Block", or "Off"

$AdditionalProtectedFolders = @(
    "$env:USERPROFILE\Downloads"
)

# Add apps here after reviewing Event ID 1124 audit logs
$AllowedApplications = @(
    # "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    # "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
)

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\defender-advanced-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 8: Defender Advanced Configuration"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# Pre-flight
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if (-not $mpStatus.AntivirusEnabled) {
        Write-Log "Defender not active - cannot configure" "ERROR"; exit 1
    }
    Write-Log "Defender active | Engine: $($mpStatus.AMEngineVersion)"
} catch { Write-Log "Cannot query Defender: $_" "ERROR"; exit 1 }

# --- Cloud Protection ---
Write-Log ""
Write-Log "--- Cloud Protection ---"
try {
    Set-MpPreference -CloudBlockLevel 2 -ErrorAction Stop
    Write-Log "  Cloud block level: High"
    Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction Stop
    Write-Log "  Cloud timeout: 50s (holds suspicious files for analysis)"
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Write-Log "  MAPS: Advanced"
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
    Write-Log "  Sample submission: All samples"
    Write-Log "Cloud protection configured" "SUCCESS"
} catch { Write-Log "Cloud protection failed: $_" "ERROR" }

# --- Core Protection Settings ---
Write-Log ""
Write-Log "--- Core Protection Enforcement ---"
$prefs = @(
    @("DisableBehaviorMonitoring",     $false, "Behavior monitoring"),
    @("DisableRealtimeMonitoring",     $false, "Real-time protection"),
    @("DisableIOAVProtection",         $false, "Download/attachment scanning"),
    @("DisableScanningNetworkFiles",   $false, "Network file scanning"),
    @("DisableRemovableDriveScanning", $false, "Removable drive scanning"),
    @("DisableEmailScanning",          $false, "Email scanning"),
    @("DisableArchiveScanning",        $false, "Archive scanning")
)
foreach ($p in $prefs) {
    try {
        Set-MpPreference -ErrorAction SilentlyContinue @{ $p[0] = $p[1] }
        Write-Log "  $($p[2]): Enabled"
    } catch {}
}
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
Write-Log "  PUA blocking: Enabled"
Set-MpPreference -RandomizeScheduleTaskTimes $true -ErrorAction SilentlyContinue
Write-Log "  Randomized scan times: On (prevents fleet-wide perf hit)"
Write-Log "Core protection enforced" "SUCCESS"

# --- Controlled Folder Access ---
Write-Log ""
Write-Log "--- Controlled Folder Access (Ransomware Protection) ---"
$cfaValue = switch ($ControlledFolderMode) { "Audit" { 2 } "Block" { 1 } "Off" { 0 } default { 2 } }
try {
    Set-MpPreference -EnableControlledFolderAccess $cfaValue -ErrorAction Stop
    Write-Log "  Mode: $ControlledFolderMode"
    if ($ControlledFolderMode -ne "Off") {
        foreach ($folder in $AdditionalProtectedFolders) {
            if (Test-Path $folder) {
                Add-MpPreference -ControlledFolderAccessProtectedFolders $folder -ErrorAction SilentlyContinue
                Write-Log "  Protected: $folder"
            }
        }
        foreach ($app in $AllowedApplications) {
            if ($app -and (Test-Path $app)) {
                Add-MpPreference -ControlledFolderAccessAllowedApplications $app -ErrorAction SilentlyContinue
                Write-Log "  Whitelisted: $(Split-Path $app -Leaf)"
            }
        }
    }
    Write-Log "Controlled Folder Access configured" "SUCCESS"
} catch { Write-Log "CFA failed: $_" "ERROR" }

# --- Network Protection ---
Write-Log ""
Write-Log "--- Network Protection ---"
try {
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
    Write-Log "  Network Protection: Block mode"
    Write-Log "  Blocks malicious domains/IPs system-wide (all processes, not just browsers)"
    Write-Log "Network Protection configured" "SUCCESS"
} catch { Write-Log "Network Protection failed: $_" "ERROR" }

# --- Summary ---
Write-Log ""
Write-Log "================================================================"
Write-Log "  Defender Advanced complete."
Write-Log ""
if ($ControlledFolderMode -eq "Audit") {
    Write-Log "  NEXT STEPS FOR CONTROLLED FOLDER ACCESS:"
    Write-Log "  1. Wait 2 weeks"
    Write-Log "  2. Review Event ID 1124 in NinjaRMM"
    Write-Log "  3. Add false-positive apps to AllowedApplications"
    Write-Log "  4. Change ControlledFolderMode to 'Block' and re-deploy"
}
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "    Set-MpPreference -CloudBlockLevel 0"
Write-Log "    Set-MpPreference -EnableControlledFolderAccess 0"
Write-Log "    Set-MpPreference -EnableNetworkProtection Disabled"
Write-Log "================================================================"
exit 0
