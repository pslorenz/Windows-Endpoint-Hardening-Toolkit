#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 10: Credential Guard and Session Security
    Isolates credentials in a hardware-backed container and enforces
    screen lock, session timeout, and logon security settings.

.DESCRIPTION
    Credential Guard uses Virtualization Based Security (VBS) to isolate
    LSASS secrets so even kernel-level malware can't dump credentials.
    Windows 11 on modern hardware almost always supports this.

    Also configures:
      - Screen lock timeout (15 min default)
      - Logon banner (legal notice - aids incident response)
      - Last username hidden from login screen
      - Ctrl+Alt+Del required for login (prevents fake login screens)
      - Cached logon limit reduced

    TEST VPN FIRST: Some older VPN clients (Cisco AnyConnect < 4.10,
    GlobalProtect < 6.0) have issues with Credential Guard. Some Remote 
    Access tools like LogMeIn or ScreenConnect can also fail.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    Reboot required for Credential Guard.
    Test on one machine with VPN first.
#>

$EnableCredentialGuard = $true
$ScreenLockMinutes     = 15
$ShowLogonBanner       = $true
$HideLastUsername       = $true
$RequireCtrlAltDel     = $false  # Set $true for higher security, some users find this annoying

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\credguard-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord", [string]$Desc = "")
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        if ($Desc) { Write-Log "  $Desc" }
    } catch { Write-Log "  FAIL: $Desc - $_" "ERROR" }
}

Write-Log "================================================================"
Write-Log "  MODULE 10: Credential Guard + Session Security"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# 1. CREDENTIAL GUARD
# ============================================================================
if ($EnableCredentialGuard) {
    Write-Log ""
    Write-Log "--- Credential Guard ---"

    # Check hardware support
    $vbsSupported = $false
    try {
        $devGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($devGuard) {
            $vbsAvailable = $devGuard.AvailableSecurityProperties
            $vbsRunning = $devGuard.VirtualizationBasedSecurityStatus
            Write-Log "  VBS status: $vbsRunning (0=off, 1=enabled, 2=running)"
            Write-Log "  Available features: $($vbsAvailable -join ', ')"

            if ($vbsRunning -eq 2) {
                Write-Log "  Credential Guard already running" "SUCCESS"
                $vbsSupported = $true
            } elseif ($vbsAvailable -contains 1 -or $vbsAvailable -contains 2) {
                $vbsSupported = $true
            }
        }
    } catch {}

    if ($vbsSupported) {
        $cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        Set-Reg $cgPath "EnableVirtualizationBasedSecurity" 1 "DWord" "VBS: Enabled"
        Set-Reg $cgPath "RequirePlatformSecurityFeatures" 1 "DWord" "VBS: Require Secure Boot"

        $lsaCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-Reg $lsaCfgPath "LsaCfgFlags" 1 "DWord" "Credential Guard: Enabled with UEFI lock"

        # Enable HVCI (Hypervisor-enforced Code Integrity)
        $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        Set-Reg $hvciPath "Enabled" 1 "DWord" "HVCI: Enabled"

        Write-Log "Credential Guard configured (reboot required)" "SUCCESS"
    } else {
        Write-Log "Hardware does not support VBS - skipping Credential Guard" "WARN"
        Write-Log "This machine may lack: Hyper-V, SLAT, Secure Boot, or UEFI"
    }
}

# ============================================================================
# 2. SCREEN LOCK TIMEOUT
# ============================================================================
Write-Log ""
Write-Log "--- Screen Lock Timeout ---"

# Machine-level screensaver policy
$ssPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
Set-Reg $ssPath "ScreenSaveActive" "1" "String" "Screensaver: Active"
Set-Reg $ssPath "ScreenSaverIsSecure" "1" "String" "Screensaver: Password protected"
$timeoutSeconds = $ScreenLockMinutes * 60
Set-Reg $ssPath "ScreenSaveTimeOut" "$timeoutSeconds" "String" "Screensaver timeout: $ScreenLockMinutes minutes"

# Also set via user policy for current user template
$ssUserPath = "HKU:\.DEFAULT\Control Panel\Desktop"
if (Test-Path "HKU:\.DEFAULT") {
    Set-Reg $ssUserPath "ScreenSaveActive" "1" "String" "Default user screensaver: Active"
    Set-Reg $ssUserPath "ScreenSaverIsSecure" "1" "String" "Default user screensaver: Locked"
    Set-Reg $ssUserPath "ScreenSaveTimeOut" "$timeoutSeconds" "String" "Default user timeout: $ScreenLockMinutes min"
}

# Machine inactivity timeout (separate from screensaver)
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" $timeoutSeconds "DWord" "Machine inactivity lock: $ScreenLockMinutes min"

Write-Log "Screen lock configured: $ScreenLockMinutes minutes" "SUCCESS"

# ============================================================================
# 3. LOGON SECURITY
# ============================================================================
Write-Log ""
Write-Log "--- Logon Security ---"

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Hide last logged-in username (makes credential guessing harder)
if ($HideLastUsername) {
    Set-Reg $winlogonPath "DontDisplayLastUserName" 1 "DWord" "Hide last username at login"
}

# Require Ctrl+Alt+Del (prevents fake login screen attacks)
if ($RequireCtrlAltDel) {
    Set-Reg $winlogonPath "DisableCAD" 0 "DWord" "Require Ctrl+Alt+Del at login"
} else {
    Write-Log "  Ctrl+Alt+Del: Not enforced (set RequireCtrlAltDel=true for higher security)"
}

# Legal notice / logon banner
if ($ShowLogonBanner) {
    Set-Reg $winlogonPath "LegalNoticeCaption" "Authorized Use Only" "String" "Logon banner: Title"
    Set-Reg $winlogonPath "LegalNoticeText" "This system is for authorized use only. All activity is monitored and logged. Unauthorized access is prohibited and may result in legal action." "String" "Logon banner: Text"
    Write-Log "  Logon banner configured"
}

# Reduce cached logon count (limits offline credential attacks)
# Default is 10, reduce to 2 (still allows login if network is down)
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "2" "String" "Cached logons: 2 (reduced from default 10)"

# Disable remote logon for accounts with blank passwords
Set-Reg $winlogonPath "LimitBlankPasswordUse" 1 "DWord" "Block blank password remote logon"

Write-Log "Logon security configured" "SUCCESS"

# ============================================================================
# 4. ADDITIONAL SESSION HARDENING
# ============================================================================
Write-Log ""
Write-Log "--- Session Hardening ---"

# Prevent Windows from storing credentials for task/service accounts
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" 1 "DWord" "Disable domain credential storage"

# Clear page file on shutdown (prevents memory scraping of credentials)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 1 "DWord" "Clear page file on shutdown"

Write-Log "Session hardening configured" "SUCCESS"

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Credential Guard + Session Security complete."
Write-Log "  Reboot required for Credential Guard to activate."
Write-Log ""
Write-Log "  VERIFY AFTER REBOOT:"
Write-Log '    (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning'
Write-Log "    Value should include 1 (Credential Guard)"
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "    Credential Guard: Set LsaCfgFlags to 0, reboot"
Write-Log "    Screen lock: Set InactivityTimeoutSecs to 0"
Write-Log "================================================================"
exit 0
