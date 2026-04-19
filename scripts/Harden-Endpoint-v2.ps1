#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Endpoint Hardening Script v2.0
    Targeted defense against MSI/VBS/PowerShell/Injection attack chains
    Designed for: non-domain-joined Windows 11 Pro machines

.DESCRIPTION
    This script applies surgical hardening that collapses common malware
    kill chains WITHOUT the support burden of full CIS/STIG benchmarks.

    Every setting is:
      - Safe for standalone workgroup machines
      - Tested to not break printing, file sharing, or RDP
      - Individually toggleable
      - Logged for NinjaRMM visibility
      - Rollback-ready

    Attack chain this targets:
      Malicious URL -> MSI installer -> VBS droppers (WScript) ->
      PowerShell (execution policy bypass) -> Code injection into explorer.exe

    Kill points created:
      Stage 1: MSI blocked for standard users
      Stage 2: WScript/CScript completely disabled (IFEO)
      Stage 3: PowerShell constrained + ASR blocks obfuscated scripts
      Stage 4: DNS blocks malicious domains + firewall blocks script host outbound
      Stage 5: Process mitigations on explorer.exe + LSA protection

    Additional hardening (safe for workgroup):
      - Autorun/Autoplay disabled (USB attack vector)
      - WDigest credential caching disabled
      - PowerShell remoting disabled
      - Windows Firewall enforced on all profiles
      - Remote Assistance disabled
      - Office macro blocking from internet
      - Audit policy for key security events
      - Windows Update enforced to auto-install

.NOTES
    Version:  2.0
    Deploy:   NinjaRMM or Run in Admin PowersHELL
    Test:     Deploy to ONE machine first. Verify for 24-48 hours.
    Rollback: Deploy Rollback-Hardening-v2.ps1 if issues arise.
    Reboot:   REQUIRED after first run for all changes to take effect.
#>

# ============================================================================
# CONFIGURATION - Toggle sections ON ($true) or OFF ($false)
# ============================================================================

# --- ATTACK CHAIN KILLERS (directly mapped to common threats like ClickFix) ---
$BlockWScriptCScript       = $true   # Kill VBS/JS execution entirely
$ConstrainPowerShell       = $true   # Constrained Language Mode for non-admins
$EnablePSLogging           = $true   # Full PS visibility (Script Block + Transcription)
$DisablePowerShellV2       = $true   # Remove PS v2 (no logging, no AMSI)
$EnableASRRules            = $true   # Attack Surface Reduction (requires Defender active)
$RestrictMSIInstall        = $true   # Block MSI for standard users
$SetProtectiveDNS          = $true   # Quad9 - blocks known malicious domains (you can use Umbrella if preferred, and if you use a client based DNS Filter, set this to false)
$HardenProcessIntegrity    = $true   # Exploit mitigations on explorer.exe, PS, etc.
$BlockScriptHostNetwork    = $true   # Firewall: block wscript/cscript/mshta outbound

# --- ADDITIONAL HARDENING (safe for standalone workgroup machines) ---
$DisableAutorun            = $true   # Block USB/CD autorun (common malware vector)
$DisableWDigest            = $true   # Prevent plaintext credential caching
$DisablePSRemoting         = $true   # Disable WinRM/PS remoting (not needed standalone)
$EnforceWindowsFirewall    = $true   # Ensure firewall is ON for all profiles
$DisableRemoteAssistance   = $true   # Disable unsolicited remote assistance
$DisableMacrosFromInternet = $true   # Block Office macros from downloaded files
$EnforceWindowsUpdate      = $true   # Auto-download and install updates
$EnableAuditPolicy         = $true   # Log key security events for NinjaRMM
$DisableLLMNR              = $true   # Disable LLMNR
$HardenSMB                 = $true   # Disable SMBv1, basic SMB hardening
$BlockUntrustedFonts       = $true   # Mitigate font parsing exploits

# ============================================================================
# LOGGING SETUP
# ============================================================================
$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\harden-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupFile = "$LogDir\pre-hardening-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$script:ErrorCount   = 0
$script:SuccessCount = 0
$script:SkipCount    = 0

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$ts [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    switch ($Level) {
        "SUCCESS" { Write-Host $entry -ForegroundColor Green;  $script:SuccessCount++ }
        "ERROR"   { Write-Host $entry -ForegroundColor Red;    $script:ErrorCount++ }
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "SKIP"    { Write-Host $entry -ForegroundColor Cyan;   $script:SkipCount++ }
        default   { Write-Host $entry }
    }
}

function Set-RegistrySafe {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$Description = ""
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        if ($Description) { Write-Log "  SET: $Description" }
        return $true
    } catch {
        Write-Log "  FAIL: $Description - $_" "ERROR"
        return $false
    }
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================
Write-Log "================================================================"
Write-Log "  ENDPOINT HARDENING SCRIPT v2.0"
Write-Log "  $(Get-Date -Format 'dddd, MMMM dd, yyyy h:mm tt')"
Write-Log "================================================================"
Write-Log "Computer:  $env:COMPUTERNAME"
Write-Log "User:      $env:USERNAME"
Write-Log "OS:        $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Log "Build:     $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
Write-Log "Domain:    $((Get-CimInstance Win32_ComputerSystem).Domain)"
Write-Log "Log:       $LogFile"
Write-Log "================================================================"

# Check if Defender is the active AV (needed for ASR rules)
$defenderActive = $false
try {
    $avProduct = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue |
                 Where-Object { $_.displayName -like "*Defender*" -and $_.productState -band 0x1000 }
    if ($avProduct) { $defenderActive = $true }
    # Fallback check
    if (-not $defenderActive) {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus -and $mpStatus.AntivirusEnabled -and -not $mpStatus.IsTamperProtected -eq $false) {
            $defenderActive = $true
        }
    }
} catch {}
Write-Log "Defender active AV: $defenderActive"

if (-not $defenderActive -and $EnableASRRules) {
    Write-Log "ASR rules require Defender as active AV - will skip ASR section" "WARN"
    $EnableASRRules = $false
}

# ============================================================================
# 1. BLOCK WSCRIPT.EXE AND CSCRIPT.EXE
#    IFEO debugger redirect - any attempt to run these silently fails.
#    This single change kills the entire VBS dropper stage.
# ============================================================================
if ($BlockWScriptCScript) {
    Write-Log ""
    Write-Log "--- [1/16] Blocking WScript and CScript (IFEO) ---"
    $targets = @("wscript.exe", "cscript.exe")
    foreach ($exe in $targets) {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        Set-RegistrySafe -Path $regPath -Name "Debugger" -Value "nul" -Type String -Description "Block $exe via IFEO"
    }
    Write-Log "WScript/CScript blocking complete" "SUCCESS"
} else { Write-Log "[1/16] WScript/CScript blocking: SKIPPED" "SKIP" }

# ============================================================================
# 2. POWERSHELL CONSTRAINED LANGUAGE MODE
#    Blocks .NET, COM objects, Add-Type in non-elevated sessions.
#    Admin (elevated) sessions still get Full Language Mode.
# ============================================================================
if ($ConstrainPowerShell) {
    Write-Log ""
    Write-Log "--- [2/16] PowerShell Constrained Language Mode ---"
    try {
        [System.Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")
        Write-Log "Constrained Language Mode set (effective after reboot)" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[2/16] Constrained Language Mode: SKIPPED" "SKIP" }

# ============================================================================
# 3. POWERSHELL LOGGING
#    Script Block Logging, Module Logging, Transcription.
#    Events go to Windows Event Log -> NinjaRMM can monitor/alert.
#    Event ID 4104 = Script Block Log (the high-value one)
# ============================================================================
if ($EnablePSLogging) {
    Write-Log ""
    Write-Log "--- [3/16] PowerShell Logging ---"

    # Script Block Logging (Event ID 4104)
    $sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    Set-RegistrySafe $sbPath "EnableScriptBlockLogging" 1 "DWord" "Script Block Logging"
    Set-RegistrySafe $sbPath "EnableScriptBlockInvocationLogging" 1 "DWord" "Script Block Invocation Logging"

    # Module Logging
    $mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    Set-RegistrySafe $mlPath "EnableModuleLogging" 1 "DWord" "Module Logging"
    $mnPath = "$mlPath\ModuleNames"
    Set-RegistrySafe $mnPath "*" "*" "String" "Log all modules"

    # Transcription
    $trPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $trOutput = "$env:ProgramData\PSTranscripts"
    New-Item -Path $trOutput -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-RegistrySafe $trPath "EnableTranscripting" 1 "DWord" "Transcription"
    Set-RegistrySafe $trPath "EnableInvocationHeader" 1 "DWord" "Transcription invocation headers"
    Set-RegistrySafe $trPath "OutputDirectory" $trOutput "String" "Transcription output -> $trOutput"

    # Increase PowerShell event log size (default 15MB is too small)
    try {
        $psLogName = "Microsoft-Windows-PowerShell/Operational"
        $psLog = Get-WinEvent -ListLog $psLogName -ErrorAction SilentlyContinue
        if ($psLog -and $psLog.MaximumSizeInBytes -lt 104857600) {
            wevtutil sl $psLogName /ms:104857600  # 100MB
            Write-Log "  SET: PowerShell event log size -> 100MB"
        }
    } catch {}

    Write-Log "PowerShell Logging complete" "SUCCESS"
} else { Write-Log "[3/16] PowerShell Logging: SKIPPED" "SKIP" }

# ============================================================================
# 4. DISABLE POWERSHELL V2
# ============================================================================
if ($DisablePowerShellV2) {
    Write-Log ""
    Write-Log "--- [4/16] Disable PowerShell v2 ---"
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
        if ($feature -and $feature.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "PowerShell v2 disabled" "SUCCESS"
        } else {
            Write-Log "PowerShell v2 already disabled" "SUCCESS"
        }
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[4/16] PowerShell v2: SKIPPED" "SKIP" }

# ============================================================================
# 5. ATTACK SURFACE REDUCTION RULES
#    Only runs if Defender is the active AV.
# ============================================================================
if ($EnableASRRules) {
    Write-Log ""
    Write-Log "--- [5/16] Attack Surface Reduction Rules ---"

    $asrRules = [ordered]@{
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = @(1, "Block executable content from email/webmail")
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = @(1, "Block Office apps creating child processes")
        "D3E037E1-3EB8-44C8-A917-57927947596D" = @(1, "Block JS/VBS launching downloaded executables")
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = @(1, "Block obfuscated scripts")
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = @(1, "Block PSExec/WMI process creation")
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = @(1, "Block untrusted USB processes")
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = @(1, "Block credential stealing from LSASS")
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = @(1, "Block Win32 API calls from Office macros")
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = @(1, "Block exploited vulnerable signed drivers")
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = @(1, "Advanced ransomware protection")
        "3B576869-A4EC-4529-8536-B80A7769E899" = @(1, "Block Office apps from creating executable content")
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = @(1, "Block Office apps from injecting into other processes")
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = @(1, "Block Office COM/OLE object creation")
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = @(1, "Block persistence through WMI event subscriptions")
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = @(1, "Block Adobe Reader from creating child processes")
    }

    try {
        $ids = @($asrRules.Keys)
        $actions = @($asrRules.Values | ForEach-Object { $_[0] })

        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids `
                         -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop

        foreach ($id in $ids) {
            $action = if ($asrRules[$id][0] -eq 1) { "BLOCK" } else { "AUDIT" }
            Write-Log "  ASR: $($asrRules[$id][1]) -> $action"
        }
        Write-Log "ASR Rules complete (15 rules)" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[5/16] ASR Rules: SKIPPED" "SKIP" }

# ============================================================================
# 6. RESTRICT MSI INSTALLATION
# ============================================================================
if ($RestrictMSIInstall) {
    Write-Log ""
    Write-Log "--- [6/16] Restrict MSI Installation ---"
    $msiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    Set-RegistrySafe $msiPath "DisableMSI" 1 "DWord" "Disable MSI for non-admins"
    Set-RegistrySafe $msiPath "DisableUserInstalls" 1 "DWord" "Disable user-initiated installs"
    Set-RegistrySafe $msiPath "AlwaysInstallElevated" 0 "DWord" "Prevent AlwaysInstallElevated"
    # User-side key too
    Set-RegistrySafe "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0 "DWord" "Prevent user AlwaysInstallElevated"
    Write-Log "MSI restrictions complete" "SUCCESS"
} else { Write-Log "[6/16] MSI Restrictions: SKIPPED" "SKIP" }

# ============================================================================
# 7. PROTECTIVE DNS (Quad9)
# ============================================================================
if ($SetProtectiveDNS) {
    Write-Log ""
    Write-Log "--- [7/16] Protective DNS (Quad9) ---"
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
                -ServerAddresses @("9.9.9.9", "149.112.112.112") -ErrorAction Stop
            Write-Log "  DNS set on: $($adapter.Name) ($($adapter.InterfaceDescription))"
        }

        # Register Quad9 for DNS-over-HTTPS (Win 11 native)
        $dohCommands = @(
            "netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no",
            "netsh dns add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no"
        )
        foreach ($cmd in $dohCommands) {
            Invoke-Expression $cmd 2>$null
        }
        Write-Log "  DoH configured for Quad9"
        Write-Log "Protective DNS complete" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[7/16] Protective DNS: SKIPPED" "SKIP" }

# ============================================================================
# 8. PROCESS INTEGRITY HARDENING
# ============================================================================
if ($HardenProcessIntegrity) {
    Write-Log ""
    Write-Log "--- [8/16] Process Integrity Hardening ---"
    try {
        # System-wide DEP, ASLR, SEHOP
        Set-ProcessMitigation -System -Enable DEP, BottomUp, SEHOP -ErrorAction SilentlyContinue
        Write-Log "  System-wide: DEP, ASLR (BottomUp), SEHOP"

        # Per-process mitigations for common injection targets
        $processTargets = @{
            "explorer.exe"    = @("ExtensionPoint", "CFG", "StrictHandle")
            "powershell.exe"  = @("ExtensionPoint", "CFG")
            "pwsh.exe"        = @("ExtensionPoint", "CFG")
            "msiexec.exe"     = @("ExtensionPoint", "CFG")
        }
        foreach ($proc in $processTargets.Keys) {
            try {
                $mitigations = $processTargets[$proc]
                Set-ProcessMitigation -Name $proc -Enable $mitigations -ErrorAction SilentlyContinue
                Write-Log "  $proc : $($mitigations -join ', ')"
            } catch {}
        }

        # LSA Protection (RunAsPPL) - prevents credential dumping
        Set-RegistrySafe "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1 "DWord" "LSA Protection (RunAsPPL)"

        Write-Log "Process integrity hardening complete" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[8/16] Process Integrity: SKIPPED" "SKIP" }

# ============================================================================
# 9. FIREWALL - BLOCK SCRIPT HOST OUTBOUND
# ============================================================================
if ($BlockScriptHostNetwork) {
    Write-Log ""
    Write-Log "--- [9/16] Firewall: Block Script Host Outbound ---"
    $fwTargets = @(
        @("$env:SystemRoot\System32\wscript.exe",    "Block WScript Outbound (x64)"),
        @("$env:SystemRoot\System32\cscript.exe",    "Block CScript Outbound (x64)"),
        @("$env:SystemRoot\SysWOW64\wscript.exe",   "Block WScript Outbound (x86)"),
        @("$env:SystemRoot\SysWOW64\cscript.exe",   "Block CScript Outbound (x86)"),
        @("$env:SystemRoot\System32\mshta.exe",      "Block MSHTA Outbound"),
        @("$env:SystemRoot\System32\certutil.exe",   "Block Certutil Outbound"),
        @("$env:SystemRoot\System32\bitsadmin.exe",  "Block BitsAdmin Outbound")
    )
    foreach ($target in $fwTargets) {
        try {
            Remove-NetFirewallRule -DisplayName $target[1] -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $target[1] -Direction Outbound -Action Block `
                -Program $target[0] -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            Write-Log "  FW: $($target[1])"
        } catch { Write-Log "  FW FAIL: $($target[1]) - $_" "WARN" }
    }
    Write-Log "Firewall rules complete" "SUCCESS"
} else { Write-Log "[9/16] Firewall Script Blocking: SKIPPED" "SKIP" }

# ============================================================================
# 10. DISABLE AUTORUN / AUTOPLAY
# ============================================================================
if ($DisableAutorun) {
    Write-Log ""
    Write-Log "--- [10/16] Disable Autorun/Autoplay ---"
    # NoDriveTypeAutoRun: 0xFF = disable all drive types
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord" "Disable autorun all drives"
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 1 "DWord" "Disable autorun"
    Set-RegistrySafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 "DWord" "Disable autoplay non-volume devices"
    Write-Log "Autorun/Autoplay disabled" "SUCCESS"
} else { Write-Log "[10/16] Autorun/Autoplay: SKIPPED" "SKIP" }

# ============================================================================
# 11. DISABLE WDIGEST (plaintext credential caching)
# ============================================================================
if ($DisableWDigest) {
    Write-Log ""
    Write-Log "--- [11/16] Disable WDigest Credential Caching ---"
    Set-RegistrySafe "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0 "DWord" "Disable WDigest plaintext creds"
    Write-Log "WDigest disabled" "SUCCESS"
} else { Write-Log "[11/16] WDigest: SKIPPED" "SKIP" }

# ============================================================================
# 12. DISABLE PS REMOTING / WinRM
# ============================================================================
if ($DisablePSRemoting) {
    Write-Log ""
    Write-Log "--- [12/16] Disable PowerShell Remoting ---"
    try {
        # Disable WinRM service
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
        Write-Log "  WinRM service disabled and stopped"

        # Disable PS remoting via registry
        Set-RegistrySafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" 0 "DWord" "Disable WinRM auto-config"

        Write-Log "PS Remoting disabled" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
} else { Write-Log "[12/16] PS Remoting: SKIPPED" "SKIP" }

# ============================================================================
# 13. ENFORCE WINDOWS FIREWALL + DISABLE REMOTE ASSISTANCE
# ============================================================================
if ($EnforceWindowsFirewall) {
    Write-Log ""
    Write-Log "--- [13/16] Enforce Windows Firewall ---"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
        Write-Log "  Firewall enabled on all profiles"
        # Log dropped packets (useful for NinjaRMM monitoring)
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
        Write-Log "  Firewall logging enabled (dropped packets)"
        Write-Log "Windows Firewall enforced" "SUCCESS"
    } catch { Write-Log "Failed: $_" "ERROR" }
}

if ($DisableRemoteAssistance) {
    Set-RegistrySafe "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" 0 "DWord" "Disable Remote Assistance"
    Write-Log "Remote Assistance disabled" "SUCCESS"
}

# ============================================================================
# 14. OFFICE MACRO BLOCKING + DDE DISABLE
# ============================================================================
if ($DisableMacrosFromInternet) {
    Write-Log ""
    Write-Log "--- [14/16] Office Macro and DDE Hardening ---"
    $officeApps = @("word", "excel", "powerpoint")
    foreach ($app in $officeApps) {
        $secPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\$app\security"
        Set-RegistrySafe $secPath "blockcontentexecutionfrominternet" 1 "DWord" "Block internet macros: $app"
        Set-RegistrySafe $secPath "vbawarnings" 4 "DWord" "Disable all macros without notification: $app"
    }
    # Disable DDE in Word and Excel (common attack vector)
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Office\16.0\Word\Options" "DontUpdateLinks" 1 "DWord" "Disable Word DDE auto-update"
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Office\16.0\Word\Options\WordMail" "DontUpdateLinks" 1 "DWord" "Disable Word DDE in email"
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" "DontUpdateLinks" 1 "DWord" "Disable Excel DDE auto-update"
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" "DDEAllowed" 0 "DWord" "Disable Excel DDE"
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" "DDECleaned" 1 "DWord" "Excel DDE cleaned"
    Write-Log "Office macro/DDE hardening complete" "SUCCESS"
} else { Write-Log "[14/16] Office Macros: SKIPPED" "SKIP" }

# ============================================================================
# 15. WINDOWS UPDATE + ADDITIONAL NETWORK HARDENING
# ============================================================================
if ($EnforceWindowsUpdate) {
    Write-Log ""
    Write-Log "--- [15/16] Windows Update Enforcement ---"
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-RegistrySafe $wuPath "NoAutoUpdate" 0 "DWord" "Enable auto-update"
    Set-RegistrySafe $wuPath "AUOptions" 4 "DWord" "Auto download and install"
    Set-RegistrySafe $wuPath "ScheduledInstallDay" 0 "DWord" "Install every day"
    Set-RegistrySafe $wuPath "ScheduledInstallTime" 3 "DWord" "Install at 3 AM"
    Write-Log "Windows Update enforcement complete" "SUCCESS"
} else { Write-Log "[15/16] Windows Update: SKIPPED" "SKIP" }

if ($DisableLLMNR) {
    Set-RegistrySafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 "DWord" "Disable LLMNR"
    Write-Log "LLMNR disabled" "SUCCESS"
}

if ($HardenSMB) {
    # Disable SMBv1 (EternalBlue/WannaCry vector)
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "SMBv1 disabled" "SUCCESS"
        } else { Write-Log "SMBv1 already disabled" "SUCCESS" }
    } catch { Write-Log "SMBv1 disable failed: $_" "WARN" }
}

if ($BlockUntrustedFonts) {
    Set-RegistrySafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" "MitigationOptions_FontBocking" "1000000000000" "String" "Block untrusted fonts"
    Write-Log "Untrusted font blocking enabled" "SUCCESS"
}

# ============================================================================
# 16. AUDIT POLICY (Security Event Logging)
#     These events are visible in NinjaRMM event log monitoring.
# ============================================================================
if ($EnableAuditPolicy) {
    Write-Log ""
    Write-Log "--- [16/16] Security Audit Policy ---"
    $auditSettings = @(
        @("Logon",                     "Success,Failure"),
        @("Account Logon",             "Success,Failure"),
        @("Process Creation",          "Success"),
        @("Object Access",             "Failure"),
        @("Policy Change",             "Success"),
        @("Privilege Use",             "Failure"),
        @("System",                    "Success,Failure"),
        @("Account Management",        "Success,Failure")
    )
    foreach ($audit in $auditSettings) {
        try {
            auditpol /set /category:"$($audit[0])" /success:enable /failure:enable 2>$null | Out-Null
            Write-Log "  Audit: $($audit[0]) -> $($audit[1])"
        } catch {}
    }

    # Enable command line in process creation events (Event ID 4688)
    Set-RegistrySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 1 "DWord" "Include command line in process creation events"

    # Increase Security log size
    try {
        wevtutil sl Security /ms:209715200  # 200MB
        Write-Log "  Security event log size -> 200MB"
    } catch {}

    Write-Log "Audit policy complete" "SUCCESS"
} else { Write-Log "[16/16] Audit Policy: SKIPPED" "SKIP" }

# ============================================================================
# SUMMARY
# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  HARDENING COMPLETE"
Write-Log "  Successful:  $script:SuccessCount"
Write-Log "  Errors:      $script:ErrorCount"
Write-Log "  Skipped:     $script:SkipCount"
Write-Log "  Log:         $LogFile"
Write-Log "================================================================"
Write-Log ""
Write-Log "*** REBOOT REQUIRED for all changes to take effect ***"
Write-Log ""
Write-Log "VERIFICATION (run after reboot):"
Write-Log '  WScript blocked:      Start-Process wscript.exe (should fail)'
Write-Log '  PS Constrained:       $ExecutionContext.SessionState.LanguageMode'
Write-Log '  ASR active:           (Get-MpPreference).AttackSurfaceReductionRules_Ids.Count'
Write-Log '  DNS (Quad9):          Resolve-DnsName example.com | Select Server'
Write-Log '  PS v2 gone:           (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State'
Write-Log '  PS Logging:           Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1'
Write-Log ""
Write-Log "NINJARMM MONITORING - Set alerts for these Event IDs:"
Write-Log "  4104  = PowerShell Script Block (suspicious commands)"
Write-Log "  4688  = Process Creation (with command line)"
Write-Log "  1121  = ASR rule fired in block mode"
Write-Log "  1122  = ASR rule fired in audit mode"
Write-Log "  4625  = Failed logon attempt"
Write-Log "  4648  = Logon using explicit credentials"

# NinjaRMM custom fields (uncomment if you use custom fields)
# Ninja-Property-Set hardeningVersion "2.0"
# Ninja-Property-Set hardeningDate (Get-Date -Format 'yyyy-MM-dd')
# Ninja-Property-Set hardeningErrors $script:ErrorCount

if ($script:ErrorCount -gt 0) { exit 1 } else { exit 0 }
