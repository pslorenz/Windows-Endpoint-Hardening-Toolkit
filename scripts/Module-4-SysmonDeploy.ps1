#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 4: Sysmon Deployment
    Installs Sysmon with SwiftOnSecurity's community config.
    Transforms your Windows event logging from basic to forensic-grade.

.DESCRIPTION
    Windows audit logs tell you THAT something happened.
    Sysmon tells you EXACTLY what happened - full process trees, network
    connections, file creation, registry changes, and more.

    This script:
      1. Downloads Sysmon from Microsoft Sysinternals (official source)
      2. Downloads SwiftOnSecurity's sysmon-config (community standard)
      3. Installs Sysmon as a service with the config
      4. Sets event log size to 200MB
      5. Validates installation

    Events go to: "Microsoft-Windows-Sysmon/Operational"
    NinjaRMM can collect and alert on these events.

    KEY EVENT IDS:
      1  = Process Creation (with full command line + parent process)
      3  = Network Connection (what process connected where)
      7  = Image Loaded (DLL loading - detect injection)
      8  = CreateRemoteThread (process injection detection)
      11 = File Created
      12 = Registry key created/deleted
      13 = Registry value set
      22 = DNS Query (what process queried what domain)

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 300s
    Requires internet access to download Sysmon and config.
    No reboot needed.

    ROLLBACK: sysmon64 -u force
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\sysmon-deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$WorkDir = "$env:TEMP\SysmonDeploy"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $WorkDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 4: Sysmon Deployment"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# CHECK FOR EXISTING INSTALLATION
# ============================================================================
$existingSysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($existingSysmon) {
    Write-Log "Sysmon already installed: $($existingSysmon.DisplayName) ($($existingSysmon.Status))"
    Write-Log "To reinstall, run: sysmon64 -u force   then re-run this script"

    # Even if installed, update the config
    $updateOnly = $true
} else {
    $updateOnly = $false
}

# ============================================================================
# DOWNLOAD SYSMON
# ============================================================================
$sysmonUrl    = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip    = "$WorkDir\Sysmon.zip"
$sysmonDir    = "$WorkDir\Sysmon"
$sysmonExe    = "$sysmonDir\Sysmon64.exe"
$installDir   = "$env:ProgramFiles\Sysmon"

if (-not $updateOnly) {
    Write-Log ""
    Write-Log "--- Downloading Sysmon ---"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing -ErrorAction Stop
        Write-Log "  Downloaded: $sysmonUrl"

        # Extract
        Expand-Archive -Path $sysmonZip -Destination $sysmonDir -Force -ErrorAction Stop
        Write-Log "  Extracted to: $sysmonDir"

        if (-not (Test-Path $sysmonExe)) {
            Write-Log "Sysmon64.exe not found after extraction" "ERROR"
            exit 1
        }
    } catch {
        Write-Log "Download failed: $_" "ERROR"
        Write-Log "Ensure the machine has internet access to download.sysinternals.com" "ERROR"
        exit 1
    }
}

# ============================================================================
# DOWNLOAD SWIFONSECURITY SYSMON CONFIG
# ============================================================================
$configUrl  = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$configFile = "$WorkDir\sysmonconfig.xml"

Write-Log ""
Write-Log "--- Downloading Sysmon config (SwiftOnSecurity) ---"
try {
    Invoke-WebRequest -Uri $configUrl -OutFile $configFile -UseBasicParsing -ErrorAction Stop
    Write-Log "  Downloaded: SwiftOnSecurity sysmon-config"
} catch {
    Write-Log "Config download failed: $_" "ERROR"
    Write-Log "Ensure access to raw.githubusercontent.com" "ERROR"
    exit 1
}

# ============================================================================
# INSTALL OR UPDATE SYSMON
# ============================================================================
if ($updateOnly) {
    Write-Log ""
    Write-Log "--- Updating Sysmon config ---"
    try {
        # Find existing sysmon executable
        $existingExe = (Get-Process -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1).Path
        if (-not $existingExe) {
            $existingExe = "$installDir\Sysmon64.exe"
            if (-not (Test-Path $existingExe)) {
                $existingExe = "$env:SystemRoot\Sysmon64.exe"
            }
        }

        if (Test-Path $existingExe) {
            & $existingExe -c $configFile 2>&1 | Out-Null
            Write-Log "Config updated using: $existingExe" "SUCCESS"
        } else {
            Write-Log "Cannot find Sysmon executable to update config" "ERROR"
        }
    } catch { Write-Log "Config update failed: $_" "ERROR" }
} else {
    Write-Log ""
    Write-Log "--- Installing Sysmon ---"
    try {
        # Create permanent install directory
        New-Item -Path $installDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item -Path "$sysmonDir\*" -Destination $installDir -Recurse -Force
        $installedExe = "$installDir\Sysmon64.exe"

        # Install with config, accept EULA
        $installResult = & $installedExe -accepteula -i $configFile 2>&1
        Write-Log "  Install output: $installResult"

        # Verify service is running
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Log "Sysmon installed and running" "SUCCESS"
        } else {
            $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Write-Log "Sysmon installed and running" "SUCCESS"
            } else {
                Write-Log "Sysmon service not detected after install" "ERROR"
            }
        }
    } catch {
        Write-Log "Installation failed: $_" "ERROR"
        exit 1
    }
}

# ============================================================================
# CONFIGURE EVENT LOG SIZE
# ============================================================================
Write-Log ""
Write-Log "--- Configuring Sysmon event log ---"
try {
    $sysmonLogName = "Microsoft-Windows-Sysmon/Operational"
    wevtutil sl $sysmonLogName /ms:209715200  # 200MB
    Write-Log "  Sysmon event log size: 200MB"

    # Verify events are flowing
    Start-Sleep -Seconds 2
    $testEvent = Get-WinEvent -LogName $sysmonLogName -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($testEvent) {
        Write-Log "  Events flowing: confirmed (latest: $($testEvent.TimeCreated))"
    } else {
        Write-Log "  No events yet (may take a moment)" "WARN"
    }
    Write-Log "Event log configured" "SUCCESS"
} catch { Write-Log "Event log config: $_" "WARN" }

# ============================================================================
# CLEANUP
# ============================================================================
Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Sysmon deployment complete."
Write-Log "================================================================"
Write-Log ""
Write-Log "  HIGH-VALUE EVENTS FOR NINJARMM MONITORING:"
Write-Log "  Log: Microsoft-Windows-Sysmon/Operational"
Write-Log ""
Write-Log "  ID 1  = Process created (FULL command line + parent tree)"
Write-Log "  ID 3  = Network connection (which process called which IP)"
Write-Log "  ID 7  = DLL loaded (detect reflective DLL injection)"
Write-Log "  ID 8  = CreateRemoteThread (process injection!)"
Write-Log "  ID 10 = Process access (credential dumping indicator)"
Write-Log "  ID 11 = File created (malware dropped to disk)"
Write-Log "  ID 13 = Registry value set (persistence mechanisms)"
Write-Log "  ID 22 = DNS query (C2 domain resolution)"
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log '  & "$env:ProgramFiles\Sysmon\Sysmon64.exe" -u force'
Write-Log "  Remove-Item '$installDir' -Recurse -Force"

exit 0
