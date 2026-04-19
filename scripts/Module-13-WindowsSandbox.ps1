#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 13: Windows Sandbox + Defender Sandbox
    Enables Windows Sandbox for safe file detonation and puts
    Defender itself into a sandboxed process.

.DESCRIPTION
    WINDOWS SANDBOX:
    A disposable virtual machine built into Windows 11 Pro.
    Users can open suspicious files inside Sandbox - when they close
    the window, everything is destroyed. Zero persistence risk.
    
    Great for:
      - Attachments from unknown senders
      - Downloaded files that seem suspicious
      - Links they're not sure about
    
    Users launch it from Start Menu -> "Windows Sandbox"
    No training needed beyond "if you're not sure, open it in Sandbox first."

    DEFENDER SANDBOX:
    Runs the Defender antivirus engine in an isolated container so that
    if malware exploits a vulnerability in Defender's scanning engine,
    it can't escape to the main OS. Zero user impact.

    REQUIREMENTS:
    - Windows 11 Pro (not Home)
    - Virtualization enabled in BIOS (VT-x / AMD-V)
    - At least 4GB RAM (8GB+ recommended)
    - At least 1GB free disk space

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 300s
    Reboot required for Windows Sandbox.
    Defender Sandbox takes effect immediately.
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\sandbox-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 13: Windows Sandbox + Defender Sandbox"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# 1. PRE-FLIGHT CHECKS
# ============================================================================
Write-Log ""
Write-Log "--- Pre-flight checks ---"

# Check Windows edition
$os = Get-CimInstance Win32_OperatingSystem
$edition = $os.Caption
if ($edition -like "*Home*") {
    Write-Log "Windows Home detected - Sandbox not available" "ERROR"
    Write-Log "Windows Pro, Enterprise, or Education required"
    exit 1
}
Write-Log "  Edition: $edition"

# Check RAM
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
Write-Log "  RAM: ${ram} GB"
if ($ram -lt 4) {
    Write-Log "Insufficient RAM (minimum 4GB, recommended 8GB)" "ERROR"
    exit 1
}
if ($ram -lt 8) {
    Write-Log "  Warning: 4-8GB RAM - Sandbox will work but may be slow" "WARN"
}

# Check virtualization
$virtEnabled = $false
try {
    $cpu = Get-CimInstance Win32_Processor
    if ($cpu.VirtualizationFirmwareEnabled) {
        $virtEnabled = $true
        Write-Log "  Virtualization: Enabled in BIOS"
    } else {
        Write-Log "  Virtualization: Not enabled in BIOS" "WARN"
        Write-Log "  Sandbox requires VT-x (Intel) or AMD-V to be enabled in BIOS"
        Write-Log "  Continuing anyway - it may already be enabled at the OS level"
    }
} catch {
    Write-Log "  Could not check virtualization status" "WARN"
}

# ============================================================================
# 2. ENABLE WINDOWS SANDBOX
# ============================================================================
Write-Log ""
Write-Log "--- Windows Sandbox ---"

$sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
if ($sandboxFeature) {
    if ($sandboxFeature.State -eq "Enabled") {
        Write-Log "Windows Sandbox already enabled" "SUCCESS"
    } else {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "Windows Sandbox enabled (reboot required)" "SUCCESS"
        } catch {
            Write-Log "Failed to enable Windows Sandbox: $_" "ERROR"
            Write-Log "Common cause: Virtualization not enabled in BIOS" "WARN"
        }
    }
} else {
    Write-Log "Windows Sandbox feature not available on this system" "ERROR"
}

# Also enable Hyper-V platform if not already (Sandbox depends on it)
$hyperv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction SilentlyContinue
if ($hyperv -and $hyperv.State -ne "Enabled") {
    try {
        # Enable just the hypervisor platform, not the full management tools
        Enable-WindowsOptionalFeature -Online -FeatureName "HypervisorPlatform" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Log "  Hypervisor Platform enabled"
    } catch { Write-Log "  Hypervisor Platform: $_" "WARN" }
}

# ============================================================================
# 3. CREATE A SANDBOX CONFIGURATION FILE (HARDENED)
#    This config file starts Sandbox with no networking by default.
#    Users can use the networking version if they need to test URLs.
# ============================================================================
Write-Log ""
Write-Log "--- Creating Sandbox Configurations ---"

$sandboxDir = "$env:PUBLIC\Desktop"

# Sandbox config: No networking (safest for file analysis)
$offlineConfig = @"
<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Enable</vGPU>
  <MemoryInMB>2048</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Enable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
</Configuration>
"@

# Sandbox config: With networking (for testing suspicious URLs)
$onlineConfig = @"
<Configuration>
  <Networking>Default</Networking>
  <vGPU>Enable</vGPU>
  <MemoryInMB>2048</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Enable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
</Configuration>
"@

try {
    $offlineConfig | Out-File -FilePath "$sandboxDir\Sandbox - Offline (Safe).wsb" -Encoding UTF8 -Force
    Write-Log "  Created: Desktop\Sandbox - Offline (Safe).wsb"

    $onlineConfig | Out-File -FilePath "$sandboxDir\Sandbox - Online (For URLs).wsb" -Encoding UTF8 -Force
    Write-Log "  Created: Desktop\Sandbox - Online (For URLs).wsb"

    Write-Log "Sandbox shortcuts created" "SUCCESS"
} catch { Write-Log "Sandbox config creation: $_" "WARN" }

# ============================================================================
# 4. DEFENDER SANDBOX (separate from Windows Sandbox)
#    Runs the Defender engine itself in an AppContainer sandbox.
#    If malware exploits a bug in Defender's parser, it can't escape.
#    Zero user impact.
# ============================================================================
Write-Log ""
Write-Log "--- Defender Sandbox ---"
try {
    # Check current state
    $defenderSandbox = [System.Environment]::GetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "Machine")
    if ($defenderSandbox -eq "1") {
        Write-Log "Defender Sandbox already enabled" "SUCCESS"
    } else {
        [System.Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")
        Write-Log "Defender Sandbox enabled (takes effect on next Defender restart)" "SUCCESS"
    }
} catch { Write-Log "Defender Sandbox: $_" "WARN" }

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Sandbox Configuration complete."
Write-Log "  Reboot required for Windows Sandbox."
Write-Log ""
Write-Log "  USER INSTRUCTIONS:"
Write-Log "  Two shortcuts are now on the Public Desktop:"
Write-Log "    'Sandbox - Offline (Safe)' - For opening suspicious files"
Write-Log "      No internet access inside. Copy/paste files in via clipboard."
Write-Log "    'Sandbox - Online (For URLs)' - For testing suspicious links"
Write-Log "      Has internet access. Close window when done."
Write-Log ""
Write-Log "  Both destroy everything when closed. Nothing persists."
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "    Disable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM"
Write-Log '    [System.Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", $null, "Machine")'
Write-Log "================================================================"
exit 0
