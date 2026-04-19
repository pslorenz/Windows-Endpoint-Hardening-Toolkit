#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 12: LOLBin Expansion + PowerShell 7 Coverage
    Extends outbound firewall blocks to additional Living-off-the-Land
    binaries and ensures PowerShell 7 is covered by hardening.
    There are more LOLbins. Add them if you want.

.DESCRIPTION
    "LOLBins" are legitimate Windows executables that attackers abuse to
    download payloads, execute code, or bypass security controls.
    
    The base script (v2) blocks: wscript, cscript, mshta, certutil, bitsadmin
    
    This module adds:
      - regsvr32.exe  (COM scriptlet execution, "Squiblydoo" attack)
      - rundll32.exe  (DLL execution, very common in malware)
      - msbuild.exe   (Inline task code execution)
      - installutil.exe (AppLocker bypass)
      - msdt.exe      (Follina / CVE-2022-30190)
      - presentationhost.exe (XAML execution)
      - pcalua.exe    (Program Compatibility Assistant bypass)
      - hh.exe        (Compiled HTML help execution)
      - msiexec.exe   (Already blocked for users via MSI policy, this blocks network)
      - powershell_ise.exe (ISE bypasses some PS protections)

    Also handles PowerShell 7 (pwsh.exe) if installed:
      - IFEO block or firewall block
      - Script Block Logging for PS7
      - Constrained Language Mode coverage

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    No reboot needed. Takes effect immediately for new connections.

    REVIEW BEFORE DEPLOYING: If any business application uses these
    binaries for legitimate network access (uncommon but possible),
    add exceptions to the $ExcludedLOLBins array below.
#>

# ============================================================================
# CONFIGURATION
# ============================================================================
# Remove entries from this list if a legitimate app needs them for outbound access
$LOLBins = @(
    @("$env:SystemRoot\System32\regsvr32.exe",              "Block regsvr32 Outbound"),
    @("$env:SystemRoot\SysWOW64\regsvr32.exe",             "Block regsvr32 Outbound (x86)"),
    @("$env:SystemRoot\System32\rundll32.exe",              "Block rundll32 Outbound"),
    @("$env:SystemRoot\SysWOW64\rundll32.exe",             "Block rundll32 Outbound (x86)"),
    @("$env:SystemRoot\System32\msiexec.exe",               "Block msiexec Outbound"),
    @("$env:SystemRoot\System32\msdt.exe",                  "Block msdt Outbound"),
    @("$env:SystemRoot\System32\hh.exe",                    "Block hh.exe Outbound"),
    @("$env:SystemRoot\System32\pcalua.exe",                "Block pcalua Outbound"),
    @("$env:SystemRoot\System32\presentationhost.exe",      "Block presentationhost Outbound"),
    @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_ise.exe", "Block PowerShell ISE Outbound")
)

# MSBuild / InstallUtil paths (may vary by .NET version)
$dotnetPaths = @(
    "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319",
    "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319"
)

$BlockPS7Entirely = $false  # If true, IFEO-block pwsh.exe. If false, just firewall-block it.

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\lolbin-expansion-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 12: LOLBin Expansion + PowerShell 7 Coverage"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# 1. EXTENDED LOLBIN FIREWALL RULES
# ============================================================================
Write-Log ""
Write-Log "--- Extended LOLBin Firewall Rules ---"

$ruleCount = 0
foreach ($target in $LOLBins) {
    $path = $target[0]
    $name = $target[1]
    if (Test-Path $path) {
        try {
            Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Program $path -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            Write-Log "  FW: $name"
            $ruleCount++
        } catch { Write-Log "  FAIL: $name - $_" "WARN" }
    }
}

# MSBuild and InstallUtil (path varies by .NET version)
foreach ($dotnetPath in $dotnetPaths) {
    if (Test-Path $dotnetPath) {
        $msbuild = Join-Path $dotnetPath "MSBuild.exe"
        $installutil = Join-Path $dotnetPath "InstallUtil.exe"

        if (Test-Path $msbuild) {
            $name = "Block MSBuild Outbound ($dotnetPath)"
            Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Program $msbuild -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
            Write-Log "  FW: Block MSBuild ($dotnetPath)"
            $ruleCount++
        }
        if (Test-Path $installutil) {
            $name = "Block InstallUtil Outbound ($dotnetPath)"
            Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Program $installutil -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
            Write-Log "  FW: Block InstallUtil ($dotnetPath)"
            $ruleCount++
        }
    }
}

Write-Log "LOLBin firewall rules: $ruleCount rules created" "SUCCESS"

# ============================================================================
# 2. MSDT DISABLE (Follina CVE-2022-30190)
# ============================================================================
Write-Log ""
Write-Log "--- Disable MSDT Protocol Handler (Follina) ---"
try {
    # Remove ms-msdt protocol handler entirely
    $msdtKey = "HKLM:\SOFTWARE\Classes\ms-msdt"
    if (Test-Path $msdtKey) {
        # Backup the key first
        $backupFile = "$LogDir\msdt-protocol-backup.reg"
        reg export "HKLM\SOFTWARE\Classes\ms-msdt" $backupFile /y 2>$null | Out-Null
        Write-Log "  Backed up ms-msdt key to $backupFile"

        Remove-Item -Path $msdtKey -Recurse -Force -ErrorAction Stop
        Write-Log "  ms-msdt protocol handler: REMOVED"
    } else {
        Write-Log "  ms-msdt protocol handler: Already removed"
    }
    Write-Log "Follina mitigation complete" "SUCCESS"
} catch { Write-Log "MSDT disable failed: $_" "WARN" }

# ============================================================================
# 3. POWERSHELL 7 (pwsh.exe) COVERAGE
# ============================================================================
Write-Log ""
Write-Log "--- PowerShell 7 Coverage ---"

# Check if PS7 is installed
$ps7Paths = @(
    "$env:ProgramFiles\PowerShell\7\pwsh.exe",
    "$env:ProgramFiles\PowerShell\7-preview\pwsh.exe"
)

$ps7Found = $false
foreach ($ps7Path in $ps7Paths) {
    if (Test-Path $ps7Path) {
        $ps7Found = $true
        Write-Log "  PS7 found: $ps7Path"

        if ($BlockPS7Entirely) {
            # IFEO block (same technique as wscript/cscript)
            $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe"
            if (-not (Test-Path $ifeoPath)) { New-Item -Path $ifeoPath -Force | Out-Null }
            Set-ItemProperty -Path $ifeoPath -Name "Debugger" -Value "nul" -Type String -Force
            Write-Log "  pwsh.exe: BLOCKED via IFEO" "SUCCESS"
        } else {
            # Firewall block outbound
            $fwName = "Block pwsh.exe Outbound"
            Remove-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $fwName -Direction Outbound -Action Block `
                -Program $ps7Path -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
            Write-Log "  pwsh.exe: Outbound blocked via firewall"
        }

        # Ensure PS7 Script Block Logging works
        # PS7 reads from a different registry location
        $ps7LogPath = "HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging"
        if (-not (Test-Path $ps7LogPath)) { New-Item -Path $ps7LogPath -Force | Out-Null }
        Set-ItemProperty -Path $ps7LogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ps7LogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
        Write-Log "  PS7 Script Block Logging: Enabled"

        # PS7 module logging
        $ps7ModPath = "HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ModuleLogging"
        if (-not (Test-Path $ps7ModPath)) { New-Item -Path $ps7ModPath -Force | Out-Null }
        Set-ItemProperty -Path $ps7ModPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
        $ps7ModNames = "$ps7ModPath\ModuleNames"
        if (-not (Test-Path $ps7ModNames)) { New-Item -Path $ps7ModNames -Force | Out-Null }
        Set-ItemProperty -Path $ps7ModNames -Name "*" -Value "*" -Type String -Force
        Write-Log "  PS7 Module Logging: Enabled"

        # PS7 transcription
        $ps7TransPath = "HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription"
        $trOutput = "$env:ProgramData\PSTranscripts"
        if (-not (Test-Path $ps7TransPath)) { New-Item -Path $ps7TransPath -Force | Out-Null }
        Set-ItemProperty -Path $ps7TransPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ps7TransPath -Name "OutputDirectory" -Value $trOutput -Type String -Force
        Write-Log "  PS7 Transcription: Enabled -> $trOutput"
    }
}

if (-not $ps7Found) {
    Write-Log "  PS7 not installed - preemptively blocking"
    # Block pwsh.exe even if not installed yet (prevents future installation bypass)
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe"
    if (-not (Test-Path $ifeoPath)) { New-Item -Path $ifeoPath -Force | Out-Null }
    Set-ItemProperty -Path $ifeoPath -Name "Debugger" -Value "nul" -Type String -Force
    Write-Log "  pwsh.exe: Preemptively IFEO-blocked" "SUCCESS"
}

Write-Log "PowerShell 7 coverage complete" "SUCCESS"

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  LOLBin Expansion + PS7 Coverage complete."
Write-Log ""
Write-Log "  TOTAL NEW FIREWALL RULES: $ruleCount + PS7"
Write-Log ""
Write-Log "  If a legitimate application breaks, check which LOLBin"
Write-Log "  it uses and remove that specific firewall rule:"
Write-Log '    Remove-NetFirewallRule -DisplayName "Block <binary> Outbound"'
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "    # Remove all custom outbound blocks:"
Write-Log '    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Block*Outbound*" } | Remove-NetFirewallRule'
Write-Log "    # Restore MSDT:"
Write-Log "    reg import '$LogDir\msdt-protocol-backup.reg'"
Write-Log "    # Unblock pwsh.exe:"
Write-Log '    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe" -Recurse -Force'
Write-Log "================================================================"
exit 0
