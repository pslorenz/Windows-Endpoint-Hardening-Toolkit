#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 11: Print Spooler Hardening
    Mitigates PrintNightmare and related vulnerabilities WITHOUT
    breaking existing printer configurations.

.DESCRIPTION
    PrintNightmare (CVE-2021-34527, CVE-2021-1675) allowed remote code
    execution through the Print Spooler service. Microsoft patched it,
    but the default configuration is still too permissive.

    This module applies the SAFE hardening settings:
      - Require admin for new printer driver installation
      - Restrict Point and Print to specific servers (or block entirely)
      - Disable remote Print Spooler access for non-admins
      - Block PrintSpooler from accepting client connections

    KEY DESIGN DECISION: Existing printers continue to work. These
    settings only trigger when ADDING a new printer or updating a driver.
    Users will need admin credentials (from Module 1's LocalITAdmin
    account) to add new printers — which is the correct behavior.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    No reboot needed. Existing printers unaffected.
    Users will need admin approval to ADD new printers.
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\printspooler-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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
Write-Log "  MODULE 11: Print Spooler Hardening"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# 1. RESTRICT DRIVER INSTALLATION TO ADMINISTRATORS
#    This is the single most important PrintNightmare mitigation.
#    KB5005010 introduced this setting.
# ============================================================================
Write-Log ""
Write-Log "--- Restrict Driver Installation ---"
$ppPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
Set-Reg $ppPath "RestrictDriverInstallationToAdministrators" 1 "DWord" "Printer drivers: Admin only install"

# When installing drivers for a new connection: 0 = Show warning and elevation prompt
Set-Reg $ppPath "NoWarningNoElevationOnInstall" 0 "DWord" "New printer connection: Require elevation"

# When updating drivers for an existing connection: 0 = Show warning and elevation prompt
Set-Reg $ppPath "UpdatePromptSettings" 0 "DWord" "Driver update: Require elevation"

Write-Log "Driver installation restricted to admins" "SUCCESS"

# ============================================================================
# 2. DISABLE REMOTE PRINT SPOOLER (INBOUND)
#    Prevents remote machines from exploiting the Print Spooler.
#    Local printing still works perfectly.
# ============================================================================
Write-Log ""
Write-Log "--- Disable Remote Print Spooler ---"

# Disallow remote RPC connections to the spooler
$printPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Set-Reg $printPath "RegisterSpoolerRemoteRpcEndPoint" 2 "DWord" "Spooler: Deny remote RPC connections"

# Disable printer sharing (standalone machines shouldn't share printers)
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" 1 "DWord" "Disable HTTP printing"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" 1 "DWord" "Disable web PnP driver download"

Write-Log "Remote Print Spooler access disabled" "SUCCESS"

# ============================================================================
# 3. PACKAGE POINT AND PRINT (SAFER ALTERNATIVE)
#    Only allow installing pre-packaged print drivers.
#    Package drivers don't require kernel-level access.
# ============================================================================
Write-Log ""
Write-Log "--- Package Point and Print ---"
Set-Reg $ppPath "PackagePointAndPrintOnly" 1 "DWord" "Point and Print: Package drivers only"
Set-Reg $ppPath "PackagePointAndPrintServerList" 1 "DWord" "Point and Print: Approved servers only"

Write-Log "Package Point and Print enforced" "SUCCESS"

# ============================================================================
# 4. PRINT SPOOLER SERVICE HARDENING
# ============================================================================
Write-Log ""
Write-Log "--- Spooler Service Settings ---"

# Disable legacy directory listing (CVE-2021-36958)
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "CopyFilesPolicy" 1 "DWord" "Copy Files policy: Restricted"

# Redirection Guard (prevents print driver DLL planting)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RedirectionGuard" 1 "DWord" "Print Redirection Guard: Enabled"

Write-Log "Spooler service hardened" "SUCCESS"

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Print Spooler Hardening complete."
Write-Log ""
Write-Log "  WHAT USERS WILL EXPERIENCE:"
Write-Log "  - Existing printers: NO CHANGE (continue working)"
Write-Log "  - Adding new printer: Requires admin credentials"
Write-Log "  - Driver updates: Requires admin approval"
Write-Log ""
Write-Log "  If using Module 1 (LocalAdminRemoval), users will be"
Write-Log "  prompted for LocalITAdmin credentials when adding printers."
Write-Log "  This is the correct and secure behavior."
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "  Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Recurse -Force"
Write-Log "  Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint'"
Write-Log "================================================================"
exit 0
  
