#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 6: USB Storage Control
    Restricts USB removable storage access.
    Three modes: Audit (log only), ReadOnly, or FullBlock.

.DESCRIPTION
    USB drives are a top malware delivery vector and data exfiltration path.
    The v2 hardening script disabled autorun, but users can still plug in
    a USB drive and manually run malware or exfil data.

    This module offers three levels:
      Audit    = Log USB insertions but allow full access (detection only)
      ReadOnly = Allow reading USB but block writing (prevent data exfil)
      FullBlock = Block all removable storage access

    Default is ReadOnly - a good balance of security vs usability.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    Takes effect immediately for new USB insertions.
    Already-mounted drives may need to be re-inserted.

    ROLLBACK: Set $Mode = "Allow" and re-run, or delete the registry keys.
#>

# ============================================================================
# CONFIGURATION - Choose ONE mode
# ============================================================================
$Mode = "ReadOnly"   # Options: "Audit", "ReadOnly", "FullBlock", "Allow"

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\usb-control-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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
Write-Log "  MODULE 6: USB Storage Control"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "  Mode: $Mode"
Write-Log "================================================================"

$removablePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"

switch ($Mode) {
    "Audit" {
        Write-Log ""
        Write-Log "--- Audit Mode: Log USB activity only ---"
        # Remove any existing blocks
        Remove-ItemProperty -Path $removablePath -Name "Deny_Read" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $removablePath -Name "Deny_Write" -ErrorAction SilentlyContinue

        # Enable PnP auditing to log USB insertions
        try {
            auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable 2>$null | Out-Null
            Write-Log "  PnP audit logging enabled"
            Write-Log "  USB access: ALLOWED (logging all insertions)"
            Write-Log "  Monitor Event ID 6416 (PnP device connected)" 
        } catch {}
        Write-Log "Audit mode configured" "SUCCESS"
    }

    "ReadOnly" {
        Write-Log ""
        Write-Log "--- Read-Only Mode: Block USB writes ---"
        Set-Reg $removablePath "Deny_Read" 0 "DWord" "USB read: ALLOWED"
        Set-Reg $removablePath "Deny_Write" 1 "DWord" "USB write: BLOCKED"

        # Also block write on WPD devices (phones, cameras)
        $wpdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}"
        Set-Reg $wpdPath "Deny_Write" 1 "DWord" "WPD device write: BLOCKED"

        # Enable PnP audit logging
        auditpol /set /subcategory:"Plug and Play Events" /success:enable 2>$null | Out-Null

        Write-Log "Read-Only mode configured" "SUCCESS"
        Write-Log "Users can READ from USB drives but cannot WRITE to them"
    }

    "FullBlock" {
        Write-Log ""
        Write-Log "--- Full Block Mode: No USB storage access ---"
        Set-Reg $removablePath "Deny_Read" 1 "DWord" "USB read: BLOCKED"
        Set-Reg $removablePath "Deny_Write" 1 "DWord" "USB write: BLOCKED"

        # Block WPD devices too
        $wpdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}"
        Set-Reg $wpdPath "Deny_Read" 1 "DWord" "WPD read: BLOCKED"
        Set-Reg $wpdPath "Deny_Write" 1 "DWord" "WPD write: BLOCKED"

        # Block floppy (yes, still exploited via VM tools)
        $floppyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}"
        Set-Reg $floppyPath "Deny_Read" 1 "DWord" "Floppy read: BLOCKED"
        Set-Reg $floppyPath "Deny_Write" 1 "DWord" "Floppy write: BLOCKED"

        auditpol /set /subcategory:"Plug and Play Events" /success:enable 2>$null | Out-Null

        Write-Log "Full Block mode configured" "SUCCESS"
        Write-Log "*** ALL removable storage access is blocked ***"
    }

    "Allow" {
        Write-Log ""
        Write-Log "--- Removing all USB restrictions ---"
        $parentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
        if (Test-Path $parentPath) {
            Remove-Item -Path $parentPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Log "All USB restrictions removed" "SUCCESS"
    }

    default {
        Write-Log "Invalid mode: $Mode (use Audit, ReadOnly, FullBlock, or Allow)" "ERROR"
        exit 1
    }
}

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  USB Storage Control complete."
Write-Log "  Takes effect immediately."
Write-Log ""
Write-Log "  ROLLBACK: Re-run with `$Mode = 'Allow'"
Write-Log "  Or: Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Recurse -Force"
Write-Log "================================================================"

exit 0
