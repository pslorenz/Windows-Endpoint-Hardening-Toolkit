#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 5: BitLocker Silent Enablement
    Encrypts the OS drive with BitLocker and outputs the recovery key
    for storage in NinjaRMM documentation.

.DESCRIPTION
    If a laptop is stolen, BitLocker is the difference between
    "we lost a laptop" and "we have a data breach to report." 
    There are far more secure methodologies to enable BitLocker - See CIS guidance 

    This script:
      1. Checks TPM 2.0 availability (required for silent enable)
      2. Enables BitLocker on C: with TPM protector
      3. Adds a Recovery Password protector
      4. Outputs the Recovery Key to script output (capture in NinjaRMM!)
      5. Starts encryption in the background

    Encryption happens in the background and does NOT impact user
    productivity. Modern Win 11 machines complete in 30-90 minutes.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 120s
    No reboot needed (Win 11 encrypts online).
    CRITICAL: Capture the recovery key from script output!

    ROLLBACK: manage-bde -off C:
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\bitlocker-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 5: BitLocker Enablement"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================
Write-Log ""
Write-Log "--- Pre-flight checks ---"

# Check if already encrypted
$blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($blStatus) {
    Write-Log "  Current protection: $($blStatus.ProtectionStatus)"
    Write-Log "  Encryption %: $($blStatus.EncryptionPercentage)"
    Write-Log "  Volume status: $($blStatus.VolumeStatus)"

    if ($blStatus.ProtectionStatus -eq "On") {
        Write-Log ""
        Write-Log "BitLocker is already ON and protecting C:" "SUCCESS"

        # Still output the recovery key for documentation
        $recoveryProtector = $blStatus.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
        if ($recoveryProtector) {
            Write-Host ""
            Write-Host "========================================================" -ForegroundColor Green
            Write-Host "  EXISTING RECOVERY KEY (for documentation):" -ForegroundColor Green
            Write-Host "  Key ID:   $($recoveryProtector.KeyProtectorId)" -ForegroundColor Yellow
            Write-Host "  Recovery: $($recoveryProtector.RecoveryPassword)" -ForegroundColor Yellow
            Write-Host "========================================================" -ForegroundColor Green
        }
        exit 0
    }
}

# Check TPM
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if (-not $tpm -or -not $tpm.TpmPresent) {
    Write-Log "TPM not present - BitLocker requires TPM 2.0" "ERROR"
    Write-Log "This machine cannot use silent BitLocker encryption" "ERROR"
    exit 1
}
if (-not $tpm.TpmReady) {
    Write-Log "TPM present but not ready - may need BIOS configuration" "ERROR"
    exit 1
}
Write-Log "  TPM: Present and ready (version $($tpm.ManufacturerVersion))"

# Check OS drive is NTFS (required for BitLocker)
$osDrive = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
if ($osDrive.FileSystemType -ne "NTFS") {
    Write-Log "C: is not NTFS - BitLocker requires NTFS" "ERROR"
    exit 1
}
Write-Log "  File system: NTFS"
Write-Log "  Drive size: $([math]::Round($osDrive.Size / 1GB, 1)) GB"
Write-Log "Pre-flight checks passed" "SUCCESS"

# ============================================================================
# ENABLE BITLOCKER
# ============================================================================
Write-Log ""
Write-Log "--- Enabling BitLocker ---"
try {
    # Add TPM protector
    $tpmResult = Enable-BitLocker -MountPoint "C:" `
        -TpmProtector `
        -EncryptionMethod XtsAes256 `
        -UsedSpaceOnly `
        -SkipHardwareTest `
        -ErrorAction Stop

    Write-Log "  TPM protector added"

    # Add Recovery Password protector
    $recoveryResult = Add-BitLockerKeyProtector -MountPoint "C:" `
        -RecoveryPasswordProtector `
        -ErrorAction Stop

    Write-Log "  Recovery Password protector added"

    # Get the recovery key
    Start-Sleep -Seconds 2
    $blVolume = Get-BitLockerVolume -MountPoint "C:"
    $recoveryKey = $blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

    if ($recoveryKey) {
        Write-Log ""
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Red
        Write-Host "  BITLOCKER RECOVERY KEY" -ForegroundColor Red
        Write-Host "  COPY THIS INTO NINJARMM DOCUMENTATION NOW!" -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "  Computer:  $env:COMPUTERNAME" -ForegroundColor Yellow
        Write-Host "  Key ID:    $($recoveryKey.KeyProtectorId)" -ForegroundColor Yellow
        Write-Host "  Recovery:  $($recoveryKey.RecoveryPassword)" -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Red
        Write-Host ""

        # Also save locally as backup
        $keyBackup = "$LogDir\bitlocker-recovery-key.txt"
        @"
Computer:     $env:COMPUTERNAME
Date:         $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Key ID:       $($recoveryKey.KeyProtectorId)
Recovery Key: $($recoveryKey.RecoveryPassword)

STORE THIS SECURELY AND DELETE THIS FILE.
"@ | Out-File -FilePath $keyBackup -Encoding UTF8
        Write-Log "  Recovery key also saved to: $keyBackup"
        Write-Log "  *** DELETE THIS FILE after copying key to NinjaRMM ***"
    }

    # NinjaRMM custom field (uncomment and adjust)
    # Ninja-Property-Set bitlockerRecoveryKey "$($recoveryKey.RecoveryPassword)"
    # Ninja-Property-Set bitlockerKeyId "$($recoveryKey.KeyProtectorId)"

    Write-Log ""
    Write-Log "BitLocker encryption started" "SUCCESS"
    Write-Log "Encryption will complete in the background (30-90 minutes)"
    Write-Log "User can continue working normally during encryption"

} catch {
    Write-Log "BitLocker enablement failed: $_" "ERROR"
    exit 1
}

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  BitLocker enablement complete."
Write-Log "  Encryption is running in the background."
Write-Log "  Check progress: manage-bde -status C:"
Write-Log ""
Write-Log "  ROLLBACK: manage-bde -off C:"
Write-Log "================================================================"

exit 0
