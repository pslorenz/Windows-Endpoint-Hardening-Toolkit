#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 1: Local Admin Removal
    Creates a dedicated local admin account, downgrades daily user to Standard.
    THE single highest-value security change for standalone machines.

    This script:
      1. Creates a local admin account "LocalITAdmin" with a unique random password
      2. Outputs the password to the NinjaRMM script output (capture it!)
      3. Identifies the currently logged-in non-admin user(s)
      4. Removes them from the local Administrators group
      5. Leaves a breadcrumb in the event log

    IMPORTANT: The password is shown ONCE in the script output. Copy it into
    NinjaRMM's Documentation or a custom field immediately.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 120s
    TEST ON ONE MACHINE FIRST.
    Ensure you have another way in (NinjaRMM remote, physical access)
    before removing admin rights from the daily user.

    ROLLBACK: Add the user back to Administrators group:
      net localgroup Administrators <username> /add
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\admin-removal-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

# ============================================================================
# CONFIGURATION
# ============================================================================
$AdminAccountName = "LocalITAdmin"
$AdminFullName    = "IT Administration Account"
$AdminDescription = "Managed by MSP - Do not modify"
$PasswordLength   = 24

# Generate a cryptographically random password
Add-Type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, 4)

# ============================================================================
# EXECUTION
# ============================================================================
Write-Log "================================================================"
Write-Log "  MODULE 1: Local Admin Removal"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# Step 1: Create the local admin account
Write-Log ""
Write-Log "--- Step 1: Create local admin account ---"
$existingAccount = Get-LocalUser -Name $AdminAccountName -ErrorAction SilentlyContinue
if ($existingAccount) {
    Write-Log "$AdminAccountName already exists - resetting password"
    try {
        $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
        Set-LocalUser -Name $AdminAccountName -Password $securePass -ErrorAction Stop
        Enable-LocalUser -Name $AdminAccountName -ErrorAction SilentlyContinue
        Write-Log "Password reset successful" "SUCCESS"
    } catch { Write-Log "Password reset failed: $_" "ERROR"; exit 1 }
} else {
    try {
        $securePass = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $AdminAccountName -Password $securePass `
            -FullName $AdminFullName -Description $AdminDescription `
            -PasswordNeverExpires -UserMayNotChangePassword `
            -ErrorAction Stop | Out-Null
        Write-Log "$AdminAccountName created" "SUCCESS"
    } catch { Write-Log "Account creation failed: $_" "ERROR"; exit 1 }
}

# Ensure it's in the Administrators group
try {
    Add-LocalGroupMember -Group "Administrators" -Member $AdminAccountName -ErrorAction SilentlyContinue
    Write-Log "$AdminAccountName added to Administrators group"
} catch {}

# Hide the account from the login screen (optional but cleaner)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name $AdminAccountName -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Log "$AdminAccountName hidden from login screen"

# Step 2: Identify daily-use accounts that are currently local admins
Write-Log ""
Write-Log "--- Step 2: Identify users to downgrade ---"
$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$systemAccounts = @("Administrator", $AdminAccountName, "DefaultAccount", "WDAGUtilityAccount")

$usersToDowngrade = @()
foreach ($member in $adminGroup) {
    $name = $member.Name.Split('\')[-1]
    if ($name -notin $systemAccounts -and $member.ObjectClass -eq "User" -and $member.PrincipalSource -eq "Local") {
        $usersToDowngrade += $name
        Write-Log "  Found: $name (will downgrade to Standard User)"
    }
}

if ($usersToDowngrade.Count -eq 0) {
    Write-Log "No daily-use accounts found in Administrators group" "WARN"
    Write-Log "Users may already be standard users, or using domain/Azure AD accounts"
} else {
    # Step 3: Remove admin rights
    Write-Log ""
    Write-Log "--- Step 3: Downgrade users to Standard ---"
    foreach ($user in $usersToDowngrade) {
        try {
            Remove-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction Stop
            Write-Log "  DOWNGRADED: $user -> Standard User" "SUCCESS"
        } catch {
            Write-Log "  FAILED to downgrade $user : $_" "ERROR"
        }
    }
}

# Ensure downgraded users are in the Users group (they should be already)
foreach ($user in $usersToDowngrade) {
    Add-LocalGroupMember -Group "Users" -Member $user -ErrorAction SilentlyContinue
}

# ============================================================================
# OUTPUT - Important
# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  RESULTS"
Write-Log "================================================================"
Write-Log ""
Write-Log "  Computer:     $env:COMPUTERNAME"
Write-Log "  Admin Account: $AdminAccountName"
Write-Log ""
Write-Host "========================================================" -ForegroundColor Red
Write-Host "  PASSWORD (copy this NOW):" -ForegroundColor Red
Write-Host "  $Password" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Red
Write-Log ""
Write-Log "  Users downgraded: $($usersToDowngrade -join ', ')"
Write-Log ""
Write-Log "  ROLLBACK: net localgroup Administrators <username> /add"
Write-Log ""
Write-Log "  The user will need to log out and back in for the"
Write-Log "  change to take effect. UAC prompts will now ask for"
Write-Log "  the LocalITAdmin password instead of just Yes/No."
Write-Log "================================================================"

# NinjaRMM custom field output (uncomment and adjust field names)
# Ninja-Property-Set localAdminAccount $AdminAccountName
# Ninja-Property-Set localAdminPassword $Password

exit 0
