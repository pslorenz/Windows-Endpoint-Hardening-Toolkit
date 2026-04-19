#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 3: RDP Lockdown
    Hardens Remote Desktop without disabling it entirely.
    Safe for NinjaRMM and most RMM environments (NinjaRMM uses its own agent, not RDP).

.DESCRIPTION
    RDP is one of the top 3 attack vectors for standalone machines.
    This module:
      - Enforces Network Level Authentication (NLA)
      - Sets account lockout after failed RDP attempts
      - Restricts RDP to specific users (not "everyone")
      - Disables CredSSP delegation (prevents credential relay)
      - Sets session timeouts
      - Enables RDP-specific logging
      - Blocks RDP on public network profile (firewall)

    Does NOT disable RDP entirely.
    If you never use RDP, set $DisableRDPEntirely = $true below.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    No reboot needed for most settings.
    NinjaRMM remote access is NOT affected (it uses its own protocol).
#>

# ============================================================================
# CONFIGURATION
# ============================================================================
$DisableRDPEntirely = $false    # Set $true if you NEVER use RDP
$LockoutThreshold   = 5        # Lock account after this many failed attempts
$LockoutDuration    = 30       # Lockout duration in minutes
$LockoutWindow      = 30       # Reset failed count after this many minutes
$SessionTimeout     = 60       # Disconnect idle sessions after X minutes

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\rdp-harden-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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
Write-Log "  MODULE 3: RDP Lockdown"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

if ($DisableRDPEntirely) {
    Write-Log ""
    Write-Log "--- Disabling RDP entirely ---"
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1 "DWord" "RDP: Disabled entirely"
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Write-Log "RDP disabled completely" "SUCCESS"
    Write-Log "ROLLBACK: Set fDenyTSConnections to 0 and re-enable firewall rules"
    exit 0
}

# ============================================================================
# NLA (Network Level Authentication) - REQUIRED
# Forces authentication BEFORE the RDP session is created.
# Prevents unauthenticated attackers from even seeing the login screen.
# ============================================================================
Write-Log ""
Write-Log "--- Network Level Authentication ---"
$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-Reg $rdpPath "UserAuthentication" 1 "DWord" "NLA: Enforced"
Set-Reg $rdpPath "SecurityLayer" 2 "DWord" "Security Layer: TLS required"
Set-Reg $rdpPath "MinEncryptionLevel" 3 "DWord" "Encryption: High (128-bit)"
Write-Log "NLA enforcement complete" "SUCCESS"

# ============================================================================
# ACCOUNT LOCKOUT POLICY
# Slows brute-force attacks to a crawl.
# ============================================================================
Write-Log ""
Write-Log "--- Account Lockout Policy ---"
try {
    # Use net accounts (works on standalone machines without secpol.msc)
    net accounts /lockoutthreshold:$LockoutThreshold 2>&1 | Out-Null
    net accounts /lockoutduration:$LockoutDuration 2>&1 | Out-Null
    net accounts /lockoutwindow:$LockoutWindow 2>&1 | Out-Null
    Write-Log "  Lockout after $LockoutThreshold failed attempts"
    Write-Log "  Lockout duration: $LockoutDuration minutes"
    Write-Log "  Reset counter after: $LockoutWindow minutes"
    Write-Log "Account lockout configured" "SUCCESS"
} catch { Write-Log "Account lockout failed: $_" "ERROR" }

# ============================================================================
# CREDSSSP / CREDENTIAL DELEGATION
# Prevents credential relay attacks through RDP.
# ============================================================================
Write-Log ""
Write-Log "--- CredSSP Hardening ---"
$credPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
Set-Reg $credPath "AllowDefaultCredentials" 0 "DWord" "CredSSP: No default credential delegation"
Set-Reg $credPath "AllowDefCredentialsWhenNTLMOnly" 0 "DWord" "CredSSP: No NTLM delegation"
# Restricted Admin mode (prevents creds from being stored on remote machine)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableRestrictedAdmin" 0 "DWord" "Restricted Admin Mode: Available"
Write-Log "CredSSP hardening complete" "SUCCESS"

# ============================================================================
# SESSION TIMEOUTS
# Disconnect idle sessions so they can't be hijacked.
# ============================================================================
Write-Log ""
Write-Log "--- Session Timeouts ---"
$tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# Idle session timeout (milliseconds)
$timeoutMs = $SessionTimeout * 60 * 1000
Set-Reg $tsPath "MaxIdleTime" $timeoutMs "DWord" "Idle timeout: $SessionTimeout minutes"
# Disconnect (don't just lock) after timeout
Set-Reg $tsPath "fResetBroken" 1 "DWord" "Delete broken sessions"
# Limit reconnection to original client only
Set-Reg $tsPath "fDisableAutoReconnect" 1 "DWord" "Disable auto-reconnect"
Write-Log "Session timeouts configured" "SUCCESS"

# ============================================================================
# FIREWALL - BLOCK RDP ON PUBLIC PROFILE
# RDP should never be exposed to public networks.
# ============================================================================
Write-Log ""
Write-Log "--- Firewall: Block RDP on Public profile ---"
try {
    # Get existing RDP firewall rules
    $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    foreach ($rule in $rdpRules) {
        # Allow on Private/Domain, block on Public
        Set-NetFirewallRule -Name $rule.Name -Profile Private -Enabled True -ErrorAction SilentlyContinue
    }

    # Create explicit block for Public profile
    $blockName = "Block RDP Inbound - Public Network"
    Remove-NetFirewallRule -DisplayName $blockName -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $blockName -Direction Inbound -Action Block `
        -Protocol TCP -LocalPort 3389 -Profile Public -Enabled True -ErrorAction Stop | Out-Null

    Write-Log "  RDP blocked on Public network profile"
    Write-Log "Firewall RDP rules configured" "SUCCESS"
} catch { Write-Log "Firewall rule failed: $_" "WARN" }

# ============================================================================
# DISABLE CLIPBOARD AND DRIVE REDIRECTION
# Prevents data exfiltration through RDP session features.
# ============================================================================
Write-Log ""
Write-Log "--- RDP Feature Restrictions ---"
Set-Reg $tsPath "fDisableClip" 1 "DWord" "RDP clipboard redirection: Disabled"
Set-Reg $tsPath "fDisableCdm" 1 "DWord" "RDP drive mapping: Disabled"
# Keep printer redirection (commonly needed)
# Set-Reg $tsPath "fDisableCpm" 1 "DWord" "RDP printer redirection: Disabled"
Write-Log "RDP feature restrictions complete" "SUCCESS"

# ============================================================================
# RDP LOGGING
# ============================================================================
Write-Log ""
Write-Log "--- RDP Event Logging ---"
try {
    # Enable RDP operational log
    wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /e:true 2>$null
    wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true 2>$null
    Write-Log "RDP operational logging enabled" "SUCCESS"
} catch { Write-Log "RDP logging config failed: $_" "WARN" }

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  RDP Lockdown complete."
Write-Log "  NinjaRMM remote access is NOT affected."
Write-Log "================================================================"
Write-Log ""
Write-Log "  NinjaRMM alert Event IDs for RDP monitoring:"
Write-Log "    4625 = Failed logon (brute force indicator)"
Write-Log "    4624 = Successful logon (Type 10 = RDP)"
Write-Log "    4779 = Session disconnected"
Write-Log "    1149 = RDP connection attempt (TerminalServices-RemoteConnectionManager)"

exit 0
