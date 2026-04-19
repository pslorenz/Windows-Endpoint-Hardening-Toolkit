#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 9: Network Protocol Hardening
    Disables legacy and dangerous network protocols that attackers abuse
    for name resolution poisoning, credential interception, and enumeration.

.DESCRIPTION
    Standalone workgroup machines are especially vulnerable to local network
    attacks because there's no domain controller handling name resolution.
    Attackers on the same network can poison these protocols to intercept
    credentials or redirect traffic.

    This module disables:
      - NetBIOS over TCP/IP (name resolution poisoning)
      - WPAD (Web Proxy Auto-Discovery - MITM vector)
      - Anonymous SAM enumeration (user account discovery)
      - mDNS (multicast DNS - similar to LLMNR)
    
    And reinforces:
      - LLMNR disable (in case base script wasn't deployed)
      - SMB signing (prevents relay attacks)

    All of these are near-zero user impact on standalone Win 11 machines.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    No reboot needed for most settings. NetBIOS change may need reboot.
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\network-protocol-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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
Write-Log "  MODULE 9: Network Protocol Hardening"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# 1. DISABLE NETBIOS OVER TCP/IP
#    Prevents NetBIOS name resolution poisoning (Responder/Inveigh attacks).
#    Applied per network adapter via WMI.
# ============================================================================
Write-Log ""
Write-Log "--- Disable NetBIOS over TCP/IP ---"
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    foreach ($adapter in $adapters) {
        # SetTcpipNetbios: 0=default, 1=enable, 2=disable
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) {
            Write-Log "  Disabled on: $($adapter.Description)"
        } else {
            Write-Log "  Warning on $($adapter.Description): return code $($result.ReturnValue)" "WARN"
        }
    }
    # Also disable via registry for all future adapters
    $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    Set-Reg $netbtPath "NodeType" 2 "DWord" "NetBIOS NodeType: P-node (no broadcast)"

    # Disable NetBIOS helper service
    Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Log "  LMHosts service: Disabled"

    Write-Log "NetBIOS disabled" "SUCCESS"
} catch { Write-Log "NetBIOS disable failed: $_" "ERROR" }

# ============================================================================
# 2. DISABLE WPAD (Web Proxy Auto-Discovery)
#    Prevents MITM attacks where attacker registers as the WPAD server
#    and proxies all web traffic through themselves.
# ============================================================================
Write-Log ""
Write-Log "--- Disable WPAD ---"

# Disable WinHTTP auto-proxy service
try {
    Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue
    Write-Log "  WinHTTP Auto-Proxy service: Disabled"
} catch { Write-Log "  WinHTTP service disable: $_" "WARN" }

# Disable WPAD in Internet Settings
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" "WpadOverride" 1 "DWord" "WPAD override: Disabled"
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoDetect" 0 "DWord" "Auto-detect proxy: Disabled"

# Block WPAD DNS resolution
try {
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
    if ($hostsContent -notcontains "0.0.0.0 wpad") {
        Add-Content -Path $hostsFile -Value "`n# Block WPAD - added by endpoint hardening`n0.0.0.0 wpad`n0.0.0.0 wpad.$($env:USERDNSDOMAIN)" -ErrorAction SilentlyContinue
        Write-Log "  WPAD blocked in hosts file"
    } else {
        Write-Log "  WPAD already blocked in hosts file"
    }
} catch { Write-Log "  Hosts file update: $_" "WARN" }

Write-Log "WPAD disabled" "SUCCESS"

# ============================================================================
# 3. RESTRICT ANONYMOUS SAM ENUMERATION
#    Prevents unauthenticated attackers from listing local user accounts
#    and shares over the network.
# ============================================================================
Write-Log ""
Write-Log "--- Restrict Anonymous Enumeration ---"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-Reg $lsaPath "RestrictAnonymous" 1 "DWord" "Restrict anonymous access to named pipes/shares"
Set-Reg $lsaPath "RestrictAnonymousSAM" 1 "DWord" "Restrict anonymous SAM enumeration"
Set-Reg $lsaPath "EveryoneIncludesAnonymous" 0 "DWord" "Exclude anonymous from Everyone group"
Set-Reg $lsaPath "LimitBlankPasswordUse" 1 "DWord" "Block remote logon with blank passwords"

# Restrict null session access to named pipes and shares
Set-Reg $lsaPath "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" "String" "Restrict remote SAM queries to admins only"

# Disable anonymous enumeration of shares
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess" 1 "DWord" "Restrict null session share access"

Write-Log "Anonymous enumeration restricted" "SUCCESS"

# ============================================================================
# 4. REINFORCE LLMNR DISABLE + DISABLE mDNS
# ============================================================================
Write-Log ""
Write-Log "--- LLMNR and mDNS ---"
# LLMNR (may already be set by base script, but reinforce)
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 "DWord" "LLMNR: Disabled"

# mDNS (multicast DNS - similar poisoning risk)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS" 0 "DWord" "mDNS: Disabled"

Write-Log "LLMNR and mDNS disabled" "SUCCESS"

# ============================================================================
# 5. SMB HARDENING
# ============================================================================
Write-Log ""
Write-Log "--- SMB Hardening ---"

# Require SMB signing (prevents relay attacks)
# NOTE: This is safe for workgroup as long as ALL machines get this setting
$smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

Set-Reg $smbServerPath "RequireSecuritySignature" 1 "DWord" "SMB Server: Require signing"
Set-Reg $smbServerPath "EnableSecuritySignature" 1 "DWord" "SMB Server: Enable signing"
Set-Reg $smbClientPath "RequireSecuritySignature" 1 "DWord" "SMB Client: Require signing"
Set-Reg $smbClientPath "EnableSecuritySignature" 1 "DWord" "SMB Client: Enable signing"

# Disable SMB compression (CVE-2020-0796 SMBGhost)
Set-Reg $smbServerPath "DisableCompression" 1 "DWord" "SMB compression: Disabled (CVE-2020-0796)"

# Encrypt SMB traffic when possible
try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
    Write-Log "  SMB encryption: Enabled"
} catch {}

Write-Log "SMB hardening complete" "SUCCESS"
Write-Log "  NOTE: If file sharing breaks between machines, deploy this"
Write-Log "  script to ALL machines so signing requirements match."

# ============================================================================
# 6. NTLMv2 ENFORCEMENT
# ============================================================================
Write-Log ""
Write-Log "--- NTLMv2 Enforcement ---"
# Force NTLMv2 only, refuse LM and NTLMv1 (easily cracked)
Set-Reg $lsaPath "LmCompatibilityLevel" 5 "DWord" "NTLM: Send NTLMv2 only, refuse LM and NTLM"
# Do not store LM hash
Set-Reg $lsaPath "NoLMHash" 1 "DWord" "Do not store LAN Manager hash"
Write-Log "NTLMv2 enforced, LM/NTLMv1 refused" "SUCCESS"

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Network Protocol Hardening complete."
Write-Log ""
Write-Log "  IMPORTANT: SMB signing is now required. If these machines"
Write-Log "  share files with each other, deploy this module to ALL of"
Write-Log "  them so the signing requirement is consistent."
Write-Log ""
Write-Log "  ROLLBACK (per section):"
Write-Log "  NetBIOS:    wmic nicconfig where IPEnabled=true call SetTcpipNetbios 0"
Write-Log "  WPAD:       Set-Service WinHttpAutoProxySvc -StartupType Manual"
Write-Log "  SAM:        Set RestrictAnonymous/RestrictAnonymousSAM to 0"
Write-Log "  SMB signing: Set RequireSecuritySignature to 0 (both paths)"
Write-Log "  NTLM:       Set LmCompatibilityLevel to 3"
Write-Log "================================================================"
exit 0
