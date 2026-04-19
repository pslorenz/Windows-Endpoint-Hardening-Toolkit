# Module Reference

A concise reference for each module in the toolkit. Use this to understand what each module does, what it changes, and what toggles are available. Be informed, turn around, don't drown. Scripts have been tested, but there may be better/safer ways to accomplish some of this.  

## Base Script: Harden-Endpoint-v2.ps1

The foundation layer. Deploy this first, always.

**What it does:** Blocks WScript/CScript via IFEO. Enables PowerShell Constrained Language Mode. Enables Script Block Logging, Module Logging, and Transcription. Disables PowerShell v2. Applies 15 ASR rules (requires Defender as active AV). Restricts MSI installation to admins. Sets DNS to Quad9 with DoH. Applies exploit mitigations to explorer.exe and powershell.exe. Enables LSA Protection. Blocks script hosts and LOLBins outbound via firewall. Disables autorun, WDigest, PS remoting, LLMNR. Removes SMBv1. Enforces Windows Firewall. Blocks internet-sourced Office macros and DDE. Enforces Windows Update auto-install. Configures security audit policy with command-line logging.

**Key toggles (all default to $true):**

| Toggle | What it controls |
|--------|-----------------|
| `$BlockWScriptCScript` | IFEO block on wscript.exe and cscript.exe |
| `$ConstrainPowerShell` | `__PSLockdownPolicy` environment variable |
| `$DisablePowerShellV2` | removes PSV2 which had no AMSI or logging |
| `$EnablePSLogging` | Script Block, Module, and Transcription logging |
| `$EnableASRRules` | 15 Attack Surface Reduction rules (auto-skips if Defender is not active AV) |
| `$RestrictMSIInstall` | MSI installer policy for standard users |
| `$SetProtectiveDNS` | Quad9 DNS on all active adapters, modify if you prefer Umbrella |
| `$BlockScriptHostNetwork` | Firewall outbound blocks for wscript, cscript, mshta, certutil, bitsadmin |
| `$DisableAutorun` | Autorun/autoplay on all drive types |
| `DisableWDigest` | Prevents plaintext cred caching | 
| `$EnforceWindowsFirewall` | Enables firewall for all profiles |
| `$DisableRemoteAssistance` | Disable unsolicited remote assistance |
| `$DisableMacrosFromInternet` | Blocks Macros from downloaded files |
| `$EnforceWindowsUpdate` | Auto-download and install updates (DISABLE IF YOU MANAGE PATCHING VIA RMM OR WSUS)|
| `$EnableAuditPolicy` | Enables logging of some new security events |
| `$DisableLLMNR` | Disables LLMNR |
| `$HardenSMB` | SMBv1 removal, basic SMB Hardening |
| `$BlockUntrustedFonts` | Blocks untrusted fonts |

**Reboot required:** Yes.

## Module 1: Local Admin Removal (Can skip if you use AzureLAPS or already have per-device admin creds)

**What it does:** Creates a `LocalITAdmin` account with a random 24-character password. Downgrades the daily user account from Administrator to Standard User. Hides the admin account from the login screen.

**Critical:** The password is displayed once in the script output. Capture it immediately manually or via your RMM.

**User impact:** UAC prompts now require LocalITAdmin credentials. Software installation requires IT/MSP involvement.

**Reboot required:** No. User must log out and back in.

## Module 2: Browser Hardening

**What it does:** Applies security policies to Edge and Chrome via local registry. Enforces SmartScreen. Blocks user bypass of SmartScreen warnings. Blocks all extensions by default (allowlist model). Enables DNS-over-HTTPS. Blocks SSL error bypass. Reassociates dangerous file types (.js, .vbs, .hta, .scr, etc.) to open in Notepad instead of executing.

**Key consideration:** Extension blocking is the most user-visible change. Maintain an allowlist of approved extension IDs per customer.

**Reboot required:** No. Browsers pick up policy on next launch.

## Module 3: RDP Lockdown

**What it does:** Enforces Network Level Authentication. Sets account lockout (5 attempts, 30-minute lockout). Hardens CredSSP delegation. Sets idle session timeout (60 minutes). Blocks RDP on public network profile. Disables clipboard and drive redirection through RDP sessions. Enables RDP event logging.

**Toggle:** `$DisableRDPEntirely` (default $false). Set to $true if RDP is never used.

**NinjaRMM impact:** None. NinjaRMM uses its own agent, not RDP.

**Reboot required:** No.

## Module 4: Sysmon Deployment

**What it does:** Downloads and installs Sysmon from Microsoft Sysinternals. Applies SwiftOnSecurity's community config. Sets the Sysmon event log to 200MB.

**Internet required:** Yes (downloads from download.sysinternals.com and raw.githubusercontent.com).

**Key events:** ID 1 (process creation), ID 3 (network connection), ID 8 (CreateRemoteThread / injection), ID 22 (DNS query).

**Reboot required:** No.

## Module 5: BitLocker

**What it does:** Enables BitLocker on C: with TPM protector and XTS-AES-256 encryption. Adds a Recovery Password protector. Outputs the recovery key.

**Requirements:** TPM 2.0, NTFS on C:.

**Critical:** Recovery key displayed once. Capture it.

**Reboot required:** No. Encryption runs in the background.

## Module 6: USB Control

**What it does:** Restricts USB removable storage access.

**Modes:** `Audit` (log only), `ReadOnly` (read allowed, write blocked), `FullBlock` (no access), `Allow` (remove restrictions).

**Default mode:** ReadOnly.

**Reboot required:** No. Applies to new USB insertions immediately.

## Module 7: WDAC Audit Mode

**What it does:** Deploys Windows Defender Application Control in audit mode. Logs every unsigned or unknown executable without blocking anything.

**User impact:** None (audit mode only).

**Key event:** ID 3076 in `Microsoft-Windows-CodeIntegrity/Operational`.

**Reboot required:** Yes.

## Module 8: Defender Advanced

**What it does:** Sets cloud protection to High with 50-second extended timeout. Enables MAPS Advanced reporting and automatic sample submission. Enables Network Protection in Block mode (blocks malicious domains/IPs system-wide). Deploys Controlled Folder Access (default: Audit mode). Enables PUA blocking. Randomizes scan times across the fleet.

**Key toggle:** `$ControlledFolderMode` ("Audit" or "Block"). Start with Audit. Switch to Block after reviewing Event ID 1124 logs for two weeks.

**Key event:** ID 1124 (Controlled Folder Access), ID 1125 (Network Protection).

**Reboot required:** No.

## Module 9: Network Protocol Hardening

**What it does:** Disables NetBIOS over TCP/IP on all adapters. Disables WPAD (service, registry, hosts file). Restricts anonymous SAM enumeration and null session access. Disables mDNS. Requires SMB signing. Disables SMB compression. Enables SMB encryption. Enforces NTLMv2 only, refuses LM and NTLMv1.

**Fleet dependency:** SMB signing must be deployed to all machines that share files with each other. Deploy to the full fleet simultaneously, or accept that file sharing will break between hardened and unhardened machines.

**Reboot required:** Recommended for NetBIOS change.

## Module 10: Credential Guard + Session Security

**What it does:** Enables Virtualization Based Security and Credential Guard. Enables HVCI (Hypervisor-enforced Code Integrity). Sets screen lock timeout (default: 15 minutes). Hides last username from login screen. Configures logon banner. Reduces cached logon count to 2. Clears page file on shutdown.

**Toggle:** `$EnableCredentialGuard` (default $true). Set to $false if VPN compatibility is a concern.

**VPN warning:** Test with the customer's VPN client before fleet deployment. May also break tools like LogMeIn or other remote access tools. TEST FIRST...

**Reboot required:** Yes (for Credential Guard).

## Module 11: Print Spooler Hardening

**What it does:** Restricts printer driver installation to administrators (KB5005010). Requires elevation for Point and Print. Disables remote Print Spooler RPC access. Enforces package Point and Print only. Enables Print Redirection Guard.

**User impact:** Existing printers work. Adding new printers requires admin credentials.

**Reboot required:** No.

## Module 12: LOLBin Expansion + PS7 Coverage

**What it does:** Adds outbound firewall blocks for regsvr32, rundll32, msiexec, msdt, hh.exe, pcalua, presentationhost, PowerShell ISE, MSBuild, and InstallUtil. Removes the ms-msdt protocol handler (Follina mitigation). Blocks or restricts PowerShell 7 (pwsh.exe). Enables PS7 Script Block Logging and Transcription if PS7 is installed.

**Follina note:** The script backs up the ms-msdt registry key before deletion. Restore with `reg import` if needed.

**Reboot required:** No.

## Module 13: Windows Sandbox + Defender Sandbox

**What it does:** Enables the Windows Sandbox optional feature. Creates two sandbox config files on the Public Desktop (offline and online). Enables the Defender Sandbox (runs the AV engine in an AppContainer).

**Requirements:** Hyper-V capable hardware, virtualization enabled in BIOS, 4GB+ RAM.

**User impact:** Two new shortcuts on the desktop. Sandbox is opt-in; users choose to use it.

**Reboot required:** Yes (for Windows Sandbox feature).
