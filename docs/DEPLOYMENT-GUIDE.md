# Deployment Guide

This document covers sequencing, NinjaRMM configuration, and the rollout plan for the endpoint hardening toolkit. Read it fully before touching production machines.

## The Rule

Deploy to one machine. Verify for 24 hours. Then deploy to some more machines. Then maybe the managed fleet. Every module, every time. Skipping the test machine is how you spend a Saturday re-imaging 500 endpoints.

## NinjaRMM Setup

For each script in this toolkit, create a corresponding entry in NinjaRMM under Administration > Scripts > Add New Script. Configure every script the same way:

**Language:** PowerShell  
**Run As:** System  
**Timeout:** 120 seconds (use 300 for Module 4 and Module 13, which download files)  
**Parameters:** None  

Script output (including passwords for Module 1 and recovery keys for Module 5) appears in the script results tab in NinjaRMM. Capture these immediately. They are displayed once.

All scripts log to `C:\ProgramData\EndpointHardening\` on the local machine. NinjaRMM can retrieve these logs via file retrieval if you need them later.

## NinjaRMM or other RMM Monitoring Setup

After deploying the base script and Modules 3, 4, and 8, configure these event log monitoring conditions in NinjaRMM. These are some of the high-value alerts that tell you something is happening on an endpoint. Of course, tune for false positives. 

**Condition 1: PowerShell Script Block (suspicious activity)**  
Log: Microsoft-Windows-PowerShell/Operational  
Event ID: 4104  
Severity: Warning or Error  
Action: Create a ticket  

**Condition 2: ASR Rule Fired**  
Log: Microsoft-Windows-Windows Defender/Operational  
Event ID: 1121 (blocked) or 1122 (audited)  
Action: Create a ticket  

**Condition 3: Controlled Folder Access Event**  
Log: Microsoft-Windows-Windows Defender/Operational  
Event ID: 1124  
Action: Create a ticket (used to build whitelist before switching to Block mode)  

**Condition 4: Failed Logon Attempts (brute force indicator)**  
Log: Security  
Event ID: 4625  
Threshold: 10 events in 5 minutes  
Action: Create a ticket  

**Condition 5: Sysmon Process Injection**  
Log: Microsoft-Windows-Sysmon/Operational  
Event ID: 8 (CreateRemoteThread)  
Action: Create a ticket, priority high  

**Condition 6: Sysmon Suspicious DNS**  
Log: Microsoft-Windows-Sysmon/Operational  
Event ID: 22  
Action: Log only (high volume, review weekly)  

## Deployment Sequence

The order matters. Each phase builds on the previous one, and the phases are spaced to give you time to catch problems before stacking more changes on top.

### Phase 1: Foundation (Day 1)

Deploy `Harden-Endpoint-v2.ps1` to your test machine. This is the base layer: WScript/CScript blocking, PowerShell Constrained Language Mode, ASR rules, DNS, logging, firewall rules, and and several other features documented in the script header. If you don't understand one, set $false, don't hope.

Reboot the test machine. Then verify:

Open a non-elevated PowerShell prompt and run `$ExecutionContext.SessionState.LanguageMode`. It should return `ConstrainedLanguage`. Open an elevated prompt and confirm it returns `FullLanguage`. Try to run `wscript.exe` from a command prompt; it should fail silently. Run `nslookup example.com` and confirm the server is `9.9.9.9`.

If the test machine passes, schedule the base script to run across all endpoints. Set a follow-up task to reboot them overnight.

If you experience issues, run Rollback-Hardening-v2.ps1. NOTE: I haven't created rollback scripts for the extra modules. They are pretty easy to undo if you read them though.

### Phase 2: The 80% Layer (Week 1)

These three modules get you to the Pareto threshold. Deploy them in this order, one per day, verifying the test machine each time.

**Module 1 (Local Admin Removal)** is the most impactful and the most operationally sensitive. It creates a `LocalITAdmin` account, displays the password in the script output, and downgrades the daily user to Standard. You could capture that password from NinjaRMM's script results and store it in the device documentation or a custom field immediately before changing it to something you stre in you password manager and not the RMM. The user will not notice the change until they try to install software or approve a UAC prompt, at which point they will be asked for the LocalITAdmin credentials instead of just clicking Yes. You should probably tell them before you remove their admin creds, but it is 2026 so if you haven't taken their admin away yet, you are a few years behind. That probably also means you have a spreadsheet with a shared password (which is part of my rationale for adding this script. NO MORE SHARED PASSWORDS ACROSS YOUR ENTIRE MANAGED FLEET...)

Two things to communicate to users before deploying Module 1: they will need to contact IT to install new software, and their computer will ask for a password on certain prompts that previously just required a click. Frame it as protection, not restriction. "We're adding a layer that prevents malware from making changes to your computer, even if it tricks you into clicking something."

**Module 2 (Browser Hardening)** applies Edge and Chrome security policies via registry. Users will see a "Managed by your organization" indicator in their browser settings. They will also find that browser extensions are blocked by default. If a user needs a specific extension (password manager, ad blocker), you will need to add its ID to the allowlist. The script includes instructions for this. Deploy the same day as Module 1 if the test machine is clean.

**Module 3 (RDP Lockdown)** enforces NLA, sets account lockout policy, and blocks RDP on public networks. RMM access like  NinjaRMM's remote access is not affected because it uses its own agent protocol, not RDP. (If it is, you need a new RMM.) If you or your team use direct RDP to manage these machines, verify that RDP still works from your management network after deploying this module.

### Phase 3: Detection (Week 2)

**Module 4 (Sysmon)** requires internet access to download Sysmon from Microsoft and the SwiftOnSecurity config from GitHub. If endpoints are behind a restrictive proxy that blocks these domains, download the files to a network share and modify the script to point at local paths instead. After deployment, confirm events are flowing by checking for the `Microsoft-Windows-Sysmon/Operational` log in Event Viewer. Set up the NinjaRMM monitoring conditions listed above. You can also use Olaf Hartong's Sysmon Modular, update the script. 

**Module 5 (BitLocker)** is straightforward on Win 11 machines with TPM 2.0, which is nearly all of them. Like Module 1, the recovery key is displayed once in the script output. Capture it immediately. If you lose the recovery key and the user triggers a BitLocker recovery prompt (BIOS update, hardware change, certain Windows updates), you will not be able to unlock the drive. Store the key in NinjaRMM device documentation and/or Entra.

**Module 6 (USB Control)** defaults to ReadOnly mode, which means users can read from USB drives but cannot write to them. This prevents data exfiltration while still allowing them to receive files via USB. If a user needs to write to USB (transferring files to a client, loading firmware onto a device), you have two choices: temporarily re-run the script with `$Mode = "Allow"` on that specific machine, or accept the risk of ReadOnly being the permanent setting. You might want to communicate this one to users.

**Module 7 (WDAC Audit)** generates no user-visible change. It logs every unsigned or unknown executable that runs, without blocking anything. Deploy it and forget it for a month. Review the `Microsoft-Windows-CodeIntegrity/Operational` log (Event ID 3076) to understand what software your users actually run. This data tells you whether WDAC enforcement is feasible for a given customer.

### Phase 4: Deep Hardening (Weeks 3-4)

These modules are lower risk individually but touch more system components. Space them out and monitor the test machine between each.

**Module 8 (Defender Advanced)** cranks cloud protection to High, enables Network Protection (which blocks malicious domains system-wide, not just in browsers), and deploys Controlled Folder Access in Audit mode. Network Protection is the setting most likely to cause a call: if a legitimate application phones home to a domain that Microsoft considers suspicious, the connection will be blocked. If this happens, the Event ID 1125 in the Defender operational log will tell you exactly which domain and which process were involved. Whitelist the process in Defender exclusions. Of course if you use anything other than Defender, you probably should ignore this.

After two weeks of Controlled Folder Access running in Audit mode, review the Event ID 1124 logs, add any false-positive applications to the `$AllowedApplications` list in the script, and re-deploy with `$ControlledFolderMode = "Block"`. This two-phase approach avoids the false-positive storm that makes most people abandon CFA on day one.

**Module 9 (Network Protocol Hardening)** has one important constraint: deploy it to all machines in the environment at the same time. The SMB signing requirement must match on both ends of a file share. If Machine A requires signing and Machine B does not support it, file sharing between them breaks. Since you are deploying this to all managed machines, this is only a problem if those machines share files with other machines outside the fleet (a NAS, a server, a vendor's system). If they do, confirm that the other device supports SMB signing before deploying.

**Module 10 (Credential Guard)** requires VBS-capable hardware and has one known compatibility concern: older VPN clients. If your users run Cisco AnyConnect older than 4.10, GlobalProtect older than 6.0, or any VPN client that hooks into LSASS directly, test this module on one machine that uses the VPN before fleet deployment. Modern VPN clients work fine with Credential Guard. The screen lock timeout (15 minutes by default) and logon banner are cosmetic and low-risk.

**Module 11 (Print Spooler)** is deliberately conservative. It does not disable the Print Spooler service. It restricts new printer driver installation to administrators and blocks remote Spooler access. Existing printers continue to work. The only user-visible change is that adding a new printer now requires the LocalITAdmin credentials from Module 1. If a user plugs in a new USB printer and it requires a driver, they will need your help. This is correct behavior.

**Module 12 (LOLBin Expansion)** adds outbound firewall rules for additional Living-off-the-Land binaries and blocks the ms-msdt protocol handler (Follina). It also preemptively blocks PowerShell 7 (pwsh.exe) via IFEO if it is not installed, or applies logging and firewall rules if it is. The Follina mitigation backs up the original registry key before deleting it, so rollback is possible.

**Module 13 (Windows Sandbox)** enables the Sandbox feature and places two shortcut files on the Public Desktop: one for offline sandboxing (no network, safest for files) and one for online sandboxing (has network, for testing URLs). This requires Hyper-V capable hardware. The Defender Sandbox setting (separate from Windows Sandbox) runs the Defender engine itself in an AppContainer with zero user impact.

## Ongoing Maintenance

Schedule the base script (`Harden-Endpoint-v2.ps1`) to re-run monthly via NinjaRMM as a scheduled task. This is your drift prevention. If a Windows update, a software installer, or a user resets a setting, the monthly re-run corrects it. The script is idempotent: running it on an already-hardened machine changes nothing and generates no errors.

Sysmon configs should be updated quarterly. Check the SwiftOnSecurity repo for new releases and re-run Module 4 to update the config (it detects existing installations and updates without reinstalling).

Review PowerShell transcription logs in `C:\ProgramData\PSTranscripts\` periodically. Rotate or archive them, as they will grow over time. A NinjaRMM scheduled task that deletes transcripts older than 90 days is a reasonable approach.

## Customer Communication Template

When deploying this to a new customer, send a brief heads-up. Here is the version you can adapt:

> We are applying a set of security configurations to your workstations this week. These changes protect against the most common ways attackers compromise standalone Windows machines: malicious scripts, credential theft, unauthorized software installation, and browser-based threats.
>
> You may notice a few differences. Your browser will show "Managed by your organization" in settings. Installing new software or adding printers will require IT approval. Your screen will lock automatically after 15 minutes of inactivity. Two "Sandbox" shortcuts will appear on your desktop for safely opening suspicious files.
>
> These changes are based on Microsoft's own security benchmarks and are the same controls used in regulated industries. If anything feels different or you have trouble with a specific application, contact us and we will sort it out quickly.
