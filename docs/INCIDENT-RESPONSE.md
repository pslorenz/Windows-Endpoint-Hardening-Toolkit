# Incident Response Quick Reference

This document tells you what to do when the hardening toolkit generates an alert. It is not a comprehensive IR plan. It covers the specific alerts this toolkit produces and the initial triage steps for each. Follow your organizations IR plans.

I am not an incident responder, but I did stay at a Holliday Inn Express that one time... Anyway, follow your corporate procedures. This guide offers some limited guidance for some of the newer settings.

## Triage Mindset

Every alert from this toolkit represents one of three things: hardening doing its job and blocking something benign, hardening catching something suspicious that needs investigation, or hardening catching an active attack. Your first task is to figure out which one you are looking at. The answer is usually in the event details.

## Alert: ASR Rule Fired (Event ID 1121)

**Where:** Microsoft-Windows-Windows Defender/Operational

**What it means:** An Attack Surface Reduction rule blocked a specific behavior. The event contains the rule ID, the process that was blocked, and the file path involved.

**Triage steps:**

Look at the process path and the rule that fired. If the blocked process is a known business application doing something expected (Word launching a child process, Excel making a COM call), this is a false positive. Set that specific rule to Audit mode (2) for that process using an ASR exclusion, then investigate whether the application can be configured to not trigger the rule.

If the blocked process is unexpected (a script host running from AppData, an Office application spawning PowerShell, an executable running from a temp directory), treat it as suspicious. Check what the user was doing at the time. If they opened an email attachment or downloaded a file, you may be looking at the early stage of an attack that the hardening caught. Collect the file hash, check it on VirusTotal, and escalate if it comes back positive.

The most common ASR false positives are from line-of-business applications that use COM automation (QuickBooks, older ERP systems, macro-heavy Excel workbooks). Document these and build your exclusion list over the first two weeks.

## Alert: PowerShell Script Block Log (Event ID 4104)

**Where:** Microsoft-Windows-PowerShell/Operational

**What it means:** PowerShell executed a script block, and the full text of that script is recorded in the event. NinjaRMM should be configured to alert on Warning or Error severity events, which typically indicate suspicious content that AMSI flagged.

**Triage steps:**

Read the script content in the event. PowerShell logging captures everything, including your own management scripts, so not every 4104 event is malicious. Look for:

Encoded commands (`-EncodedCommand`, `-e`, Base64 strings). Legitimate management tools occasionally use encoding, but malware uses it routinely. If you see a Base64 string, decode it: `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("base64-here"))`.

Download cradles (`Invoke-WebRequest`, `Invoke-RestMethod`, `Net.WebClient`, `DownloadString`, `DownloadFile`). If PowerShell is downloading something from an external URL, determine whether the URL is a known vendor (Microsoft, your RMM, a patch management tool) or unknown. Unknown download URLs are high-priority.

Reflection and .NET abuse (`Add-Type`, `[Reflection.Assembly]`, `DllImport`). These are hallmarks of in-memory attacks that load malicious code without writing to disk. On a hardened endpoint with Constrained Language Mode, these should fail for non-admin users. If you see a successful execution, the user may be running as admin (Module 1 not deployed) or the attacker found an elevation method.

AMSI bypass attempts (strings like `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`). These are explicit attempts to disable the antimalware scanning interface. This is an active attack. Isolate the machine.

If the script content is clearly your own management tooling (NinjaRMM scripts, hardening scripts, update scripts), suppress the alert for that specific script or adjust your NinjaRMM condition to filter by source.

## Alert: Sysmon Process Injection (Event ID 8)

**Where:** Microsoft-Windows-Sysmon/Operational

**What it means:** A process created a remote thread in another process. This is the technique used in the original attack that prompted this toolkit: injecting code into explorer.exe. This is a high-priority alert.

**Triage steps:**

Check the source process (the one doing the injecting) and the target process (the one being injected into). Some legitimate software uses CreateRemoteThread: antivirus products, accessibility tools, and some application frameworks. The SwiftOnSecurity Sysmon config already filters out the most common benign sources.

If the source process is unfamiliar, running from a user-writable directory (Desktop, Downloads, AppData, Temp), or has a suspicious name, treat this as a confirmed compromise indicator. Isolate the machine from the network via NinjaRMM, collect the Sysmon logs and the source executable, and begin your IR process.

If the target is explorer.exe, lsass.exe, or another system process, and the source is not a known security product, escalate immediately. This is the exact attack pattern this toolkit was built to detect.

## Alert: Controlled Folder Access (Event ID 1124)

**Where:** Microsoft-Windows-Windows Defender/Operational

**What it means:** A process attempted to write to a protected folder and was either blocked (if CFA is in Block mode) or would have been blocked (if in Audit mode).

**Triage steps:**

In Audit mode, this event is informational. Review the process path and determine if it is a legitimate application that needs write access to user data folders. If it is, add it to the `$AllowedApplications` list in Module 8 before switching to Block mode.

In Block mode, a burst of 1124 events from the same process writing to many files in rapid succession is consistent with ransomware behavior. If you see dozens of events in seconds from an unknown process, isolate the machine immediately.

A single 1124 event from a known application (a backup agent writing to Documents, a sync client updating files) is a false positive. Whitelist it.

## Alert: Failed Logon Clusters (Event ID 4625)

**Where:** Security

**What it means:** Multiple failed logon attempts in a short window. The account lockout policy from Module 3 will lock the account after 5 failures, but the alert tells you someone is trying.

**Triage steps:**

Check the Logon Type field in the event:

Type 2 (Interactive): someone is at the physical console entering wrong passwords. Probably the user who forgot their password, especially after Module 1 changed their privilege level. Help them.

Type 3 (Network): a remote machine is trying to authenticate. Could be a misconfigured service, a mapped drive with stale credentials, or a brute-force attack over the network. Check the source IP address. If it is internal, investigate the source machine. If it is external, check whether RDP is exposed (it should not be on public profile after Module 3).

Type 10 (Remote Interactive / RDP): someone is trying to log in via RDP. If this is from an unexpected IP and occurring in rapid succession, this is a brute-force attempt. Confirm that Module 3's firewall rule is blocking RDP on the public profile. If the machine is on a private network and the source is internal, investigate who is trying to connect and why.

## Alert: Sysmon DNS Query to Suspicious Domain (Event ID 22)

**Where:** Microsoft-Windows-Sysmon/Operational

**What it means:** A process resolved a DNS name. Sysmon logs the process and the queried domain.

**Triage steps:**

This is a high-volume log. Do not alert on every event. Review it weekly or use NinjaRMM scripted conditions that look for specific patterns: domains with high entropy (random-looking strings like the C2 domain in the original attack), domains resolving to known-bad IP ranges, or processes that should not be making DNS queries at all (notepad.exe, calc.exe, wscript.exe).

If a blocked LOLBin (from the base script or Module 12) shows up making DNS queries, something bypassed the firewall block or the query happened before the block loaded at boot. Investigate the process and its parent chain.

## Alert: WDAC Audit (Event ID 3076)

**Where:** Microsoft-Windows-CodeIntegrity/Operational

**What it means:** An executable ran that would have been blocked if WDAC were in enforcement mode. This is informational only (Module 7 runs in audit mode).

**Triage steps:**

Review these weekly, not per-event. The goal is to understand what unsigned or unknown software your users run. Over time, this log tells you whether WDAC enforcement is feasible: if the only unsigned executables are one or two known business apps, enforcement is viable with exclusions. If dozens of unknown executables run daily, enforcement will require significant policy tuning.

If you see an unsigned executable running from a temp directory, a browser download folder, or an AppData path, and you do not recognize it, investigate it even though WDAC is only auditing. The audit mode is telling you something that the other controls may not have caught.

## General Principles

When in doubt, isolate first and investigate second. A false positive that causes 30 minutes of downtime is better than an active compromise that spreads for 30 minutes while you deliberate. Of course, your companies policies override any of this. 

Collect before you remediate. If you suspect a real compromise, pull the Sysmon logs, PowerShell transcripts (from `C:\ProgramData\PSTranscripts\`), and the Defender operational log before you start cleaning. These logs are your evidence and your timeline.

Check the parent process chain. Every Sysmon Event ID 1 includes the parent process. Walk the chain backward: what launched the suspicious process? What launched that? The chain usually tells you whether the origin was a user action (they clicked something) or a persistence mechanism (something auto-started at logon).

The hardening toolkit is not a silver bullet. It blocks common techniques and logs what it cannot block. If an attacker uses a technique that none of these controls cover, the detection layer (Sysmon, PS logging, audit policy) is your safety net. Review logs regularly, not just when an alert fires.
