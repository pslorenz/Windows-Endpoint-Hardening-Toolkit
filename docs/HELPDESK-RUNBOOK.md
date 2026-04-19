# Helpdesk Runbook

This is the document you open when a user calls with a problem on a hardened endpoint. Find the symptom, follow the resolution. Every section names the module responsible so you know exactly what to roll back if needed. If the answer isn't here, try a search engine.

## How Hardened Endpoints Behave Differently

Before troubleshooting, understand what changed. A hardened endpoint is not broken; it is restrictive by design. Users cannot install software without admin credentials. Scripts do not execute when double-clicked. Browsers block unknown extensions. USB drives are read-only. These are features, not bugs. Your job is to distinguish "hardening working as intended" from "hardening broke something."

All hardening logs live at `C:\ProgramData\EndpointHardening\`. If you need to confirm which modules have been applied, list the files in that directory. Each module writes a timestamped log when it runs.

## Symptom: "I can't install a program"

**Module responsible:** Module 1 (Local Admin Removal) and Base Script (MSI restriction)

This is the most common call you will receive. The user's daily account is now a Standard User. Software installation requires the LocalITAdmin credentials.

To assist: connect to the machine via NinjaRMM remote access. Open the installer yourself using Run As Administrator, enter the LocalITAdmin credentials stored in the device documentation, and complete the installation. Do not give the LocalITAdmin password to the user.

If the user is trying to install an MSI specifically and it fails even with admin credentials, the base script's MSI policy may be interfering. Verify by checking `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` for `DisableMSI`. If you need to temporarily allow an MSI install, set `DisableMSI` to 0, run the installer, then set it back to 1.

## Symptom: "I double-clicked a file and it opened in Notepad"

**Module responsible:** Module 2 (Browser Hardening)

This is intentional. Module 2 reassociates dangerous file types (.js, .jse, .vbs, .vbe, .wsf, .wsh, .hta, .scr) to open in Notepad instead of executing. If the user received a legitimate script file from a vendor, open it in Notepad first to inspect the contents. If it is safe and needs to run, execute it from an elevated command prompt using `cscript <filename>` or `wscript <filename>`.

Note: if the base script is also deployed (it should be), WScript and CScript are blocked via IFEO, so even running from a command prompt will fail. If a vendor truly requires a VBS script to run, this is a conversation with the customer about risk acceptance, not a helpdesk fix. Escalate to the lead engineer.

## Symptom: "My browser says it's managed by my organization"

**Module responsible:** Module 2 (Browser Hardening)

This is cosmetic and expected. The "Managed by your organization" indicator appears in Edge and Chrome settings because security policies are applied via the local registry. The browser is working normally. Reassure the user that this is a security configuration, not a sign of compromise.

## Symptom: "I can't install a browser extension"

**Module responsible:** Module 2 (Browser Hardening)

Module 2 blocks all extensions by default. To allow a specific extension, you need its extension ID.

For Edge: visit the extension's page on the Edge Add-ons store. The ID is the long string of characters at the end of the URL. Add it to the allowlist:

```powershell
$id = "extension-id-here"
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist"
$next = ((Get-Item $path).Property | Measure-Object -Maximum).Maximum + 1
Set-ItemProperty -Path $path -Name $next -Value $id -Type String
```

For Chrome, the process is identical but the path is `HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist`.

Common extension IDs you will likely need to whitelist:

| Extension | Edge ID | Chrome ID |
|-----------|---------|-----------|
| uBlock Origin | `odfafepnkmbhccpbejgmiehpchacaeak` | `cjpalhdlnbpafiamejdnhcphjbkeiagm` |

The user needs to restart their browser after you add the allowlist entry.

## Symptom: "I can't add a new printer"

**Module responsible:** Module 11 (Print Spooler Hardening)

Existing printers are not affected. Adding a new printer requires administrator credentials because Module 11 restricts driver installation to admins. Connect via NinjaRMM, add the printer using the LocalITAdmin account, and the user is set.

If the printer requires a driver download from the manufacturer, download and install it yourself with admin credentials. The user will then be able to print normally.

## Symptom: "My VPN stopped working"

**Module responsible:** Module 10 (Credential Guard)

Some older VPN clients are incompatible with Credential Guard. If the VPN worked before Module 10 and stopped after, this is the likely cause. Confirm by checking:

```powershell
(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning
```

If the output includes `1` (Credential Guard is running) and the VPN is broken, disable Credential Guard on this machine:

```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0
```

Reboot the machine. The VPN should work again. File a note that this specific VPN client version is incompatible with Credential Guard, and skip Module 10 on machines that use it until the VPN client is updated.

## Symptom: "I can't access a shared folder on another computer"

**Module responsible:** Module 9 (Network Protocol Hardening)

Module 9 requires SMB signing on both ends of a connection. If Machine A is hardened and Machine B is not, file sharing between them will fail. The fix is to deploy Module 9 to Machine B as well.

If Machine B is not one of your managed endpoints (a NAS, a server, a vendor device), you need to enable SMB signing on that device. For a Windows server or NAS, the setting is:

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

For a NAS running Linux or a proprietary OS, consult its documentation for SMB signing support. If the device does not support SMB signing, you have two options: accept the risk and disable the signing requirement on the hardened machines that need to talk to it, or replace the device. The registry values to revert are in `HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters` and `LanmanWorkstation\Parameters`, setting `RequireSecuritySignature` to 0.

## Symptom: "A program I use every day stopped working" (general)

Start with these diagnostic steps:

First, check if the program makes outbound network connections that are now blocked. Open `C:\ProgramData\EndpointHardening\` and look at the most recent log files to see which modules are deployed. If Module 12 (LOLBin Expansion) is deployed, the program may depend on a binary that is now firewall-blocked.

Run this to see which outbound rules are active:

```powershell
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True |
    Where-Object { $_.DisplayName -like "Block*" } |
    Select-Object DisplayName, Enabled
```

If the broken application launches `rundll32.exe`, `regsvr32.exe`, or another blocked binary to phone home for updates or licensing, you will see a matching rule. Remove that specific rule:

```powershell
Remove-NetFirewallRule -DisplayName "Block rundll32 Outbound"
```

Second, check if Defender Network Protection (Module 8) is blocking a domain the application needs. Look at Event ID 1125 in the `Microsoft-Windows-Windows Defender/Operational` log. If it shows the application's domain being blocked, add an exclusion:

```powershell
Add-MpPreference -ExclusionProcess "C:\Path\To\Application.exe"
```

Third, check if an ASR rule (Base Script) is interfering. Event ID 1121 in the Defender operational log names the specific rule and the blocked process. If you need to temporarily set an ASR rule to Audit instead of Block while you investigate:

```powershell
# Get current ASR rules
$rules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$actions = (Get-MpPreference).AttackSurfaceReductionRules_Actions

# Find the rule ID from the event log, then set it to Audit (2) instead of Block (1)
# Example for "Block obfuscated scripts":
Set-MpPreference -AttackSurfaceReductionRules_Ids "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -AttackSurfaceReductionRules_Actions 2
```

Document which rule you changed and why. Follow up by determining whether the application genuinely needs that behavior or whether the ASR rule caught something suspicious.

## Symptom: "My computer is asking for a password when it never did before" (UAC prompt)

**Module responsible:** Module 1 (Local Admin Removal)

The user's account is now Standard. UAC prompts that previously just required clicking "Yes" now require the LocalITAdmin username and password. This is the correct behavior. If the prompt is for a routine action the user performs daily (a specific application that always needs elevation), investigate whether that application can be configured to run without admin rights. Many applications write to `Program Files` or `HKLM` registry unnecessarily and can be redirected.

If the application genuinely requires elevation every time it runs, create a scheduled task that launches it with elevated privileges, or use a shim. Do not give the user the admin password.

## Symptom: "I can't save files to my USB drive"

**Module responsible:** Module 6 (USB Control)

USB drives are read-only by default. The user can read files from USB but cannot write to them. If they need to copy files to a USB drive for a legitimate reason, you have three options:

Temporary: re-run Module 6 with `$Mode = "Allow"` on that specific machine, let the user complete their task, then re-run with `$Mode = "ReadOnly"`.

Permanent exception: if this user regularly needs USB write access (transferring files to clients, loading firmware), accept the risk for that specific machine and leave it in Allow mode. Document the exception.

Alternative: suggest the user share the files via email, OneDrive, or another approved method instead.

## Symptom: "A website isn't loading" or "I get a connection error for a specific site"

**Module responsible:** Base Script (Quad9 DNS) or Module 8 (Network Protection)

Quad9 blocks known malicious domains. Defender Network Protection (Module 8) blocks Microsoft-classified malicious domains and IPs at the OS level. If a legitimate site is being blocked:

Check DNS first. From the affected machine:

```powershell
nslookup problematic-domain.com 9.9.9.9
nslookup problematic-domain.com 8.8.8.8
```

If Quad9 returns no result but Google DNS does, the domain is flagged by Quad9's threat intelligence. This is a judgment call: the domain may be legitimately flagged (new domain, shared hosting with malware, recently compromised) or it may be a false positive. If you are confident it is safe, you can add it to the local hosts file as a bypass:

```
# In C:\Windows\System32\drivers\etc\hosts
1.2.3.4  problematic-domain.com
```

Replace `1.2.3.4` with the IP address returned by the Google DNS lookup. This bypasses Quad9 for that specific domain only.

If DNS resolves fine but the connection still fails, check the Defender operational log for Event ID 1125 (Network Protection block). If Network Protection is the cause, the event will name the process and domain. Whitelist the process if the application is legitimate.

## Symptom: "I see a legal warning when I log in"

**Module responsible:** Module 10 (Credential Guard / Session Security)

This is the logon banner. It is intentional. The banner reads "Authorized Use Only" and a brief statement about monitoring. It appears once at login and the user clicks OK to proceed. This is a standard security practice that supports incident response and legal proceedings by establishing notice that the system is monitored. Reassure the user that it is a normal part of the security configuration.

## Symptom: "Windows Sandbox won't start"

**Module responsible:** Module 13 (Windows Sandbox)

Windows Sandbox requires hardware virtualization (VT-x on Intel, AMD-V on AMD) to be enabled in the BIOS. If Sandbox fails to start with an error about Hyper-V or virtualization, the machine's BIOS needs to be configured. Reboot into BIOS/UEFI settings and enable the virtualization option. The exact menu location varies by manufacturer: look under CPU, Security, or Advanced settings for "Intel Virtualization Technology," "VT-x," or "SVM Mode."

If virtualization is already enabled and Sandbox still fails, the hardware may not support it. Check the processor model against Microsoft's requirements. Sandbox is a convenience feature, not a critical control; if it does not work on a specific machine, remove the desktop shortcuts and move on.

## When to Escalate

Escalate to the lead engineer if:

The symptom does not match anything in this runbook and you suspect the hardening is the cause. Do not guess at which module to roll back.

An ASR rule or Defender Network Protection is blocking something and you are not sure whether the blocked activity is legitimate or malicious. The whole point of these controls is to block things. Sometimes they block the right things.

A user reports that an application behaves differently after hardening, but the application is security-sensitive (VPN client, backup agent, EDR, RMM agent). Do not modify hardening settings that interact with other security tools without lead engineer approval.

Multiple users report the same symptom after a module deployment. This suggests a fleet-wide issue, not a one-off, and the response may be to roll back the module across all endpoints rather than fixing each individually.

## Quick Reference: Rollback Commands by Module, only if you really have to. Make sure someone senior on your team knows these were run and for how long. 

| Module | Rollback Command |
|--------|-----------------|
| Base Script | Run `Rollback-Hardening-v2.ps1` |
| Module 1 | `net localgroup Administrators <username> /add` |
| Module 2 | `Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -Force` |
| Module 3 | Set `UserAuthentication` to 0 in RDP-Tcp registry, remove firewall rule |
| Module 4 | `& "$env:ProgramFiles\Sysmon\Sysmon64.exe" -u force` |
| Module 5 | `manage-bde -off C:` (decryption takes time) |
| Module 6 | Re-run Module 6 with `$Mode = "Allow"` |
| Module 7 | `Remove-Item "$env:windir\System32\CodeIntegrity\SIPolicy.p7b" -Force` then reboot |
| Module 8 | `Set-MpPreference -EnableControlledFolderAccess 0; Set-MpPreference -EnableNetworkProtection Disabled` |
| Module 9 | See script header for per-setting rollback |
| Module 10 | `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0` then reboot |
| Module 11 | `Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Recurse -Force` |
| Module 12 | `Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Block*Outbound*" } | Remove-NetFirewallRule` |
| Module 13 | `Disable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM` |
