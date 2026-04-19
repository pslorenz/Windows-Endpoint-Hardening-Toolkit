# Endpoint Hardening Toolkit

A modular set of PowerShell scripts that harden standalone Windows 11 Pro machines against commodity attack chains. Built for MSPs managing non-domain-joined environments via NinjaRMM or similar. You can run these as one-offs from powershell though. 

## Origin

This toolkit was created in response to an EDR near miss. EDR is great some times, but what about those cases where something actually lands? This is not the most comprehhensive toolkit, but will help deal with current common attacks. For something way more in depth, check out https://github.com/HotCakeX/Harden-Windows-Security.

## What It Does

The base script and 13 modules create layered kill points across the entire attack chain. Each module is independently deployable and includes its own rollback instructions. Scripts can rundirect from powershell or in many cases, NinjaRMM or another RMM too.

The full stack, deployed in sequence, covers execution blocking (scripts, macros, LOLBins), credential protection (Credential Guard, LSA Protection, WDigest, NTLMv2), network hardening (DNS, NetBIOS, WPAD, LLMNR, SMB signing), detection (Sysmon, PowerShell logging, audit policy, Controlled Folder Access), and data protection (BitLocker, USB control).

## Repository Structure

```
├── README.md                          # You are here
├── docs/
│   ├── DEPLOYMENT-GUIDE.md            # Sequencing, NinjaRMM setup, rollout plan
│   ├── HELPDESK-RUNBOOK.md            # Support engineer troubleshooting guide
│   ├── MODULE-REFERENCE.md            # Per-module summary and toggle reference
│   └── INCIDENT-RESPONSE.md           # What to do when alerts fire
├── scripts/
│   ├── Harden-Endpoint-v2.ps1         # Base hardening script (deploy first)
│   ├── Rollback-Hardening-v2.ps1      # Rollback for base script
│   ├── Module-1-LocalAdminRemoval.ps1
│   ├── Module-2-BrowserHardening.ps1
│   ├── Module-3-RDPLockdown.ps1
│   ├── Module-4-SysmonDeploy.ps1
│   ├── Module-5-BitLocker.ps1
│   ├── Module-6-USBControl.ps1
│   ├── Module-7-WDACAudit.ps1
│   ├── Module-8-DefenderAdvanced.ps1
│   ├── Module-9-NetworkProtocol.ps1
│   ├── Module-10-CredentialGuard.ps1
│   ├── Module-11-PrintSpooler.ps1
│   ├── Module-12-LOLBinExpansion.ps1
│   └── Module-13-WindowsSandbox.ps1
```

## Deployment

Read `docs/DEPLOYMENT-GUIDE.md` before deploying anything. The short version: deploy the base script to one test machine, verify for 24 hours, then roll to all endpoints. Add modules in the order listed in the deployment guide, one per week.

Every script runs as System via NinjaRMM and logs to `C:\ProgramData\EndpointHardening\`. Every script includes rollback instructions in its header comments.

## Support

Please don't call me. I've written up some basic guidelines, so ehen a user calls with a problem after hardening, start with `docs/HELPDESK-RUNBOOK.md`. It maps common symptoms to specific modules and gives exact rollback commands.

## Requirements

All scripts require Windows 11 Pro, local administrator (or run as System via NinjaRMM), and PowerShell 5.1. Module 4 (Sysmon) and Module 13 (Windows Sandbox) require internet access during deployment. Module 5 (BitLocker) requires TPM 2.0. Module 10 (Credential Guard) requires virtualization support in BIOS. Module 13 (Sandbox) requires Hyper-V capable hardware.

## Disclaimer

Test every script on one machine before deploying to your fleet. The rollback scripts revert most changes, but they are not a substitute for a proper system image or backup. Read the scripts before you run them and understand what each cmdlet does. If you are not comfortable reading PowerShell, get comfortable before deploying this to production. 
