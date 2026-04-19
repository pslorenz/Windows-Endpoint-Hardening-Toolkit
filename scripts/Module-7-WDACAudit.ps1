#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 7: WDAC Audit Mode (Windows Defender Application Control)
    Deploys application control in AUDIT mode - logs what WOULD be blocked
    without actually blocking anything. Zero user impact. If you use ThreatLocker, 
    you probably don't need this. 

.DESCRIPTION
    WDAC is the most powerful security control in Windows, but deploying it
    in enforcement mode without preparation will break things.

    This module deploys Microsoft's recommended default policy in AUDIT mode:
      - Logs every unsigned/unknown executable that runs
      - Logs every DLL load from untrusted sources
      - Does NOT block anything - zero user impact
      - Gives you data to build an enforcement policy later

    Run this for 2-4 weeks, review the logs, then decide if enforcement
    is feasible for each customer.

    Events go to: "Microsoft-Windows-CodeIntegrity/Operational"
    Event ID 3076 = Would have been blocked (audit)
    Event ID 3077 = Actually blocked (enforcement mode, not used here)

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 120s
    Reboot recommended (WDAC loads at boot).
    This is AUDIT ONLY - nothing will break.

    ROLLBACK: Delete the policy file and reboot:
      Remove-Item "$env:windir\System32\CodeIntegrity\SIPolicy.p7b" -Force
      Restart-Computer
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\wdac-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $entry
}

Write-Log "================================================================"
Write-Log "  MODULE 7: WDAC Audit Mode"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# CHECK FOR EXISTING POLICY
# ============================================================================
$policyPath = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"
if (Test-Path $policyPath) {
    Write-Log "Existing WDAC policy found at $policyPath" "WARN"
    Write-Log "A policy is already deployed. Check if it's audit or enforce mode."
    Write-Log 'Run: citool --list-policies  to see current policy details'
    Write-Log "Exiting to avoid overwriting an existing policy."
    exit 0
}

# ============================================================================
# CREATE AUDIT POLICY FROM MICROSOFT DEFAULT
# ============================================================================
Write-Log ""
Write-Log "--- Creating WDAC Audit Policy ---"

$policyXml = "$LogDir\WDACpolicy-audit.xml"
$policyBin = "$LogDir\WDACpolicy-audit.bin"

try {
    # Use the Microsoft-recommended default policy as a base
    # DefaultWindows_Audit allows everything signed by Microsoft/WHQL
    # and AUDITS (logs) everything else
    $defaultPolicies = @(
        "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml",
        "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
    )

    $basePolicy = $null
    foreach ($dp in $defaultPolicies) {
        if (Test-Path $dp) {
            $basePolicy = $dp
            break
        }
    }

    if (-not $basePolicy) {
        Write-Log "No default WDAC policy template found" "ERROR"
        Write-Log "WDAC example policies may not be available on this Windows edition" "WARN"
        exit 1
    }

    Write-Log "  Base policy: $basePolicy"

    # Copy and modify the policy
    Copy-Item -Path $basePolicy -Destination $policyXml -Force

    # Load and modify the XML to ensure audit mode
    [xml]$policy = Get-Content $policyXml
    $ns = New-Object System.Xml.XmlNamespaceManager($policy.NameTable)
    $ns.AddNamespace("si", "urn:schemas-microsoft-com:sipolicy")

    # Ensure Audit Mode rule is present
    $rulesNode = $policy.SelectSingleNode("//si:Rules", $ns)
    if ($rulesNode) {
        # Check if audit mode rule exists
        $auditRule = $policy.SelectSingleNode("//si:Rules/si:Rule[si:Option='Enabled:Audit Mode']", $ns)
        if (-not $auditRule) {
            $newRule = $policy.CreateElement("Rule", "urn:schemas-microsoft-com:sipolicy")
            $option = $policy.CreateElement("Option", "urn:schemas-microsoft-com:sipolicy")
            $option.InnerText = "Enabled:Audit Mode"
            $newRule.AppendChild($option) | Out-Null
            $rulesNode.AppendChild($newRule) | Out-Null
            Write-Log "  Audit Mode rule added to policy"
        } else {
            Write-Log "  Audit Mode already enabled in policy"
        }
    }

    $policy.Save($policyXml)
    Write-Log "  Policy XML saved: $policyXml"

    # Convert to binary
    ConvertFrom-CIPolicy -XmlFilePath $policyXml -BinaryFilePath $policyBin -ErrorAction Stop
    Write-Log "  Policy binary created: $policyBin"

    # Deploy the policy
    Copy-Item -Path $policyBin -Destination $policyPath -Force -ErrorAction Stop
    Write-Log "  Policy deployed to: $policyPath"

    Write-Log ""
    Write-Log "WDAC Audit policy deployed" "SUCCESS"
    Write-Log "Reboot needed for policy to take effect"

} catch {
    Write-Log "WDAC policy deployment failed: $_" "ERROR"
    Write-Log "This is non-critical - WDAC audit is optional" "WARN"
    exit 1
}

# ============================================================================
# CONFIGURE EVENT LOG
# ============================================================================
Write-Log ""
Write-Log "--- Configuring CodeIntegrity event log ---"
try {
    wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:104857600  # 100MB
    wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /e:true
    Write-Log "  CodeIntegrity log: 100MB, enabled"
} catch { Write-Log "  Log config: $_" "WARN" }

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  WDAC Audit Mode deployed."
Write-Log "  Reboot required for policy activation."
Write-Log ""
Write-Log "  THIS IS AUDIT ONLY - NOTHING IS BLOCKED"
Write-Log ""
Write-Log "  After 2-4 weeks, review logs for false positives:"
Write-Log "  Event Log: Microsoft-Windows-CodeIntegrity/Operational"
Write-Log "  Event ID 3076 = Would have been blocked"
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log "  Remove-Item '$policyPath' -Force"
Write-Log "  Restart-Computer"
Write-Log "================================================================"

exit 0
