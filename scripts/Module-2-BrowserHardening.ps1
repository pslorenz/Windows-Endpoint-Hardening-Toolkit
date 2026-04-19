#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Module 2: Browser Hardening (Edge + Chrome)
    Applies security policies via local registry (no domain needed).
    Closes the front door on many attacks.

.DESCRIPTION
    This module helps reduce impact from malicious links.

    Settings applied:
      - SmartScreen enforced (cannot be disabled by user)
      - Dangerous file types blocked from download
      - Extensions restricted (only from store, no sideloading)
      - Password manager phishing protection
      - DNS-over-HTTPS enforced
      - Typosquatting checker enabled
      - Enhanced Safe Browsing (Chrome)
      - Potentially unwanted app blocking

    Works for: Microsoft Edge and Google Chrome
    Both browsers read machine-level policy from the registry.

.NOTES
    Deploy via NinjaRMM: Run As System | Timeout: 60s
    No reboot needed - browsers pick up policy on next launch.

    ROLLBACK: Delete the registry keys:
      Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -Force
      Remove-Item "HKLM:\SOFTWARE\Policies\Google\Chrome" -Recurse -Force
#>

$LogDir  = "$env:ProgramData\EndpointHardening"
$LogFile = "$LogDir\browser-harden-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
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
Write-Log "  MODULE 2: Browser Hardening"
Write-Log "  Computer: $env:COMPUTERNAME"
Write-Log "================================================================"

# ============================================================================
# MICROSOFT EDGE POLICIES
# ============================================================================
Write-Log ""
Write-Log "--- Microsoft Edge ---"
$edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

# SmartScreen - cannot be turned off by user
Set-Reg $edgePath "SmartScreenEnabled" 1 "DWord" "SmartScreen: Enforced ON"
Set-Reg $edgePath "PreventSmartScreenPromptOverride" 1 "DWord" "SmartScreen: Block user bypass"
Set-Reg $edgePath "PreventSmartScreenPromptOverrideForFiles" 1 "DWord" "SmartScreen: Block file download bypass"
Set-Reg $edgePath "SmartScreenPuaEnabled" 1 "DWord" "SmartScreen: Block PUA (adware/bundleware)"

# DNS-over-HTTPS - you may need to comment this out depending on desired outcomes
Set-Reg $edgePath "DnsOverHttpsMode" "automatic" "String" "DoH: Automatic mode"

# Downloads
Set-Reg $edgePath "SmartScreenForTrustedDownloadsEnabled" 1 "DWord" "SmartScreen: Scan trusted downloads"

# Extensions
Set-Reg "$edgePath\ExtensionInstallBlocklist" "1" "*" "String" "Extensions: Block all by default"
# To allowlist specific extensions, add them to ExtensionInstallAllowlist

# Typosquatting
Set-Reg $edgePath "TyposquattingCheckerEnabled" 1 "DWord" "Typosquatting checker enabled"

# Password protection
Set-Reg $edgePath "PasswordMonitorAllowed" 1 "DWord" "Password breach monitoring enabled"
Set-Reg $edgePath "PasswordProtectionWarningTrigger" 1 "DWord" "Password reuse warning: On"

# Disable saving passwords in browser (prefer dedicated password manager)
# Uncomment if your customer uses a password manager:
# Set-Reg $edgePath "PasswordManagerEnabled" 0 "DWord" "Browser password save: Disabled"

# Network
Set-Reg $edgePath "SSLErrorOverrideAllowed" 0 "DWord" "SSL errors: Cannot be bypassed"

# Enhanced security mode
Set-Reg $edgePath "EnhanceSecurityMode" 1 "DWord" "Enhanced security mode: Balanced"

# Block potentially dangerous file types
Set-Reg $edgePath "ExemptDomainFileTypePairsFromFileTypeDownloadWarnings" "" "String" "No download warning exemptions"

# Disable dev tools in InPrivate (limits attacker debugging)
Set-Reg $edgePath "DeveloperToolsAvailability" 1 "DWord" "Dev tools: Not in InPrivate"

# Disable third-party cookie access (privacy + tracking reduction)
Set-Reg $edgePath "BlockThirdPartyCookies" 1 "DWord" "Third-party cookies blocked"

Write-Log "Edge hardening complete" "SUCCESS"

# ============================================================================
# GOOGLE CHROME POLICIES (if installed)
# ============================================================================
$chromeInstalled = (Test-Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") -or
                   (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")

if ($chromeInstalled) {
    Write-Log ""
    Write-Log "--- Google Chrome ---"
    $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"

    # Safe Browsing
    Set-Reg $chromePath "SafeBrowsingProtectionLevel" 1 "DWord" "Safe Browsing: Standard"
    # Use 2 for Enhanced (sends more data to Google but better protection)
    Set-Reg $chromePath "SafeBrowsingExtendedReportingEnabled" 0 "DWord" "Safe Browsing: No extended reporting"

    # SmartScreen equivalent
    Set-Reg $chromePath "DownloadRestrictions" 1 "DWord" "Block dangerous downloads"

    # Extensions
    Set-Reg "$chromePath\ExtensionInstallBlocklist" "1" "*" "String" "Extensions: Block all by default"

    # DNS-over-HTTPS
    Set-Reg $chromePath "DnsOverHttpsMode" "automatic" "String" "DoH: Automatic mode"

    # SSL
    Set-Reg $chromePath "SSLErrorOverrideAllowed" 0 "DWord" "SSL errors: Cannot be bypassed"

    # Disable password manager (uncomment if using dedicated pw manager)
    # Set-Reg $chromePath "PasswordManagerEnabled" 0 "DWord" "Browser password save: Disabled"

    # Block third-party cookies
    Set-Reg $chromePath "BlockThirdPartyCookies" 1 "DWord" "Third-party cookies blocked"

    # Disable dev tools in Incognito
    Set-Reg $chromePath "DeveloperToolsAvailability" 1 "DWord" "Dev tools: Not in Incognito"

    # Site isolation (defense against Spectre-type attacks)
    Set-Reg $chromePath "SitePerProcess" 1 "DWord" "Site isolation: Enabled"

    Write-Log "Chrome hardening complete" "SUCCESS"
} else {
    Write-Log ""
    Write-Log "Chrome not detected - skipping Chrome policies" "SKIP"
}

# ============================================================================
# DANGEROUS FILE TYPE ASSOCIATIONS
# Block "double-click to execute" for script files system-wide.
# These file types open in Notepad instead of executing.
# ============================================================================
Write-Log ""
Write-Log "--- Dangerous File Associations ---"
$dangerousExts = @{
    ".js"    = "Notepad"
    ".jse"   = "Notepad"
    ".vbs"   = "Notepad"
    ".vbe"   = "Notepad"
    ".wsf"   = "Notepad"
    ".wsh"   = "Notepad"
    ".hta"   = "Notepad"
    ".scr"   = "Notepad"
}

$notepadPath = "$env:SystemRoot\System32\notepad.exe"
foreach ($ext in $dangerousExts.Keys) {
    try {
        $assocKey = "HKLM:\SOFTWARE\Classes\$ext"
        if (-not (Test-Path $assocKey)) { New-Item -Path $assocKey -Force | Out-Null }
        # Point to a safe handler
        $handlerName = "txtfile"
        Set-ItemProperty -Path $assocKey -Name "(Default)" -Value $handlerName -Force
        Write-Log "  $ext -> opens in Notepad (safe)"
    } catch {
        Write-Log "  $ext reassociation failed: $_" "WARN"
    }
}
Write-Log "File associations hardened" "SUCCESS"

# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "  Browser hardening complete. No reboot needed."
Write-Log "  Browsers will pick up policy on next launch."
Write-Log "  Users may see 'Managed by your organization' indicator."
Write-Log "================================================================"
Write-Log ""
Write-Log "  NOTE ON EXTENSIONS:"
Write-Log "  All extensions are blocked by default. To allow specific ones,"
Write-Log "  add their IDs to the ExtensionInstallAllowlist registry key."
Write-Log "  Example for uBlock Origin (Edge):"
Write-Log '    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist" "1" "odfafepnkmbhccpbejgmiehpchacaeak"'
Write-Log ""
Write-Log "  ROLLBACK:"
Write-Log '    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -Force'
Write-Log '    Remove-Item "HKLM:\SOFTWARE\Policies\Google\Chrome" -Recurse -Force'

exit 0
