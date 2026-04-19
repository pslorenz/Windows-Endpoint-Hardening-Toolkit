#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ROLLBACK for Harden-Endpoint-v2.ps1
    Reverts hardening changes if they cause issues.
    Deploy via NinjaRMM (Run As: System)

.NOTES
    Safe items left in place (no reason to revert):
      - PowerShell Logging (harmless, still useful)
      - PowerShell v2 disabled (no legitimate use)
      - Audit policies (harmless, still useful)
      - SMBv1 disabled (no legitimate use on Win 11)
      - Windows Update settings (always want this)
      - Security event log size increases
#>

Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  ROLLBACK: Harden-Endpoint-v2.ps1" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

# 1. Unblock WScript/CScript
Write-Host "[1] Unblocking WScript/CScript..." -ForegroundColor Cyan
@("wscript.exe", "cscript.exe") | ForEach-Object {
    $p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
    if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "     Unblocked: $_" -ForegroundColor Green
}

# 2. Remove Constrained Language Mode
Write-Host "[2] Removing Constrained Language Mode..." -ForegroundColor Cyan
[System.Environment]::SetEnvironmentVariable("__PSLockdownPolicy", $null, "Machine")
Write-Host "     Removed" -ForegroundColor Green

# 3. Disable ASR rules
Write-Host "[3] Disabling ASR rules..." -ForegroundColor Cyan
try {
    $ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    if ($ids -and $ids.Count -gt 0) {
        $actions = @($ids | ForEach-Object { 0 })
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
        Write-Host "     $($ids.Count) ASR rules disabled" -ForegroundColor Green
    } else { Write-Host "     No ASR rules found" -ForegroundColor Gray }
} catch { Write-Host "     ASR rollback skipped: $_" -ForegroundColor Gray }

# 4. Remove MSI restrictions
Write-Host "[4] Removing MSI restrictions..." -ForegroundColor Cyan
$msiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
@("DisableMSI", "DisableUserInstalls", "AlwaysInstallElevated") | ForEach-Object {
    Remove-ItemProperty -Path $msiPath -Name $_ -ErrorAction SilentlyContinue
}
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
Write-Host "     MSI restrictions removed" -ForegroundColor Green

# 5. Restore DNS to DHCP-assigned
Write-Host "[5] Restoring DNS to automatic (DHCP)..." -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    Write-Host "     Reset DNS on: $($_.Name)" -ForegroundColor Green
}

# 6. Remove process mitigations
Write-Host "[6] Removing process mitigations..." -ForegroundColor Cyan
@("explorer.exe", "powershell.exe", "pwsh.exe", "msiexec.exe") | ForEach-Object {
    try { Set-ProcessMitigation -Name $_ -Remove -ErrorAction SilentlyContinue } catch {}
}
Write-Host "     Process mitigations removed" -ForegroundColor Green

# 7. Remove firewall rules
Write-Host "[7] Removing custom firewall rules..." -ForegroundColor Cyan
$fwRules = @(
    "Block WScript Outbound (x64)", "Block CScript Outbound (x64)",
    "Block WScript Outbound (x86)", "Block CScript Outbound (x86)",
    "Block MSHTA Outbound", "Block Certutil Outbound", "Block BitsAdmin Outbound"
)
foreach ($rule in $fwRules) {
    Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
}
Write-Host "     Firewall rules removed" -ForegroundColor Green

# 8. Re-enable autorun (if needed)
Write-Host "[8] Re-enabling autorun..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
Write-Host "     Autorun restored" -ForegroundColor Green

# 9. Re-enable WDigest (unlikely to be needed, but included)
Write-Host "[9] Re-enabling WDigest..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
Write-Host "     WDigest restored to default" -ForegroundColor Green

# 10. Re-enable WinRM (if needed for NinjaRMM)
Write-Host "[10] Re-enabling WinRM..." -ForegroundColor Cyan
Set-Service -Name WinRM -StartupType Manual -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -ErrorAction SilentlyContinue
Write-Host "      WinRM set to manual" -ForegroundColor Green

# 11. Re-enable Remote Assistance
Write-Host "[11] Re-enabling Remote Assistance..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 1 -ErrorAction SilentlyContinue
Write-Host "      Remote Assistance enabled" -ForegroundColor Green

# 12. Remove Office macro restrictions
Write-Host "[12] Removing Office macro restrictions..." -ForegroundColor Cyan
@("word", "excel", "powerpoint") | ForEach-Object {
    $p = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\$_\security"
    Remove-ItemProperty -Path $p -Name "blockcontentexecutionfrominternet" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $p -Name "vbawarnings" -ErrorAction SilentlyContinue
}
Write-Host "      Office macro defaults restored" -ForegroundColor Green

# 13. Re-enable LLMNR
Write-Host "[13] Re-enabling LLMNR..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
Write-Host "      LLMNR enabled" -ForegroundColor Green

# 14. Remove LSA protection (if causing login issues)
Write-Host "[14] Removing LSA Protection..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
Write-Host "      LSA Protection removed" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  ROLLBACK COMPLETE" -ForegroundColor Green
Write-Host "  Reboot required for all changes to take effect." -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "  Items left in place (harmless/beneficial):" -ForegroundColor Gray
Write-Host "    - PowerShell logging (detection value)" -ForegroundColor Gray
Write-Host "    - PowerShell v2 disabled (no legit use)" -ForegroundColor Gray
Write-Host "    - Security audit policies (detection value)" -ForegroundColor Gray
Write-Host "    - SMBv1 disabled (no legit use on Win 11)" -ForegroundColor Gray
Write-Host "    - Windows Update enforcement" -ForegroundColor Gray
Write-Host "    - Event log size increases" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green

exit 0
