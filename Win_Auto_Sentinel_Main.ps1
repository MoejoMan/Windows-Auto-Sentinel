# WinAutoSentinel Main Script
# Entry point for Windows autostart and persistence review
# Framework only – add scan logic and functions as needed

# Script metadata
<#
    WinAutoSentinel
    Purpose: Review and summarize Windows autostart and persistence mechanisms
    Author: [Your Name]
    License: MIT
#>

param(
    [switch]$ExportHTML,
    [string]$OutputPath = "WinAutoSentinel_Report.html"
)

# Import functions if split into a second file
. "$PSScriptRoot\Win_Auto_Sentinel_Functions.ps1"

# Scan scheduled tasks
$scheduledTasks = Get-ScheduledTasksSummary
# Scan registry Run/RunOnce keys
$registryRunKeys = Get-RegistryRunKeysSummary
# Scan startup folders
$startupFolders = Get-StartupFoldersSummary
# Scan USB device history
$usbHistory = Get-USBHistorySummary
# Scan browser extensions
$browserExtensions = Get-BrowserExtensionsSummary
# Scan PowerShell history
$psHistory = Get-PowerShellHistorySummary
# Scan prefetch files
$prefetchFiles = Get-PrefetchFilesSummary
# Scan unusual services
$unusualServices = Get-UnusualServicesSummary
# Scan event log entries
$eventLogEntries = Get-EventLogEntriesSummary
# Scan hosts file entries
$hostsFileEntries = Get-HostsFileEntriesSummary
# Scan firewall rules
$firewallRules = Get-FirewallRulesSummary

# Group and present results
$results = @{
    "Scheduled Tasks" = $scheduledTasks
    "Registry Run Keys" = $registryRunKeys
    "Startup Folders" = $startupFolders
    "USB Device History" = $usbHistory
    "Browser Extensions" = $browserExtensions
    "PowerShell History" = $psHistory
    "Prefetch Files" = $prefetchFiles
    "Unusual Services" = $unusualServices
    "Event Log Entries" = $eventLogEntries
    "Hosts File Entries" = $hostsFileEntries
    "Firewall Rules" = $firewallRules
}

foreach ($category in $results.Keys) {
    Write-Host "\n=== $category ===" -ForegroundColor Yellow
    foreach ($item in $results[$category]) {
        Write-Host "- $item"
    }
}

# Generate HTML report if requested
if ($ExportHTML) {
    New-HTMLReport -Results $results -OutputPath $OutputPath
}

# Display helpful tips for reviewing findings
Write-Host "\n=== Helpful Tips for Reviewing Findings ===" -ForegroundColor Cyan
Write-Host "Scheduled Tasks: Look for tasks with unusual names, unknown publishers, or suspicious commands. Check task triggers and actions."
Write-Host "Registry Run Keys: These run at startup. Verify all entries are from trusted software. Remove unknown entries carefully."
Write-Host "Startup Folders: Files here run when any user logs in. Check file properties and signatures for legitimacy."
Write-Host "USB History: Review device names and connection times. Look for unexpected or suspicious devices."
Write-Host "Browser Extensions: Check extension permissions and publishers. Remove extensions you don't recognize or use."
Write-Host "PowerShell History: Review recent commands for suspicious activity. Clear history if privacy is a concern."
Write-Host "Prefetch Files: These show recently run programs. Look for unknown executables or suspicious file paths."
Write-Host "Unusual Services: Services listed here are not in the known legitimate services database. Research each one."
Write-Host "Event Log Entries: Look for error patterns, security events, or unusual system activity."
Write-Host "Hosts File Entries: Custom entries can redirect traffic. Ensure all entries are legitimate."
Write-Host "Firewall Rules: Review inbound/outbound rules. Unexpected open ports may indicate security risks."
Write-Host "\nTip: Use the HTML export (-ExportHTML) for an interactive report with checkboxes to mark reviewed items."
Write-Host "Tip: Research any unknown findings online before taking action. False positives are possible."

Write-Host "\nFramework ready. Add scan logic and functions as needed."
