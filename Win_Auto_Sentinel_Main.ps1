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

Write-Host "\nFramework ready. Add scan logic and functions as needed."
