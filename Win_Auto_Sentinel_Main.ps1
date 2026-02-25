#Requires -Version 5.1
<#
    WinAutoSentinel - Main Entry Point
    Purpose : Review and summarise Windows autostart/persistence mechanisms
    Author  : WinAutoSentinel Contributors
    License : MIT
    Usage   : .\Win_Auto_Sentinel_Main.ps1 [-ExportHTML] [-ExportCSV] [-ExportJSON] [-OutputDir <path>]
              Run elevated (as Administrator) for full results.
#>

param(
    [switch]$ExportHTML,
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [string]$OutputDir = $PSScriptRoot,
    [string]$HTMLPath   = '',
    [string]$CSVPath    = '',
    [string]$JSONPath   = ''
)

# ============================================================================
# INITIALISATION
# ============================================================================
$ErrorActionPreference = 'Continue'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Import functions
. "$PSScriptRoot\Win_Auto_Sentinel_Functions.ps1"

# Banner
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host '   WinAutoSentinel - Windows Autostart & Persistence Review'    -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host "   Computer : $env:COMPUTERNAME"           -ForegroundColor Gray
Write-Host "   User     : $env:USERNAME"               -ForegroundColor Gray
Write-Host "   Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$isAdmin = Test-IsAdministrator
if ($isAdmin) {
    Write-Host '   Elevated : Yes (full scan)' -ForegroundColor Green
} else {
    Write-Host '   Elevated : No  (some scans will be limited)' -ForegroundColor Yellow
    Write-Host '   Tip: Run as Administrator for complete results.' -ForegroundColor Yellow
}
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host ''

# ============================================================================
# RUN ALL SCANS
# ============================================================================
Write-Host '  Starting scans...' -ForegroundColor White
Write-Host ''

# Use an OrderedDictionary so sections appear in a logical, consistent order
$results = [ordered]@{}

# --- Persistence mechanisms (highest priority) ---
$results['Scheduled Tasks']       = Get-ScheduledTasksSummary
$results['Registry Run Keys']     = Get-RegistryRunKeysSummary
$results['Startup Folders']       = Get-StartupFoldersSummary
$results['WMI Persistence']       = Get-WMIPersistenceSummary
$results['Unusual Services']      = Get-UnusualServicesSummary

# --- Defence evasion ---
$results['Defender Exclusions']   = Get-DefenderExclusionsSummary

# --- Live system state ---
$results['Running Processes']     = Get-RunningProcessesSummary
$results['Network Connections']   = Get-NetworkConnectionsSummary

# --- Browser & user activity ---
$results['Browser Extensions']    = Get-BrowserExtensionsSummary
$results['PowerShell History']    = Get-PowerShellHistorySummary

# --- System artefacts ---
$results['Prefetch Files']        = Get-PrefetchFilesSummary
$results['Event Log Entries']     = Get-EventLogEntriesSummary
$results['DNS Cache']             = Get-DNSCacheSummary

# --- File system ---
$results['Alternate Data Streams']= Get-AlternateDataStreamsSummary
$results['USB Device History']    = Get-USBHistorySummary
$results['Hosts File']            = Get-HostsFileEntriesSummary
$results['Firewall Rules']        = Get-FirewallRulesSummary

# ============================================================================
# RISK SUMMARY DASHBOARD
# ============================================================================
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host '   SCAN COMPLETE - RISK SUMMARY'                               -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Cyan

$riskOrder   = @('Critical','High','Medium','Low','Info')
$riskColors  = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
$riskCounts  = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
$totalItems  = 0

foreach ($cat in $results.Keys) {
    foreach ($item in $results[$cat]) {
        $totalItems++
        $r = if ($item.Risk) { $item.Risk } else { 'Info' }
        if ($riskCounts.ContainsKey($r)) { $riskCounts[$r]++ }
    }
}

foreach ($r in $riskOrder) {
    $count = $riskCounts[$r]
    $color = $riskColors[$r]
    $bar   = '#' * [Math]::Min($count, 50)
    Write-Host "   $($r.PadRight(10)) : $($count.ToString().PadLeft(4))  $bar" -ForegroundColor $color
}
Write-Host "   $('Total'.PadRight(10)) : $($totalItems.ToString().PadLeft(4))" -ForegroundColor White
Write-Host ''

# ============================================================================
# PER-CATEGORY CONSOLE OUTPUT
# ============================================================================
foreach ($category in $results.Keys) {
    $items = $results[$category]
    $count = if ($items) { @($items).Count } else { 0 }

    # Category header
    $catColor = 'Yellow'
    if ($items | Where-Object { $_.Risk -eq 'Critical' }) { $catColor = 'Red' }
    elseif ($items | Where-Object { $_.Risk -eq 'High' })   { $catColor = 'DarkYellow' }

    Write-Host "  === $category ($count) ===" -ForegroundColor $catColor

    if ($count -eq 0) {
        Write-Host '      (no findings)' -ForegroundColor DarkGray
    } else {
        foreach ($item in $items) {
            $risk  = if ($item.Risk) { $item.Risk } else { 'Info' }
            $color = if ($riskColors.ContainsKey($risk)) { $riskColors[$risk] } else { 'Gray' }

            # Build a concise one-liner from the first few meaningful properties
            $props = $item.PSObject.Properties | Where-Object { $_.Name -notin @('Category','Risk') -and $_.Value }
            $line  = ($props | Select-Object -First 4 | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ' | '

            Write-Host "    [$risk] " -ForegroundColor $color -NoNewline
            Write-Host $line -ForegroundColor Gray
        }
    }
    Write-Host ''
}

# ============================================================================
# EXPORTS
# ============================================================================
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# HTML Report
if ($ExportHTML) {
    $htmlFile = if ($HTMLPath) { $HTMLPath } else { Join-Path $OutputDir "WinAutoSentinel_Report_$timestamp.html" }
    New-HTMLReport -Results $results -OutputPath $htmlFile
}

# CSV Export
if ($ExportCSV) {
    $csvFile = if ($CSVPath) { $CSVPath } else { Join-Path $OutputDir "WinAutoSentinel_Export_$timestamp.csv" }
    Write-Host "  [*] Exporting CSV..." -ForegroundColor DarkGray
    try {
        $allItems = foreach ($cat in $results.Keys) {
            foreach ($item in $results[$cat]) { $item }
        }
        $allItems | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Host "  [+] CSV saved: $csvFile" -ForegroundColor Green
    } catch {
        Write-Warning "  CSV export failed: $($_.Exception.Message)"
    }
}

# JSON Export
if ($ExportJSON) {
    $jsonFile = if ($JSONPath) { $JSONPath } else { Join-Path $OutputDir "WinAutoSentinel_Export_$timestamp.json" }
    Write-Host "  [*] Exporting JSON..." -ForegroundColor DarkGray
    try {
        $allItems = foreach ($cat in $results.Keys) {
            foreach ($item in $results[$cat]) { $item }
        }
        $allItems | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Host "  [+] JSON saved: $jsonFile" -ForegroundColor Green
    } catch {
        Write-Warning "  JSON export failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# WRAP-UP
# ============================================================================
$stopwatch.Stop()
$elapsed = $stopwatch.Elapsed

Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host "   Scan completed in $([Math]::Round($elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
if ($riskCounts.Critical -gt 0 -or $riskCounts.High -gt 0) {
    Write-Host "   ACTION NEEDED: $($riskCounts.Critical) critical, $($riskCounts.High) high-risk findings." -ForegroundColor Red
}
Write-Host '   Use -ExportHTML for an interactive report with search and filtering.' -ForegroundColor Gray
Write-Host '   Use -ExportCSV / -ExportJSON for machine-readable output.' -ForegroundColor Gray
Write-Host '   Run as Administrator for full scan coverage.' -ForegroundColor Gray
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host ''
