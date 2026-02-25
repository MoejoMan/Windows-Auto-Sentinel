#Requires -Version 5.1
<#
    WinAutoSentinel - Main Entry Point
    Purpose : Review and summarise Windows autostart/persistence mechanisms
    Author  : WinAutoSentinel Contributors
    License : MIT
    Usage   : .\Win_Auto_Sentinel_Main.ps1 [-ExportHTML] [-ExportCSV] [-ExportJSON] [-OutputDir <path>]
              .\Win_Auto_Sentinel_Main.ps1 -ExportHTML -AutoOpen    (scan + open report in browser)
              .\Win_Auto_Sentinel_Main.ps1 -WhatIf   (dry-run: shows what each scan reads, then exits)
              Run elevated (as Administrator) for full results.
#>

param(
    [switch]$ExportHTML,
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [string]$OutputDir = $PSScriptRoot,
    [string]$HTMLPath   = '',
    [string]$CSVPath    = '',
    [string]$JSONPath   = '',
    [Alias('DryRun')]
    [switch]$WhatIf,
    [switch]$AutoOpen,
    [switch]$Log
)

# ============================================================================
# INITIALISATION
# ============================================================================
$ErrorActionPreference = 'Continue'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Import functions
. "$PSScriptRoot\Win_Auto_Sentinel_Functions.ps1"

# Enable optional file logging
if ($Log) {
    Enable-WASLog
    Write-WASLog "Session started  Computer=$env:COMPUTERNAME  User=$env:USERNAME  Admin=$(Test-IsAdministrator)"
}

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
# WHATIF / DRY-RUN MODE
# ============================================================================
if ($WhatIf) {
    Write-Host '  ============================================================' -ForegroundColor Magenta
    Write-Host '   DRY-RUN MODE -- No scans will be executed.'                   -ForegroundColor Magenta
    Write-Host '   Below is exactly what each scan reads. Nothing is modified.' -ForegroundColor Magenta
    Write-Host '  ============================================================' -ForegroundColor Magenta
    Write-Host ''

    $scanDetails = [ordered]@{
        'Scheduled Tasks'       = @(
            'Get-ScheduledTask                              -- Lists active task definitions (name, triggers, actions)'
            'Get-AuthenticodeSignature                      -- Checks code signatures on task binaries'
        )
        'Registry Run Keys'     = @(
            'Get-ItemProperty HKLM:\...\Run                 -- Reads HKLM Run, RunOnce, WOW6432Node keys'
            'Get-ItemProperty HKCU:\...\Run                 -- Reads HKCU Run, RunOnce, WOW6432Node keys'
        )
        'Startup Folders'       = @(
            'Get-ChildItem "$env:APPDATA\...\Startup"       -- Lists per-user startup folder contents'
            'Get-ChildItem "$env:PROGRAMDATA\...\Startup"   -- Lists all-users startup folder contents'
        )
        'WMI Persistence'       = @(
            'Get-CimInstance root\subscription               -- Reads WMI event filters, consumers, and bindings'
        )
        'Unusual Services'      = @(
            'Get-CimInstance Win32_Service                   -- Lists running auto-start services'
            'Get-Content legitimate_services.txt             -- Loads whitelist patterns'
            'Get-AuthenticodeSignature                       -- Checks code signatures on service binaries'
        )
        'Defender Exclusions'   = @(
            'Get-MpPreference                                -- Reads Defender exclusion lists (paths, processes, extensions)'
        )
        'Running Processes'     = @(
            'Get-CimInstance Win32_Process                   -- Lists all running processes with paths and command lines'
        )
        'Network Connections'   = @(
            'Get-NetTCPConnection                            -- Lists active TCP connections (Established + Listening)'
            'Get-CimInstance Win32_Process                   -- Maps PIDs to process names'
        )
        'Browser Extensions'    = @(
            'Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\..." -- Reads Chrome extension manifests'
            'Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\..." -- Reads Edge extension manifests'
            'Get-ChildItem "$env:APPDATA\Mozilla\Firefox\..."    -- Reads Firefox addon JSON'
        )
        'PowerShell History'    = @(
            'Get-Content (Get-PSReadLineOption).HistorySavePath  -- Reads PSReadLine command history file'
        )
        'Prefetch Files'        = @(
            'Get-ChildItem C:\Windows\Prefetch\*.pf         -- Lists recently executed programs (requires admin)'
        )
        'Event Log Entries'     = @(
            'Get-WinEvent Security (4625,4720,4732,4648,1102) -- Reads security events (logon failures, etc.)'
            'Get-WinEvent System   (7045,7034,41,1074,6008)   -- Reads system events (service installs, etc.)'
        )
        'DNS Cache'             = @(
            'Get-DnsClientCache                              -- Reads the DNS resolver cache'
        )
        'Alternate Data Streams'= @(
            'Get-ChildItem -Recurse Desktop,Downloads,Docs,Temp -- Scans user directories'
            'Get-Item -Stream *                               -- Reads ADS metadata on each file'
        )
        'USB Device History'    = @(
            'Get-ItemProperty HKLM:\SYSTEM\...\Enum\USBSTOR  -- Reads USB device registry records'
        )
        'Hosts File'            = @(
            'Get-Content $env:SystemRoot\System32\drivers\etc\hosts -- Reads the hosts file'
        )
        'Firewall Rules'        = @(
            'Get-NetFirewallRule                              -- Lists enabled firewall rules'
            'Get-NetFirewallPortFilter -All                   -- Reads port filters (batch)'
            'Get-NetFirewallAddressFilter -All                -- Reads address filters (batch)'
            'Get-NetFirewallApplicationFilter -All            -- Reads application filters (batch)'
        )
    }

    foreach ($scan in $scanDetails.Keys) {
        Write-Host "  === $scan ===" -ForegroundColor Yellow
        foreach ($detail in $scanDetails[$scan]) {
            Write-Host "      $detail" -ForegroundColor Gray
        }
        Write-Host ''
    }

    Write-Host '  ============================================================' -ForegroundColor Magenta
    Write-Host '   SUMMARY: All operations above are READ-ONLY (Get-* cmdlets).' -ForegroundColor Magenta
    Write-Host '   No files, registry keys, services, or settings are modified.' -ForegroundColor Magenta
    Write-Host '   Reports are saved only if you pass -ExportHTML/-ExportCSV/-ExportJSON.' -ForegroundColor Magenta
    Write-Host '  ============================================================' -ForegroundColor Magenta
    Write-Host ''
    Write-Host '   Remove -WhatIf to run the actual scan.' -ForegroundColor Cyan
    Write-Host ''
    return
}

# ============================================================================
# RUN ALL SCANS
# ============================================================================
Write-Host '  Starting scans...' -ForegroundColor White
Write-Host ''
Write-WASLog 'Starting scans'

# Use an OrderedDictionary so sections appear in a logical, consistent order
$results = [ordered]@{}

# --- Persistence mechanisms (highest priority) ---
Write-WASLog 'Category: Scheduled Tasks'
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
Write-WASLog "All scans complete  TotalCategories=$($results.Count)"

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

    # Auto-open the report in the default browser
    if ($AutoOpen -and (Test-Path $htmlFile)) {
        Write-Host "  [*] Opening report in browser..." -ForegroundColor DarkGray
        Start-Process $htmlFile
    }
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
Write-WASLog "Session finished  Elapsed=$([Math]::Round($elapsed.TotalSeconds,1))s  Critical=$($riskCounts.Critical)  High=$($riskCounts.High)"
Write-Host '  All done! You can close this window.' -ForegroundColor Green
Write-Host ''
