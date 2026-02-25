#Requires -Version 5.1
<#
    WinAutoSentinel GUI Launcher
    Purpose : Launch an interactive web-based security review GUI
    Usage   : .\Win_Auto_Sentinel_GUI.ps1 [-Port 8765] [-NoBrowser]
    Notes   : Opens your browser to a local web server. All data stays on your machine.
              Press Ctrl+C in the terminal to stop the server.
#>

param(
    [int]$Port = 8765,
    [switch]$NoBrowser,
    [switch]$QuickScan
)

$ErrorActionPreference = 'Continue'

# ============================================================================
# SCAN CATEGORIES DEFINITION
# ============================================================================
$ScanCategories = @(
    @{ Id='scheduled-tasks';  Name='Scheduled Tasks';        Func='Get-ScheduledTasksSummary';       Admin=$false; Desc='Tasks set to run automatically' }
    @{ Id='registry-run';     Name='Registry Run Keys';      Func='Get-RegistryRunKeysSummary';      Admin=$false; Desc='Programs that start with Windows' }
    @{ Id='startup-folders';  Name='Startup Folders';         Func='Get-StartupFoldersSummary';       Admin=$false; Desc='Files in startup directories' }
    @{ Id='wmi-persistence';  Name='WMI Persistence';         Func='Get-WMIPersistenceSummary';       Admin=$false; Desc='Fileless persistence via WMI events' }
    @{ Id='services';         Name='Unusual Services';        Func='Get-UnusualServicesSummary';      Admin=$false; Desc='Running services not in whitelist' }
    @{ Id='defender';         Name='Defender Exclusions';     Func='Get-DefenderExclusionsSummary';   Admin=$false; Desc='Windows Defender scan exclusions' }
    @{ Id='processes';        Name='Running Processes';       Func='Get-RunningProcessesSummary';     Admin=$false; Desc='Processes from suspicious locations' }
    @{ Id='network';          Name='Network Connections';     Func='Get-NetworkConnectionsSummary';   Admin=$false; Desc='Active TCP connections' }
    @{ Id='browser-ext';      Name='Browser Extensions';      Func='Get-BrowserExtensionsSummary';    Admin=$false; Desc='Chrome, Edge, Firefox extensions' }
    @{ Id='ps-history';       Name='PowerShell History';      Func='Get-PowerShellHistorySummary';    Admin=$false; Desc='Recent PowerShell commands' }
    @{ Id='prefetch';         Name='Prefetch Files';          Func='Get-PrefetchFilesSummary';        Admin=$true;  Desc='Recently executed programs' }
    @{ Id='event-logs';       Name='Event Log Entries';       Func='Get-EventLogEntriesSummary';      Admin=$true;  Desc='Security and system log events' }
    @{ Id='dns-cache';        Name='DNS Cache';               Func='Get-DNSCacheSummary';             Admin=$false; Desc='Recent DNS lookups' }
    @{ Id='ads';              Name='Alternate Data Streams';  Func='Get-AlternateDataStreamsSummary'; Admin=$false; Desc='Hidden data streams on files' }
    @{ Id='usb';              Name='USB Device History';      Func='Get-USBHistorySummary';           Admin=$false; Desc='Previously connected USB devices' }
    @{ Id='hosts';            Name='Hosts File';              Func='Get-HostsFileEntriesSummary';     Admin=$false; Desc='Custom DNS redirections' }
    @{ Id='firewall';         Name='Firewall Rules';          Func='Get-FirewallRulesSummary';        Admin=$false; Desc='Enabled firewall rules' }
)

# ============================================================================
# SHARED STATE (thread-safe between HTTP handler and scan runspace)
# ============================================================================
$Global:ScanState = [hashtable]::Synchronized(@{
    Status             = 'idle'
    CurrentCategory    = ''
    Progress           = 0
    TotalCategories    = 0
    CompletedCategories= 0
    CompletedList      = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    ShutdownRequested  = $false
    FindingCounts      = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    ResultsJson        = ''
    StartTime          = $null
    EndTime            = $null
    Error              = ''
})

# Keep reference to prevent GC
$Global:ScanPowerShell = $null
$Global:ScanRunspace   = $null

# ============================================================================
# IMPORT FUNCTIONS
# ============================================================================
$functionsFile = Join-Path $PSScriptRoot 'Win_Auto_Sentinel_Functions.ps1'
if (-not (Test-Path $functionsFile)) {
    Write-Error "Cannot find $functionsFile. Make sure it is in the same directory."
    exit 1
}
. $functionsFile

# ============================================================================
# HTML CONTENT (loaded from external file for maintainability)
# ============================================================================
$htmlFile = Join-Path $PSScriptRoot 'gui.html'
if (-not (Test-Path $htmlFile)) {
    Write-Error "Cannot find $htmlFile. Make sure gui.html is in the same directory."
    exit 1
}
$HtmlContent = Get-Content -Path $htmlFile -Raw -Encoding UTF8

# --- REMOVED: 870-line inline HTML heredoc ---
# The GUI SPA now lives in gui.html alongside this script.
# This keeps HTML/CSS/JS editable with proper syntax highlighting and linting.

# ============================================================================
# HTTP HELPERS# ============================================================================
function Send-Response {
    param($Response, [string]$Body, [string]$ContentType = 'text/html', [int]$StatusCode = 200)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "$ContentType; charset=utf-8"
    $Response.Headers.Add('Cache-Control', 'no-cache')
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

function Send-Json {
    param($Response, $Data)
    $json = $Data | ConvertTo-Json -Depth 10 -Compress
    Send-Response $Response $json 'application/json'
}

# ============================================================================
# API: SYSTEM INFO
# ============================================================================
function Handle-InfoRequest {
    param($Response)

    $isAdmin = Test-IsAdministrator
    $os = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    if (-not $os) { $os = [System.Environment]::OSVersion.VersionString }

    $info = @{
        system = @{
            computerName = $env:COMPUTERNAME
            userName     = $env:USERNAME
            os           = $os
            isAdmin      = $isAdmin
            psVersion    = $PSVersionTable.PSVersion.ToString()
            date         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        categories = @($ScanCategories | ForEach-Object {
            @{ id = $_.Id; name = $_.Name; desc = $_.Desc; admin = $_.Admin }
        })
    }

    Send-Json $Response $info
}

# ============================================================================
# API: START SCAN
# ============================================================================
function Handle-ScanRequest {
    param($Request, $Response)

    if ($Global:ScanState.Status -eq 'running') {
        Send-Json $Response @{ error = 'Scan already running' }
        return
    }

    # Read request body
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $body   = $reader.ReadToEnd()
    $reader.Close()
    $config = $body | ConvertFrom-Json

    $selectedIds = @($config.categories)
    $selectedCats = @($ScanCategories | Where-Object { $_.Id -in $selectedIds })

    if ($selectedCats.Count -eq 0) {
        Send-Json $Response @{ error = 'No valid categories selected' }
        return
    }

    # Reset state
    $Global:ScanState.Status              = 'running'
    $Global:ScanState.CurrentCategory     = ''
    $Global:ScanState.Progress            = 0
    $Global:ScanState.TotalCategories     = $selectedCats.Count
    $Global:ScanState.CompletedCategories = 0
    $Global:ScanState.CompletedList       = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    $Global:ScanState.FindingCounts       = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    $Global:ScanState.ResultsJson         = ''
    $Global:ScanState.StartTime           = Get-Date
    $Global:ScanState.EndTime             = $null
    $Global:ScanState.Error               = ''

    # Build the scan script to run in a background runspace
    $catJson = ($selectedCats | ForEach-Object { @{ Id=$_.Id; Name=$_.Name; Func=$_.Func } }) | ConvertTo-Json -Depth 5 -Compress

    $scanScript = @"
Set-Location '$($PSScriptRoot -replace "'","''")'
`$PSScriptRoot = '$($PSScriptRoot -replace "'","''")'
. '$($functionsFile -replace "'","''")'

`$catsToScan = '$catJson' | ConvertFrom-Json

`$allResults = [ordered]@{}

foreach (`$cat in `$catsToScan) {
    `$ScanState.CurrentCategory = `$cat.Name
    `$ScanState['CurrentId'] = `$cat.Id

    try {
        `$findings = @(& `$cat.Func)
    } catch {
        `$findings = @()
    }

    `$allResults[`$cat.Name] = `$findings

    # Update counts
    foreach (`$f in `$findings) {
        `$r = if (`$f.Risk) { `$f.Risk } else { 'Info' }
        if (`$ScanState.FindingCounts.ContainsKey(`$r)) { `$ScanState.FindingCounts[`$r]++ }
    }

    [void]`$ScanState.CompletedList.Add(@{ id = `$cat.Id; count = `$findings.Count })
    `$ScanState.CompletedCategories++
    `$ScanState.Progress = [math]::Round((`$ScanState.CompletedCategories / `$ScanState.TotalCategories) * 100)
}

# Serialise results to JSON for cross-thread safety
`$jsonItems = [ordered]@{}
foreach (`$key in `$allResults.Keys) {
    `$jsonItems[`$key] = @(`$allResults[`$key] | ForEach-Object {
        `$obj = [ordered]@{}
        foreach (`$p in `$_.PSObject.Properties) { `$obj[`$p.Name] = `$p.Value }
        `$obj
    })
}
`$ScanState.ResultsJson = (`$jsonItems | ConvertTo-Json -Depth 10 -Compress)
`$ScanState.EndTime = Get-Date
`$ScanState.Status = 'complete'
"@

    # Create and start background runspace
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('ScanState', $Global:ScanState)

    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript($scanScript)
    [void]$ps.BeginInvoke()

    $Global:ScanPowerShell = $ps
    $Global:ScanRunspace   = $runspace

    Send-Json $Response @{ status = 'started'; categories = $selectedCats.Count }
}

# ============================================================================
# API: SCAN STATUS
# ============================================================================
function Handle-StatusRequest {
    param($Response)

    $elapsed = 0
    if ($Global:ScanState.StartTime) {
        $elapsed = [math]::Round(((Get-Date) - $Global:ScanState.StartTime).TotalSeconds, 1)
    }

    $data = @{
        status             = $Global:ScanState.Status
        currentCategory    = $Global:ScanState.CurrentCategory
        currentId          = $Global:ScanState['CurrentId']
        progress           = $Global:ScanState.Progress
        completedCategories= $Global:ScanState.CompletedCategories
        totalCategories    = $Global:ScanState.TotalCategories
        completed          = @($Global:ScanState.CompletedList.ToArray())
        findingCounts      = $Global:ScanState.FindingCounts
        elapsedSeconds     = $elapsed
        error              = $Global:ScanState.Error
    }

    if ($Global:ScanState.Status -eq 'complete' -and $Global:ScanState.ResultsJson) {
        # Parse the JSON back so ConvertTo-Json wraps it properly in the response
        # Actually, embed it raw to avoid double-encoding
        $json = @"
{"status":"complete","progress":100,"currentCategory":"","currentId":"","completedCategories":$($Global:ScanState.TotalCategories),"totalCategories":$($Global:ScanState.TotalCategories),"completed":$($Global:ScanState.CompletedList.ToArray() | ConvertTo-Json -Depth 5 -Compress),"findingCounts":$($Global:ScanState.FindingCounts | ConvertTo-Json -Compress),"elapsedSeconds":$elapsed,"error":"","results":$($Global:ScanState.ResultsJson)}
"@
        Send-Response $Response $json 'application/json'
        return
    }

    Send-Json $Response $data
}

# ============================================================================
# MAIN SERVER LOOP
# ============================================================================
$listener = [System.Net.HttpListener]::new()
$url = "http://localhost:$Port/"

try {
    $listener.Prefixes.Add($url)
    $listener.Start()
} catch {
    # Port might be in use, try another
    $Port = Get-Random -Minimum 8000 -Maximum 9999
    $url  = "http://localhost:$Port/"
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($url)
    $listener.Start()
}

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host '   WinAutoSentinel GUI Server' -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host "   URL  : $url" -ForegroundColor White
Write-Host "   Stop : Press Ctrl+C or use the Close button in the browser" -ForegroundColor Gray
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host ''

# Inject Quick Scan flag into HTML
if ($QuickScan) {
    $HtmlContent = $HtmlContent -replace '__QUICKSCAN__', 'true'
} else {
    $HtmlContent = $HtmlContent -replace '__QUICKSCAN__', 'false'
}

# Open browser
if (-not $NoBrowser) {
    Start-Process $url
}

try {
    while ($listener.IsListening) {
        $context  = $listener.GetContext()
        $request  = $context.Request
        $response = $context.Response

        $path   = $request.Url.AbsolutePath
        $method = $request.HttpMethod

        try {
            switch -Regex ("$method $path") {
                '^GET /$'          { Send-Response $response $HtmlContent 'text/html'; break }
                '^GET /api/info$'  { Handle-InfoRequest $response; break }
                '^POST /api/scan$' { Handle-ScanRequest $request $response; break }
                '^GET /api/status$'{ Handle-StatusRequest $response; break }
                '^POST /api/shutdown$' {
                    Send-Response $response '{"status":"shutting down"}' 'application/json'
                    $Global:ScanState.ShutdownRequested = $true
                    break
                }
                default            { Send-Response $response '{"error":"Not Found"}' 'application/json' 404 }
            }
        } catch {
            try { Send-Response $response "{`"error`":`"$($_.Exception.Message)`"}" 'application/json' 500 } catch { }
        }

        Write-Host "  $method $path" -ForegroundColor DarkGray -NoNewline
        Write-Host " [$($response.StatusCode)]" -ForegroundColor $(if ($response.StatusCode -eq 200) { 'DarkGreen' } else { 'DarkYellow' })

        # Check for graceful shutdown request
        if ($Global:ScanState.ShutdownRequested) {
            Write-Host ''
            Write-Host '  Shutdown requested from browser. Stopping server...' -ForegroundColor Cyan
            break
        }
    }
} catch {
    # Ctrl+C or listener error
} finally {
    Write-Host ''
    Write-Host '  Server stopped.' -ForegroundColor Yellow

    # Clean up runspace
    if ($Global:ScanPowerShell) {
        try { $Global:ScanPowerShell.Stop(); $Global:ScanPowerShell.Dispose() } catch { }
    }
    if ($Global:ScanRunspace) {
        try { $Global:ScanRunspace.Close(); $Global:ScanRunspace.Dispose() } catch { }
    }

    $listener.Stop()
    $listener.Close()
}
