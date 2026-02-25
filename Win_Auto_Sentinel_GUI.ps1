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
# HTML CONTENT (Single Page Application)
# ============================================================================
$HtmlContent = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinAutoSentinel</title>
<meta name="quick-scan" content="__QUICKSCAN__">
<style>
:root {
    --bg: #0a0e1a; --surface: #141929; --card: #1c2237; --card2: #252d47;
    --text: #e2e8f0; --muted: #64748b; --border: #2d3756;
    --accent: #3b82f6; --accent2: #38bdf8;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --success: #10b981;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;overflow-x:hidden}
.container{max-width:1200px;margin:0 auto;padding:20px}

/* Views */
.view{display:none;animation:fadeIn .4s ease}
.view.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
@keyframes scanLine{0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}

/* Header */
.logo{text-align:center;padding:40px 0 10px}
.logo h1{font-size:2.2em;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-.5px}
.logo .sub{color:var(--muted);font-size:.95em;margin-top:4px}

/* Cards */
.card{background:var(--card);border-radius:12px;padding:20px;margin-bottom:16px;border:1px solid var(--border)}
.card h3{font-size:1em;color:var(--accent2);margin-bottom:12px;font-weight:600}

/* System info */
.sys-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.sys-item{background:var(--surface);padding:12px 16px;border-radius:8px}
.sys-item .label{font-size:.75em;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}
.sys-item .value{font-size:1.05em;font-weight:600;margin-top:2px}

/* Category toggles */
.cat-list{display:flex;flex-direction:column;gap:8px}
.cat-item{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;background:var(--surface);border-radius:8px;transition:all .2s}
.cat-item:hover{background:var(--card2)}
.cat-item .cat-info{flex:1}
.cat-item .cat-name{font-weight:600;font-size:.95em}
.cat-item .cat-desc{font-size:.8em;color:var(--muted)}
.cat-item .cat-badge{font-size:.7em;padding:2px 8px;border-radius:4px;background:#f59e0b22;color:#f59e0b;margin-left:8px}

/* Toggle switch */
.toggle{position:relative;width:44px;height:24px;flex-shrink:0;margin-left:12px}
.toggle input{opacity:0;width:0;height:0}
.toggle .slider{position:absolute;inset:0;background:var(--border);border-radius:12px;cursor:pointer;transition:.3s}
.toggle .slider:before{content:'';position:absolute;width:18px;height:18px;bottom:3px;left:3px;background:#fff;border-radius:50%;transition:.3s}
.toggle input:checked+.slider{background:var(--accent)}
.toggle input:checked+.slider:before{transform:translateX(20px)}

/* Buttons */
.btn{padding:12px 32px;border:none;border-radius:10px;font-size:1em;font-weight:700;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(59,130,246,.3)}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
.btn-secondary{background:var(--card);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:var(--critical);color:#fff}
.btn-sm{padding:8px 16px;font-size:.85em;border-radius:8px}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-center{display:flex;justify-content:center;margin-top:24px;gap:12px}

/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.modal-overlay.active{display:flex}
.modal{background:var(--card);border-radius:16px;padding:32px;max-width:480px;width:90%;border:1px solid var(--border);animation:fadeIn .3s ease}
.modal h2{font-size:1.3em;margin-bottom:8px}
.modal p{color:var(--muted);margin-bottom:20px;font-size:.95em}

/* Progress */
.progress-container{margin:24px 0}
.progress-bar{height:8px;background:var(--surface);border-radius:4px;overflow:hidden;position:relative}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:4px;transition:width .5s ease;position:relative}
.progress-fill::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);animation:scanLine 1.5s infinite}
.progress-text{text-align:center;margin-top:8px;font-size:.9em;color:var(--muted)}
.progress-pct{font-size:2em;font-weight:800;text-align:center;color:var(--accent2)}

/* Scan category status */
.scan-cats{display:flex;flex-direction:column;gap:6px;margin-top:20px}
.scan-cat{display:flex;align-items:center;gap:12px;padding:8px 14px;background:var(--surface);border-radius:8px;font-size:.9em}
.scan-cat .icon{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.75em;flex-shrink:0}
.scan-cat .icon.pending{background:var(--border);color:var(--muted)}
.scan-cat .icon.running{background:var(--accent);color:#fff;animation:pulse 1s infinite}
.scan-cat .icon.done{background:var(--success);color:#fff}
.scan-cat .icon.skipped{background:var(--muted);color:var(--bg)}
.scan-cat .findings{margin-left:auto;font-size:.8em;color:var(--muted)}
.live-counts{display:flex;gap:16px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.live-count{font-size:.85em;font-weight:600}

/* Dashboard */
.dash-grid{display:grid;grid-template-columns:280px 1fr;gap:20px;margin-bottom:20px}
@media(max-width:768px){.dash-grid{grid-template-columns:1fr}}
.score-card{text-align:center;padding:30px 20px}
.score-circle{position:relative;width:180px;height:180px;margin:0 auto}
.score-circle svg{width:100%;height:100%;transform:rotate(-90deg)}
.score-circle .score-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-circle .score-num{font-size:3em;font-weight:800;line-height:1}
.score-circle .score-grade{font-size:1.4em;font-weight:700;margin-top:2px}
.score-label{margin-top:12px;color:var(--muted);font-size:.85em}
.summary-card p{color:var(--muted);font-size:.93em;line-height:1.7}
.summary-card .highlight{color:var(--text);font-weight:600}

/* Stats row */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:20px}
.stat{background:var(--card);border-radius:10px;padding:16px;text-align:center;border-left:3px solid var(--info)}
.stat.critical{border-left-color:var(--critical)}.stat.high{border-left-color:var(--high)}
.stat.medium{border-left-color:var(--medium)}.stat.low{border-left-color:var(--low)}
.stat .num{font-size:1.8em;font-weight:800}.stat .lbl{font-size:.75em;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}

/* Donut chart */
.donut-chart{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.donut-legend{display:flex;flex-direction:column;gap:6px}
.donut-legend .leg-item{display:flex;align-items:center;gap:8px;font-size:.85em}
.leg-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

/* Controls */
.controls{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
.controls input[type="text"]{flex:1;min-width:200px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.9em;outline:none}
.controls input:focus{border-color:var(--accent)}
.fbtn{padding:6px 14px;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:6px;cursor:pointer;font-size:.8em;transition:all .2s}
.fbtn:hover,.fbtn.active{background:var(--accent);color:#fff;border-color:var(--accent)}

/* Finding sections */
.section{background:var(--card);border-radius:10px;margin-bottom:12px;overflow:hidden;border:1px solid var(--border)}
.sec-header{padding:14px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;transition:background .2s}
.sec-header:hover{background:var(--card2)}
.sec-header h3{font-size:.95em;font-weight:600;display:flex;align-items:center;gap:8px}
.sec-header .meta{display:flex;align-items:center;gap:10px}
.sec-header .badge{padding:2px 10px;border-radius:10px;font-size:.8em;background:var(--surface)}
.sec-header .arrow{transition:transform .3s;color:var(--muted);font-size:.8em}
.sec-header.open .arrow{transform:rotate(180deg)}
.sec-body{display:none;padding:0 18px 14px}
.sec-body.open{display:block}
.sec-health{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* Items */
.item{display:flex;gap:10px;padding:12px 14px;margin:6px 0;background:var(--surface);border-radius:8px;border-left:3px solid var(--info);font-size:.87em;align-items:flex-start;transition:opacity .2s}
.item.critical{border-left-color:var(--critical)}.item.high{border-left-color:var(--high)}
.item.medium{border-left-color:var(--medium)}.item.low{border-left-color:var(--low)}
.item.reviewed{opacity:.4}
.risk-badge{padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700;text-transform:uppercase;min-width:60px;text-align:center;flex-shrink:0}
.risk-badge.critical{background:var(--critical);color:#fff}.risk-badge.high{background:var(--high);color:#000}
.risk-badge.medium{background:var(--medium);color:#000}.risk-badge.low{background:var(--low);color:#fff}
.risk-badge.info{background:var(--info);color:#fff}
.item-details{flex:1;min-width:0}
.detail-row{display:flex;gap:8px;margin:1px 0}
.detail-label{color:var(--muted);min-width:110px;font-size:.82em;flex-shrink:0}
.detail-value{word-break:break-all}
.item input[type="checkbox"]{margin-top:2px;accent-color:var(--accent)}

/* Tips panel */
.tips-panel{background:var(--card);border-radius:10px;padding:20px;margin-top:16px;border:1px solid var(--border)}
.tips-panel h3{color:var(--accent2);margin-bottom:12px;font-size:1em}
.tip{padding:8px 0;border-bottom:1px solid var(--border);font-size:.87em;color:var(--muted)}
.tip:last-child{border-bottom:none}
.tip strong{color:var(--text)}

/* Remediation */
.remed{margin-top:8px;padding:10px;background:var(--bg);border-radius:6px;font-size:.82em}
.remed-title{color:var(--accent2);font-weight:600;margin-bottom:4px}
.remed code{display:block;background:var(--card2);padding:6px 10px;border-radius:4px;margin-top:4px;font-family:'Cascadia Code','Fira Code',monospace;font-size:.9em;word-break:break-all;cursor:pointer;position:relative}
.remed code:hover::after{content:'Click to copy';position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:.75em;color:var(--accent);font-family:'Segoe UI',sans-serif}
.copied-toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--success);color:#fff;padding:8px 20px;border-radius:8px;font-size:.9em;z-index:200;animation:fadeIn .3s ease}

/* Footer */
.footer{text-align:center;padding:30px;color:var(--muted);font-size:.82em}

/* Onboarding banner */
.onboard{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--accent);border-radius:14px;padding:24px 28px;margin-bottom:20px;position:relative}
.onboard h3{color:var(--accent2);font-size:1.1em;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.onboard p{color:var(--muted);font-size:.9em;line-height:1.7}
.onboard ul{color:var(--muted);font-size:.87em;margin:8px 0 0 20px;line-height:1.8}
.onboard ul li strong{color:var(--text)}
.onboard .dismiss{position:absolute;top:12px;right:16px;background:none;border:none;color:var(--muted);cursor:pointer;font-size:1.2em;padding:4px}
.onboard .dismiss:hover{color:var(--text)}

/* Preset buttons */
.presets{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.preset-btn{padding:10px 20px;border:2px solid var(--border);background:var(--surface);color:var(--text);border-radius:10px;cursor:pointer;font-size:.9em;font-weight:600;transition:all .2s;display:flex;align-items:center;gap:8px}
.preset-btn:hover{border-color:var(--accent);background:var(--card2)}
.preset-btn.active{border-color:var(--accent);background:rgba(59,130,246,.1)}
.preset-btn .preset-desc{font-size:.78em;font-weight:400;color:var(--muted)}

/* Scan complete notify */
.notify-bar{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,var(--success),#059669);color:#fff;text-align:center;padding:14px 20px;font-weight:700;font-size:1em;z-index:200;transform:translateY(-100%);transition:transform .4s ease;display:flex;align-items:center;justify-content:center;gap:10px}
.notify-bar.show{transform:translateY(0)}
.notify-bar .dismiss-notify{background:rgba(255,255,255,.2);border:none;color:#fff;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:.85em}

/* Print */
@media print{
    body{background:#fff;color:#000}
    .card,.section,.stat,.item{background:#f8f9fa;border-color:#dee2e6;color:#000}
    .controls,.btn,.toggle,.modal-overlay{display:none!important}
    .sec-body{display:block!important}
    .item{break-inside:avoid}
    :root{--text:#000;--muted:#555;--accent:#2563eb}
}
</style>
</head>
<body>
<div class="container">

<!-- ==================== VIEW: WELCOME / CONFIG ==================== -->
<div id="view-config" class="view active">
    <div class="logo">
        <h1>&#x1f6e1; WinAutoSentinel</h1>
        <div class="sub">Windows Autostart &amp; Persistence Security Review</div>
    </div>

    <!-- Onboarding banner (dismissible) -->
    <div class="onboard" id="onboardBanner">
        <button class="dismiss" onclick="dismissOnboard()" title="Dismiss">&times;</button>
        <h3>&#x1f44b; Welcome to WinAutoSentinel</h3>
        <p>This tool scans your Windows system for autostart entries, persistence mechanisms, and security misconfigurations. Here's what you need to know:</p>
        <ul>
            <li><strong>100% Read-Only</strong> &mdash; Nothing is modified, deleted, or sent anywhere</li>
            <li><strong>Fully Offline</strong> &mdash; No internet connection needed or used</li>
            <li><strong>Your Data Stays Here</strong> &mdash; All results are displayed locally in this browser tab</li>
            <li><strong>Admin Recommended</strong> &mdash; Running elevated gives access to Prefetch &amp; full Event Logs</li>
        </ul>
        <p style="margin-top:10px;color:var(--accent2)">Choose a preset below or customise which categories to scan, then click <strong>Begin Security Scan</strong>.</p>
    </div>

    <div class="card">
        <h3>System Information</h3>
        <div class="sys-grid" id="sysInfo">
            <div class="sys-item"><div class="label">Loading...</div><div class="value">--</div></div>
        </div>
    </div>

    <div class="card">
        <h3>Scan Categories</h3>
        <div class="presets">
            <button class="preset-btn" onclick="applyPreset('quick')" id="presetQuick">
                &#x26a1; Quick Scan
                <span class="preset-desc">(5 critical categories)</span>
            </button>
            <button class="preset-btn" onclick="applyPreset('full')" id="presetFull">
                &#x1f50d; Full Scan
                <span class="preset-desc">(all 17 categories)</span>
            </button>
            <button class="preset-btn" onclick="applyPreset('persistence')" id="presetPersist">
                &#x1f512; Persistence Only
                <span class="preset-desc">(autoruns &amp; persistence)</span>
            </button>
            <button class="preset-btn" onclick="applyPreset('network')" id="presetNet">
                &#x1f310; Network Focus
                <span class="preset-desc">(connections, DNS, firewall)</span>
            </button>
        </div>
        <div style="display:flex;gap:8px;margin-bottom:12px">
            <button class="btn btn-sm btn-secondary" onclick="toggleAllCategories(true)">Select All</button>
            <button class="btn btn-sm btn-secondary" onclick="toggleAllCategories(false)">Deselect All</button>
        </div>
        <div class="cat-list" id="catList"></div>
    </div>

    <div class="btn-center">
        <button class="btn btn-primary" onclick="showConfirmModal()" id="startBtn">
            &#x1f50d; Begin Security Scan
        </button>
    </div>
</div>

<!-- ==================== VIEW: SCANNING ==================== -->
<div id="view-scanning" class="view">
    <div class="logo">
        <h1>&#x1f6e1; WinAutoSentinel</h1>
        <div class="sub">Scanning your system...</div>
    </div>

    <div class="card" style="text-align:center">
        <div class="progress-pct" id="scanPct">0%</div>
        <div class="progress-container">
            <div class="progress-bar"><div class="progress-fill" id="scanBar" style="width:0%"></div></div>
        </div>
        <div class="progress-text" id="scanStatus">Initialising...</div>
    </div>

    <div class="card">
        <h3>Category Progress</h3>
        <div class="scan-cats" id="scanCats"></div>
    </div>

    <div class="live-counts" id="liveCounts"></div>
</div>

<!-- ==================== VIEW: DASHBOARD ==================== -->
<div id="view-dashboard" class="view">
    <div class="logo">
        <h1>&#x1f6e1; WinAutoSentinel</h1>
        <div class="sub">Scan Complete &mdash; Review Your Findings</div>
    </div>

    <div class="dash-grid">
        <div class="card score-card" id="scoreCard"></div>
        <div class="card summary-card" id="summaryCard"></div>
    </div>

    <div class="stats" id="statsRow"></div>

    <div class="controls" id="dashControls">
        <input type="text" id="search" placeholder="&#x1f50e; Search findings..." oninput="filterFindings()">
        <button class="fbtn active" onclick="setFilter('all',this)">All</button>
        <button class="fbtn" onclick="setFilter('critical',this)">Critical</button>
        <button class="fbtn" onclick="setFilter('high',this)">High</button>
        <button class="fbtn" onclick="setFilter('medium',this)">Medium</button>
        <button class="fbtn" onclick="setFilter('low',this)">Low</button>
        <button class="btn btn-sm btn-secondary" onclick="doExportCSV()">Export CSV</button>
        <button class="btn btn-sm btn-secondary" onclick="doExportJSON()">Export JSON</button>
        <button class="btn btn-sm btn-secondary" onclick="window.print()">Print</button>
        <button class="btn btn-sm btn-secondary" onclick="showView('config')">New Scan</button>
    </div>

    <div id="sections"></div>

    <div class="tips-panel">
        <h3>&#x1f4a1; Review &amp; Remediation Tips</h3>
        <div class="tip"><strong>Scheduled Tasks:</strong> Look for tasks running PowerShell, CMD, or with URLs in actions. Task Scheduler: <code>taskschd.msc</code></div>
        <div class="tip"><strong>Registry Run Keys:</strong> Every entry runs at startup. Right-click suspicious entries in <code>regedit.exe</code> to inspect.</div>
        <div class="tip"><strong>WMI Persistence:</strong> Legitimate WMI subscriptions are rare. Any finding here is high priority. Remove with <code>Get-WMIObject -Namespace root\subscription -Class __EventFilter | Remove-WMIObject</code></div>
        <div class="tip"><strong>Defender Exclusions:</strong> Malware adds itself here. Check via <code>Get-MpPreference | Select ExclusionPath, ExclusionProcess</code></div>
        <div class="tip"><strong>Services:</strong> Unsigned services outside System32/Program Files deserve investigation. Check signature: <code>Get-AuthenticodeSignature "path\to\binary.exe"</code></div>
        <div class="tip"><strong>Browser Extensions:</strong> Extensions with <code>&lt;all_urls&gt;</code>, <code>nativeMessaging</code>, or <code>debugger</code> perms can access everything.</div>
        <div class="tip"><strong>Network:</strong> Established connections to unknown IPs on unusual ports may indicate C2. Check with <code>Get-NetTCPConnection | Where-Object State -eq Established</code></div>
        <div class="tip"><strong>Hosts File:</strong> Redirections for microsoft.com, google.com, or banking sites are major red flags.</div>
        <div class="tip"><strong>Alternate Data Streams:</strong> Hidden data attached to files. Inspect: <code>Get-Item "file" -Stream *</code>. Remove: <code>Remove-Item "file" -Stream "streamname"</code></div>
        <div class="tip" style="color:var(--medium)"><strong>General:</strong> Always research unknown findings before removing. False positives happen. Use checkboxes to track your review.</div>
    </div>

    <div class="footer">
        <p>WinAutoSentinel &mdash; All data collected and displayed locally. Nothing leaves your machine.</p>
        <button class="btn btn-sm" style="margin-top:10px;background:#d63031;color:#fff;border:none;padding:8px 24px;border-radius:6px;cursor:pointer;font-size:0.95em" onclick="shutdownServer()">&#x23FB; Close WinAutoSentinel</button>
    </div>
</div>

<!-- ==================== MODAL: CONFIRM SCAN ==================== -->
<div class="modal-overlay" id="confirmModal">
    <div class="modal">
        <h2>&#x1f6e1; Ready to Scan?</h2>
        <p id="modalText">This will analyse your system across selected categories. The scan is read-only and makes no changes. Estimated time: 30-90 seconds.</p>
        <div class="btn-center" style="margin-top:0">
            <button class="btn btn-secondary" onclick="hideModal()">Cancel</button>
            <button class="btn btn-primary" onclick="startScan()">Start Scan</button>
        </div>
    </div>
</div>

</div><!-- /container -->

<!-- Scan-complete notification bar -->
<div class="notify-bar" id="notifyBar">
    <span>&#x2705; Scan complete! Scroll down to review your findings.</span>
    <button class="dismiss-notify" onclick="dismissNotify()">Dismiss</button>
</div>

<script>
// ============================================================================
// PRESETS
// ============================================================================
const presets = {
    quick: ['scheduled-tasks','registry-run','wmi-persistence','services','defender'],
    full: null, // means select all
    persistence: ['scheduled-tasks','registry-run','startup-folders','wmi-persistence','services'],
    network: ['network','dns-cache','firewall','hosts','browser-ext']
};

function applyPreset(name) {
    // Highlight active preset button
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById('preset' + name.charAt(0).toUpperCase() + name.slice(1));
    if (btn) btn.classList.add('active');

    const ids = presets[name];
    if (ids === null) {
        toggleAllCategories(true);
    } else {
        document.querySelectorAll('#catList input[type="checkbox"]').forEach(cb => {
            if (!cb.disabled) cb.checked = ids.includes(cb.dataset.catId);
        });
    }
}

// ============================================================================
// ONBOARDING
// ============================================================================
function dismissOnboard() {
    const banner = document.getElementById('onboardBanner');
    banner.style.transition = 'all .3s ease';
    banner.style.opacity = '0';
    banner.style.maxHeight = '0';
    banner.style.padding = '0 28px';
    banner.style.marginBottom = '0';
    banner.style.overflow = 'hidden';
    setTimeout(() => banner.remove(), 300);
    try { localStorage.setItem('was_onboarded','1'); } catch(e) {}
}

function checkOnboard() {
    try {
        if (localStorage.getItem('was_onboarded') === '1') {
            const b = document.getElementById('onboardBanner');
            if (b) b.remove();
        }
    } catch(e) {}
}

// ============================================================================
// SCAN COMPLETE NOTIFICATION
// ============================================================================
function showNotify() {
    const bar = document.getElementById('notifyBar');
    bar.classList.add('show');
    // Play a subtle system beep via AudioContext
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain); gain.connect(ctx.destination);
        osc.frequency.value = 880; gain.gain.value = 0.1;
        osc.start(); osc.stop(ctx.currentTime + 0.15);
        setTimeout(() => { osc.frequency.value = 1100; }, 100);
    } catch(e) {}
    // Update page title
    document.title = '✅ Scan Complete — WinAutoSentinel';
    setTimeout(() => dismissNotify(), 8000);
}
function dismissNotify() {
    document.getElementById('notifyBar').classList.remove('show');
    document.title = 'WinAutoSentinel';
}
function shutdownServer() {
    if (!confirm('Close WinAutoSentinel? This will stop the server and close this page.')) return;
    fetch('/api/shutdown', {method:'POST'}).catch(()=>{});
    document.title = 'WinAutoSentinel — Stopped';
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#ccc;font-family:sans-serif;flex-direction:column"><h1>&#x1f6e1; WinAutoSentinel</h1><p style="font-size:1.2em;margin-top:10px">Server stopped. You can close this tab.</p></div>';
}

// ============================================================================
// APP STATE
// ============================================================================
let systemInfo = null;
let categories = [];
let scanResults = null;
let pollTimer = null;
let riskFilter = 'all';

const riskOrder = ['Critical','High','Medium','Low','Info'];
const riskColors = {Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#3b82f6',Info:'#6b7280'};

const categoryTips = {
    'Scheduled Tasks': 'Disable suspicious tasks: Get-ScheduledTask "TaskName" | Disable-ScheduledTask',
    'Registry Run Keys': 'Remove entry: Remove-ItemProperty -Path "HKCU:\\...\\Run" -Name "EntryName"',
    'Startup Folders': 'Delete file: Remove-Item "C:\\Users\\...\\Startup\\suspicious.lnk"',
    'WMI Persistence': 'Remove: Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WMIObject',
    'Unusual Services': 'Stop & disable: Stop-Service "Name" -Force; Set-Service "Name" -StartupType Disabled',
    'Defender Exclusions': 'Remove exclusion: Remove-MpPreference -ExclusionPath "C:\\path"',
    'Running Processes': 'Kill process: Stop-Process -Id <PID> -Force',
    'Network Connections': 'Investigate: Get-Process -Id <PID> | Select Name,Path',
    'Browser Extensions': 'Open browser extension settings to review and remove.',
    'PowerShell History': 'Clear history: Remove-Item (Get-PSReadlineOption).HistorySavePath',
    'Hosts File': 'Edit hosts: notepad C:\\Windows\\System32\\drivers\\etc\\hosts',
    'Firewall Rules': 'Remove rule: Remove-NetFirewallRule -DisplayName "RuleName"'
};

// ============================================================================
// INITIALISATION
// ============================================================================
async function init() {
    checkOnboard();
    try {
        const res = await fetch('/api/info');
        const data = await res.json();
        systemInfo = data.system;
        categories = data.categories;
        renderSystemInfo();
        renderCategories();

        // Check if QuickScan mode was requested via server flag
        const qsMeta = document.querySelector('meta[name="quick-scan"]');
        if (qsMeta && qsMeta.content === 'true') {
            applyPreset('quick');
            // Auto-start after a brief delay so user sees what's happening
            setTimeout(() => { showConfirmModal(); }, 600);
        }
    } catch(e) {
        document.getElementById('sysInfo').innerHTML = '<div class="sys-item"><div class="label">Error</div><div class="value">Could not connect to server</div></div>';
    }
}

function renderSystemInfo() {
    const s = systemInfo;
    const adminHtml = s.isAdmin ? '<span style="color:var(--success)">&#x2713; Yes</span>' : '<span style="color:var(--medium)">&#x2717; No (limited)</span>';
    document.getElementById('sysInfo').innerHTML = `
        <div class="sys-item"><div class="label">Computer</div><div class="value">${esc(s.computerName)}</div></div>
        <div class="sys-item"><div class="label">User</div><div class="value">${esc(s.userName)}</div></div>
        <div class="sys-item"><div class="label">OS</div><div class="value">${esc(s.os)}</div></div>
        <div class="sys-item"><div class="label">Administrator</div><div class="value">${adminHtml}</div></div>
        <div class="sys-item"><div class="label">PowerShell</div><div class="value">${esc(s.psVersion)}</div></div>
        <div class="sys-item"><div class="label">Date</div><div class="value">${esc(s.date)}</div></div>
    `;
}

function renderCategories() {
    const el = document.getElementById('catList');
    el.innerHTML = categories.map(c => `
        <div class="cat-item">
            <div class="cat-info">
                <span class="cat-name">${esc(c.name)}</span>
                ${c.admin ? '<span class="cat-badge">Requires Admin</span>' : ''}
                <div class="cat-desc">${esc(c.desc)}</div>
            </div>
            <label class="toggle">
                <input type="checkbox" data-cat-id="${c.id}" checked ${c.admin && !systemInfo.isAdmin ? 'disabled title="Requires admin"' : ''}>
                <span class="slider"></span>
            </label>
        </div>
    `).join('');
    // Auto-uncheck admin-required when not admin
    if (!systemInfo.isAdmin) {
        el.querySelectorAll('input[disabled]').forEach(cb => cb.checked = false);
    }
}

function toggleAllCategories(state) {
    document.querySelectorAll('#catList input[type="checkbox"]:not([disabled])').forEach(cb => cb.checked = state);
}

// ============================================================================
// SCAN CONTROL
// ============================================================================
function showConfirmModal() {
    const selected = getSelectedCategories();
    if (selected.length === 0) { alert('Please select at least one scan category.'); return; }
    document.getElementById('modalText').textContent =
        `This will analyse ${selected.length} categor${selected.length === 1 ? 'y' : 'ies'} on your system. The scan is read-only and makes no changes. Estimated time: ${Math.max(10, selected.length * 5)}-${selected.length * 8} seconds.`;
    document.getElementById('confirmModal').classList.add('active');
}
function hideModal() { document.getElementById('confirmModal').classList.remove('active'); }

function getSelectedCategories() {
    return Array.from(document.querySelectorAll('#catList input[type="checkbox"]:checked')).map(cb => cb.dataset.catId);
}

async function startScan() {
    hideModal();
    const selected = getSelectedCategories();

    // Build scan category status list
    const scanCatsEl = document.getElementById('scanCats');
    scanCatsEl.innerHTML = categories
        .filter(c => selected.includes(c.id))
        .map(c => `<div class="scan-cat" data-scan-id="${c.id}">
            <div class="icon pending">&#x25CB;</div>
            <span>${esc(c.name)}</span>
            <span class="findings"></span>
        </div>`).join('');

    showView('scanning');

    try {
        await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({categories: selected})
        });
        pollTimer = setInterval(pollStatus, 600);
    } catch(e) {
        document.getElementById('scanStatus').textContent = 'Error starting scan: ' + e.message;
    }
}

async function pollStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();

        // Update progress
        document.getElementById('scanPct').textContent = data.progress + '%';
        document.getElementById('scanBar').style.width = data.progress + '%';
        document.getElementById('scanStatus').textContent = data.status === 'running'
            ? `Scanning: ${data.currentCategory}...`
            : data.status === 'complete' ? 'Scan complete!' : data.status;

        // Update category statuses
        if (data.completed) {
            data.completed.forEach(item => {
                const el = document.querySelector(`.scan-cat[data-scan-id="${item.id}"]`);
                if (el) {
                    el.querySelector('.icon').className = 'icon done';
                    el.querySelector('.icon').innerHTML = '&#x2713;';
                    el.querySelector('.findings').textContent = item.count + ' findings';
                }
            });
        }
        // Mark current as running
        if (data.currentId) {
            const cur = document.querySelector(`.scan-cat[data-scan-id="${data.currentId}"] .icon`);
            if (cur && !cur.classList.contains('done')) { cur.className = 'icon running'; cur.innerHTML = '&#x25CF;'; }
        }

        // Live risk counts
        if (data.findingCounts) {
            document.getElementById('liveCounts').innerHTML = riskOrder.map(r =>
                `<span class="live-count" style="color:${riskColors[r]}">${r}: ${data.findingCounts[r] || 0}</span>`
            ).join('');
        }

        // Done?
        if (data.status === 'complete') {
            clearInterval(pollTimer);
            scanResults = data.results;
            showNotify();
            setTimeout(() => renderDashboard(), 800);
        } else if (data.status === 'error') {
            clearInterval(pollTimer);
            document.getElementById('scanStatus').textContent = 'Error: ' + (data.error || 'Unknown');
        }
    } catch(e) { /* retry next poll */ }
}

// ============================================================================
// DASHBOARD RENDERING
// ============================================================================
function renderDashboard() {
    if (!scanResults) return;

    // Count findings
    const counts = {Critical:0,High:0,Medium:0,Low:0,Info:0};
    let total = 0;
    const catData = {};
    for (const [cat, items] of Object.entries(scanResults)) {
        catData[cat] = {items: items || [], counts: {Critical:0,High:0,Medium:0,Low:0,Info:0}};
        for (const item of (items || [])) {
            const r = item.Risk || 'Info';
            counts[r] = (counts[r]||0) + 1;
            catData[cat].counts[r] = (catData[cat].counts[r]||0) + 1;
            total++;
        }
    }

    // Score
    const score = calcScore(counts);
    const grade = getGrade(score);
    renderScoreCard(score, grade, counts);

    // Summary
    renderSummary(counts, total, score, grade, catData);

    // Stats row
    document.getElementById('statsRow').innerHTML = riskOrder.map(r =>
        `<div class="stat ${r.toLowerCase()}"><div class="num" style="color:${riskColors[r]}">${counts[r]}</div><div class="lbl">${r}</div></div>`
    ).join('') + `<div class="stat"><div class="num" style="color:var(--accent2)">${total}</div><div class="lbl">Total</div></div>`;

    // Sections
    renderSections(catData);

    showView('dashboard');
}

function calcScore(c) {
    let s = 100;
    s -= Math.min((c.Critical||0) * 15, 45);
    s -= Math.min((c.High||0) * 8, 32);
    s -= Math.min((c.Medium||0) * 3, 15);
    s -= Math.min((c.Low||0) * 1, 8);
    return Math.max(0, Math.round(s));
}

function getGrade(s) {
    if (s>=95) return {g:'A+',c:'#10b981'}; if (s>=90) return {g:'A',c:'#10b981'};
    if (s>=85) return {g:'B+',c:'#3b82f6'}; if (s>=80) return {g:'B',c:'#3b82f6'};
    if (s>=75) return {g:'C+',c:'#f59e0b'}; if (s>=70) return {g:'C',c:'#f59e0b'};
    if (s>=60) return {g:'D',c:'#f97316'}; return {g:'F',c:'#ef4444'};
}

function renderScoreCard(score, grade, counts) {
    const total = Object.values(counts).reduce((a,b)=>a+b,0) || 1;
    const circ = 2 * Math.PI * 70; // r=70
    let segments = '', offset = 0;
    for (const r of riskOrder) {
        const pct = (counts[r]||0) / total;
        if (pct === 0) continue;
        const len = pct * circ;
        segments += `<circle cx="90" cy="90" r="70" fill="none" stroke="${riskColors[r]}" stroke-width="14" stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${-offset}" stroke-linecap="round"/>`;
        offset += len;
    }
    if (total === 0 || offset === 0) segments = `<circle cx="90" cy="90" r="70" fill="none" stroke="var(--border)" stroke-width="14"/>`;

    document.getElementById('scoreCard').innerHTML = `
        <h3>Security Score</h3>
        <div class="score-circle">
            <svg viewBox="0 0 180 180">${segments}</svg>
            <div class="score-text">
                <div class="score-num" style="color:${grade.c}">${score}</div>
                <div class="score-grade" style="color:${grade.c}">${grade.g}</div>
            </div>
        </div>
        <div class="score-label">out of 100</div>
    `;
}

function renderSummary(counts, total, score, grade, catData) {
    let topConcern = '';
    let topRisk = 0;
    for (const [cat, d] of Object.entries(catData)) {
        const w = (d.counts.Critical||0)*4 + (d.counts.High||0)*3 + (d.counts.Medium||0)*2 + (d.counts.Low||0);
        if (w > topRisk) { topRisk = w; topConcern = cat; }
    }

    let summary = `Scanned <span class="highlight">${Object.keys(scanResults).length} categories</span> on <span class="highlight">${esc(systemInfo.computerName)}</span>. `;
    summary += `Found <span class="highlight">${total} items</span> total. `;
    if (counts.Critical > 0) summary += `<span style="color:var(--critical)">&#x26a0; ${counts.Critical} critical findings require immediate attention.</span> `;
    if (counts.High > 0) summary += `<span style="color:var(--high)">${counts.High} high-risk items should be investigated.</span> `;
    if (topConcern && topRisk > 0) summary += `Top area of concern: <span class="highlight">${esc(topConcern)}</span>. `;
    summary += `Overall security score: <span class="highlight" style="color:${grade.c}">${score}/100 (${grade.g})</span>.`;

    let advice = '';
    if (score >= 90) advice = 'Your system looks healthy. Keep software updated and review periodically.';
    else if (score >= 70) advice = 'Some items need attention. Review the flagged findings below and address high-priority ones.';
    else if (score >= 50) advice = 'Several concerning findings detected. Prioritise critical and high items for investigation.';
    else advice = 'Significant security concerns found. Immediate review recommended. Consider running a full AV scan alongside this review.';

    document.getElementById('summaryCard').innerHTML = `
        <h3>Executive Summary</h3>
        <p>${summary}</p>
        <p style="margin-top:12px;color:var(--accent2);font-weight:600">${advice}</p>
    `;
}

function renderSections(catData) {
    const container = document.getElementById('sections');
    let html = '';
    let secIdx = 0;

    for (const [cat, d] of Object.entries(catData)) {
        secIdx++;
        const items = d.items;
        const hasCritical = d.counts.Critical > 0;
        const hasHigh = d.counts.High > 0;
        const healthColor = hasCritical ? 'var(--critical)' : hasHigh ? 'var(--high)' : d.counts.Medium > 0 ? 'var(--medium)' : 'var(--success)';
        const autoOpen = hasCritical || hasHigh;
        const tip = categoryTips[cat] || '';

        html += `<div class="section" data-category="${esc(cat)}">
            <div class="sec-header${autoOpen?' open':''}" onclick="toggleSec('sec${secIdx}',this)">
                <h3><span class="sec-health" style="background:${healthColor}"></span> ${esc(cat)}</h3>
                <div class="meta">
                    <span class="badge">${items.length} items</span>
                    <span class="arrow">&#x25BC;</span>
                </div>
            </div>
            <div class="sec-body${autoOpen?' open':''}" id="sec${secIdx}">`;

        if (items.length === 0) {
            html += '<div class="item info"><span class="risk-badge info">CLEAR</span><div class="item-details">No findings in this category.</div></div>';
        } else {
            for (const item of items) {
                const risk = (item.Risk||'Info').toLowerCase();
                let details = '';
                for (const [k,v] of Object.entries(item)) {
                    if (k === 'Category' || k === 'Risk' || v == null || v === '') continue;
                    details += `<div class="detail-row"><span class="detail-label">${esc(k)}:</span><span class="detail-value">${esc(String(v))}</span></div>`;
                }
                const searchText = Object.values(item).filter(v=>v!=null).join(' ');
                html += `<div class="item ${risk}" data-risk="${risk}" data-text="${esc(searchText)}">
                    <input type="checkbox" title="Mark reviewed" onchange="this.parentElement.classList.toggle('reviewed')">
                    <span class="risk-badge ${risk}">${item.Risk||'Info'}</span>
                    <div class="item-details">${details}</div>
                </div>`;
            }
        }

        if (tip) {
            html += `<div class="remed"><div class="remed-title">Remediation</div><code onclick="copyCode(this)">${esc(tip)}</code></div>`;
        }

        html += '</div></div>';
    }
    container.innerHTML = html;
}

// ============================================================================
// INTERACTIONS
// ============================================================================
function showView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById('view-' + name).classList.add('active');
    window.scrollTo(0, 0);
}

function toggleSec(id, header) {
    document.getElementById(id).classList.toggle('open');
    header.classList.toggle('open');
}

function filterFindings() {
    const q = document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('.item[data-risk]').forEach(el => {
        const rMatch = riskFilter === 'all' || el.dataset.risk === riskFilter;
        const tMatch = !q || (el.dataset.text||'').toLowerCase().includes(q);
        el.style.display = (rMatch && tMatch) ? '' : 'none';
    });
}

function setFilter(f, btn) {
    riskFilter = f;
    document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (f !== 'all') document.querySelectorAll('.sec-body').forEach(b => { b.classList.add('open'); b.previousElementSibling.classList.add('open'); });
    filterFindings();
}

function copyCode(el) {
    navigator.clipboard.writeText(el.textContent).then(() => {
        const toast = document.createElement('div');
        toast.className = 'copied-toast';
        toast.textContent = 'Copied to clipboard!';
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 1500);
    });
}

function doExportCSV() {
    if (!scanResults) return;
    let csv = 'Category,Risk,Details\n';
    for (const [cat, items] of Object.entries(scanResults)) {
        for (const item of (items||[])) {
            const details = Object.entries(item).filter(([k])=>k!=='Category'&&k!=='Risk').map(([k,v])=>`${k}: ${v}`).join(' | ').replace(/"/g,'""');
            csv += `"${cat}","${item.Risk||'Info'}","${details}"\n`;
        }
    }
    download('WinAutoSentinel_Export.csv', csv, 'text/csv');
}

function doExportJSON() {
    if (!scanResults) return;
    download('WinAutoSentinel_Export.json', JSON.stringify(scanResults, null, 2), 'application/json');
}

function download(name, content, type) {
    const blob = new Blob([content], {type});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

// Keyboard shortcuts
document.addEventListener('keydown', e => {
    if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        const s = document.getElementById('search');
        if (s) s.focus();
    }
    if (e.key === 'Escape') { hideModal(); const s = document.getElementById('search'); if (s) s.blur(); }
});

// Boot
init();
</script>
</body>
</html>
'@

# ============================================================================
# HTTP HELPERS
# ============================================================================
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
