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

# --- Admin Privilege Check ---
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $currentUser
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "WARNING: You are not running as Administrator. Some scan categories (e.g., Prefetch, some Event Logs) may be incomplete." -ForegroundColor Yellow
    $adminWarning = $true
} else {
    $adminWarning = $false
}

# --- Force script to relaunch in interactive mode if needed (prevent infinite relaunch) ---
if (-not $env:WIN_AUTOSENTINEL_GUI) {
    if ($Host.Name -notlike '*Windows PowerShell*' -or $env:WT_SESSION -or $env:TERM_PROGRAM -or $args -contains '-File') {
        $psExe = (Get-Command powershell.exe).Source
        $scriptPath = $MyInvocation.MyCommand.Definition
        $argList = @()
        if ($args) { $argList += $args }
        $envPrefix = '$env:WIN_AUTOSENTINEL_GUI=1; '
        $cmd = $envPrefix + "& '$scriptPath' $($argList -join ' ')"
        Start-Process -FilePath $psExe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-Command", $cmd -Verb RunAs
        exit
    }
}


# --- Import GUI module and show pre-scan options ---
. "$PSScriptRoot\WinAutoSentinel_GUI.ps1"

$selectedOptions = Show-PreScanOptions -IsAdmin:(!$adminWarning)

# --- Run scan logic if user clicked Launch Scan ---
if ($selectedOptions) {
    Write-Host "Starting scan with selected options..." -ForegroundColor Cyan
    $results = @{}
    if ($selectedOptions.scheduledTasks) { $results.scheduledTasks = Get-ScheduledTasksSummary }
    if ($selectedOptions.registryRunKeys) { $results.registryRunKeys = Get-RegistryRunKeysSummary }
    if ($selectedOptions.startupFolders) { $results.startupFolders = Get-StartupFoldersSummary }
    # ...add other scan calls as needed, using $selectedOptions keys...

    # --- Build HTML sections for each scan ---

    function New-Section {
        param($title, $items, $sectionId)
        $count = ($items | Measure-Object).Count
        $lines = @()
        $lines += "        <div class=\"section\">"
        $lines += "            <div class=\"section-header\" onclick=\"toggleSection('$sectionId')\">"
        $lines += "                <strong>$title</strong> ($count items)"
        $lines += "            </div>"
        $lines += "            <div class=\"section-content\" id=\"$sectionId\">"
        foreach ($item in $items) {
            $lines += "                <div class=\"item\">"
            $lines += "                    <input type=\"checkbox\" class=\"checkbox\" onchange=\"markRecognized(this)\">"
            $lines += "                    <span>" + [System.Web.HttpUtility]::HtmlEncode($item) + "</span>"
            $lines += "                </div>"
        }
        $lines += "            </div>"
        $lines += "        </div>"
        return ($lines -join "`n")
    }

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $computer = $env:COMPUTERNAME

    $sections = @()
    if ($results.registryRunKeys) { $sections += New-Section 'Registry Run Keys' $results.registryRunKeys 'section1' }
    if ($results.firewallRules) { $sections += New-Section 'Firewall Rules' $results.firewallRules 'section2' }
    if ($results.unusualServices) { $sections += New-Section 'Unusual Services' $results.unusualServices 'section3' }
    if ($results.eventLogEntries) { $sections += New-Section 'Event Log Entries' $results.eventLogEntries 'section4' }
    if ($results.usbHistory) { $sections += New-Section 'USB Device History' $results.usbHistory 'section5' }
    if ($results.browserExtensions) { $sections += New-Section 'Browser Extensions' $results.browserExtensions 'section6' }
    if ($results.scheduledTasks) { $sections += New-Section 'Scheduled Tasks' $results.scheduledTasks 'section7' }
    if ($results.prefetchFiles) { $sections += New-Section 'Prefetch Files' $results.prefetchFiles 'section8' }
    if ($results.psHistory) { $sections += New-Section 'PowerShell History' $results.psHistory 'section9' }
    if ($results.hostsFileEntries) { $sections += New-Section 'Hosts File Entries' $results.hostsFileEntries 'section10' }
    if ($results.startupFolders) { $sections += New-Section 'Startup Folders' $results.startupFolders 'section11' }

    $tips = @(
        '<div class="item"><strong>Scheduled Tasks:</strong> Look for tasks with unusual names, unknown publishers, or suspicious commands. Check task triggers and actions.</div>',
        '<div class="item"><strong>Registry Run Keys:</strong> These run at startup. Verify all entries are from trusted software. Remove unknown entries carefully.</div>',
        '<div class="item"><strong>Startup Folders:</strong> Files here run when any user logs in. Check file properties and signatures for legitimacy.</div>',
        '<div class="item"><strong>USB History:</strong> Review device names and connection times. Look for unexpected or suspicious devices.</div>',
        '<div class="item"><strong>Browser Extensions:</strong> Check extension permissions and publishers. Remove extensions you don`t recognize or use.</div>',
        '<div class="item"><strong>PowerShell History:</strong> Review recent commands for suspicious activity. Clear history if privacy is a concern.</div>',
        '<div class="item"><strong>Prefetch Files:</strong> These show recently run programs. Look for unknown executables or suspicious file paths.</div>',
        '<div class="item"><strong>Unusual Services:</strong> Services listed here are not in the known legitimate services database. Research each one.</div>',
        '<div class="item"><strong>Event Log Entries:</strong> Look for error patterns, security events, or unusual system activity.</div>',
        '<div class="item"><strong>Hosts File Entries:</strong> Custom entries can redirect traffic. Ensure all entries are legitimate.</div>',
        '<div class="item"><strong>Firewall Rules:</strong> Review inbound/outbound rules. Unexpected open ports may indicate security risks.</div>',
        '<div class="item" style="background: #fff3cd;"><strong>General Tips:</strong> Research any unknown findings online before taking action. False positives are possible. Use checkboxes to mark items you`ve reviewed and recognize.</div>'
    )

    $sectionsHtml = $sections -join "`n"
    $tipsHtml = $tips -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinAutoSentinel Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .section-header { background: #3498db; color: white; padding: 10px; cursor: pointer; border-radius: 5px 5px 0 0; }
        .section-content { padding: 15px; display: none; }
        .item { margin: 10px 0; padding: 10px; background: #f9f9f9; border-radius: 3px; }
        .checkbox { margin-right: 10px; }
        .recognized { background: #d4edda !important; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 0.9em; }
    </style>
    <script>
        function toggleSection(id) {
            var content = document.getElementById(id);
            content.style.display = content.style.display === 'block' ? 'none' : 'block';
        }
        function markRecognized(checkbox) {
            var item = checkbox.parentElement;
            if (checkbox.checked) {
                item.classList.add('recognized');
            } else {
                item.classList.remove('recognized');
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>WinAutoSentinel Report</h1>
        <div class="summary">
            <h2>Report Summary</h2>
            <p>This report shows Windows autostart and persistence mechanisms found on your system. Check the boxes for items you recognize, and expand sections for details.</p>
            <p><strong>Generated:</strong> $now</p>
            <p><strong>Computer:</strong> $computer</p>
        </div>
$sectionsHtml
        <div class="section">
            <div class="section-header" onclick="toggleSection('tips')">
                <strong>Helpful Tips for Reviewing Findings</strong>
            </div>
            <div class="section-content" id="tips">
$tipsHtml
            </div>
        </div>
        <div class="footer">
            <p>WinAutoSentinel - Review your Windows autostart items safely</p>
            <p>Report generated for educational and security review purposes</p>
        </div>
    </div>
</body>
</html>
"@
    $OutputPath = $OutputPath -replace '"',''  # Remove quotes if present
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}
else {
    Write-Host "Scan cancelled or window closed." -ForegroundColor Yellow
}
