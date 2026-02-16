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
