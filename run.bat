@echo off
setlocal EnableDelayedExpansion
title WinAutoSentinel
color 0F
mode con: cols=100 lines=50
REM Set a large scroll buffer so output is scrollable
powershell -NoProfile -Command "$b=$Host.UI.RawUI.BufferSize; $b.Height=9999; $b.Width=100; $Host.UI.RawUI.BufferSize=$b" >nul 2>&1

REM ============================================================================
REM  WinAutoSentinel - One-Click Launcher
REM  Double-click this file or right-click → Run as Administrator
REM ============================================================================

REM --- Navigate to script directory first ---
cd /d "%~dp0"

REM --- Prerequisite Checks ---
call :checkPrereqs
if %errorlevel% neq 0 (
    echo.
    echo  [FAIL] Prerequisites not met. See above for details.
    echo.
    pause
    exit /b 1
)

REM --- Check admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    cls
    echo.
    echo  +--------------------------------------------------------------+
    echo  ^|              WinAutoSentinel needs elevation                 ^|
    echo  ^|                                                              ^|
    echo  ^|   This tool reads system security data that requires         ^|
    echo  ^|   Administrator access for full results.                     ^|
    echo  ^|                                                              ^|
    echo  ^|   A UAC prompt will appear - click Yes to continue.          ^|
    echo  +--------------------------------------------------------------+
    echo.
    echo  Requesting elevation...
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\" %*' -Verb RunAs"
    exit /b
)

REM --- Main Menu ---
:mainMenu
cls
echo.
echo  +--------------------------------------------------------------+
echo  ^|                                                              ^|
echo  ^|          W I N   A U T O   S E N T I N E L                  ^|
echo  ^|                                                              ^|
echo  ^|        Windows Security Scanner + Persistence Reviewer       ^|
echo  ^|                                                              ^|
echo  +--------------------------------------------------------------+
echo  ^|                                                              ^|
echo  ^|   [1]  Web GUI          Interactive dashboard in browser     ^|
echo  ^|                         (recommended for most users)         ^|
echo  ^|                                                              ^|
echo  ^|   [2]  Quick Scan       Browser GUI with top-5 critical     ^|
echo  ^|                         categories pre-selected              ^|
echo  ^|                                                              ^|
echo  ^|   [3]  CLI + Report     Console output + HTML report        ^|
echo  ^|                         (auto-opens in browser when done)    ^|
echo  ^|                                                              ^|
echo  ^|   [4]  Dry Run          Preview what will be scanned        ^|
echo  ^|                         (nothing executed, just a list)      ^|
echo  ^|                                                              ^|
echo  ^|   [5]  Desktop Shortcut Create a shortcut on your Desktop   ^|
echo  ^|                                                              ^|
echo  ^|   [6]  Verify Integrity Check file hashes for tampering     ^|
echo  ^|                                                              ^|
echo  ^|   [0]  Exit                                                  ^|
echo  ^|                                                              ^|
echo  +--------------------------------------------------------------+
echo  ^|  Running as: Administrator  ^|  All data stays on this PC    ^|
echo  +--------------------------------------------------------------+
echo.
set /p "choice=  Select an option [1-6, 0=exit]: "

if "%choice%"=="0" exit /b
if "%choice%"=="1" goto :guiFull
if "%choice%"=="2" goto :guiQuick
if "%choice%"=="3" goto :cliReport
if "%choice%"=="4" goto :dryRun
if "%choice%"=="5" goto :shortcut
if "%choice%"=="6" goto :verify
echo.
echo  Invalid choice. Please enter 1-6 or 0.
timeout /t 2 >nul
goto :mainMenu

REM ============================================================================
REM  Option 1: Full Web GUI
REM ============================================================================
:guiFull
cls
echo.
echo  +--------------------------------------------------------------+
echo  ^|  Starting WinAutoSentinel Web GUI...                        ^|
echo  ^|                                                              ^|
echo  ^|  Your browser will open automatically.                      ^|
echo  ^|  When you're done, click the red "Close WinAutoSentinel"    ^|
echo  ^|  button at the bottom of the page.                          ^|
echo  +--------------------------------------------------------------+
echo.
powershell.exe -ExecutionPolicy Bypass -File "Win_Auto_Sentinel_GUI.ps1"
echo.
echo  +--------------------------------------------------------------+
echo  ^|  WinAutoSentinel has stopped.                               ^|
echo  +--------------------------------------------------------------+
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Option 2: Quick Scan (GUI with top-5 pre-selected)
REM ============================================================================
:guiQuick
cls
echo.
echo  +--------------------------------------------------------------+
echo  ^|  Starting Quick Scan (Web GUI)...                           ^|
echo  ^|                                                              ^|
echo  ^|  Pre-selects: Scheduled Tasks, Registry Run Keys, WMI      ^|
echo  ^|  Persistence, Unusual Services, Defender Exclusions         ^|
echo  ^|                                                              ^|
echo  ^|  Your browser will open automatically.                      ^|
echo  ^|  When done, click "Close WinAutoSentinel" in the browser.   ^|
echo  +--------------------------------------------------------------+
echo.
powershell.exe -ExecutionPolicy Bypass -File "Win_Auto_Sentinel_GUI.ps1" -QuickScan
echo.
echo  +--------------------------------------------------------------+
echo  ^|  WinAutoSentinel has stopped.                               ^|
echo  +--------------------------------------------------------------+
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Option 3: CLI + HTML Report
REM ============================================================================
:cliReport
echo.
echo  +--------------------------------------------------------------+
echo  ^|  Running CLI scan with HTML report generation...            ^|
echo  ^|  (Scroll up to review output after scan completes)          ^|
echo  +--------------------------------------------------------------+
echo.
powershell.exe -ExecutionPolicy Bypass -File "Win_Auto_Sentinel_Main.ps1" -ExportHTML -AutoOpen
echo.
echo  +--------------------------------------------------------------+
echo  ^|  Scan complete! The HTML report should have opened in       ^|
echo  ^|  your browser. Check this folder for the report file.       ^|
echo  +--------------------------------------------------------------+
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Option 4: Dry Run
REM ============================================================================
:dryRun
echo.
echo  +--------------------------------------------------------------+
echo  ^|  DRY RUN - showing what each scan reads (nothing runs)      ^|
echo  ^|  (Scroll up to review output after it completes)            ^|
echo  +--------------------------------------------------------------+
echo.
powershell.exe -ExecutionPolicy Bypass -File "Win_Auto_Sentinel_Main.ps1" -WhatIf
echo.
echo  ==============================================================
echo   That was a dry run. No scans were actually executed.
echo   Remove -WhatIf or choose option 1/3 to perform a real scan.
echo  ==============================================================
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Option 5: Create Desktop Shortcut
REM ============================================================================
:shortcut
cls
echo.
echo  Creating desktop shortcut...
powershell.exe -ExecutionPolicy Bypass -Command ^
    "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut([IO.Path]::Combine($ws.SpecialFolders('Desktop'), 'WinAutoSentinel.lnk')); $sc.TargetPath = '%~f0'; $sc.WorkingDirectory = '%~dp0'; $sc.IconLocation = 'shell32.dll,48'; $sc.Description = 'WinAutoSentinel - Windows Security Scanner'; $sc.Save(); Write-Host '  [OK] Shortcut created on your Desktop!' -ForegroundColor Green"
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Option 6: Verify File Integrity
REM ============================================================================
:verify
cls
echo.
echo  +--------------------------------------------------------------+
echo  ^|  File Integrity Check                                       ^|
echo  ^|  Compare these SHA256 hashes with the official release.     ^|
echo  +--------------------------------------------------------------+
echo.
powershell.exe -ExecutionPolicy Bypass -Command ^
    "Get-FileHash *.ps1,*.txt,*.md,*.bat -Algorithm SHA256 -ErrorAction SilentlyContinue | Format-Table @{N='SHA256';E={$_.Hash};Width=64}, @{N='File';E={Split-Path $_.Path -Leaf}} -AutoSize; Write-Host ''; Write-Host '  Compare these hashes with the ones in SECURITY.md or the GitHub release.' -ForegroundColor Cyan"
echo.
set /p "again=  Return to menu? [Y/n]: "
if /i "!again!"=="n" exit /b
goto :mainMenu

REM ============================================================================
REM  Prerequisite Checks
REM ============================================================================
:checkPrereqs

REM Check PowerShell exists
where powershell.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] PowerShell not found. This tool requires PowerShell 5.1+.
    exit /b 1
)

REM Check PowerShell version is 5.1+
for /f "delims=" %%v in ('powershell.exe -NoProfile -Command "$PSVersionTable.PSVersion.Major"') do set "psver=%%v"
if "!psver!" lss "5" (
    echo  [ERROR] PowerShell !psver! detected. Version 5.1+ is required.
    echo          Windows 10/11 includes PowerShell 5.1 by default.
    exit /b 1
)

REM Check required files exist
set "missing=0"
if not exist "Win_Auto_Sentinel_Functions.ps1" (
    echo  [ERROR] Missing: Win_Auto_Sentinel_Functions.ps1
    set "missing=1"
)
if not exist "Win_Auto_Sentinel_Main.ps1" (
    echo  [ERROR] Missing: Win_Auto_Sentinel_Main.ps1
    set "missing=1"
)
if not exist "Win_Auto_Sentinel_GUI.ps1" (
    echo  [ERROR] Missing: Win_Auto_Sentinel_GUI.ps1
    set "missing=1"
)
if not exist "legitimate_services.txt" (
    echo  [WARN]  Missing: legitimate_services.txt (will use defaults)
)
if "!missing!"=="1" (
    echo.
    echo  Some required files are missing. Make sure all files are in:
    echo  %~dp0
    exit /b 1
)

echo  [OK] Prerequisites met. PowerShell !psver!
exit /b 0
