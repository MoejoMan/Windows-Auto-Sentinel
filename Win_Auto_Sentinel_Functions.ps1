# WinAutoSentinel Functions Script
# Contains reusable functions for autostart and persistence review

# Scheduled Tasks summary
function Get-ScheduledTasksSummary {
    # This function scans Windows Scheduled Tasks to show what tasks are set to run automatically.
    # Scheduled tasks can be used by legitimate software (like updates) or potentially by malware to persist.
    # We only look at tasks that are ready or running, and list their names and paths for review.
    Write-Host "Scanning scheduled tasks..." -ForegroundColor Gray
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | Select-Object -Property TaskName, TaskPath
        $summary = $tasks | ForEach-Object { "Task: $($_.TaskName) ($($_.TaskPath))" }
        if ($summary.Count -eq 0) {
            return @("No scheduled tasks found.")
        }
        return $summary
    } catch {
        return @("Error scanning scheduled tasks: $($_.Exception.Message)")
    }
}

# Registry Run/RunOnce keys summary
function Get-RegistryRunKeysSummary {
    # This function checks the Windows Registry for programs set to run at startup.
    # The Run and RunOnce keys are common places where software adds itself to start automatically.
    # We scan both local machine (system-wide) and current user keys, listing the program names and paths.
    Write-Host "Scanning registry Run/RunOnce keys..." -ForegroundColor Gray
    try {
        $runKeys = @()
        $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
        foreach ($path in $paths) {
            if (Test-Path $path) {
                $properties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                        $runKeys += "$($path.Split(':')[0]): $($prop.Name) - $($prop.Value)"
                    }
                }
            }
        }
        if ($runKeys.Count -eq 0) {
            return @("No registry Run keys found.")
        }
        return $runKeys
    } catch {
        return @("Error scanning registry Run keys: $($_.Exception.Message)")
    }
}

# Startup folders summary
function Get-StartupFoldersSummary {
    # This function looks at the Windows Startup folders where shortcuts can be placed to run programs at login.
    # There are two folders: one for all users (system-wide) and one for the current user.
    # We list any files (usually shortcuts) found in these folders for you to review.
    Write-Host "Scanning startup folders..." -ForegroundColor Gray
    try {
        $startupItems = @()
        $paths = @("$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp")
        foreach ($path in $paths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $startupItems += "Startup: $($file.Name) ($path)"
                }
            }
        }
        if ($startupItems.Count -eq 0) {
            return @("No startup folder items found.")
        }
        return $startupItems
    } catch {
        return @("Error scanning startup folders: $($_.Exception.Message)")
    }
}

# USB device history summary
function Get-USBHistorySummary {
    # This function checks the registry for a history of USB devices that have been connected to the computer.
    # This can help you see what external devices have been plugged in, which might be useful for security review.
    # We look in the USBSTOR registry key and list device friendly names.
    Write-Host "Scanning USB device history..." -ForegroundColor Gray
    try {
        $usbDevices = @()
        $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbStorPath) {
            $devices = Get-ChildItem -Path $usbStorPath -ErrorAction SilentlyContinue
            foreach ($device in $devices) {
                $friendlyName = (Get-ItemProperty -Path $device.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
                if ($friendlyName) {
                    $usbDevices += "USB: $friendlyName"
                }
            }
        }
        if ($usbDevices.Count -eq 0) {
            return @("No USB devices found in history.")
        }
        return $usbDevices
    } catch {
        return @("Error scanning USB history: $($_.Exception.Message)")
    }
}

# Browser extensions summary
function Get-BrowserExtensionsSummary {
    # This function scans for installed browser extensions in Chrome and Firefox.
    # Extensions can add features but sometimes include unwanted or malicious code.
    # For Chrome, we read extension manifest files to get names; for Firefox, we list extension files.
    Write-Host "Scanning browser extensions..." -ForegroundColor Gray
    try {
        $extensions = @()
        # Chrome extensions
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromePath) {
            $chromeExts = Get-ChildItem -Path $chromePath -Directory -ErrorAction SilentlyContinue
            foreach ($ext in $chromeExts) {
                $manifestPath = "$($ext.FullName)\$((Get-ChildItem -Path $ext.FullName -Directory | Select-Object -First 1).Name)\manifest.json"
                if (Test-Path $manifestPath) {
                    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($manifest.name) {
                        $extensions += "Chrome: $($manifest.name)"
                    }
                }
            }
        }
        # Firefox extensions (simplified, as they use XPI files)
        $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxPath) {
            $profiles = Get-ChildItem -Path $firefoxPath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $extensionsPath = "$($profile.FullName)\extensions"
                if (Test-Path $extensionsPath) {
                    $firefoxExts = Get-ChildItem -Path $extensionsPath -File -Filter "*.xpi" -ErrorAction SilentlyContinue
                    foreach ($ext in $firefoxExts) {
                        $extensions += "Firefox: $($ext.BaseName)"
                    }
                }
            }
        }
        if ($extensions.Count -eq 0) {
            return @("No browser extensions found.")
        }
        return $extensions
    } catch {
        return @("Error scanning browser extensions: $($_.Exception.Message)")
    }
}

# PowerShell history summary
function Get-PowerShellHistorySummary {
    # This function checks the PowerShell command history to see recent commands entered.
    # This can show what scripts or commands have been run, which might be useful for review.
    # We read the last 10 lines from the history file.
    Write-Host "Scanning PowerShell history..." -ForegroundColor Gray
    try {
        $historyPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $historyPath) {
            $history = Get-Content -Path $historyPath -Tail 10 -ErrorAction SilentlyContinue
            $summary = $history | ForEach-Object { "PS Command: $_" }
            if ($summary.Count -eq 0) {
                return @("No PowerShell history found.")
            }
            return $summary
        } else {
            return @("PowerShell history file not found.")
        }
    } catch {
        return @("Error scanning PowerShell history: $($_.Exception.Message)")
    }
}

# Prefetch files summary
function Get-PrefetchFilesSummary {
    # This function lists prefetch files, which Windows creates to speed up program loading.
    # Prefetch files can indicate what programs have been run recently.
    # We list the first 10 .pf files from the Prefetch directory.
    Write-Host "Scanning prefetch files..." -ForegroundColor Gray
    try {
        $prefetchPath = "C:\Windows\Prefetch"
        if (Test-Path $prefetchPath) {
            $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -File -ErrorAction SilentlyContinue | Select-Object -First 10
            $summary = $prefetchFiles | ForEach-Object { "Prefetch: $($_.Name)" }
            if ($summary.Count -eq 0) {
                return @("No prefetch files found.")
            }
            return $summary
        } else {
            return @("Prefetch directory not found.")
        }
    } catch {
        return @("Error scanning prefetch files: $($_.Exception.Message)")
    }
}

# Unusual services summary
function Get-UnusualServicesSummary {
    # This function looks at Windows services that are running and set to start automatically.
    # Services are background programs; we filter out Microsoft ones to highlight potentially unusual ones.
    # We list the first 10 non-Microsoft services for review.
    Write-Host "Scanning for unusual services..." -ForegroundColor Gray
    try {
        $services = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.StartType -eq 'Automatic' -and $_.Name -notlike 'Microsoft*' } | Select-Object -First 10
        $summary = $services | ForEach-Object { "Service: $($_.Name) - $($_.DisplayName)" }
        if ($summary.Count -eq 0) {
            return @("No unusual services found.")
        }
        return $summary
    } catch {
        return @("Error scanning services: $($_.Exception.Message)")
    }
}

# Event log entries summary
function Get-EventLogEntriesSummary {
    # This function checks the Windows System event log for recent entries.
    # Event logs record system events, errors, and warnings, which can indicate issues or activity.
    # We show the newest 10 entries with source and a snippet of the message.
    Write-Host "Scanning event log entries..." -ForegroundColor Gray
    try {
        $events = Get-EventLog -LogName System -Newest 10 -ErrorAction SilentlyContinue
        $summary = $events | ForEach-Object { "Event: $($_.Source) - $($_.Message.Substring(0,50))..." }
        if ($summary.Count -eq 0) {
            return @("No event log entries found.")
        }
        return $summary
    } catch {
        return @("Error scanning event logs: $($_.Exception.Message)")
    }
}

# Hosts file entries summary
function Get-HostsFileEntriesSummary {
    # This function reads the Windows hosts file, which maps hostnames to IP addresses.
    # The hosts file can be modified to redirect traffic or block sites.
    # We list non-comment lines that might have custom entries.
    Write-Host "Scanning hosts file entries..." -ForegroundColor Gray
    try {
        $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^#' -and $_.Trim() -ne '' }
            $summary = $hostsContent | ForEach-Object { "Hosts: $_" }
            if ($summary.Count -eq 0) {
                return @("No custom hosts entries found.")
            }
            return $summary
        } else {
            return @("Hosts file not found.")
        }
    } catch {
        return @("Error scanning hosts file: $($_.Exception.Message)")
    }
}

# Firewall rules summary
function Get-FirewallRulesSummary {
    # This function lists enabled Windows Firewall rules.
    # Firewall rules control what network traffic is allowed or blocked.
    # We show the first 10 enabled rules with their names and actions.
    Write-Host "Scanning firewall rules..." -ForegroundColor Gray
    try {
        $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 10
        $summary = $rules | ForEach-Object { "Rule: $($_.DisplayName) - $($_.Action)" }
        if ($summary.Count -eq 0) {
            return @("No enabled firewall rules found.")
        }
        return $summary
    } catch {
        return @("Error scanning firewall rules: $($_.Exception.Message)")
    }
}

# HTML Report Generation
function New-HTMLReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath = "WinAutoSentinel_Report.html"
    )

    # This function generates an interactive HTML report with collapsible sections and review checkboxes.
    # Users can check items they recognize and expand sections to see details.
    # The report is saved to the specified path for easy sharing and offline review.

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
"@

    $html += @"
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
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Computer:</strong> $env:COMPUTERNAME</p>
        </div>
"@

    $sectionId = 0
    foreach ($category in $Results.Keys) {
        $sectionId++
        $html += @"
        <div class="section">
            <div class="section-header" onclick="toggleSection('section$sectionId')">
                <strong>$category</strong> ($($Results[$category].Count) items)
            </div>
            <div class="section-content" id="section$sectionId">
"@

        foreach ($item in $Results[$category]) {
            $html += @"
                <div class="item">
                    <input type="checkbox" class="checkbox" onchange="markRecognized(this)">
                    <span>$item</span>
                </div>
"@
        }

        $html += @"
            </div>
        </div>
"@
    }

    $html += @"
        <div class="footer">
            <p>WinAutoSentinel - Review your Windows autostart items safely</p>
            <p>Report generated for educational and security review purposes</p>
        </div>
    </div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Output "HTML report saved to: $OutputPath"
    } catch {
        Write-Output "Error saving HTML report: $($_.Exception.Message)"
    }
}

