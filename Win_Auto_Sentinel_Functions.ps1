# WinAutoSentinel Functions Script
# Contains reusable functions for autostart and persistence review

# Scheduled Tasks summary
function Get-ScheduledTasksSummary {
    # This function scans Windows Scheduled Tasks to show what tasks are set to run automatically.
    # Scheduled tasks can be used by legitimate software (like updates) or potentially by malware to persist.
    # We only look at tasks that are ready or running, and list their names and paths for review.
    Write-Output "Scanning scheduled tasks..."
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
    Write-Output "Scanning registry Run/RunOnce keys..."
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
    Write-Output "Scanning startup folders..."
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
    Write-Output "Scanning USB device history..."
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
    Write-Output "Scanning browser extensions..."
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
    Write-Output "Scanning PowerShell history..."
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
    Write-Output "Scanning prefetch files..."
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
    Write-Output "Scanning for unusual services..."
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
    Write-Output "Scanning event log entries..."
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
    Write-Output "Scanning hosts file entries..."
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
    Write-Output "Scanning firewall rules..."
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
