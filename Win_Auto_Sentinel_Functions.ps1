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
    # We look in the USBSTOR registry key and parse device names to extract vendor and product information.
    Write-Host "Scanning USB device history..." -ForegroundColor Gray
    try {
        $usbDevices = @()
        $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbStorPath) {
            $devices = Get-ChildItem -Path $usbStorPath -ErrorAction SilentlyContinue
            foreach ($device in $devices) {
                # Parse device name: Disk&Ven_Vendor&Prod_Product&Rev_Revision
                $deviceName = $device.Name.Split('\')[-1]
                if ($deviceName -match 'Disk&Ven_(.*?)&Prod_(.*?)&Rev_(.*)') {
                    $vendor = $matches[1]
                    $product = $matches[2]
                    $revision = $matches[3]
                    $usbDevices += "USB: $vendor $product (Rev: $revision)"
                } else {
                    # Fallback to showing the raw device identifier
                    $usbDevices += "USB: $deviceName"
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
    # For Chrome, we read extension manifest files and resolve localized names; for Firefox, we list extension files.
    Write-Host "Scanning browser extensions..." -ForegroundColor Gray
    try {
        $extensions = @()
        # Chrome extensions
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromePath) {
            $chromeExts = Get-ChildItem -Path $chromePath -Directory -ErrorAction SilentlyContinue
            foreach ($ext in $chromeExts) {
                $versionDir = Get-ChildItem -Path $ext.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($versionDir) {
                    $manifestPath = "$($versionDir.FullName)\manifest.json"
                    if (Test-Path $manifestPath) {
                        $manifest = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($manifest) {
                            $extName = $manifest.name
                            # Resolve localized names
                            if ($extName -like "__MSG_*__") {
                                $msgKey = $extName -replace "__MSG_|__"
                                $localesPath = "$($versionDir.FullName)\_locales"
                                if (Test-Path $localesPath) {
                                    # Try English first, then fallback to any available locale
                                    $enPath = "$localesPath\en\messages.json"
                                    if (Test-Path $enPath) {
                                        $messages = Get-Content -Path $enPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                        if ($messages -and $messages.$msgKey -and $messages.$msgKey.message) {
                                            $extName = $messages.$msgKey.message
                                        }
                                    } else {
                                        # Try any available locale
                                        $localeDirs = Get-ChildItem -Path $localesPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                                        if ($localeDirs) {
                                            $msgPath = "$($localeDirs.FullName)\messages.json"
                                            $messages = Get-Content -Path $msgPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                            if ($messages -and $messages.$msgKey -and $messages.$msgKey.message) {
                                                $extName = $messages.$msgKey.message
                                            }
                                        }
                                    }
                                }
                            }
                            if ($extName) {
                                $extensions += "Chrome: $extName"
                            }
                        }
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
    # NOTE: Requires administrator privileges to access C:\Windows\Prefetch
    Write-Host "Scanning prefetch files..." -ForegroundColor Gray
    try {
        $prefetchPath = "C:\Windows\Prefetch"
        if (Test-Path $prefetchPath) {
            $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -File -ErrorAction SilentlyContinue | Select-Object -First 10
            $summary = $prefetchFiles | ForEach-Object { "Prefetch: $($_.Name)" }
            if ($summary.Count -eq 0) {
                return @("No prefetch files found (may require admin privileges).")
            }
            return $summary
        } else {
            return @("Prefetch directory not found.")
        }
    } catch {
        if ($_.Exception.Message -like "*Access*denied*") {
            return @("Access denied to prefetch directory (requires admin privileges).")
        }
        return @("Error scanning prefetch files: $($_.Exception.Message)")
    }
}

# Unusual services summary
function Get-UnusualServicesSummary {
    # This function looks at Windows services that are running and set to start automatically.
    # Services are background programs; we filter out known legitimate Microsoft and system services to highlight potentially unusual ones.
    # We use a whitelist of known legitimate services and show only services that aren't in this list.
    Write-Host "Scanning for unusual services..." -ForegroundColor Gray
    try {
        # Comprehensive whitelist of legitimate Windows services
        $legitimateServices = @(
            # Core Windows services
            "spooler", "wuauserv", "eventlog", "dns", "dhcp", "lanmanserver", "lanmanworkstation",
            "netlogon", "rpcss", "rpc locator", "winmgmt", "w32time", "schedule", "samss",
            "lsass", "services", "svchost", "system events broker", "security center",
            "windows defender antivirus service", "windows defender firewall",
            "windows security service", "windows update", "bits", "cryptsvc", "trustedinstaller",
            "wscsvc", "sens", "event system", "com+ event system", "com+ system application",
            "distributed link tracking client", "server", "workstation", "tcp/ip netbios helper",
            "dns client", "dhcp client", "network location awareness", "network store interface service",
            "nsi", "ip helper", "ike and authip ipsec keying modules", "ipsec policy agent",
            "windows firewall", "base filtering engine", "windows defender security intelligence service",
            "microsoft defender antivirus service", "security accounts manager", "remote procedure call (rpc)",
            "remote procedure call (rpc) locator", "windows management instrumentation",
            "windows time", "task scheduler", "secondary logon", "application information",
            "application management", "background intelligent transfer service",
            "certificate propagation", "cryptographic services", "dcsvc", "device association service",
            "device install service", "device setup manager", "diagnostic policy service",
            "diagnostic service host", "diagnostic system host", "distributed cache",
            "extensible authentication protocol", "function discovery provider host",
            "function discovery resource publication", "group policy client", "health key and certificate management",
            "human interface device access", "hyper-v guest service interface",
            "hyper-v heartbeat service", "hyper-v data exchange service", "hyper-v time synchronization service",
            "hyper-v power shell direct service", "hyper-v remote desktop virtualization service",
            "hyper-v guest shutdown service", "hyper-v volume shadow copy requestor",
            "internet connection sharing (ics)", "kdc", "ktmrm for distributed transaction coordinator",
            "link-layer topology discovery mapper", "local session manager", "microsoft account sign-in assistant",
            "microsoft passport", "microsoft passport container", "microsoft software shadow copy provider",
            "microsoft storage spaces smp", "net.tcp port sharing service", "netlogon",
            "network access protection agent", "network connections", "network list service",
            "network location awareness 2", "offline files", "peer name resolution protocol",
            "peer networking grouping", "peer networking identity manager", "performance counter dll host",
            "performance logs & alerts", "phone service", "plug and play", "pnp-x device host",
            "pnp-x ip bus enumerator", "portable device enumerator service", "power",
            "print spooler", "problem reports and solutions control panel support",
            "program compatibility assistant service", "quality windows audio video experience",
            "radio management service", "remote access auto connection manager",
            "remote access connection manager", "remote desktop configuration",
            "remote desktop services", "remote desktop services user mode port redirector",
            "remote procedure call (rpc) with authentication", "remote registry",
            "resultant set of policy provider", "routing and remote access", "rpc endpoint mapper",
            "secondary logon", "secure socket tunneling protocol service", "security accounts manager",
            "server", "shell hardware detection", "smart card", "smart card device enumeration service",
            "smart card removal policy", "snmp trap", "software protection", "special administration console helper",
            "spot verifier", "ssdp discovery", "state repository service", "still image acquisition events",
            "storage service", "storage treshold", "superfetch", "sync host", "sysmain",
            "system event notification service", "system events broker", "tablet pc input service",
            "task scheduler", "tcp/ip netbios helper", "telephony", "themes", "thread ordering server",
            "tile data model server", "time broker", "touch keyboard and handwriting panel service",
            "upnp device host", "user access logging service", "user data access", "user data storage",
            "user experience virtualization service", "user manager", "user profile service",
            "virtual disk", "volume shadow copy", "wallet service", "webclient", "webthreatdefsvc",
            "webthreatdefusersvc", "windows activation technologies service", "windows audio",
            "windows audio endpoint builder", "windows backup", "windows biometrics service",
            "windows camera frame server", "windows color system", "windows connection manager",
            "windows defender advanced threat protection service", "windows defender antivirus network inspection service",
            "windows defender firewall", "windows defender security intelligence service",
            "windows device guard", "windows driver foundation - user-mode driver framework",
            "windows encryption provider host service", "windows error reporting service",
            "windows event collector", "windows event log", "windows firewall", "windows font cache service",
            "windows image acquisition (wia)", "windows insider service", "windows license manager service",
            "windows live id sign-in assistant", "windows location framework", "windows management instrumentation",
            "windows media player network sharing service", "windows mobile hotspot service",
            "windows modules installer", "windows push notifications system service",
            "windows push notifications user service", "windows remote management (ws-management)",
            "windows search", "windows security center", "windows security service",
            "windows store service (wservice)", "windows system assessment tool",
            "windows update", "windows update medic service", "winhttp web proxy auto-discovery service",
            "winrm", "wmi performance adapter", "work folders", "workstation", "wwan auto config",
            "xbox accessory management service", "xbox live auth manager", "xbox live game save",
            "xbox live licensing service", "xbox live net auth manager", "xbox live saving",

            # Common third-party services from trusted vendors
            "adobe*", "apple*", "google*", "intel*", "nvidia*", "amd*", "realtek*", "asus*",
            "lenovo*", "dell*", "hp*", "acer*", "toshiba*", "samsung*", "sony*", "panasonic*",
            "vmware*", "virtualbox*", "hyper-v*", "oracle*", "java*", "python*", "nodejs*",
            "steam*", "epic*", "uplay*", "origin*", "battlenet*", "discord*", "teamspeak*",
            "skype*", "zoom*", "webex*", "gotomeeting*", "slack*", "teams*", "outlook*",
            "office*", "onenote*", "excel*", "word*", "powerpoint*", "access*", "publisher*",
            "visio*", "project*", "sharepoint*", "exchange*", "sql*", "mysql*", "postgresql*",
            "mongodb*", "redis*", "elasticsearch*", "kibana*", "logstash*", "beats*",
            "apache*", "nginx*", "iis*", "tomcat*", "jboss*", "wildfly*", "weblogic*",
            "websphere*", "glassfish*", "jetty*", "lighttpd*", "cherokee*", "haproxy*",
            "varnish*", "squid*", "bind*", "dnsmasq*", "unbound*", "powerdns*",
            "dhcpd*", "isc-dhcp*", "freeradius*", "openvpn*", "wireguard*", "strongswan*",
            "pptp*", "l2tp*", "ipsec*", "openssh*", "dropbear*", "putty*", "winscp*",
            "filezilla*", "cyberduck*", "beyondcompare*", "winmerge*", "meld*", "diffmerge*",
            "tortoisesvn*", "tortoisegit*", "git*", "svn*", "mercurial*", "bazaar*",
            "perforce*", "clearcase*", "accurev*", "plasticscm*", "unity*", "unreal*",
            "blender*", "maya*", "3dsmax*", "cinema4d*", "houdini*", "nuke*", "fusion*",
            "aftereffects*", "premiere*", "photoshop*", "illustrator*", "indesign*", "xd*",
            "sketch*", "figma*", "zeplin*", "invision*", "framer*", "principle*", "flinto*",
            "origami*", "form*", "proto*", "marvel*", "uxpin*", "balsamiq*", "axure*",
            "justinmind*", "pidoco*", "mockplus*", "moqups*", "lucidchart*", "drawio*",
            "visio*", "diagrams*", "gliffy*", "cacoo*", "processon*", "edraw*", "smartdraw*",
            "libreoffice*", "openoffice*", "wps*", "kingsoft*", "polaris*", "hancom*",
            "abiword*", "gnumeric*", "calligra*", "scribus*", "gimp*", "krita*", "inkscape*",
            "coreldraw*", "painter*", "photopaint*", "designer*", "xara*", "serif*",
            "adobe*", "autocad*", "solidworks*", "inventor*", "fusion360*", "revit*",
            "sketchup*", "rhino*", "blender*", "maya*", "3dsmax*", "cinema4d*", "houdini*",
            "nuke*", "fusion*", "aftereffects*", "premiere*", "photoshop*", "illustrator*",
            "indesign*", "xd*", "sketch*", "figma*", "zeplin*", "invision*", "framer*",
            "principle*", "flinto*", "origami*", "form*", "proto*", "marvel*", "uxpin*",
            "balsamiq*", "axure*", "justinmind*", "pidoco*", "mockplus*", "moqups*",
            "lucidchart*", "drawio*", "visio*", "diagrams*", "gliffy*", "cacoo*",
            "processon*", "edraw*", "smartdraw*", "libreoffice*", "openoffice*", "wps*",
            "kingsoft*", "polaris*", "hancom*", "abiword*", "gnumeric*", "calligra*",
            "scribus*", "gimp*", "krita*", "inkscape*", "coreldraw*", "painter*",
            "photopaint*", "designer*", "xara*", "serif*", "adobe*", "autocad*",
            "solidworks*", "inventor*", "fusion360*", "revit*", "sketchup*", "rhino*"
        )

        # Get all running automatic services
        $allServices = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.StartType -eq 'Automatic' }

        # Filter out legitimate services
        $unusualServices = $allServices | Where-Object {
            $serviceName = $_.Name.ToLower()
            $displayName = $_.DisplayName.ToLower()
            $isLegitimate = $false

            # Check if service name matches any whitelist pattern
            foreach ($pattern in $legitimateServices) {
                if ($serviceName -like $pattern -or $displayName -like $pattern) {
                    $isLegitimate = $true
                    break
                }
            }

            # Also exclude services that start with common prefixes
            if ($serviceName -like "microsoft*" -or $serviceName -like "windows*" -or
                $serviceName -like "system*" -or $serviceName -like "local*" -or
                $serviceName -like "network*" -or $serviceName -like "user*") {
                $isLegitimate = $true
            }

            -not $isLegitimate
        }

        # Take first 10 unusual services for review
        $services = $unusualServices | Select-Object -First 10
        $summary = $services | ForEach-Object { "Service: $($_.Name) - $($_.DisplayName)" }

        if ($summary.Count -eq 0) {
            return @("No unusual services found.")
        }

        # Add a note about the filtering
        $note = "Note: Filtered out $($allServices.Count - $unusualServices.Count) known legitimate services."
        return @($note) + $summary
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
        <div class="section">
            <div class="section-header" onclick="toggleSection('tips')">
                <strong>Helpful Tips for Reviewing Findings</strong>
            </div>
            <div class="section-content" id="tips">
                <div class="item"><strong>Scheduled Tasks:</strong> Look for tasks with unusual names, unknown publishers, or suspicious commands. Check task triggers and actions.</div>
                <div class="item"><strong>Registry Run Keys:</strong> These run at startup. Verify all entries are from trusted software. Remove unknown entries carefully.</div>
                <div class="item"><strong>Startup Folders:</strong> Files here run when any user logs in. Check file properties and signatures for legitimacy.</div>
                <div class="item"><strong>USB History:</strong> Review device names and connection times. Look for unexpected or suspicious devices.</div>
                <div class="item"><strong>Browser Extensions:</strong> Check extension permissions and publishers. Remove extensions you don't recognize or use.</div>
                <div class="item"><strong>PowerShell History:</strong> Review recent commands for suspicious activity. Clear history if privacy is a concern.</div>
                <div class="item"><strong>Prefetch Files:</strong> These show recently run programs. Look for unknown executables or suspicious file paths.</div>
                <div class="item"><strong>Unusual Services:</strong> Services listed here are not in the known legitimate services database. Research each one.</div>
                <div class="item"><strong>Event Log Entries:</strong> Look for error patterns, security events, or unusual system activity.</div>
                <div class="item"><strong>Hosts File Entries:</strong> Custom entries can redirect traffic. Ensure all entries are legitimate.</div>
                <div class="item"><strong>Firewall Rules:</strong> Review inbound/outbound rules. Unexpected open ports may indicate security risks.</div>
                <div class="item" style="background: #fff3cd;"><strong>General Tips:</strong> Research any unknown findings online before taking action. False positives are possible. Use checkboxes to mark items you've reviewed and recognize.</div>
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

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Output "HTML report saved to: $OutputPath"
    } catch {
        Write-Output "Error saving HTML report: $($_.Exception.Message)"
    }
}

