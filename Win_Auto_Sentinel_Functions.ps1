#Requires -Version 5.1
# WinAutoSentinel Functions Script
# Contains reusable functions for autostart, persistence, and security review
# All functions return [PSCustomObject[]] for structured filtering, sorting, and export

# Load System.Web for HTML encoding (used in report generation)
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ============================================================================
# SHARED CONSTANTS  (single source of truth — used by all scan functions)
# ============================================================================

# LOLBin / living-off-the-land binaries (lowercase for case-insensitive matching)
$script:SuspiciousBinaries = @(
    'powershell','pwsh','cmd','wscript','cscript','mshta',
    'regsvr32','rundll32','certutil','bitsadmin','msiexec',
    'psexec','mimikatz','procdump','nc','ncat'
)

# Same list in uppercase for prefetch-file matching
$script:SuspiciousBinariesUpper = $script:SuspiciousBinaries | ForEach-Object { $_.ToUpper() }

# Directories that should never contain persistent/autostart binaries
$script:SuspiciousDirectories = @(
    "$env:TEMP", "$env:TMP", "$env:APPDATA",
    "$env:APPDATA\Local\Temp",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC"
)

# Trusted install / system directories
$script:TrustedDirectories = @(
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    "$env:windir\System32",
    "$env:windir\SysWOW64",
    "$env:ProgramData\Microsoft\",
    "$env:ProgramFiles\Common Files\",
    "$env:ProgramFiles\WindowsApps\"
)

# Trusted process paths (more specific than TrustedDirectories — includes user-profile apps
# that are legitimately signed, like VS Code and PowerToys)
$script:TrustedProcessPaths = @(
    "$env:windir\System32\WindowsPowerShell\",
    "$env:windir\System32\cmd.exe",
    "$env:windir\System32\msiexec.exe",
    "$env:windir\System32\rundll32.exe",
    "$env:windir\SysWOW64\msiexec.exe",
    "$env:windir\SysWOW64\rundll32.exe",
    "$env:ProgramFiles\WindowsApps\",
    "$env:windir\SystemApps\",
    "$env:LOCALAPPDATA\PowerToys\",
    "$env:LOCALAPPDATA\Microsoft\",
    "$env:LOCALAPPDATA\Programs\Microsoft VS Code\"
)

# Trusted scheduled-task paths (only writable by SYSTEM / TrustedInstaller)
$script:TrustedTaskPaths = @(
    '\Microsoft\Windows\',
    '\Microsoft\Office\',
    '\Microsoft\XblGameSave\',
    '\Microsoft\Windows Defender\',
    '\Microsoft\Configuration Manager\',
    '\Microsoft\VisualStudio\',
    '\Microsoft\.NET\'
)

# Keywords that strongly indicate malicious intent (service display-name check)
$script:MaliciousKeywords = @(
    'hack','crack','keygen','trojan','virus','malware','backdoor',
    'rootkit','exploit','payload','keylogger','spy','inject'
)

# PowerShell history patterns flagged as suspicious
$script:SuspiciousHistoryPatterns = @(
    'Invoke-Expression', 'iex\s', 'IEX\s', 'DownloadString', 'DownloadFile',
    'Net\.WebClient', 'Invoke-WebRequest', 'Start-BitsTransfer',
    'New-Object\s+IO\.MemoryStream', 'FromBase64String', '-enc\s',
    '-EncodedCommand', 'Set-MpPreference', 'Add-MpPreference',
    'reg\s+add', 'schtasks\s+/create', 'sc\.exe\s+create'
)

# Prefetch filenames for standard Windows system binaries — always present on healthy systems
$script:SystemBinariesPrefetch = @(
    'POWERSHELL.EXE','CMD.EXE','RUNDLL32.EXE','MSIEXEC.EXE',
    'REGSVR32.EXE','BITSADMIN.EXE','CERTUTIL.EXE'
)

# ============================================================================
# LOGGING
# ============================================================================

# Module-level log state (callers set $script:LogPath before import or via Enable-WASLog)
$script:LogPath = $null

function Enable-WASLog {
    <#
    .SYNOPSIS
        Enable file logging.  Call once before scans to redirect all Write-WASLog
        output to a timestamped log file alongside the script.
    #>
    param([string]$Path)
    if (-not $Path) {
        $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
        $Path = Join-Path $PSScriptRoot "WinAutoSentinel_$ts.log"
    }
    $script:LogPath = $Path
    Write-WASLog "Log started: $Path"
}

function Write-WASLog {
    <#
    .SYNOPSIS
        Write a timestamped line to both the console (verbose) and the log file
        (if logging has been enabled via Enable-WASLog).
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    if ($script:LogPath) {
        $line | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    }
    # Also emit to verbose stream so -Verbose surfaces it
    Write-Verbose $line
}

# ============================================================================
# HELPER UTILITIES
# ============================================================================

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Returns $true if the current session is elevated (Run as Administrator).
    #>
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TruncatedString {
    <#
    .SYNOPSIS
        Safely truncate a string to a given length, avoiding Substring crashes.
    #>
    param(
        [string]$Text,
        [int]$MaxLength = 120
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = $Text -replace '[\r\n]+', ' '
    if ($clean.Length -le $MaxLength) { return $clean }
    return $clean.Substring(0, $MaxLength) + '...'
}

function Get-FileSignatureStatus {
    <#
    .SYNOPSIS
        Check Authenticode signature of a file path and return a friendly status string.
    #>
    param([string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($FilePath)) { return 'Unknown (no path)' }

    # Strip quotes and arguments from service binary paths like: "C:\...\svc.exe" -arg
    $cleanPath = $FilePath -replace '^"([^"]+)".*', '$1'
    $cleanPath = $cleanPath -replace '\s+[-/].*$', ''
    $cleanPath = $cleanPath.Trim()

    if (-not (Test-Path $cleanPath -ErrorAction SilentlyContinue)) { return 'Unknown (file not found)' }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $cleanPath -ErrorAction Stop
        switch ($sig.Status) {
            'Valid'        { return "Valid ($($sig.SignerCertificate.Subject))" }
            'NotSigned'    { return 'Not Signed' }
            default        { return "$($sig.Status)" }
        }
    } catch {
        return "Error ($($_.Exception.Message))"
    }
}

# ============================================================================
# SCAN: SCHEDULED TASKS
# ============================================================================
function Get-ScheduledTasksSummary {
    <#
    .SYNOPSIS
        Enumerate active (Ready/Running) scheduled tasks with action details and risk hints.
        Uses TaskPath-based trust (Microsoft system tasks) and Authenticode signature
        verification to dramatically reduce false positives while catching real threats.
    #>
    param([int]$Limit = 0)  # 0 = unlimited

    Write-WASLog 'Scanning scheduled tasks'
    Write-Host '  [*] Scanning scheduled tasks...' -ForegroundColor DarkGray
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' }

        # Signature cache to avoid re-checking the same binary multiple times
        $sigCache = @{}

        $results = foreach ($t in $tasks) {
            $actions = ($t.Actions | ForEach-Object {
                if ($_.Execute) { "$($_.Execute) $($_.Arguments)" }
            }) -join '; '

            $author   = if ($t.Author) { $t.Author } else { '' }
            $triggers = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task', '' }) -join ', '
            $taskPath = $t.TaskPath

            # ----- Tier 1: TaskPath-based trust -----
            # Tasks under Microsoft system paths can only be created by SYSTEM-level installers.
            # These are inherently trusted and should not generate noise.
            $isTrustedPath = $false
            foreach ($tp in $script:TrustedTaskPaths) {
                if ($taskPath -like "$tp*") { $isTrustedPath = $true; break }
            }

            if ($isTrustedPath) {
                # Even trusted tasks get High if they phone home to URLs/UNC
                $risk = 'Info'
                if ($actions -match '(https?://|ftp://|\\\\[^\\])') { $risk = 'High' }

                [PSCustomObject]@{
                    Category  = 'Scheduled Tasks'
                    Risk      = $risk
                    TaskName  = $t.TaskName
                    TaskPath  = $taskPath
                    State     = [string]$t.State
                    Author    = $author
                    Actions   = Get-TruncatedString $actions 200
                    Triggers  = $triggers
                }
                continue
            }

            # ----- Tier 2: Non-Microsoft tasks — use Authenticode + heuristics -----
            $risk = 'Info'

            # Resolve the primary executable path for signature checking
            $exePath = $null
            if ($t.Actions.Count -gt 0 -and $t.Actions[0].Execute) {
                $rawExe = $t.Actions[0].Execute -replace '^"([^"]+)".*', '$1'
                $rawExe = $rawExe.Trim()
                # Resolve environment variables (e.g. %windir%)
                $rawExe = [Environment]::ExpandEnvironmentVariables($rawExe)
                if (Test-Path $rawExe -ErrorAction SilentlyContinue) { $exePath = $rawExe }
            }

            # Check Authenticode signature (cached)
            $sigStatus = 'Unknown'
            $sigSigner = ''
            if ($exePath) {
                if ($sigCache.ContainsKey($exePath)) {
                    $sigStatus = $sigCache[$exePath].Status
                    $sigSigner = $sigCache[$exePath].Signer
                } else {
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction Stop
                        $sigStatus = [string]$sig.Status
                        if ($sig.SignerCertificate) { $sigSigner = $sig.SignerCertificate.Subject }
                        $sigCache[$exePath] = @{ Status = $sigStatus; Signer = $sigSigner }
                    } catch {
                        $sigCache[$exePath] = @{ Status = 'Error'; Signer = '' }
                    }
                }
            }

            $isSigned = ($sigStatus -eq 'Valid')

            # Check for suspicious (LOLBin) binaries
            $hasSuspiciousBin = $false
            foreach ($s in $script:SuspiciousBinaries) {
                if ($actions -match [regex]::Escape($s)) { $hasSuspiciousBin = $true; break }
            }

            # Check for network callouts (URL/UNC paths in actions)
            $hasNetworkCallout = ($actions -match '(https?://|ftp://|\\\\[^\\])')

            # Check for suspicious directories
            $inSuspiciousDir = $false
            foreach ($d in $script:SuspiciousDirectories) {
                if ($actions -like "*$d*") { $inSuspiciousDir = $true; break }
            }

            # Risk scoring matrix
            if ($hasNetworkCallout) {
                $risk = 'High'
            } elseif ($inSuspiciousDir -and -not $isSigned) {
                $risk = 'High'
            } elseif ($hasSuspiciousBin -and -not $isSigned) {
                $risk = 'Medium'
            } elseif (-not $isSigned -and [string]::IsNullOrWhiteSpace($author)) {
                # Unsigned with no author — mildly suspicious
                $risk = 'Low'
            } elseif ($hasSuspiciousBin -and $isSigned) {
                # Signed + LOLBin (e.g. legitimate tool using rundll32) — informational note
                $risk = 'Info'
            }

            [PSCustomObject]@{
                Category  = 'Scheduled Tasks'
                Risk      = $risk
                TaskName  = $t.TaskName
                TaskPath  = $taskPath
                State     = [string]$t.State
                Author    = $author
                Actions   = Get-TruncatedString $actions 200
                Triggers  = $triggers
            }
        }

        if ($Limit -gt 0) { $results = $results | Select-Object -First $Limit }
        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Scheduled tasks scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: REGISTRY RUN / RUNONCE KEYS
# ============================================================================
function Get-RegistryRunKeysSummary {
    <#
    .SYNOPSIS
        Check HKLM and HKCU Run/RunOnce keys for autostart entries.
        Also checks WOW6432Node for 32-bit entries on 64-bit systems.
    #>
    Write-Host '  [*] Scanning registry Run/RunOnce keys...' -ForegroundColor DarkGray
    try {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            # WOW64 keys (32-bit on 64-bit)
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )

        $skipProps = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')

        $results = foreach ($path in $paths) {
            if (-not (Test-Path $path)) { continue }
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in $skipProps) { continue }

                $hive  = if ($path -like 'HKLM*') { 'HKLM' } else { 'HKCU' }
                $value = [string]$p.Value

                # Risk heuristic
                $risk = 'Info'
                $lowerVal = $value.ToLower()
                if ($lowerVal -match 'powershell|cmd\.exe|wscript|cscript|mshta') { $risk = 'Medium' }
                if ($lowerVal -match 'temp|tmp|appdata\\local\\temp') { $risk = 'High' }
                if ($path -like '*RunOnce*' -and $risk -eq 'Info') { $risk = 'Low' }

                $sig = Get-FileSignatureStatus $value

                [PSCustomObject]@{
                    Category     = 'Registry Run Keys'
                    Risk         = $risk
                    Hive         = $hive
                    KeyPath      = $path
                    EntryName    = $p.Name
                    Value        = Get-TruncatedString $value 300
                    Signature    = $sig
                }
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Registry Run keys scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: STARTUP FOLDERS
# ============================================================================
function Get-StartupFoldersSummary {
    <#
    .SYNOPSIS
        List files in per-user and all-users Startup folders with signature checks.
    #>
    Write-Host '  [*] Scanning startup folders...' -ForegroundColor DarkGray
    try {
        $folders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp",
            "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp"
        )

        $results = foreach ($folder in $folders) {
            if (-not (Test-Path $folder)) { continue }
            $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $scope = if ($folder -like "*$env:APPDATA*") { 'Current User' } else { 'All Users' }
                $sig   = Get-FileSignatureStatus $f.FullName

                $risk = 'Info'
                if ($f.Extension -in @('.vbs','.js','.bat','.cmd','.ps1','.wsf')) { $risk = 'Medium' }
                if ($sig -eq 'Not Signed') { $risk = 'Low' }

                [PSCustomObject]@{
                    Category    = 'Startup Folders'
                    Risk        = $risk
                    FileName    = $f.Name
                    FullPath    = $f.FullName
                    Scope       = $scope
                    Extension   = $f.Extension
                    Size        = $f.Length
                    LastWritten = $f.LastWriteTime
                    Signature   = $sig
                }
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Startup folders scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: USB DEVICE HISTORY
# ============================================================================
function Get-USBHistorySummary {
    <#
    .SYNOPSIS
        Parse USBSTOR registry key for historically connected USB storage devices.
        Extracts vendor, product, revision, serial, and friendly name.
    #>
    Write-Host '  [*] Scanning USB device history...' -ForegroundColor DarkGray
    try {
        $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (-not (Test-Path $usbStorPath)) { return @() }

        $results = foreach ($device in (Get-ChildItem -Path $usbStorPath -ErrorAction SilentlyContinue)) {
            $deviceName = $device.PSChildName
            $vendor = ''; $product = ''; $revision = ''

            if ($deviceName -match 'Disk&Ven_(.*?)&Prod_(.*?)&Rev_(.*)') {
                $vendor   = $Matches[1] -replace '_', ' '
                $product  = $Matches[2] -replace '_', ' '
                $revision = $Matches[3]
            }

            # Get serial number instances
            $instances = Get-ChildItem -Path $device.PSPath -ErrorAction SilentlyContinue
            foreach ($inst in $instances) {
                $friendlyName = (Get-ItemProperty -Path $inst.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
                $serial = $inst.PSChildName

                [PSCustomObject]@{
                    Category     = 'USB Device History'
                    Risk         = 'Info'
                    Vendor       = $vendor
                    Product      = $product
                    Revision     = $revision
                    SerialNumber = $serial
                    FriendlyName = if ($friendlyName) { $friendlyName } else { "$vendor $product" }
                }
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  USB history scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: BROWSER EXTENSIONS (Chrome, Edge, Firefox)
# ============================================================================
function Get-BrowserExtensionsSummary {
    <#
    .SYNOPSIS
        Enumerate installed browser extensions for Chrome, Edge, and Firefox.
        Resolves localised names via _locales and reads addon metadata for Firefox.
    #>
    Write-Host '  [*] Scanning browser extensions...' -ForegroundColor DarkGray
    try {
        $results = [System.Collections.ArrayList]::new()

        # --- Helper: resolve Chrome/Edge manifest name ---
        $resolveManifestName = {
            param($manifest, $versionDir)
            $name = $manifest.name
            if ($name -like '__MSG_*__') {
                $msgKey = ($name -replace '__MSG_|__', '').Trim()
                $localesPath = Join-Path $versionDir '_locales'
                $candidates  = @(
                    (Join-Path $localesPath 'en\messages.json'),
                    (Join-Path $localesPath 'en_US\messages.json')
                )
                # Also try first available locale
                if (Test-Path $localesPath) {
                    $first = Get-ChildItem $localesPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($first) { $candidates += Join-Path $first.FullName 'messages.json' }
                }
                foreach ($c in $candidates) {
                    if (Test-Path $c) {
                        $msgs = Get-Content $c -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($msgs.$msgKey.message) { $name = $msgs.$msgKey.message; break }
                        # Case-insensitive fallback
                        $found = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $msgKey } | Select-Object -First 1
                        if ($found.Value.message) { $name = $found.Value.message; break }
                    }
                }
            }
            return $name
        }

        # --- Chromium-based browsers (Chrome & Edge) ---
        $chromiumBrowsers = @(
            @{ Name = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
            @{ Name = 'Edge';   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
        )

        foreach ($browser in $chromiumBrowsers) {
            if (-not (Test-Path $browser.Path)) { continue }
            # Scan all profiles (Default, Profile 1, Profile 2, etc.)
            $profiles = Get-ChildItem -Path $browser.Path -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' }

            foreach ($profile in $profiles) {
                $extDir = Join-Path $profile.FullName 'Extensions'
                if (-not (Test-Path $extDir)) { continue }

                foreach ($ext in (Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue)) {
                    $verDir = Get-ChildItem $ext.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (-not $verDir) { continue }
                    $manifestPath = Join-Path $verDir.FullName 'manifest.json'
                    if (-not (Test-Path $manifestPath)) { continue }

                    $manifest = Get-Content $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if (-not $manifest) { continue }

                    $extName    = & $resolveManifestName $manifest $verDir.FullName
                    $version    = $manifest.version
                    $perms      = ($manifest.permissions -join ', ')
                    $hostPerms  = if ($manifest.host_permissions) { ($manifest.host_permissions -join ', ') } else { '' }

                    $risk = 'Info'
                    if ($perms -match '<all_urls>|tabs|webRequest|cookies|management') { $risk = 'Low' }
                    if ($perms -match 'nativeMessaging|debugger|proxy') { $risk = 'Medium' }

                    [void]$results.Add([PSCustomObject]@{
                        Category        = 'Browser Extensions'
                        Risk            = $risk
                        Browser         = $browser.Name
                        Profile         = $profile.Name
                        ExtensionName   = if ($extName) { $extName } else { $ext.Name }
                        ExtensionId     = $ext.Name
                        Version         = $version
                        Permissions     = Get-TruncatedString $perms 200
                        HostPermissions = Get-TruncatedString $hostPerms 200
                    })
                }
            }
        }

        # --- Firefox ---
        $ffProfileRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $ffProfileRoot) {
            foreach ($profile in (Get-ChildItem $ffProfileRoot -Directory -ErrorAction SilentlyContinue)) {
                # extensions.json has the best metadata
                $extJsonPath = Join-Path $profile.FullName 'extensions.json'
                if (Test-Path $extJsonPath) {
                    try {
                        $extData = Get-Content $extJsonPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                        foreach ($addon in $extData.addons) {
                            if ($addon.type -ne 'extension') { continue }
                            $risk = 'Info'
                            $perms = ($addon.userPermissions.permissions -join ', ')
                            if ($perms -match '<all_urls>|tabs|webRequest|cookies') { $risk = 'Low' }

                            [void]$results.Add([PSCustomObject]@{
                                Category        = 'Browser Extensions'
                                Risk            = $risk
                                Browser         = 'Firefox'
                                Profile         = $profile.Name
                                ExtensionName   = if ($addon.defaultLocale.name) { $addon.defaultLocale.name } else { $addon.id }
                                ExtensionId     = $addon.id
                                Version         = $addon.version
                                Permissions     = Get-TruncatedString $perms 200
                                HostPermissions = ''
                            })
                        }
                    } catch { }
                } else {
                    # Fallback: list XPI files
                    $extDir = Join-Path $profile.FullName 'extensions'
                    if (Test-Path $extDir) {
                        foreach ($xpi in (Get-ChildItem $extDir -File -Filter '*.xpi' -ErrorAction SilentlyContinue)) {
                            [void]$results.Add([PSCustomObject]@{
                                Category        = 'Browser Extensions'
                                Risk            = 'Low'
                                Browser         = 'Firefox'
                                Profile         = $profile.Name
                                ExtensionName   = $xpi.BaseName
                                ExtensionId     = $xpi.BaseName
                                Version         = ''
                                Permissions     = ''
                                HostPermissions = ''
                            })
                        }
                    }
                }
            }
        }

        if ($results.Count -eq 0) { return @() }
        return $results.ToArray()
    } catch {
        Write-Warning "  Browser extensions scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: POWERSHELL HISTORY
# ============================================================================
function Get-PowerShellHistorySummary {
    <#
    .SYNOPSIS
        Read the PSReadLine history file for recent commands. Flag suspicious patterns.
    #>
    param([int]$Lines = 50)

    Write-Host '  [*] Scanning PowerShell history...' -ForegroundColor DarkGray
    try {
        $historyPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
        if (-not $historyPath -or -not (Test-Path $historyPath)) { return @() }

        $history = Get-Content -Path $historyPath -Tail $Lines -ErrorAction SilentlyContinue
        if (-not $history) { return @() }

        $pattern = ($script:SuspiciousHistoryPatterns -join '|')

        $allLines = Get-Content $historyPath -ErrorAction SilentlyContinue
        $totalLines = if ($allLines) { $allLines.Count } else { 0 }
        $startLine = [Math]::Max(0, $totalLines - $Lines)

        $lineNum = $startLine
        $results = foreach ($cmd in $history) {
            $lineNum++
            $risk = 'Info'
            if ($cmd -match $pattern) { $risk = 'High' }

            [PSCustomObject]@{
                Category   = 'PowerShell History'
                Risk       = $risk
                LineNumber = $lineNum
                Command    = Get-TruncatedString $cmd 300
            }
        }

        return $results
    } catch {
        Write-Warning "  PowerShell history scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: PREFETCH FILES
# ============================================================================
function Get-PrefetchFilesSummary {
    <#
    .SYNOPSIS
        List prefetch files showing recently executed programs. Requires admin.
    #>
    param([int]$Limit = 50)

    Write-Host '  [*] Scanning prefetch files...' -ForegroundColor DarkGray
    if (-not (Test-IsAdministrator)) {
        Write-Host '      (skipped - requires admin privileges)' -ForegroundColor DarkYellow
        return @()
    }
    try {
        $pfPath = "$env:windir\Prefetch"
        if (-not (Test-Path $pfPath)) { return @() }

        $files = Get-ChildItem -Path $pfPath -Filter '*.pf' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $Limit

        $suspiciousExes = $script:SuspiciousBinariesUpper
        $systemBinariesPrefetch = $script:SystemBinariesPrefetch

        $results = foreach ($f in $files) {
            $exeName = ($f.BaseName -replace '-[A-F0-9]+$', '')
            $risk = 'Info'

            # Skip system binaries that are expected in prefetch on every Windows machine
            if ($exeName -in $systemBinariesPrefetch) { $risk = 'Info' }
            else {
                foreach ($s in $suspiciousExes) {
                    if ($exeName -like "*$s*") { $risk = 'Medium'; break }
                }
            }

            [PSCustomObject]@{
                Category       = 'Prefetch Files'
                Risk           = $risk
                FileName       = $f.Name
                ExecutableName = $exeName
                LastRun        = $f.LastWriteTime
                Size           = $f.Length
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Prefetch scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: UNUSUAL SERVICES (uses Get-CimInstance, not deprecated Get-WmiObject)
# ============================================================================
function Get-UnusualServicesSummary {
    <#
    .SYNOPSIS
        Identify running automatic services that are not whitelisted, not in trusted
        paths, or not digitally signed. Uses actual Authenticode signature verification.
    #>
    Write-Host '  [*] Scanning services...' -ForegroundColor DarkGray
    try {
        # Load whitelist
        $whitelistPath = Join-Path $PSScriptRoot 'legitimate_services.txt'
        $patterns = @()
        if (Test-Path $whitelistPath) {
            $patterns = Get-Content $whitelistPath -ErrorAction SilentlyContinue |
                Where-Object { $_ -and -not $_.Trim().StartsWith('#') } |
                ForEach-Object { $_.Trim().ToLower() }
        }
        if ($patterns.Count -eq 0) {
            $patterns = @('microsoft*','windows*','system*','local*','network*','user*')
        }

        # Use Get-CimInstance instead of deprecated Get-WmiObject
        $allServices = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.State -eq 'Running' -and $_.StartMode -eq 'Auto' }

        $results = foreach ($svc in $allServices) {
            $svcNameLower    = $svc.Name.ToLower()
            $displayLower    = $svc.DisplayName.ToLower()
            $binaryPath      = $svc.PathName
            $reasons         = [System.Collections.ArrayList]::new()

            # --- Whitelist check ---
            $whitelisted = $false
            foreach ($p in $patterns) {
                if ($svcNameLower -like $p -or $displayLower -like $p) { $whitelisted = $true; break }
            }
            if (-not $whitelisted) { [void]$reasons.Add('Not whitelisted') }

            # --- Path check ---
            $inSuspiciousPath = $false
            foreach ($d in $script:SuspiciousDirectories) {
                if ($binaryPath -like "*$d*") { $inSuspiciousPath = $true; [void]$reasons.Add("Suspicious path"); break }
            }

            $inTrustedPath = $false
            foreach ($d in $script:TrustedDirectories) {
                if ($binaryPath -like "$d*" -or $binaryPath -like "*$d*") { $inTrustedPath = $true; break }
            }
            if (-not $inTrustedPath -and -not $whitelisted) {
                [void]$reasons.Add('Untrusted install path')
            }

            # --- Actual signature verification ---
            $sig = Get-FileSignatureStatus $binaryPath
            $sigValid = ($sig -like 'Valid*')
            if (-not $sigValid -and -not $whitelisted) {
                [void]$reasons.Add("Signature: $sig")
            }

            # --- Suspicious keywords in display name ---
            # Skip keyword check for Microsoft-signed services (prevents 'Antivirus' false positive)
            $isMicrosoftSigned = ($sig -like 'Valid*Microsoft*')
            if (-not $isMicrosoftSigned) {
                foreach ($w in $script:MaliciousKeywords) {
                    if ($displayLower -like "*$w*") {
                        [void]$reasons.Add("Suspicious keyword: $w")
                        break
                    }
                }
            }

            # Skip if nothing flagged
            if ($reasons.Count -eq 0) { continue }

            # Risk scoring
            $risk = 'Low'
            if ($reasons.Count -ge 2 -and -not $isMicrosoftSigned) { $risk = 'Medium' }
            if ($isMicrosoftSigned -and -not $inSuspiciousPath) { $risk = 'Low' }
            if ($inSuspiciousPath)     { $risk = 'High' }
            if ($reasons -match 'Suspicious keyword') { $risk = 'Critical' }

            [PSCustomObject]@{
                Category    = 'Unusual Services'
                Risk        = $risk
                ServiceName = $svc.Name
                DisplayName = $svc.DisplayName
                BinaryPath  = Get-TruncatedString $binaryPath 250
                StartMode   = $svc.StartMode
                Signature   = $sig
                Reasons     = ($reasons -join '; ')
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Services scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: EVENT LOG ENTRIES (uses Get-WinEvent, not deprecated Get-EventLog)
# ============================================================================
function Get-EventLogEntriesSummary {
    <#
    .SYNOPSIS
        Pull recent noteworthy events from Security, System, and Application logs.
        Focuses on logon failures, service installs, policy changes, errors.
    #>
    param([int]$Hours = 24, [int]$MaxPerLog = 25)

    Write-Host '  [*] Scanning event logs...' -ForegroundColor DarkGray
    try {
        $cutoff = (Get-Date).AddHours(-$Hours)
        $results = [System.Collections.ArrayList]::new()

        # Security: logon failures (4625), account lockouts (4740), privilege use (4672, 4673),
        #           account creation (4720), account deletion (4726), group changes (4732, 4733)
        $securityIds = @(4625, 4740, 4672, 4673, 4720, 4726, 4732, 4733)
        try {
            $filter = @{ LogName = 'Security'; Id = $securityIds; StartTime = $cutoff }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerLog -ErrorAction SilentlyContinue
            foreach ($e in $events) {
                $risk = 'Info'
                if ($e.Id -in @(4625, 4740)) { $risk = 'Medium' }
                if ($e.Id -in @(4720, 4726)) { $risk = 'High' }

                [void]$results.Add([PSCustomObject]@{
                    Category    = 'Event Log Entries'
                    Risk        = $risk
                    LogName     = 'Security'
                    EventId     = $e.Id
                    TimeCreated = $e.TimeCreated
                    Source      = $e.ProviderName
                    Message     = Get-TruncatedString $e.Message 200
                })
            }
        } catch { }

        # System: service installs (7045), unexpected shutdowns (6008), errors/warnings
        try {
            $filter = @{ LogName = 'System'; Level = @(1,2,3); StartTime = $cutoff }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerLog -ErrorAction SilentlyContinue
            foreach ($e in $events) {
                $risk = 'Info'
                if ($e.Level -le 2) { $risk = 'Medium' }
                if ($e.Id -eq 7045) { $risk = 'High' }

                [void]$results.Add([PSCustomObject]@{
                    Category    = 'Event Log Entries'
                    Risk        = $risk
                    LogName     = 'System'
                    EventId     = $e.Id
                    TimeCreated = $e.TimeCreated
                    Source      = $e.ProviderName
                    Message     = Get-TruncatedString $e.Message 200
                })
            }
        } catch { }

        # Application: errors and warnings
        try {
            $filter = @{ LogName = 'Application'; Level = @(1,2,3); StartTime = $cutoff }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerLog -ErrorAction SilentlyContinue
            foreach ($e in $events) {
                [void]$results.Add([PSCustomObject]@{
                    Category    = 'Event Log Entries'
                    Risk        = 'Info'
                    LogName     = 'Application'
                    EventId     = $e.Id
                    TimeCreated = $e.TimeCreated
                    Source      = $e.ProviderName
                    Message     = Get-TruncatedString $e.Message 200
                })
            }
        } catch { }

        if ($results.Count -eq 0) { return @() }
        return $results.ToArray()
    } catch {
        Write-Warning "  Event log scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: HOSTS FILE
# ============================================================================
function Get-HostsFileEntriesSummary {
    <#
    .SYNOPSIS
        Parse the hosts file for non-default entries that may redirect traffic.
    #>
    Write-Host '  [*] Scanning hosts file...' -ForegroundColor DarkGray
    try {
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        if (-not (Test-Path $hostsPath)) { return @() }

        $lines = Get-Content $hostsPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }

        $results = foreach ($line in $lines) {
            $parts = $line.Trim() -split '\s+', 2
            $ip    = if ($parts[0]) { $parts[0] } else { '' }
            $hostEntry = if ($parts.Count -gt 1) { $parts[1] } else { '' }

            $risk = 'Info'
            if ($ip -ne '127.0.0.1' -and $ip -ne '::1' -and $ip -ne '0.0.0.0') { $risk = 'Medium' }
            if ($hostEntry -match 'microsoft|windows|google|bank|paypal') { $risk = 'High' }

            [PSCustomObject]@{
                Category  = 'Hosts File'
                Risk      = $risk
                IPAddress = $ip
                Hostname  = $hostEntry
                RawLine   = $line.Trim()
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Hosts file scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: FIREWALL RULES
# ============================================================================
function Get-FirewallRulesSummary {
    <#
    .SYNOPSIS
        List enabled firewall rules with port, address, and application filters.
        Focuses on inbound Allow rules which are higher risk.
    #>
    param([int]$Limit = 50)

    Write-Host '  [*] Scanning firewall rules...' -ForegroundColor DarkGray
    try {
        $rules = Get-NetFirewallRule -Enabled True -ErrorAction Stop

        # Batch-fetch all filters once (avoids per-rule CIM queries which are extremely slow)
        $portFilters = @{}
        Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object {
            $portFilters[$_.InstanceID] = $_
        }
        $addrFilters = @{}
        Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue | ForEach-Object {
            $addrFilters[$_.InstanceID] = $_
        }
        $appFilters = @{}
        Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object {
            $appFilters[$_.InstanceID] = $_
        }

        $results = foreach ($r in $rules) {
            $risk = 'Info'
            if ($r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow') { $risk = 'Low' }

            # Trust built-in Windows firewall rules — they ship with the OS and are managed
            # by Windows components. Identified by: Group property contains a resource string
            # reference (starts with @) which only Microsoft-shipped rules have, OR the
            # DisplayName matches well-known standard Windows rule patterns.
            $isBuiltInRule = $false
            if ($r.Group -like '@*') {
                # Resource string reference (e.g. @FirewallAPI.dll,-28502) = OS-shipped rule
                $isBuiltInRule = $true
            }
            if (-not $isBuiltInRule) {
                $builtInPatterns = @('Core Networking*','Wi-Fi Direct*','Remote Assistance*',
                                     'Windows Remote Management*','File and Printer Sharing*',
                                     'Network Discovery*','mDNS*','Delivery Optimization*',
                                     'Connected Devices Platform*','AllJoyn Router*',
                                     'Cast to Device*','DIAL protocol server*',
                                     'Proximity sharing*','Wireless Display*',
                                     'BranchCache*','Hyper-V*')
                foreach ($bp in $builtInPatterns) {
                    if ($r.DisplayName -like $bp) { $isBuiltInRule = $true; break }
                }
            }
            if ($isBuiltInRule) { $risk = 'Info' }

            # Look up filters by matching InstanceID
            $ruleId     = $r.InstanceID
            $portFilter = $portFilters[$ruleId]
            $addrFilter = $addrFilters[$ruleId]
            $appFilter  = $appFilters[$ruleId]

            $localPort  = if ($portFilter.LocalPort)  { $portFilter.LocalPort -join ',' }  else { 'Any' }
            $remoteAddr = if ($addrFilter.RemoteAddress) { ($addrFilter.RemoteAddress | Select-Object -First 3) -join ',' } else { 'Any' }
            $appPath    = if ($appFilter.Program -and $appFilter.Program -ne 'Any') { $appFilter.Program } else { '' }

            # Elevate risk for broad inbound allows (but not built-in Windows rules)
            if (-not $isBuiltInRule -and $risk -eq 'Low' -and $localPort -eq 'Any' -and $remoteAddr -eq 'Any') { $risk = 'Medium' }

            [PSCustomObject]@{
                Category      = 'Firewall Rules'
                Risk          = $risk
                DisplayName   = $r.DisplayName
                Direction     = [string]$r.Direction
                Action        = [string]$r.Action
                Protocol      = if ($portFilter.Protocol) { $portFilter.Protocol } else { 'Any' }
                LocalPort     = $localPort
                RemoteAddress = $remoteAddr
                Application   = Get-TruncatedString $appPath 150
                Profile       = [string]$r.Profile
            }
        }

        if ($Limit -gt 0) { $results = $results | Select-Object -First $Limit }
        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Firewall rules scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: RUNNING PROCESSES  [NEW]
# ============================================================================
function Get-RunningProcessesSummary {
    <#
    .SYNOPSIS
        Enumerate running processes with path and command line info.
        Flags processes running from unusual locations or with suspicious names.
    #>
    Write-Host '  [*] Scanning running processes...' -ForegroundColor DarkGray
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop

        $suspiciousNames = $script:SuspiciousBinaries
        $trustedProcessPaths = $script:TrustedProcessPaths

        $results = foreach ($p in $procs) {
            if (-not $p.ExecutablePath) { continue }

            $name = $p.Name.ToLower()
            $path = $p.ExecutablePath

            # Skip processes in known-good paths
            $isTrustedPath = $false
            foreach ($tp in $trustedProcessPaths) {
                if ($path -like "$tp*" -or $path -like "*$tp*") { $isTrustedPath = $true; break }
            }
            if ($isTrustedPath) { continue }

            $risk = 'Info'
            foreach ($s in $suspiciousNames) {
                if ($name -like "*$s*") { $risk = 'Medium'; break }
            }
            foreach ($d in $script:SuspiciousDirectories) {
                if ($path -like "$d*") { $risk = 'High'; break }
            }

            # Only return flagged processes to keep output manageable
            if ($risk -eq 'Info') { continue }

            $parentName = ''
            try {
                $parent = Get-Process -Id $p.ParentProcessId -ErrorAction SilentlyContinue
                if ($parent) { $parentName = $parent.Name }
            } catch { }

            [PSCustomObject]@{
                Category       = 'Running Processes'
                Risk           = $risk
                ProcessName    = $p.Name
                PID            = $p.ProcessId
                ParentPID      = $p.ParentProcessId
                ParentName     = $parentName
                ExecutablePath = Get-TruncatedString $path 250
                CommandLine    = Get-TruncatedString $p.CommandLine 300
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Process scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: NETWORK CONNECTIONS  [NEW]
# ============================================================================
function Get-NetworkConnectionsSummary {
    <#
    .SYNOPSIS
        List established and listening TCP connections with process mapping.
        Flags external connections and broadly listening services.
    #>
    Write-Host '  [*] Scanning network connections...' -ForegroundColor DarkGray
    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' }

        $results = foreach ($c in $connections) {
            $procName = ''
            try {
                $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                if ($proc) { $procName = $proc.Name }
            } catch { }

            $remote = $c.RemoteAddress
            $risk = 'Info'

            if ($c.State -eq 'Established' -and
                $remote -ne '127.0.0.1' -and $remote -ne '::1' -and $remote -ne '0.0.0.0') {
                $risk = 'Low'
            }

            if ($c.State -eq 'Listen' -and
                ($c.LocalAddress -eq '0.0.0.0' -or $c.LocalAddress -eq '::') -and
                $c.LocalPort -gt 1024) {
                $risk = 'Low'
            }

            [PSCustomObject]@{
                Category      = 'Network Connections'
                Risk          = $risk
                State         = [string]$c.State
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $remote
                RemotePort    = $c.RemotePort
                ProcessName   = $procName
                PID           = $c.OwningProcess
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  Network connections scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: WMI EVENT SUBSCRIPTIONS  [NEW - critical persistence vector]
# ============================================================================
function Get-WMIPersistenceSummary {
    <#
    .SYNOPSIS
        Detect WMI event subscription persistence (filters, consumers, bindings).
        This is one of the most common fileless persistence mechanisms used by
        advanced malware and threat actors.
    #>
    Write-Host '  [*] Scanning WMI event subscriptions...' -ForegroundColor DarkGray
    try {
        $results = [System.Collections.ArrayList]::new()

        # Known built-in WMI subscriptions (Windows default)
        $knownBuiltIn = @(
            'SCM Event Log Filter',
            'BVTFilter',
            'TSLogonFilter',
            'TSLogonEvents.vbs'
        )

        # Event Filters
        $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue
        foreach ($f in $filters) {
            $isBuiltIn = $f.Name -in $knownBuiltIn
            [void]$results.Add([PSCustomObject]@{
                Category   = 'WMI Persistence'
                Risk       = if ($isBuiltIn) { 'Info' } else { 'High' }
                Type       = 'EventFilter'
                Name       = $f.Name
                Detail     = Get-TruncatedString $f.Query 300
                CreatorSID = if ($f.CreatorSID) { ($f.CreatorSID -join '-') } else { '' }
            })
        }

        # CommandLine Event Consumers
        $consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue
        foreach ($c in $consumers) {
            [void]$results.Add([PSCustomObject]@{
                Category   = 'WMI Persistence'
                Risk       = 'Critical'
                Type       = 'CommandLineConsumer'
                Name       = $c.Name
                Detail     = Get-TruncatedString "$($c.ExecutablePath) $($c.CommandLineTemplate)" 300
                CreatorSID = ''
            })
        }

        # ActiveScript Event Consumers
        $scriptConsumers = Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue
        foreach ($s in $scriptConsumers) {
            [void]$results.Add([PSCustomObject]@{
                Category   = 'WMI Persistence'
                Risk       = 'Critical'
                Type       = 'ActiveScriptConsumer'
                Name       = $s.Name
                Detail     = Get-TruncatedString $s.ScriptText 300
                CreatorSID = ''
            })
        }

        # Filter-to-Consumer Bindings
        $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
        foreach ($b in $bindings) {
            $detail = Get-TruncatedString "$($b.Filter) -> $($b.Consumer)" 300
            $isBuiltInBinding = $false
            foreach ($kbi in $knownBuiltIn) {
                if ($detail -like "*$kbi*") { $isBuiltInBinding = $true; break }
            }
            [void]$results.Add([PSCustomObject]@{
                Category   = 'WMI Persistence'
                Risk       = if ($isBuiltInBinding) { 'Info' } else { 'High' }
                Type       = 'Binding'
                Name       = 'Filter-to-Consumer'
                Detail     = $detail
                CreatorSID = ''
            })
        }

        if ($results.Count -eq 0) { return @() }
        return $results.ToArray()
    } catch {
        Write-Warning "  WMI persistence scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: WINDOWS DEFENDER EXCLUSIONS  [NEW - critical]
# ============================================================================
function Get-DefenderExclusionsSummary {
    <#
    .SYNOPSIS
        List Defender exclusions (paths, processes, extensions). Malware commonly
        adds exclusions to avoid detection.
    #>
    Write-Host '  [*] Scanning Defender exclusions...' -ForegroundColor DarkGray
    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        $results = [System.Collections.ArrayList]::new()

        foreach ($p in $prefs.ExclusionPath) {
            if (-not $p) { continue }
            $risk = 'Medium'
            if ($p -like "*$env:TEMP*" -or $p -like "*Downloads*" -or $p -like "*AppData*") { $risk = 'High' }
            [void]$results.Add([PSCustomObject]@{
                Category      = 'Defender Exclusions'
                Risk          = $risk
                ExclusionType = 'Path'
                Value         = $p
            })
        }

        foreach ($p in $prefs.ExclusionProcess) {
            if (-not $p) { continue }
            $risk = 'Medium'
            if ($p -match 'powershell|cmd|wscript|cscript|mshta') { $risk = 'Critical' }
            [void]$results.Add([PSCustomObject]@{
                Category      = 'Defender Exclusions'
                Risk          = $risk
                ExclusionType = 'Process'
                Value         = $p
            })
        }

        foreach ($e in $prefs.ExclusionExtension) {
            if (-not $e) { continue }
            $risk = 'Medium'
            if ($e -in @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js')) { $risk = 'High' }
            [void]$results.Add([PSCustomObject]@{
                Category      = 'Defender Exclusions'
                Risk          = $risk
                ExclusionType = 'Extension'
                Value         = $e
            })
        }

        if ($results.Count -eq 0) { return @() }
        return $results.ToArray()
    } catch {
        Write-Warning "  Defender exclusions scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: DNS CACHE  [NEW]
# ============================================================================
function Get-DNSCacheSummary {
    <#
    .SYNOPSIS
        Dump the local DNS resolver cache. Shows recent network destinations.
    #>
    param([int]$Limit = 100)

    Write-Host '  [*] Scanning DNS cache...' -ForegroundColor DarkGray
    try {
        $entries = Get-DnsClientCache -ErrorAction Stop | Select-Object -First $Limit

        $results = foreach ($e in $entries) {
            [PSCustomObject]@{
                Category = 'DNS Cache'
                Risk     = 'Info'
                Name     = $e.Entry
                Type     = $e.Type
                TTL      = $e.TimeToLive
                Data     = $e.Data
            }
        }

        if (-not $results) { return @() }
        return $results
    } catch {
        Write-Warning "  DNS cache scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# SCAN: ALTERNATE DATA STREAMS  [NEW]
# ============================================================================
function Get-AlternateDataStreamsSummary {
    <#
    .SYNOPSIS
        Scan common user directories for files with alternate data streams,
        which can be used to hide data or executables.
    #>
    Write-Host '  [*] Scanning for alternate data streams...' -ForegroundColor DarkGray
    try {
        $dirsToScan = @(
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Documents",
            "$env:TEMP"
        )

        $results = [System.Collections.ArrayList]::new()

        foreach ($dir in $dirsToScan) {
            if (-not (Test-Path $dir)) { continue }
            $files = Get-ChildItem -Path $dir -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $streams = Get-Item $f.FullName -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' -and
                                   $_.Stream -notlike 'MBAM.*' -and $_.Stream -ne 'SmartScreen' }

                foreach ($s in $streams) {
                    $risk = 'Medium'
                    if ($s.Length -gt 10000) { $risk = 'High' }

                    [void]$results.Add([PSCustomObject]@{
                        Category   = 'Alternate Data Streams'
                        Risk       = $risk
                        FilePath   = $f.FullName
                        StreamName = $s.Stream
                        StreamSize = $s.Length
                    })
                }
            }
            if ($results.Count -ge 50) { break }
        }

        if ($results.Count -eq 0) { return @() }
        return $results.ToArray()
    } catch {
        Write-Warning "  ADS scan failed: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================
function New-HTMLReport {
    <#
    .SYNOPSIS
        Generate a modern, interactive HTML report with search, risk-based filtering,
        color coding, review checkboxes, and CSV/JSON export.
    #>
    param(
        [System.Collections.Specialized.OrderedDictionary]$Results,
        [string]$OutputPath = 'WinAutoSentinel_Report.html'
    )

    Write-Host "`n  [*] Generating HTML report..." -ForegroundColor DarkGray

    # Count findings by risk
    $totalFindings = 0
    $riskCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($cat in $Results.Keys) {
        foreach ($item in $Results[$cat]) {
            $totalFindings++
            $r = if ($item.Risk) { $item.Risk } else { 'Info' }
            if ($riskCounts.ContainsKey($r)) { $riskCounts[$r]++ }
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinAutoSentinel Report</title>
<style>
:root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --text-muted: #94a3b8; --border: #475569;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --accent: #38bdf8;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.header { text-align: center; padding: 30px 0 20px; }
.header h1 { font-size: 2em; font-weight: 700; color: var(--accent); }
.header .subtitle { color: var(--text-muted); margin-top: 5px; }
.meta { display: flex; gap: 20px; justify-content: center; margin-top: 15px; flex-wrap: wrap; }
.meta span { background: var(--surface); padding: 5px 15px; border-radius: 6px; font-size: 0.85em; color: var(--text-muted); }
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 25px 0; }
.stat-card { background: var(--surface); border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid var(--info); }
.stat-card.critical { border-left-color: var(--critical); }
.stat-card.high { border-left-color: var(--high); }
.stat-card.medium { border-left-color: var(--medium); }
.stat-card.low { border-left-color: var(--low); }
.stat-card .number { font-size: 2.2em; font-weight: 700; }
.stat-card .label { color: var(--text-muted); font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
.controls { display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; align-items: center; }
.controls input[type="text"] {
    flex: 1; min-width: 250px; padding: 10px 15px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); font-size: 0.95em; outline: none;
}
.controls input:focus { border-color: var(--accent); }
.filter-btn {
    padding: 8px 16px; border: 1px solid var(--border); background: var(--surface); color: var(--text);
    border-radius: 6px; cursor: pointer; font-size: 0.85em; transition: all 0.2s;
}
.filter-btn:hover, .filter-btn.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.export-btn {
    padding: 8px 16px; background: var(--accent); color: var(--bg); border: none;
    border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.85em;
}
.export-btn:hover { opacity: 0.9; }
.section { background: var(--surface); border-radius: 10px; margin-bottom: 15px; overflow: hidden; }
.section-header {
    padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center;
    user-select: none; transition: background 0.2s;
}
.section-header:hover { background: var(--surface2); }
.section-header h2 { font-size: 1.1em; font-weight: 600; }
.section-header .badge { padding: 3px 10px; border-radius: 12px; font-size: 0.8em; background: var(--surface2); }
.section-header .arrow { transition: transform 0.3s; font-size: 0.8em; color: var(--text-muted); }
.section-header.open .arrow { transform: rotate(180deg); }
.section-content { display: none; padding: 0 20px 15px; }
.section-content.open { display: block; }
.item { display: flex; align-items: flex-start; gap: 12px; padding: 12px 15px; margin: 8px 0; background: var(--bg);
        border-radius: 8px; border-left: 3px solid var(--info); font-size: 0.9em; flex-wrap: wrap; }
.item.critical { border-left-color: var(--critical); }
.item.high { border-left-color: var(--high); }
.item.medium { border-left-color: var(--medium); }
.item.low { border-left-color: var(--low); }
.item .risk-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 700;
    text-transform: uppercase; white-space: nowrap; min-width: 65px; text-align: center;
}
.risk-badge.critical { background: var(--critical); color: #fff; }
.risk-badge.high { background: var(--high); color: #000; }
.risk-badge.medium { background: var(--medium); color: #000; }
.risk-badge.low { background: var(--low); color: #fff; }
.risk-badge.info { background: var(--info); color: #fff; }
.item .details { flex: 1; min-width: 0; }
.item .detail-row { display: flex; gap: 8px; margin: 2px 0; }
.item .detail-label { color: var(--text-muted); min-width: 120px; font-size: 0.85em; flex-shrink: 0; }
.item .detail-value { word-break: break-all; }
.item input[type="checkbox"] { margin-top: 3px; accent-color: var(--accent); }
.item.reviewed { opacity: 0.5; }
.tips { background: var(--surface); border-radius: 10px; padding: 20px; margin-top: 20px; }
.tips h3 { color: var(--accent); margin-bottom: 10px; }
.tip { padding: 8px 0; border-bottom: 1px solid var(--surface2); color: var(--text-muted); font-size: 0.9em; }
.tip strong { color: var(--text); }
.footer { text-align: center; padding: 30px; color: var(--text-muted); font-size: 0.85em; }
@media (max-width: 768px) { .controls { flex-direction: column; } .meta { flex-direction: column; align-items: center; } }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>&#x1f6e1; WinAutoSentinel Report</h1>
        <div class="subtitle">Windows Autostart &amp; Persistence Security Review</div>
        <div class="meta">
            <span>&#x1f4bb; $env:COMPUTERNAME</span>
            <span>&#x1f4c5; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
            <span>&#x1f50d; $totalFindings findings across $($Results.Count) categories</span>
            <span>&#x1f464; $env:USERNAME</span>
        </div>
    </div>

    <div class="dashboard">
        <div class="stat-card critical"><div class="number" style="color:var(--critical)">$($riskCounts.Critical)</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="number" style="color:var(--high)">$($riskCounts.High)</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="number" style="color:var(--medium)">$($riskCounts.Medium)</div><div class="label">Medium</div></div>
        <div class="stat-card low"><div class="number" style="color:var(--low)">$($riskCounts.Low)</div><div class="label">Low</div></div>
        <div class="stat-card"><div class="number" style="color:var(--info)">$($riskCounts.Info)</div><div class="label">Info</div></div>
        <div class="stat-card"><div class="number" style="color:var(--accent)">$totalFindings</div><div class="label">Total</div></div>
    </div>

    <div class="controls">
        <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="filterItems()">
        <button class="filter-btn active" onclick="setRiskFilter('all', this)">All</button>
        <button class="filter-btn" onclick="setRiskFilter('critical', this)">Critical</button>
        <button class="filter-btn" onclick="setRiskFilter('high', this)">High</button>
        <button class="filter-btn" onclick="setRiskFilter('medium', this)">Medium</button>
        <button class="filter-btn" onclick="setRiskFilter('low', this)">Low</button>
        <button class="export-btn" onclick="exportCSV()">Export CSV</button>
        <button class="export-btn" onclick="exportJSON()">Export JSON</button>
    </div>

"@

    # Build sections
    $sectionId = 0
    foreach ($category in $Results.Keys) {
        $sectionId++
        $items = $Results[$category]
        $itemCount = if ($items) { @($items).Count } else { 0 }

        $catCritical = @($items | Where-Object { $_.Risk -eq 'Critical' }).Count
        $catHigh     = @($items | Where-Object { $_.Risk -eq 'High' }).Count
        $headerColor = if ($catCritical) { 'var(--critical)' } elseif ($catHigh) { 'var(--high)' } else { 'var(--accent)' }

        $html += @"
    <div class="section" data-category="$([System.Web.HttpUtility]::HtmlEncode($category))">
        <div class="section-header" onclick="toggleSection('sec$sectionId', this)">
            <h2 style="color: $headerColor">$([System.Web.HttpUtility]::HtmlEncode($category))</h2>
            <div>
                <span class="badge">$itemCount items</span>
                <span class="arrow">&#x25BC;</span>
            </div>
        </div>
        <div class="section-content" id="sec$sectionId">
"@

        if ($itemCount -eq 0) {
            $html += '            <div class="item info"><span class="risk-badge info">OK</span><div class="details">No findings in this category.</div></div>'
        } else {
            foreach ($item in $items) {
                $risk = if ($item.Risk) { $item.Risk.ToLower() } else { 'info' }
                $riskDisplay = if ($item.Risk) { $item.Risk } else { 'Info' }

                # Build detail rows from object properties (skip Category and Risk)
                $detailHtml = ''
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Name -in @('Category','Risk')) { continue }
                    $val = if ($null -ne $prop.Value) { [System.Web.HttpUtility]::HtmlEncode([string]$prop.Value) } else { '' }
                    if ([string]::IsNullOrWhiteSpace($val)) { continue }
                    $detailHtml += "                    <div class=`"detail-row`"><span class=`"detail-label`">$([System.Web.HttpUtility]::HtmlEncode($prop.Name)):</span><span class=`"detail-value`">$val</span></div>`n"
                }

                $searchText = [System.Web.HttpUtility]::HtmlEncode(($item.PSObject.Properties | ForEach-Object { [string]$_.Value }) -join ' ')

                $html += @"
            <div class="item $risk" data-risk="$risk" data-text="$searchText">
                <input type="checkbox" title="Mark as reviewed" onchange="this.parentElement.classList.toggle('reviewed')">
                <span class="risk-badge $risk">$riskDisplay</span>
                <div class="details">
$detailHtml
                </div>
            </div>
"@
            }
        }

        $html += @"
        </div>
    </div>
"@
    }

    # Tips section
    $html += @"
    <div class="tips">
        <h3>Review Tips</h3>
        <div class="tip"><strong>Scheduled Tasks:</strong> Look for tasks with unusual names, unknown publishers, or suspicious commands (powershell, cmd, encoded).</div>
        <div class="tip"><strong>Registry Run Keys:</strong> These run at every startup. Verify all entries come from trusted, signed software.</div>
        <div class="tip"><strong>Startup Folders:</strong> Files here run at login. Scripts (.vbs, .bat, .ps1) are higher risk than signed shortcuts.</div>
        <div class="tip"><strong>Services:</strong> Unsigned services outside Program Files/System32 deserve investigation. Check binary signature and path.</div>
        <div class="tip"><strong>WMI Persistence:</strong> Legitimate WMI subscriptions are rare. Any finding here warrants close examination.</div>
        <div class="tip"><strong>Defender Exclusions:</strong> Malware commonly adds itself to exclusions. Review and remove any you don't recognize.</div>
        <div class="tip"><strong>Browser Extensions:</strong> Extensions with broad permissions (all URLs, native messaging) can see all your browsing data.</div>
        <div class="tip"><strong>Event Logs:</strong> Event 7045 = new service installed. Events 4625/4740 = failed logins/lockouts.</div>
        <div class="tip"><strong>Hosts File:</strong> Entries redirecting microsoft.com, google.com, or banking sites are major red flags.</div>
        <div class="tip"><strong>Network:</strong> Established connections to unknown IPs, especially on unusual ports, may indicate C2 communication.</div>
        <div class="tip"><strong>Alternate Data Streams:</strong> Hidden data attached to normal files. Legitimate uses exist but can hide malicious payloads.</div>
        <div class="tip" style="color: var(--medium);"><strong>General:</strong> Research unknown findings before taking action. False positives happen. Use the checkboxes to track your review progress.</div>
    </div>

    <div class="footer">
        <p>WinAutoSentinel &mdash; Windows autostart and persistence review tool</p>
        <p>Generated for educational and security review purposes. All data collected locally.</p>
    </div>
</div>

<script>
let currentRiskFilter = 'all';

function toggleSection(id, header) {
    const el = document.getElementById(id);
    el.classList.toggle('open');
    header.classList.toggle('open');
}

function filterItems() {
    const query = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('.item[data-risk]').forEach(item => {
        const text = (item.getAttribute('data-text') || '').toLowerCase();
        const riskMatch = currentRiskFilter === 'all' || item.getAttribute('data-risk') === currentRiskFilter;
        const textMatch = !query || text.includes(query);
        item.style.display = (riskMatch && textMatch) ? '' : 'none';
    });
}

function setRiskFilter(risk, btn) {
    currentRiskFilter = risk;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (risk !== 'all') {
        document.querySelectorAll('.section-content').forEach(c => { c.classList.add('open'); c.previousElementSibling.classList.add('open'); });
    }
    filterItems();
}

function exportCSV() {
    let csv = 'Category,Risk,Details\n';
    document.querySelectorAll('.item[data-risk]').forEach(item => {
        if (item.style.display === 'none') return;
        const cat = item.closest('.section').getAttribute('data-category');
        const risk = item.getAttribute('data-risk');
        const details = item.querySelector('.details').innerText.replace(/\n/g, ' | ').replace(/"/g, '""');
        csv += '"' + cat + '","' + risk + '","' + details + '"\n';
    });
    const blob = new Blob([csv], {type: 'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'WinAutoSentinel_Export.csv';
    a.click();
}

function exportJSON() {
    const data = [];
    document.querySelectorAll('.item[data-risk]').forEach(item => {
        if (item.style.display === 'none') return;
        const obj = {
            category: item.closest('.section').getAttribute('data-category'),
            risk: item.getAttribute('data-risk'),
            details: {}
        };
        item.querySelectorAll('.detail-row').forEach(row => {
            const label = row.querySelector('.detail-label').textContent.replace(':', '').trim();
            const value = row.querySelector('.detail-value').textContent.trim();
            obj.details[label] = value;
        });
        data.push(obj);
    });
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'WinAutoSentinel_Export.json';
    a.click();
}

// Auto-expand sections with Critical/High findings
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.section').forEach(section => {
        const h2 = section.querySelector('.section-header h2');
        const color = h2 ? h2.style.color : '';
        if (color.includes('critical') || color.includes('high') || color.includes('ef4444') || color.includes('f97316')) {
            const content = section.querySelector('.section-content');
            const header = section.querySelector('.section-header');
            content.classList.add('open');
            header.classList.add('open');
        }
    });
});
</script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host "  [+] HTML report saved: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Warning "  Error saving HTML report: $($_.Exception.Message)"
    }
}
