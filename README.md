# WinAutoSentinel

**A comprehensive, interactive Windows security review tool with a browser-based GUI, real-time scanning, risk scoring, and an interactive dashboard — all in pure PowerShell with zero external dependencies.**

---

## Purpose

WinAutoSentinel is a free, portable, offline PowerShell tool that helps you review and understand what's set to auto-run or persist on your Windows machine. It scans 17 categories of security-relevant artefacts, assigns risk levels (0-100 security score), and presents findings through either a web-based GUI or CLI.

**Designed as a companion to traditional antivirus** — WinAutoSentinel focuses on persistence mechanisms, autoruns, and configuration weaknesses that AV tools often overlook.

- **Interactive Web GUI** — Local browser-based dashboard with scan configuration, live progress, charts, and remediation tips
- **Security Health Score** — 0-100 score with letter grade (A+ to F), weighted by finding severity
- **Risk-scored findings** — Critical / High / Medium / Low / Info severity on every item
- **Structured output** — All functions return proper PowerShell objects (filterable, sortable, exportable)
- **Read-only** — No changes made, no forced actions, no automatic removals
- **Privacy-focused** — Fully offline, nothing leaves your machine
- **Signature verification** — Checks Authenticode signatures on binaries where relevant

---

## Scans Performed (17 categories)

| Category | What it checks | Requires Admin |
|---|---|---|
| **Scheduled Tasks** | Active tasks with action/trigger details and author info | No |
| **Registry Run Keys** | HKLM/HKCU Run, RunOnce + WOW6432Node (32-bit on 64-bit) | No |
| **Startup Folders** | Per-user and all-users startup directories | No |
| **WMI Persistence** | Event filters, consumers (CommandLine + ActiveScript), bindings | No |
| **Unusual Services** | Running auto-start services not whitelisted, unsigned, or in suspicious paths | No |
| **Defender Exclusions** | Path, process, and extension exclusions in Windows Defender | No |
| **Running Processes** | Processes from suspicious locations or with suspicious names | No |
| **Network Connections** | Established/Listening TCP connections mapped to processes | No |
| **Browser Extensions** | Chrome, Edge, and Firefox extensions with permission analysis | No |
| **PowerShell History** | Recent commands with suspicious pattern detection | No |
| **Prefetch Files** | Recently executed programs from Windows Prefetch | **Yes** |
| **Event Log Entries** | Security (logon failures, account changes), System (service installs, errors) | **Yes** |
| **DNS Cache** | Recent DNS resolver cache entries | No |
| **Alternate Data Streams** | Hidden ADS in Desktop, Downloads, Documents, Temp | No |
| **USB Device History** | Previously connected USB storage devices with serial numbers | No |
| **Hosts File** | Non-default entries that may redirect traffic | No |
| **Firewall Rules** | Enabled rules with port, address, and application filters | No |

---

## Usage

### Web GUI (Recommended)
```powershell
.\Win_Auto_Sentinel_GUI.ps1
```
This opens your browser to a local dashboard where you can:
- See system information at a glance
- Toggle individual scan categories on/off
- Confirm before scanning starts
- Watch real-time progress per category
- Explore an interactive results dashboard with:
  - Security health score (0-100 with letter grade)
  - SVG donut chart of risk distribution
  - Auto-generated executive summary
  - Search and filter by risk level
  - Expandable category sections with per-finding details
  - Review checkboxes to track your progress
  - Copy-paste remediation commands
  - CSV/JSON export and print-friendly output

```powershell
# Custom port:
.\Win_Auto_Sentinel_GUI.ps1 -Port 9090

# Don't auto-open browser:
.\Win_Auto_Sentinel_GUI.ps1 -NoBrowser
```

### CLI Mode — Basic Console Output
```powershell
.\Win_Auto_Sentinel_Main.ps1
```

### CLI Mode — Generate Interactive HTML Report
```powershell
.\Win_Auto_Sentinel_Main.ps1 -ExportHTML
```

### CLI Mode — Export to CSV or JSON
```powershell
.\Win_Auto_Sentinel_Main.ps1 -ExportCSV
.\Win_Auto_Sentinel_Main.ps1 -ExportJSON
```

### CLI Mode — All Exports at Once
```powershell
.\Win_Auto_Sentinel_Main.ps1 -ExportHTML -ExportCSV -ExportJSON
```

### CLI Mode — Custom Output Directory
```powershell
.\Win_Auto_Sentinel_Main.ps1 -ExportHTML -OutputDir "C:\Reports"
```

### Run Elevated for Full Coverage
```powershell
# Right-click PowerShell → Run as Administrator, then:
.\Win_Auto_Sentinel_GUI.ps1
# or
.\Win_Auto_Sentinel_Main.ps1 -ExportHTML
```

---

## HTML Report Features

The interactive HTML report (CLI mode) includes:
- **Risk dashboard** — Critical/High/Medium/Low/Info counts at a glance
- **Search** — Full-text search across all findings
- **Risk filtering** — Click a severity level to show only those findings
- **Collapsible sections** — Grouped by category, auto-expands for Critical/High
- **Review checkboxes** — Mark items you've reviewed (greys them out)
- **In-browser CSV/JSON export** — Export visible (filtered) findings
- **Dark theme** — Easy on the eyes
- **Fully offline** — No external resources, works without internet

## Web GUI Features

The web-based GUI (`Win_Auto_Sentinel_GUI.ps1`) provides an enhanced experience:
- **3-view flow** — Configuration → Scanning Progress → Interactive Dashboard
- **Scan configuration** — Toggle switches per category, Select All/Deselect All, admin-required badges
- **Confirmation modal** — Review selection and estimated time before scanning
- **Live progress** — Animated progress bar, per-category status indicators, live finding counts
- **Security Health Score** — 0-100 weighted score with A+ to F letter grade
- **SVG donut chart** — Visual risk distribution (pure SVG, no external libraries)
- **Executive summary** — Auto-generated paragraph summarising findings and recommendations
- **Category remediation** — Copy-paste PowerShell commands to fix common issues
- **Keyboard shortcuts** — `/` to search, `Esc` to dismiss
- **Print stylesheet** — Clean print-friendly layout
- **Zero dependencies** — Self-contained PowerShell HTTP server, no npm/Node/Python/internet

---

## Risk Levels

| Level | Meaning | Example |
|---|---|---|
| **Critical** | Very likely malicious or extremely dangerous | WMI CommandLine consumer, Defender exclusion for `powershell.exe` |
| **High** | Strong indicator of compromise or misconfiguration | Unsigned service in Temp folder, hosts file redirecting google.com |
| **Medium** | Warrants investigation | Task running `powershell.exe`, failed logon events |
| **Low** | Mildly unusual but often benign | RunOnce entry, unsigned startup shortcut |
| **Info** | Informational, no action needed | Normal USB device, DNS cache entry |

---

## Configuration

### Service Whitelist

The file `legitimate_services.txt` defines patterns for known-good services. Services matching these patterns are excluded from the "Unusual Services" scan.

- One pattern per line, supports wildcards (`*`)
- Lines starting with `#` are comments
- Edit to add trusted software or tighten patterns

**Security note:** Broad patterns like `adobe*` reduce false positives but could mask spoofed service names. For stricter filtering, use more specific patterns (e.g., `adobe acrobat*` instead of `adobe*`).

---

## Architecture

```
Win_Auto_Sentinel_GUI.ps1       ← Web GUI launcher (local HTTP server + embedded SPA)
Win_Auto_Sentinel_Main.ps1      ← CLI entry point, orchestration, console output, export
Win_Auto_Sentinel_Functions.ps1 ← All 17 scan functions + HTML report generator
legitimate_services.txt         ← Service whitelist (editable)
examples/                       ← Reference forensic collection scripts
```

**Design principles:**
- Every scan function returns `[PSCustomObject[]]` with a `Category` and `Risk` property
- `[ordered]@{}` dictionary preserves section order (no random shuffling)
- All string operations use `Get-TruncatedString` to prevent `Substring` crashes
- `Get-CimInstance` replaces deprecated `Get-WmiObject`
- `Get-WinEvent` replaces deprecated `Get-EventLog`
- Signature checks use actual `Get-AuthenticodeSignature`, not guesswork

**GUI architecture:**
- PowerShell `HttpListener` serves an embedded HTML5/CSS3/JS single-page application on localhost
- Background scanning via PowerShell Runspaces with `[hashtable]::Synchronized()` for thread-safe state
- REST API design: `GET /` (SPA), `GET /api/info`, `POST /api/scan`, `GET /api/status`
- JavaScript polls `/api/status` every 600ms for real-time progress updates
- All charts rendered with inline SVG — zero external libraries

---

## Requirements

- PowerShell 5.1+ (ships with Windows 10/11)
- Windows 10 / 11 / Server 2016+
- Administrator elevation recommended (required for Prefetch and some Event Logs)

---

## License

MIT License

---

## Contributing

Pull requests, feedback, and suggestions are welcome.
