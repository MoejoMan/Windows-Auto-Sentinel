# Security & Transparency

**WinAutoSentinel is a read-only security scanner. It does not modify your system, contact any server, or collect any data.**

This document exists because you *should* be skeptical of any tool that asks to scan your computer. Every claim below is verifiable by reading the source code — it's all plain-text PowerShell, no compiled binaries.

---

## What This Tool Does NOT Do

| Claim | How to verify |
|---|---|
| **No network calls** | Search the codebase for `Invoke-WebRequest`, `Invoke-RestMethod`, `WebClient`, `HttpClient`, `DownloadString`, `curl`, `wget`. Zero results. The only network listener is `HttpListener` bound to `localhost` (your machine only, line ~986 of `Win_Auto_Sentinel_GUI.ps1`). |
| **No data exfiltration** | Nothing is sent anywhere. Reports are saved locally to your chosen directory. The web GUI runs on `localhost:8765` — not accessible from other computers. |
| **No registry writes** | Search for `Set-ItemProperty`, `New-ItemProperty`, `New-Item` on `HKLM`/`HKCU`. Zero results. All registry access is read-only via `Get-ItemProperty`. |
| **No service modifications** | Search for `Stop-Service`, `Set-Service`, `Remove-Service`, `Start-Service`. Zero results (the strings in the GUI are display-only remediation *advice text*, not executed code). |
| **No process killing** | Search for `Stop-Process`. Only appears as advice text in the GUI, never executed. |
| **No file modifications** | The only file writes are optional report exports (`-ExportHTML`, `-ExportCSV`, `-ExportJSON`) to paths you specify. Nothing in `System32`, `Windows`, `ProgramData`, or any system directory. |
| **No credential access** | Search for `Get-Credential`, `ConvertTo-SecureString`, `NetworkCredential`. Zero results. |
| **No code obfuscation** | Search for `-enc`, `-EncodedCommand`, `FromBase64String`, `[char]` array conversions. The only hits are detection signatures (strings the tool looks *for*, not strings it *uses*). |
| **No Invoke-Expression** | Search for `Invoke-Expression` or `iex`. Only appears as a detection signature in the PowerShell history scanner. Never called. |
| **No ExecutionPolicy changes** | The core tool does not use `-ExecutionPolicy Bypass`. The `run.bat` launcher uses it with `-Scope Process` (affects only the launched window, not your system policy). |
| **No external dependencies** | No npm, no pip, no NuGet, no CDN links, no internet required. Everything is self-contained PowerShell + inline HTML/CSS/JS. |

---

## What This Tool DOES Do (Read-Only Operations)

Every scan function uses only `Get-*` cmdlets:

| Scan | Cmdlets Used | What It Reads |
|---|---|---|
| Scheduled Tasks | `Get-ScheduledTask` | Task definitions (name, triggers, actions) |
| Registry Run Keys | `Get-ItemProperty` | `HKLM:\...\Run`, `HKCU:\...\Run` values |
| Startup Folders | `Get-ChildItem` | Files in `shell:startup` directories |
| WMI Persistence | `Get-CimInstance` | `root\subscription` WMI namespace |
| Services | `Get-CimInstance` (Win32_Service) | Running service properties |
| Defender Exclusions | `Get-MpPreference` | Defender configuration (read-only) |
| Running Processes | `Get-CimInstance` (Win32_Process) | Process list with paths |
| Network Connections | `Get-NetTCPConnection` | Active TCP connections |
| Browser Extensions | `Get-ChildItem` + `Get-Content` | Extension manifest.json files |
| PowerShell History | `Get-Content` | PSReadLine history file |
| Prefetch Files | `Get-ChildItem` | `C:\Windows\Prefetch` directory listing |
| Event Logs | `Get-WinEvent` | Security and System log entries |
| DNS Cache | `Get-DnsClientCache` | DNS resolver cache |
| Alternate Data Streams | `Get-Item -Stream` | ADS metadata on user files |
| USB History | `Get-ItemProperty` | Registry USB device records |
| Hosts File | `Get-Content` | `drivers\etc\hosts` file |
| Firewall Rules | `Get-NetFirewallRule` | Firewall rule definitions |

---

## Web GUI Security

The GUI (`Win_Auto_Sentinel_GUI.ps1`) runs a local HTTP server:

- **Binds to `localhost` only** — Not `0.0.0.0`, not `*`. Other computers on your network cannot reach it.
- **No authentication needed** — It's your machine talking to itself.
- **Auto-opens your browser** — Navigates to `http://localhost:8765`. Use `-NoBrowser` to prevent this.
- **Stops when you close the terminal** — Press `Ctrl+C` or close the PowerShell window.
- **No persistent state** — Nothing is saved between sessions. No cookies, no databases, no config files.

---

## Dry-Run Mode

Run with `-WhatIf` to see exactly what each scan will access without actually scanning:

```powershell
.\Win_Auto_Sentinel_Main.ps1 -WhatIf
```

This prints every cmdlet and path each scan will touch, then exits without running anything.

---

## How to Audit This Tool Yourself

```powershell
# 1. Search for any network calls (should return 0 actual calls)
Select-String -Path *.ps1 -Pattern 'Invoke-WebRequest|Invoke-RestMethod|WebClient|DownloadString|DownloadFile' -SimpleMatch

# 2. Search for any system modifications (should only find advice text strings)
Select-String -Path *.ps1 -Pattern 'Set-ItemProperty|Remove-Item|Stop-Service|Stop-Process|Disable-' -SimpleMatch

# 3. Search for code execution (should only find detection signatures)
Select-String -Path *.ps1 -Pattern 'Invoke-Expression|iex |IEX |ScriptBlock\]::Create' 

# 4. Verify localhost binding
Select-String -Path Win_Auto_Sentinel_GUI.ps1 -Pattern 'localhost'

# 5. Get file hashes to verify integrity
Get-FileHash *.ps1 -Algorithm SHA256 | Format-Table Hash, @{N='File';E={Split-Path $_.Path -Leaf}} -AutoSize
```

---

## File Hashes

After downloading, verify these SHA256 hashes match the release:

```
(Run Get-FileHash *.ps1 -Algorithm SHA256 to generate current hashes)
```

Update this section with hashes for each tagged release.

---

## Reporting Security Issues

If you find a security concern in this code, please open a GitHub issue or contact the maintainer directly. All reports are taken seriously.
