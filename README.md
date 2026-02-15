
# WinAutoSentinel

**A clear, interactive tool to review, understand, and learn about all major Windows autostart and persistence mechanisms on your system.**

---


## Purpose

WinAutoSentinel is a free, portable, offline PowerShell tool (with optional Python reporting) that helps you review and understand what’s set to auto-run or persist on your Windows machine. It is designed for anyone who wants a straightforward way to see, review, and learn about startup and persistence items—without technical jargon or overwhelming alerts.

- **Clarity first:** Guides you through each item with clear questions and explanations.
- **No pressure:** Read-only, no forced actions or automatic removals.
- **Privacy-focused:** Fully offline, no data leaves your machine.
- **Accessible:** Simple outputs, helpful comments, and organized results for all experience levels.

---


## Key Features

- **Scans common autostart and persistence locations (read-only):**
  - Scheduled Tasks (all, with details)
  - Registry Run/RunOnce keys (HKLM & HKCU)
  - Startup folders (user & all users)
  - Recent USB device history
  - Browser extensions (Chrome/Edge/Firefox)
  - Optional: PowerShell history, prefetch files, unusual services, event log entries

- **Organized, review-based reporting:**
  - Groups findings by category (e.g., Startup Programs, USB Devices)
  - For each item, prompts: “Do you recognize this?” or “Does this look suspicious?”
  - Provides context and tips for each section
  - Highlights items for review, but leaves decisions to you

- **User-friendly output:**
  - Console: color-coded, grouped lists with review prompts
  - HTML/Markdown: collapsible sections, checklists, and review dropdowns
  - Summary: clear counts of items to review in each category
  - Fix suggestions: safe, copy-paste commands (never auto-removes)

- **Safe and portable:**
  - Read-only by default (no changes made)
  - Portable: single .ps1 file (or minimal modules)
  - Helpful code comments
  - One-liner run option (e.g., irm ... | iex)
  - No data leaves your machine

---

## Why Use WinAutoSentinel Instead of Other Tools?

Most autostart and persistence tools for Windows are built for advanced users or security professionals. They often produce long, technical lists or alerts that are hard to interpret if you’re not an expert.

**WinAutoSentinel is different:**
- Presents information in a clear, organized way for everyone
- Helps you understand what runs at startup and why
- Guides you through each item so you can make informed choices
- No automatic scoring or overwhelming alerts—just straightforward review and context

---

## Who Should Use This?
- Anyone who wants to understand what runs at startup on their Windows system
- Students, homelabbers, privacy-conscious users
- People who want to regularly check their own machines and understand the results

---

## Roadmap / MVP Scope
- **v0.1:** Scheduled Tasks, Run keys, and Startup folders only, with console and basic HTML output.
- Add one educational blurb per category.
- Test on your machines and share feedback to help improve clarity and usefulness.

---

## Usage

### Basic Console Output
```powershell
.\Win_Auto_Sentinel_Main.ps1
```

### Generate Interactive HTML Report
```powershell
.\Win_Auto_Sentinel_Main.ps1 -ExportHTML
```

The HTML report includes:
- Collapsible sections for each scan category
- Checkboxes to mark items you recognize
- Visual highlighting for recognized items
- Offline, shareable format for review

---

## Configuration and Maintenance

### Service Whitelist
WinAutoSentinel uses a whitelist of known legitimate Windows services to reduce false positives in the "Unusual Services" scan. This whitelist is stored in a separate file called `legitimate_services.txt` for easy maintenance.

**To update the service whitelist:**
1. Open `legitimate_services.txt` in any text editor
2. Add new legitimate service patterns (one per line)
3. Use wildcards (*) for patterns (e.g., `microsoft*` matches all Microsoft services)
4. Lines starting with `#` are comments and ignored
5. Empty lines are ignored

**Example entries:**
```
# Known legitimate services
spooler
wuauserv
eventlog
microsoft*
windows*
adobe*
google*
```

The tool will automatically load this file at runtime. If the file is missing, it falls back to basic filtering (Microsoft/Windows/system services only).

---

## License
MIT License

---

## Contributing
Pull requests, feedback, and suggestions are welcome.