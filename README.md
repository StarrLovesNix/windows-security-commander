# Security Commander for Windows

A real-time security monitoring desktop application for Windows 10/11. See every network connection, process, login event, and security threat as it happens — in a clean, Wireshark-style interface — with automatic threat intelligence and optional auto-remediation.

---

## Download and Install

> **This is the easiest way to get started — no Python or Git required.**

1. Go to the [Releases page](https://github.com/StarrLovesNix/windows-security-commander/releases/latest)
2. Download **SecurityCommander-Setup.exe**
3. Run it and follow the installer (it will ask for admin — required for security monitoring)
4. Launch **Security Commander** from the desktop shortcut or Start Menu

That's it. The installer includes everything the app needs.

---

## Features

- **Live network feed** — every TCP/UDP connection shown as it opens, with process name and PID
- **Threat intelligence** — AbuseIPDB lookups on all external IPs (24-hour local cache)
- **Windows Event Log monitoring** — login events, brute-force detection, new services, audit clears
- **Process monitoring** — suspicious spawn chains (e.g. Word → PowerShell), encoded commands, known-bad names
- **DNS monitoring** — new DNS cache entries, flags suspicious domains (ngrok, pastebin, etc.)
- **LAN scanner** — ARP table polling, detects new devices and ARP spoofing
- **Firewall integration** — block IPs via Windows Firewall with one click (or automatically)
- **Filter bar** — `severity:high type:conn source:chrome` with AND logic
- **System tray** — monitoring continues with zero render overhead when minimised
- **Persistent pinned alerts** — HIGH/CRITICAL alerts survive restarts until acknowledged
- **Session logging** — rolling text log, connections-only log, SQLite database, CSV/HTML on exit
- **Dark theme** — colour-coded severity rows (CRITICAL red → INFO grey)

---

## First Run

When you launch Security Commander for the first time:

- The app starts monitoring immediately — you don't need to configure anything
- Events appear in the main table in real time, newest at the top
- **Severity colours:** red = CRITICAL, orange = HIGH, yellow = MEDIUM, blue = LOW, grey = INFO
- Click any row to see full details in the panel below
- Minimising the window sends it to the **system tray** (look for the shield icon near the clock)

To stop monitoring, right-click the tray icon → **Exit**, or use the window's close button after disabling *Close to tray* in Settings.

---

## Configuration (Optional)

Everything works out of the box. Two optional extras unlock additional features:

| What | Where to get it | What it enables |
|------|-----------------|-----------------|
| **AbuseIPDB API key** | [abuseipdb.com](https://www.abuseipdb.com/register) — free, 1 000 checks/day | Reputation scores on every external IP |
| **Gmail App Password** | [myaccount.google.com → Security → App passwords](https://support.google.com/accounts/answer/185833) | Email reports for HIGH/CRITICAL alerts |

To configure, click the **gear icon** in the toolbar to open Settings. You can also copy `config.json.example` to `config.json` and edit it directly.

### Auto-remediation

Settings → Remediation lets you turn on automatic responses. **All are off by default** — enable only what you're comfortable with:

| Setting | What it does |
|---------|-------------|
| `auto_block_brute_force` | Adds a Windows Firewall block rule for IPs that trigger brute-force alerts |
| `auto_block_c2` | Blocks IPs flagged as malicious by AbuseIPDB |
| `auto_kill_suspicious` | Kills processes that match suspicious-spawn-chain rules |

---

## Running from Source

If you prefer to run directly from Python rather than using the installer:

**Requirements:**
- Windows 10 or Windows 11 (64-bit)
- [Python 3.10+](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during install
- [Git for Windows](https://git-scm.com/download/win)
- Administrator privileges (required for Event Log access and firewall rules)

```powershell
# Open PowerShell as Administrator, then:
git clone https://github.com/StarrLovesNix/windows-security-commander.git
cd windows-security-commander
python setup.py        # installs dependencies and walks through config
python gui.py          # launch the GUI
```

`setup.py` installs all required packages automatically — you don't need to run `pip install` yourself.

For the terminal / headless mode:
```powershell
python security_commander.py
python security_commander.py --help
```

---

## Building the Installer

To produce `dist\SecurityCommander-Setup.exe` from source:

**Extra requirement:** [Inno Setup 6](https://jrsoftware.org/isdl.php)

The quickest way to install it is via winget (built into Windows 10/11):
```powershell
winget install JRSoftware.InnoSetup
```

Then run the build script from the project root:
```powershell
python build/build.py
# Output: dist\SecurityCommander-Setup.exe  (~46 MB)
```

The script handles everything automatically: installs PyInstaller and Pillow if needed, generates the icon, packages the app with PyInstaller, then compiles the Inno Setup installer. If Inno Setup is not found, it falls back to a portable ZIP instead.

---

## Architecture

```
gui.py                      ← GUI entry point
security_commander.py       ← Terminal / headless entry point
setup.py                    ← First-run wizard (source installs only)

modules/
  events.py                 ← SecurityEvent dataclass + shared queue
  connection_monitor.py     ← psutil TCP/UDP polling (1 s interval)
  dns_monitor.py            ← PowerShell DNS cache polling (5 s)
  process_monitor.py        ← psutil process monitoring (1 s)
  event_log_monitor.py      ← Windows Event Log via pywin32
  network_scanner.py        ← ARP table polling (5 min)
  threat_intel.py           ← AbuseIPDB API + 24-hour local cache
  firewall_manager.py       ← netsh advfirewall rules
  remediation.py            ← Auto-remediation engine
  baseline.py               ← System baseline capture + deviation detection
  alert_history.py          ← Per-severity cooldown deduplication
  alert_store.py            ← Persistent unacknowledged HIGH/CRITICAL alerts
  session_logger.py         ← Text logs + SQLite + CSV/HTML export
  notifier.py               ← Toast notifications + email reports

  gui/
    main_window.py          ← QMainWindow, toolbar, filter bar, splitter layout
    event_model.py          ← QAbstractTableModel + filter proxy
    tray_icon.py            ← QSystemTrayIcon with dynamic colour-coded icons
    detail_panel.py         ← Event detail / active connections / pinned alerts tabs
    settings_dialog.py      ← Configuration GUI (4 tabs)
    theme.py                ← Dark stylesheet + severity colour palette

build/
  build.py                  ← Automated build script
  SecurityCommander.spec    ← PyInstaller specification
  installer.iss             ← Inno Setup 6 installer script
  make_icon.py              ← Shield icon generator (Pillow)
  version_info.txt          ← Windows EXE version metadata
```

---

## Log Files

All logs are written to the `logs/` and `data/` directories (gitignored — personal data):

| File | Contents |
|------|----------|
| `logs/YYYY-MM-DD.log` | All events, human-readable text, rolling daily |
| `logs/YYYY-MM-DD_connections.log` | Network connections only, tabular |
| `data/events.db` | SQLite, all sessions, never truncated |
| `logs/session_*.csv` | Per-session CSV export (written on clean exit) |
| `logs/session_*.html` | Per-session HTML report (written on clean exit) |

---

## Dependencies

```
psutil>=5.9.0       # Process and network monitoring
PyQt6>=6.4.0        # GUI framework
rich>=13.0.0        # Terminal dashboard (headless mode)
pywin32>=306        # Windows Event Log access
requests>=2.28.0    # AbuseIPDB threat intel API
plyer>=2.1.0        # Windows toast notifications
```

---

## License

MIT License
