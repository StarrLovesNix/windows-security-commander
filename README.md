# Security Commander for Windows

A real-time security monitoring desktop application for Windows 10/11. Shows all network connections, processes, login events, and security threats in a chronological, Wireshark-style interface — with automatic threat intelligence lookups and optional auto-remediation.

![Security Commander Screenshot](assets/screenshot.png)

## Features

- **Live network feed** — every TCP/UDP connection shown as it opens, with process name and PID
- **Threat intelligence** — AbuseIPDB lookups on all external IPs (24h local cache)
- **Windows Event Log monitoring** — login events, brute force detection, new services, audit clears
- **Process monitoring** — suspicious spawn chains (e.g. Word → PowerShell), encoded commands, known-bad names
- **DNS monitoring** — new DNS cache entries, flags suspicious domains (ngrok, pastebin, etc.)
- **LAN scanner** — ARP table polling, detects new devices and ARP spoofing
- **Firewall integration** — block IPs via Windows Firewall with one click (or automatically)
- **Wireshark-style filter bar** — `severity:high type:conn source:chrome` with AND logic
- **System tray** — monitoring continues with zero render overhead when minimised
- **Persistent pinned alerts** — HIGH/CRITICAL alerts survive restarts until acknowledged
- **Session logging** — rolling text log, connections-only log, SQLite database, CSV/HTML on exit
- **Dark theme** — colour-coded severity rows (CRITICAL red → INFO grey)

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Python 3.10+ (for running from source)
- Administrator privileges recommended (required for Event Log access and firewall rules)

## Quick Start (from source)

```powershell
git clone https://github.com/YOUR_USERNAME/windows-security-commander.git
cd windows-security-commander
python setup.py          # first-run wizard: installs deps, writes config
python gui.py            # launch the GUI
```

Or for the terminal/headless mode:
```powershell
python security_commander.py
python security_commander.py --help
```

## Building the Installer

Requires [Inno Setup 6](https://jrsoftware.org/isdl.php) for the `.exe` installer (optional — falls back to portable ZIP).

```powershell
python build/build.py
# Output: dist\SecurityCommander-Setup.exe
```

The build script handles everything: checks dependencies, generates the icon, runs PyInstaller, then wraps the bundle with Inno Setup.

## Configuration

Copy `config.json.example` to `config.json` and edit:

| Setting | Description |
|---------|-------------|
| `email.*` | Gmail + App Password for email reports |
| `threat_intel.api_key` | AbuseIPDB API key (free tier: 1000 checks/day) |
| `thresholds.brute_force_attempts` | Failed logins before brute force alert (default: 5) |
| `remediation.*` | Auto-block IPs / kill processes (all off by default) |
| `tray.close_to_tray` | `X` hides to tray instead of exiting (default: true) |

Or configure everything via **Settings** in the GUI (gear icon in toolbar).

## Architecture

```
gui.py                      ← GUI entry point
security_commander.py       ← Terminal / headless entry point
setup.py                    ← First-run wizard

modules/
  events.py                 ← SecurityEvent dataclass + shared queue
  connection_monitor.py     ← psutil TCP/UDP polling (1s interval)
  dns_monitor.py            ← PowerShell DNS cache polling (5s)
  process_monitor.py        ← psutil process monitoring (1s)
  event_log_monitor.py      ← Windows Event Log via pywin32
  network_scanner.py        ← ARP table polling (5min)
  threat_intel.py           ← AbuseIPDB API + local cache
  firewall_manager.py       ← netsh advfirewall rules
  remediation.py            ← Auto-remediation engine
  baseline.py               ← System baseline capture + deviation detection
  alert_history.py          ← Per-severity cooldown deduplication
  alert_store.py            ← Persistent unacknowledged HIGH/CRITICAL alerts
  session_logger.py         ← Text logs + SQLite + CSV/HTML export
  notifier.py               ← Toast notifications + email reports

  gui/
    main_window.py          ← QMainWindow, toolbar, filter bar, splitter layout
    event_model.py          ← QAbstractTableModel + Wireshark-style filter proxy
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

## Log Files

All logs are written to the `logs/` and `data/` directories (gitignored — personal data):

| File | Contents |
|------|----------|
| `logs/YYYY-MM-DD.log` | All events, human-readable text, rolling daily |
| `logs/YYYY-MM-DD_connections.log` | Network connections only, tabular |
| `data/events.db` | SQLite, all sessions, never truncated |
| `logs/session_*.csv` | Per-session CSV export (written on clean exit) |
| `logs/session_*.html` | Per-session HTML report (written on clean exit) |

## Dependencies

```
psutil>=5.9.0       # Process and network monitoring
PyQt6>=6.4.0        # GUI framework
rich>=13.0.0        # Terminal dashboard mode
pywin32>=306        # Windows Event Log access
requests>=2.28.0    # AbuseIPDB threat intel API
plyer>=2.1.0        # Windows toast notifications
```

## License

MIT License
