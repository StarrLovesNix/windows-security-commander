#!/usr/bin/env python3
"""
gui.py - Security Commander GUI entry point.

Launches the PyQt6 desktop application with:
  - Live event table (Wireshark-style, colour-coded by severity)
  - Wireshark-style filter bar (severity:high  type:conn  source:chrome)
  - Quick-filter buttons (All / CRITICAL / HIGH / CONN / LOGIN)
  - Detail panel: Event Detail / Active Connections / Pinned Alerts
  - System tray icon (green/amber/red) with "close to tray" behaviour
  - Settings dialog for email, API key, and remediation toggles

Run as Administrator for full visibility (Event Log, all connections).
"""

import ctypes
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (same as security_commander.py)
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).parent
DATA_DIR      = BASE_DIR / "data"
LOGS_DIR      = BASE_DIR / "logs"
REPORTS_DIR   = BASE_DIR / "reports"
CONFIG_PATH   = BASE_DIR / "config.json"
CONFIG_EXAMPLE = BASE_DIR / "config.json.example"


def _setup_dirs():
    for d in (DATA_DIR, LOGS_DIR, REPORTS_DIR):
        d.mkdir(exist_ok=True)


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        if CONFIG_EXAMPLE.exists():
            shutil.copy(CONFIG_EXAMPLE, CONFIG_PATH)
        else:
            return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return {}


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    _setup_dirs()
    config = _load_config()

    # PyQt6 must be imported after QApplication args are prepared
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtCore import Qt
    except ImportError:
        print(
            "[ERROR] PyQt6 not installed.\n"
            "Run: pip install PyQt6\n"
            "Then restart Security Commander."
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("Security Commander")
    app.setOrganizationName("SecurityCommander")
    # Don't quit when the last window closes — we live in the tray
    app.setQuitOnLastWindowClosed(False)

    # Apply dark theme stylesheet
    from modules.gui.theme import STYLESHEET
    app.setStyleSheet(STYLESHEET)

    # Warn (don't block) if not admin
    admin = _is_admin()
    if not admin:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Limited visibility")
        msg.setText(
            "Security Commander is not running as Administrator.\n\n"
            "Event Log monitoring and the full connection list require elevated "
            "privileges. For best results, right-click the shortcut and choose "
            "'Run as administrator'.\n\n"
            "You can continue in limited mode."
        )
        msg.setStandardButtons(
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
        )
        if msg.exec() == QMessageBox.StandardButton.Cancel:
            sys.exit(0)

    # --- Instantiate backend components ---
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    from modules.session_logger  import SessionLogger
    from modules.alert_store     import AlertStore
    from modules.baseline        import Baseline
    from modules.alert_history   import AlertHistory
    from modules.threat_intel    import ThreatIntel
    from modules.remediation     import Remediator
    from modules.notifier        import Notifier

    session_logger = SessionLogger(LOGS_DIR, DATA_DIR, session_id)
    alert_store    = AlertStore(DATA_DIR)
    baseline       = Baseline(config, DATA_DIR)
    alert_history  = AlertHistory(config, DATA_DIR)
    threat_intel   = ThreatIntel(config, DATA_DIR)
    remediator     = Remediator(config)
    notifier       = Notifier(config)

    # --- Start monitoring threads ---
    from modules.connection_monitor import ConnectionMonitor
    from modules.dns_monitor        import DNSMonitor
    from modules.process_monitor    import ProcessMonitor
    from modules.event_log_monitor  import EventLogMonitor
    from modules.network_scanner    import NetworkScanner

    monitors = [
        ConnectionMonitor(config),
        DNSMonitor(config),
        ProcessMonitor(config),
        EventLogMonitor(config),
        NetworkScanner(config),
    ]
    for m in monitors:
        m.start()

    # --- Run baseline comparison (non-blocking, emits events into queue) ---
    if baseline.exists():
        baseline.load()
        baseline.compare()

    # --- Build and show main window ---
    from modules.gui.main_window import MainWindow

    window = MainWindow(
        config        = config,
        config_path   = CONFIG_PATH,
        alert_store   = alert_store,
        session_logger = session_logger,
        alert_history = alert_history,
        threat_intel  = threat_intel,
        remediator    = remediator,
        notifier      = notifier,
        monitors      = monitors,
    )
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
