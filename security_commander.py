#!/usr/bin/env python3
"""
Security Commander for Windows
================================
Real-time security monitoring with a live terminal dashboard.

Usage:
    python security_commander.py                    # Live dashboard
    python security_commander.py --baseline         # Capture security baseline
    python security_commander.py --no-email         # Skip email on exit
    python security_commander.py --no-ui            # Headless / log-only mode
    python security_commander.py --verbose          # Debug logging
    python security_commander.py --history          # Browse past event history
    python security_commander.py --history-conn     # Browse connection history only
    python security_commander.py --acknowledge      # Clear all pinned alerts

Run as Administrator for full visibility (process connections, Event Log).
"""

import argparse
import ctypes
import json
import logging
import queue
import shutil
import signal
import socket
import sys
import threading
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR     = Path(__file__).parent
DATA_DIR     = BASE_DIR / "data"
LOGS_DIR     = BASE_DIR / "logs"
REPORTS_DIR  = BASE_DIR / "reports"
CONFIG_PATH  = BASE_DIR / "config.json"
CONFIG_EXAMPLE = BASE_DIR / "config.json.example"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_dirs():
    for d in (DATA_DIR, LOGS_DIR, REPORTS_DIR):
        d.mkdir(exist_ok=True)


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        if CONFIG_EXAMPLE.exists():
            shutil.copy(CONFIG_EXAMPLE, CONFIG_PATH)
            print("[config] Created config.json from example — "
                  "edit it to add email/API keys.")
        else:
            return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception as exc:
        print(f"[config] Warning: could not parse config.json: {exc}")
        return {}


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(
                DATA_DIR / "security_commander.log", encoding="utf-8"
            )
        ],
    )


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security Commander — Windows real-time security monitor"
    )
    parser.add_argument("--baseline",     action="store_true",
                        help="Capture a security baseline snapshot and exit")
    parser.add_argument("--no-email",     action="store_true",
                        help="Skip email report on exit")
    parser.add_argument("--no-ui",        action="store_true",
                        help="Headless mode — write to log only, no dashboard")
    parser.add_argument("--verbose",      action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--history",      action="store_true",
                        help="Browse full event history from the database")
    parser.add_argument("--history-conn", action="store_true",
                        help="Browse connection history from the database")
    parser.add_argument("--acknowledge",  action="store_true",
                        help="Clear all pinned (unacknowledged) alerts and exit")
    parser.add_argument("--severity",
                        help="Filter --history by severity (e.g. HIGH, CRITICAL)")
    args = parser.parse_args()

    _setup_dirs()
    config = _load_config()
    _setup_logging(args.verbose)

    # Late imports so logging is configured first
    from modules.events             import event_queue, EventType, Severity, SecurityEvent
    from modules.connection_monitor import ConnectionMonitor
    from modules.dns_monitor        import DNSMonitor
    from modules.process_monitor    import ProcessMonitor
    from modules.event_log_monitor  import EventLogMonitor
    from modules.network_scanner    import NetworkScanner
    from modules.threat_intel       import ThreatIntel
    from modules.remediation        import Remediator
    from modules.baseline           import Baseline
    from modules.alert_history      import AlertHistory
    from modules.alert_store        import AlertStore
    from modules.notifier           import Notifier
    from modules.session_logger     import SessionLogger
    from modules.ui                 import SecurityUI

    session_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
    sess_logger  = SessionLogger(LOGS_DIR, DATA_DIR, session_id)
    alert_store  = AlertStore(DATA_DIR)
    baseline     = Baseline(config, DATA_DIR)
    alert_history = AlertHistory(config, DATA_DIR)
    threat_intel = ThreatIntel(config, DATA_DIR)
    notifier     = Notifier(config)
    remediator   = Remediator(config)
    ui           = SecurityUI(config, alert_store=alert_store)

    # -----------------------------------------------------------------------
    # --acknowledge: clear pinned alerts and exit
    # -----------------------------------------------------------------------
    if args.acknowledge:
        count = alert_store.count()
        alert_store.acknowledge_all()
        print(f"Cleared {count} pinned alert(s).")
        sess_logger.close()
        return 0

    # -----------------------------------------------------------------------
    # --history / --history-conn: browse past events and exit
    # -----------------------------------------------------------------------
    if args.history or args.history_conn:
        if args.history_conn:
            rows = sess_logger.query_connections(limit=2000)
            title = "CONNECTION HISTORY"
        else:
            rows = sess_logger.query_recent(
                limit=2000,
                severity=args.severity,
            )
            title = "EVENT HISTORY"
        if not rows:
            print("No events in database yet. Run the monitor first.")
        else:
            ui.show_history(rows, title=title)
        sess_logger.close()
        return 0

    # -----------------------------------------------------------------------
    # --baseline: snapshot and exit
    # -----------------------------------------------------------------------
    if args.baseline:
        print("Capturing security baseline...")
        result = baseline.capture()
        print(f"  Listening ports : {len(result['listening_ports'])}")
        print(f"  Running services: {len(result['services'])}")
        print(f"  Scheduled tasks : {len(result['scheduled_tasks'])}")
        print(f"  Local users     : {len(result['local_users'])}")
        print(f"  Startup programs: {len(result['startup_programs'])}")
        print(f"\nBaseline saved to: {DATA_DIR / 'baseline.json'}")
        sess_logger.close()
        return 0

    # -----------------------------------------------------------------------
    # Admin check
    # -----------------------------------------------------------------------
    admin = _is_admin()
    if not admin:
        print(
            "[!] Not running as Administrator.\n"
            "    Event Log monitoring and full connection details will be limited.\n"
            "    Right-click terminal -> Run as administrator for full visibility.\n"
        )

    # -----------------------------------------------------------------------
    # Load baseline and compare
    # -----------------------------------------------------------------------
    if baseline.exists():
        baseline.load()
        deviations = baseline.compare()
        if deviations:
            print(f"[baseline] {len(deviations)} deviation(s) from baseline detected.")
    else:
        print(
            "[baseline] No baseline found. "
            "Run with --baseline to establish a normal-state snapshot."
        )

    # -----------------------------------------------------------------------
    # Start monitors
    # -----------------------------------------------------------------------
    stop_event = threading.Event()

    monitors = [
        ConnectionMonitor(config),
        DNSMonitor(config),
        ProcessMonitor(config),
        EventLogMonitor(config),
        NetworkScanner(config),
    ]
    for m in monitors:
        m.start()

    ui.set_status(
        "Monitoring — all checks active"
        if admin else
        "! Not running as Administrator — Event Log and full connections limited"
    )

    # -----------------------------------------------------------------------
    # Event processing thread
    # -----------------------------------------------------------------------
    session_events = []

    def _process_events():
        while not stop_event.is_set():
            try:
                event = event_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            except Exception:
                continue

            # Threat intel enrichment for new outbound connections
            if event.event_type == EventType.CONN_NEW:
                remote_ip = event.details.get("remote_ip", "")
                if remote_ip:
                    is_mal, score, _ = threat_intel.check_ip(remote_ip)
                    if is_mal:
                        threat_ev = SecurityEvent(
                            timestamp=datetime.now(),
                            event_type=EventType.THREAT_IP,
                            severity=Severity.CRITICAL,
                            source=event.source,
                            description=(
                                f"MALICIOUS IP: {event.source} -> {remote_ip} "
                                f"(AbuseIPDB score: {score})"
                            ),
                            details={**event.details, "abuse_score": score},
                        )
                        event_queue.put(threat_ev)

            # Auto-remediation
            remediator.process_event(event)

            # Persistent log (text + connections + SQLite) — always, every event
            sess_logger.record(event)

            # Persistent alert store — pins HIGH/CRITICAL across restarts
            alert_store.consider(event)

            # Alert deduplication + toast notifications
            if alert_history.should_alert(event):
                alert_history.record(event)
                if event.severity in (Severity.HIGH, Severity.CRITICAL):
                    notifier.toast(
                        f"{event.severity.value} Alert",
                        event.description,
                        event.severity,
                    )

            # Live UI feed
            ui.add_event(event)
            session_events.append(event)

    processor = threading.Thread(
        target=_process_events, daemon=True, name="EventProcessor"
    )
    processor.start()

    # -----------------------------------------------------------------------
    # Shutdown handler
    # -----------------------------------------------------------------------
    def _handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    # -----------------------------------------------------------------------
    # Run UI or headless
    # -----------------------------------------------------------------------
    try:
        if args.no_ui:
            hostname = socket.gethostname()
            print(f"Security Commander running on {hostname} (headless).")
            print(f"  Text log : {LOGS_DIR}")
            print(f"  Event DB : {DATA_DIR / 'events.db'}")
            print("  Press Ctrl+C to stop.\n")
            stop_event.wait()
        else:
            ui.run(stop_event)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        print("\nShutting down monitors...")
        for m in monitors:
            m.stop()
        sess_logger.close()

    # -----------------------------------------------------------------------
    # On-exit report
    # -----------------------------------------------------------------------
    if session_events:
        # HTML report
        report_path = REPORTS_DIR / f"report_{session_id}.html"
        report_path.write_text(
            notifier._build_html(session_events, socket.gethostname()),
            encoding="utf-8",
        )

        # CSV export
        csv_path = sess_logger.write_csv_export(session_events)

        notable = [e for e in session_events if e.severity != Severity.INFO]
        print(f"Session report : {report_path}")
        print(f"CSV export     : {csv_path}")
        print(f"Text logs      : {LOGS_DIR}")
        print(f"Event database : {DATA_DIR / 'events.db'}")

        if notable and not args.no_email:
            notifier.send_email_report(
                notable,
                subject=(
                    f"Security Commander — {len(notable)} notable events "
                    f"on {socket.gethostname()}"
                ),
            )

    # Exit codes
    crit = sum(1 for e in session_events if e.severity == Severity.CRITICAL)
    high = sum(1 for e in session_events if e.severity == Severity.HIGH)
    if crit:
        return 2
    if high:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
