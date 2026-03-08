"""
setup.py - First-time setup wizard for Security Commander (Windows).

Run once after cloning:
    python setup.py

What it does:
  1. Checks Python version
  2. Installs dependencies (pip install -r requirements.txt)
  3. Runs pywin32 post-install script
  4. Prompts for optional email and AbuseIPDB API key
  5. Writes config.json
  6. Captures initial security baseline
  7. Optionally registers a Windows Task Scheduler job for daily scans
"""

import ctypes
import json
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
CONFIG_EXAMPLE = BASE_DIR / "config.json.example"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _banner():
    print("=" * 60)
    print("  Security Commander for Windows — Setup Wizard")
    print("=" * 60)
    print()


def _check_python():
    if sys.version_info < (3, 10):
        print(f"[ERROR] Python 3.10+ required. You have {sys.version}")
        sys.exit(1)
    print(f"[OK] Python {sys.version.split()[0]}")


def _install_deps():
    print("\n[*] Installing Python dependencies...")
    req = BASE_DIR / "requirements.txt"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req)],
        capture_output=False,
    )
    if result.returncode != 0:
        print("[WARNING] Some packages may not have installed correctly.")
    else:
        print("[OK] Dependencies installed")

    # pywin32 needs a post-install script
    print("[*] Running pywin32 post-install...")
    subprocess.run(
        [sys.executable, "-m", "pywin32_postinstall", "-install"],
        capture_output=True,
    )
    print("[OK] pywin32 post-install done")


def _configure() -> dict:
    print("\n[*] Configuration")
    print("    (Press Enter to skip optional fields)\n")

    config = {}

    # Email
    print("--- Email alerts (Gmail + App Password) ---")
    print("    Get an App Password at: myaccount.google.com -> Security -> App passwords")
    sender = input("    Gmail address       : ").strip()
    if sender:
        password = getpass("    App Password (hidden): ")
        recipient = input(f"    Alert recipient     [{sender}]: ").strip() or sender
        config["email"] = {
            "sender": sender,
            "app_password": password,
            "recipient": recipient,
        }
    else:
        print("    [skip] No email configured — alerts will show in dashboard only")
        config["email"] = {"sender": "", "app_password": "", "recipient": ""}

    # Threat intel
    print("\n--- Threat intelligence (AbuseIPDB) ---")
    print("    Free account: https://www.abuseipdb.com/ (1000 lookups/day)")
    api_key = input("    AbuseIPDB API key   : ").strip()
    config["threat_intel"] = {"abuseipdb_api_key": api_key}

    # Thresholds
    config["thresholds"] = {
        "failed_login_brute":   5,
        "brute_window_seconds": 60,
    }

    # Remediation — disabled by default, ask explicitly
    print("\n--- Auto-remediation (all OFF by default) ---")
    block_brute = input("    Auto-block brute-force IPs? [y/N]: ").strip().lower() == "y"
    block_c2    = input("    Auto-block confirmed malicious IPs? [y/N]: ").strip().lower() == "y"
    config["remediation"] = {
        "auto_block_brute_force": block_brute,
        "auto_block_c2":          block_c2,
        "auto_kill_suspicious":   False,  # Too aggressive for default
    }

    config["alert_history"] = {
        "cooldown_days": {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 7, "INFO": 30
        }
    }
    config["notifications"] = {"toast": True}

    return config


def _write_config(config: dict):
    DATA_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    print(f"\n[OK] Config written to {CONFIG_PATH}")


def _capture_baseline():
    print("\n[*] Capturing initial security baseline...")
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "security_commander.py"), "--baseline"],
        capture_output=False,
    )
    if result.returncode == 0:
        print("[OK] Baseline captured")
    else:
        print("[WARNING] Baseline capture had errors — you can re-run with --baseline")


def _schedule_task():
    print("\n--- Daily scheduled scan ---")
    schedule = input("    Register a daily scan at 07:00? [y/N]: ").strip().lower() == "y"
    if not schedule:
        return

    task_name = "SecurityCommanderDailyScan"
    python_exe = sys.executable
    script = str(BASE_DIR / "security_commander.py")

    cmd = [
        "schtasks", "/create", "/tn", task_name,
        "/tr", f'"{python_exe}" "{script}" --no-ui',
        "/sc", "daily",
        "/st", "07:00",
        "/rl", "highest",
        "/f",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[OK] Task '{task_name}' registered — runs daily at 07:00")
    else:
        print(f"[WARNING] Task scheduler failed: {result.stderr.strip()}")
        print("          You can create the task manually in Task Scheduler.")


def main():
    _banner()

    if not _is_admin():
        print("[WARNING] Not running as Administrator.")
        print("          Some features (Event Log, full connections) require admin.")
        print("          Re-run as admin for full setup, or continue anyway.\n")
        cont = input("Continue without admin? [y/N]: ").strip().lower()
        if cont != "y":
            print("Exiting. Right-click this script and choose 'Run as administrator'.")
            sys.exit(0)

    _check_python()
    _install_deps()
    config = _configure()
    _write_config(config)
    _capture_baseline()
    _schedule_task()

    print("\n" + "=" * 60)
    print("  Setup complete!")
    print()
    print("  Start monitoring:")
    print(f"    python \"{BASE_DIR / 'security_commander.py'}\"")
    print()
    print("  Capture a fresh baseline after major system changes:")
    print(f"    python \"{BASE_DIR / 'security_commander.py'}\" --baseline")
    print("=" * 60)


if __name__ == "__main__":
    main()
