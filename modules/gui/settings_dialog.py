"""
settings_dialog.py - Configuration editor dialog.

Reads and writes config.json. Groups settings into logical sections.
Changes take effect immediately for most options; monitors restart
on next launch for threshold changes.
"""

import json
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)


class SettingsDialog(QDialog):
    def __init__(self, config: dict, config_path: Path, parent=None):
        super().__init__(parent)
        self._config      = config
        self._config_path = config_path

        self.setWindowTitle("Settings — Security Commander")
        self.setMinimumWidth(520)
        self.setModal(True)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._build_general_tab(),    "General")
        tabs.addTab(self._build_email_tab(),      "Email Alerts")
        tabs.addTab(self._build_intel_tab(),      "Threat Intel")
        tabs.addTab(self._build_remediation_tab(), "Remediation")
        layout.addWidget(tabs)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------
    # Tab builders

    def _build_general_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        notif = QGroupBox("Notifications")
        fl = QFormLayout(notif)
        self._toast_cb = QCheckBox("Show Windows desktop toast notifications")
        self._toast_cb.setChecked(
            self._config.get("notifications", {}).get("toast", True)
        )
        fl.addRow(self._toast_cb)
        v.addWidget(notif)

        tray = QGroupBox("System Tray")
        fl2 = QFormLayout(tray)
        self._close_to_tray_cb = QCheckBox("Minimise to tray when window is closed")
        self._close_to_tray_cb.setChecked(
            self._config.get("tray", {}).get("close_to_tray", True)
        )
        fl2.addRow(self._close_to_tray_cb)
        v.addWidget(tray)

        thresh = QGroupBox("Brute-force thresholds")
        fl3 = QFormLayout(thresh)
        self._brute_count = QSpinBox()
        self._brute_count.setRange(2, 100)
        self._brute_count.setValue(
            self._config.get("thresholds", {}).get("failed_login_brute", 5)
        )
        self._brute_window = QSpinBox()
        self._brute_window.setRange(10, 3600)
        self._brute_window.setSuffix(" s")
        self._brute_window.setValue(
            self._config.get("thresholds", {}).get("brute_window_seconds", 60)
        )
        fl3.addRow("Failed logins before alert:", self._brute_count)
        fl3.addRow("Detection window:",           self._brute_window)
        v.addWidget(thresh)

        v.addStretch()
        return w

    def _build_email_tab(self) -> QWidget:
        w = QWidget()
        fl = QFormLayout(w)
        fl.setContentsMargins(16, 16, 16, 16)
        fl.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)

        email_cfg = self._config.get("email", {})

        fl.addRow(QLabel(
            "Uses Gmail SMTP with an App Password.\n"
            "Get one at: myaccount.google.com → Security → App passwords"
        ))

        self._sender     = QLineEdit(email_cfg.get("sender", ""))
        self._sender.setPlaceholderText("your@gmail.com")
        self._app_pass   = QLineEdit(email_cfg.get("app_password", ""))
        self._app_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._app_pass.setPlaceholderText("16-character app password")
        self._recipient  = QLineEdit(email_cfg.get("recipient", ""))
        self._recipient.setPlaceholderText("leave blank to send to sender")

        fl.addRow("Gmail address:",  self._sender)
        fl.addRow("App Password:",   self._app_pass)
        fl.addRow("Alert recipient:", self._recipient)
        return w

    def _build_intel_tab(self) -> QWidget:
        w = QWidget()
        fl = QFormLayout(w)
        fl.setContentsMargins(16, 16, 16, 16)

        fl.addRow(QLabel(
            "AbuseIPDB checks outbound connection IPs for known malicious hosts.\n"
            "Free account: https://www.abuseipdb.com (1000 lookups/day)"
        ))

        self._api_key = QLineEdit(
            self._config.get("threat_intel", {}).get("abuseipdb_api_key", "")
        )
        self._api_key.setPlaceholderText("AbuseIPDB API key")
        fl.addRow("API Key:", self._api_key)
        return w

    def _build_remediation_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(16, 16, 16, 16)

        rem_cfg = self._config.get("remediation", {})

        warn = QLabel(
            "Auto-remediation takes automated actions without prompting.\n"
            "All options are OFF by default. Enable with care."
        )
        warn.setStyleSheet("color: #ffb347; font-style: italic;")
        v.addWidget(warn)

        grp = QGroupBox("Automated actions")
        fl = QFormLayout(grp)

        self._block_brute = QCheckBox("Auto-block IPs that trigger brute-force detection")
        self._block_brute.setChecked(rem_cfg.get("auto_block_brute_force", False))

        self._block_c2 = QCheckBox("Auto-block IPs confirmed malicious by AbuseIPDB")
        self._block_c2.setChecked(rem_cfg.get("auto_block_c2", False))

        self._kill_proc = QCheckBox(
            "Auto-kill processes flagged as suspicious (use with caution)"
        )
        self._kill_proc.setChecked(rem_cfg.get("auto_kill_suspicious", False))

        fl.addRow(self._block_brute)
        fl.addRow(self._block_c2)
        fl.addRow(self._kill_proc)
        v.addWidget(grp)
        v.addStretch()
        return w

    # ------------------------------------------------------------------
    # Save

    def _save(self):
        cfg = dict(self._config)

        cfg.setdefault("notifications", {})["toast"] = self._toast_cb.isChecked()
        cfg.setdefault("tray", {})["close_to_tray"]  = self._close_to_tray_cb.isChecked()

        cfg.setdefault("thresholds", {})["failed_login_brute"]   = self._brute_count.value()
        cfg.setdefault("thresholds", {})["brute_window_seconds"]  = self._brute_window.value()

        cfg.setdefault("email", {}).update({
            "sender":       self._sender.text().strip(),
            "app_password": self._app_pass.text().strip(),
            "recipient":    self._recipient.text().strip(),
        })

        cfg.setdefault("threat_intel", {})["abuseipdb_api_key"] = \
            self._api_key.text().strip()

        cfg.setdefault("remediation", {}).update({
            "auto_block_brute_force": self._block_brute.isChecked(),
            "auto_block_c2":          self._block_c2.isChecked(),
            "auto_kill_suspicious":   self._kill_proc.isChecked(),
        })

        try:
            self._config_path.write_text(json.dumps(cfg, indent=2))
            self._config.update(cfg)
        except Exception as exc:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Save failed", str(exc))
            return

        self.accept()
