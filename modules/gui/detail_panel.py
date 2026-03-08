"""
detail_panel.py - Bottom tab panel: Event Detail / Active Connections / Pinned Alerts.

Event Detail tab:
    Formatted view of the selected event's full details (all fields from
    SecurityEvent.details dict, formatted for readability).

Active Connections tab:
    Live table of current TCP/UDP connections mapped to process names.
    Refreshes every 2 seconds via the main window's QTimer.

Pinned Alerts tab:
    Table of unacknowledged HIGH/CRITICAL alerts loaded from AlertStore.
    "Acknowledge" button on each row; "Acknowledge All" clears the store.
"""

import json
import socket
from typing import List, Optional

import psutil
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

from ..events import SecurityEvent, Severity
from .theme import ROW_COLORS


def _item(text: str, color: Optional[QColor] = None,
          bold: bool = False, align_center: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(str(text))
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        it.setForeground(color)
    if bold:
        f = QFont("Consolas", 11)
        f.setBold(True)
        it.setFont(f)
    if align_center:
        it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return it


class DetailPanel(QTabWidget):
    def __init__(self, alert_store=None, parent=None):
        super().__init__(parent)
        self._alert_store = alert_store

        # --- Event Detail tab ---
        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setPlaceholderText(
            "Click any event row above to see its full details here."
        )
        self.addTab(self._detail_text, "Event Detail")

        # --- Active Connections tab ---
        self._conn_tab = _ConnectionsTab()
        self.addTab(self._conn_tab, "Active Connections")

        # --- Pinned Alerts tab ---
        self._alerts_tab = _AlertsTab(alert_store)
        self.addTab(self._alerts_tab, "Pinned Alerts")

        # Refresh connections and pinned alerts every 2 s
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_tabs)
        self._refresh_timer.start(2000)

        self._update_tab_labels()

    # ------------------------------------------------------------------

    def show_event(self, event: SecurityEvent):
        """Display full details of a selected event."""
        sev = event.severity.value
        _, fg = ROW_COLORS.get(sev, ROW_COLORS["INFO"])
        color = fg.name()

        lines = [
            f'<span style="font-size:14px;font-weight:700;color:{color}">'
            f'[{sev}] {event.event_type.value}</span>',
            f'<span style="color:#8090b0">{event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</span>',
            "",
            f'<b style="color:#a0c0e0">Source:</b> {event.source}',
            f'<b style="color:#a0c0e0">Description:</b> {event.description}',
        ]
        if event.remediated:
            lines.append('<b style="color:#2ecc71">Auto-remediated: yes</b>')

        if event.details:
            lines.append("")
            lines.append('<b style="color:#a0c0e0">Details:</b>')
            for k, v in event.details.items():
                if isinstance(v, (dict, list)):
                    v = json.dumps(v, indent=2)
                lines.append(f'  <span style="color:#6090b0">{k}:</span> {v}')

        self._detail_text.setHtml(
            '<div style="font-family:Consolas,monospace;font-size:12px;'
            'color:#c0d0e0;line-height:1.6">'
            + "<br>".join(lines) + "</div>"
        )
        self.setCurrentIndex(0)

    def refresh_alerts(self):
        self._alerts_tab.refresh()
        self._update_tab_labels()

    # ------------------------------------------------------------------

    def _refresh_tabs(self):
        if self.currentIndex() == 1:
            self._conn_tab.refresh()
        elif self.currentIndex() == 2:
            self._alerts_tab.refresh()
        self._update_tab_labels()

    def _update_tab_labels(self):
        count = self._alert_store.count() if self._alert_store else 0
        label = f"Pinned Alerts ({count})" if count else "Pinned Alerts"
        self.setTabText(2, label)


# ---------------------------------------------------------------------------
# Active Connections sub-widget
# ---------------------------------------------------------------------------

class _ConnectionsTab(QWidget):
    HEADERS = ["Process", "PID", "Local Port", "Remote Host", "Remote IP", "Port", "Proto"]

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, len(self.HEADERS))
        self._table.setHorizontalHeaderLabels(self.HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setSortingEnabled(True)
        layout.addWidget(self._table)

        self.refresh()

    def refresh(self):
        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ("ESTABLISHED", "LISTEN") and conn.laddr:
                    try:
                        name = psutil.Process(conn.pid).name() if conn.pid else "?"
                        pid  = str(conn.pid or "")
                    except Exception:
                        name, pid = "?", str(conn.pid or "")

                    remote_ip   = conn.raddr.ip   if conn.raddr else ""
                    remote_port = str(conn.raddr.port) if conn.raddr else ""
                    try:
                        remote_host = socket.gethostbyaddr(remote_ip)[0] if remote_ip else ""
                    except Exception:
                        remote_host = remote_ip

                    connections.append((
                        name, pid,
                        str(conn.laddr.port),
                        remote_host, remote_ip, remote_port,
                        "TCP" if conn.type == 1 else "UDP",
                    ))
        except psutil.AccessDenied:
            connections = [("(run as admin for full list)", "", "", "", "", "", "")]

        self._table.setRowCount(len(connections))
        for r, row in enumerate(connections):
            for c, val in enumerate(row):
                it = QTableWidgetItem(val)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._table.setItem(r, c, it)


# ---------------------------------------------------------------------------
# Pinned Alerts sub-widget
# ---------------------------------------------------------------------------

class _AlertsTab(QWidget):
    HEADERS = ["Time", "Severity", "Type", "Source", "Description", ""]

    def __init__(self, alert_store, parent=None):
        super().__init__(parent)
        self._alert_store = alert_store

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Header row with Acknowledge All button
        hdr = QHBoxLayout()
        hdr.addWidget(QLabel("Unacknowledged HIGH / CRITICAL alerts — persist across restarts"))
        hdr.addStretch()
        ack_all = QPushButton("Acknowledge All")
        ack_all.setObjectName("dangerBtn")
        ack_all.clicked.connect(self._acknowledge_all)
        hdr.addWidget(ack_all)
        layout.addLayout(hdr)

        self._table = QTableWidget(0, len(self.HEADERS))
        self._table.setHorizontalHeaderLabels(self.HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        layout.addWidget(self._table)

        self.refresh()

    def refresh(self):
        if not self._alert_store:
            return
        alerts = self._alert_store.get_all()
        self._table.setRowCount(len(alerts))

        sev_colors = {
            "CRITICAL": QColor("#ff9090"),
            "HIGH":     QColor("#ffb347"),
            "MEDIUM":   QColor("#ffe066"),
        }

        for r, alert in enumerate(alerts):
            ts    = alert.get("timestamp", "")[:19]
            sev   = alert.get("severity", "")
            color = sev_colors.get(sev, QColor("#c0d0e0"))

            self._table.setItem(r, 0, _item(ts[11:19] if len(ts) > 10 else ts, color))
            self._table.setItem(r, 1, _item(sev,                  color, bold=True, align_center=True))
            self._table.setItem(r, 2, _item(alert.get("event_type", ""), color, align_center=True))
            self._table.setItem(r, 3, _item(alert.get("source", "")[:20], color))
            self._table.setItem(r, 4, _item(alert.get("description", "")[:80], color))

            btn = QPushButton("Ack")
            btn.setFixedWidth(50)
            btn.clicked.connect(lambda _, k=alert["key"]: self._acknowledge(k))
            self._table.setCellWidget(r, 5, btn)

    def _acknowledge(self, key: str):
        if self._alert_store:
            self._alert_store.acknowledge(key)
        self.refresh()

    def _acknowledge_all(self):
        if self._alert_store:
            self._alert_store.acknowledge_all()
        self.refresh()
