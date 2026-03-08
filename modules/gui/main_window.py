"""
main_window.py - QMainWindow for Security Commander.

Layout:
    toolbar         → Start/Stop, Baseline, History, Acknowledge, Settings
    filter bar      → text field + quick-filter buttons (All/CRIT/HIGH/CONN/LOGIN)
    QSplitter
        top    → event table (EventModel + EventFilterProxy + QTableView)
        bottom → DetailPanel (Event Detail / Active Connections / Pinned Alerts)
    status bar      → live counters

The window drains the event_queue every 250 ms via a QTimer on the main thread,
so all model/UI mutations happen in the Qt event loop with no extra locking.
"""

import queue
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import psutil
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QAction, QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QPushButton, QSizePolicy,
    QSplitter, QStatusBar, QTableView, QToolBar,
    QVBoxLayout, QWidget,
)

from ..events import EventType, SecurityEvent, Severity, event_queue
from .detail_panel    import DetailPanel
from .event_model     import EventFilterProxy, EventModel
from .settings_dialog import SettingsDialog
from .tray_icon       import TrayIcon


class MainWindow(QMainWindow):
    def __init__(
        self,
        config: dict,
        config_path: Path,
        alert_store,
        session_logger,
        alert_history,
        threat_intel,
        remediator,
        notifier,
        monitors: list,
    ):
        super().__init__()
        self._config        = config
        self._config_path   = config_path
        self._alert_store   = alert_store
        self._session_logger = session_logger
        self._alert_history = alert_history
        self._threat_intel  = threat_intel
        self._remediator    = remediator
        self._notifier      = notifier
        self._monitors      = monitors
        self._session_events: List[SecurityEvent] = []
        self._monitoring    = True

        self.setWindowTitle("Security Commander")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)

        self._build_ui()
        self._build_tray()

        # Drain event_queue on the main thread every 250 ms
        self._queue_timer = QTimer(self)
        self._queue_timer.timeout.connect(self._drain_queue)
        self._queue_timer.start(250)

        # Refresh status bar every 1 s
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start(1000)

    # ------------------------------------------------------------------
    # UI construction

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_filter_bar())

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._build_event_table())
        self._detail_panel = DetailPanel(self._alert_store)
        splitter.addWidget(self._detail_panel)
        splitter.setSizes([520, 220])
        root.addWidget(splitter, 1)

        self._build_status_bar()

    def _build_toolbar(self) -> QToolBar:
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)

        self._start_action = QAction("▶  Start", self)
        self._start_action.setEnabled(False)   # starts already running
        self._start_action.triggered.connect(self._start_monitoring)
        tb.addAction(self._start_action)

        self._stop_action = QAction("■  Stop", self)
        self._stop_action.triggered.connect(self._stop_monitoring)
        tb.addAction(self._stop_action)

        tb.addSeparator()

        baseline_action = QAction("Baseline", self)
        baseline_action.setToolTip("Capture a new security baseline snapshot")
        baseline_action.triggered.connect(self._capture_baseline)
        tb.addAction(baseline_action)

        history_action = QAction("History", self)
        history_action.setToolTip("Open the event history database browser")
        history_action.triggered.connect(self._open_history)
        tb.addAction(history_action)

        ack_action = QAction("Acknowledge All", self)
        ack_action.setToolTip("Clear all pinned alerts")
        ack_action.triggered.connect(self._acknowledge_all)
        tb.addAction(ack_action)

        tb.addSeparator()

        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self._open_settings)
        tb.addAction(settings_action)

        return tb

    def _build_filter_bar(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet("background-color: #16213e; padding: 4px 8px;")
        h = QHBoxLayout(container)
        h.setContentsMargins(8, 4, 8, 4)
        h.setSpacing(6)

        label = QLabel("Filter:")
        label.setStyleSheet("color: #6080a0; font-size: 12px;")
        h.addWidget(label)

        self._filter_input = QLineEdit()
        self._filter_input.setObjectName("filterBar")
        self._filter_input.setPlaceholderText(
            "severity:critical   type:conn   source:chrome   192.168.1.1"
            "   (space = AND)"
        )
        self._filter_input.textChanged.connect(self._on_filter_changed)
        self._filter_input.setMinimumWidth(340)
        h.addWidget(self._filter_input, 1)

        # Quick-filter buttons
        for label_text, severity in [
            ("All",      None),
            ("CRITICAL", "CRITICAL"),
            ("HIGH",     "HIGH"),
            ("CONN",     None),     # handled specially
            ("LOGIN",    None),
        ]:
            btn = QPushButton(label_text)
            btn.setObjectName("quickFilter")
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            if label_text == "All":
                btn.setChecked(True)
            btn.clicked.connect(
                lambda checked, lbl=label_text, sev=severity:
                self._on_quick_filter(lbl, sev)
            )
            h.addWidget(btn)

        return container

    def _build_event_table(self) -> QWidget:
        self._model = EventModel()
        self._proxy = EventFilterProxy()
        self._proxy.setSourceModel(self._model)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(False)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.setShowGrid(False)

        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)   # Description stretches

        # Initial column widths
        widths = [80, 90, 80, 110, 150, 0, 45]
        for i, w in enumerate(widths):
            if w:
                self._table.setColumnWidth(i, w)

        self._table.selectionModel().currentRowChanged.connect(self._on_row_selected)

        # Auto-scroll toggle
        self._auto_scroll = True
        self._model.row_added.connect(self._maybe_scroll)

        return self._table

    def _build_status_bar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)

        def _lbl(text=""):
            l = QLabel(text)
            l.setStyleSheet("color: #8090a8; font-size: 12px; padding: 0 8px;")
            return l

        def _sep():
            s = QLabel("|")
            s.setObjectName("statusSep")
            s.setStyleSheet("color: #2a3a50; padding: 0 2px;")
            return s

        self._st_events   = _lbl("Events: 0")
        self._st_critical = _lbl("CRITICAL: 0")
        self._st_high     = _lbl("HIGH: 0")
        self._st_conns    = _lbl("Connections: —")
        self._st_cpu      = _lbl("CPU: —")
        self._st_mem      = _lbl("MEM: —")
        self._st_status   = _lbl("Monitoring")

        for w in [
            self._st_events, _sep(),
            self._st_critical, _sep(),
            self._st_high, _sep(),
            self._st_conns, _sep(),
            self._st_cpu, _sep(),
            self._st_mem, _sep(),
            self._st_status,
        ]:
            sb.addWidget(w)

        sb.addPermanentWidget(_lbl(socket.gethostname()))

    def _build_tray(self):
        self._tray = TrayIcon(self)
        self._tray.open_requested.connect(self.show_and_raise)
        self._tray.acknowledge_requested.connect(self._acknowledge_all)
        self._tray.exit_requested.connect(self._full_exit)
        self._tray.show()

    # ------------------------------------------------------------------
    # Event queue draining (main thread, 250 ms interval)

    @pyqtSlot()
    def _drain_queue(self):
        processed = 0
        while processed < 200:   # cap per-tick to avoid UI freeze on burst
            try:
                event = event_queue.get_nowait()
            except queue.Empty:
                break

            # Threat intel enrichment
            if event.event_type == EventType.CONN_NEW:
                remote_ip = event.details.get("remote_ip", "")
                if remote_ip:
                    is_mal, score, _ = self._threat_intel.check_ip(remote_ip)
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

            # Remediation
            self._remediator.process_event(event)

            # Persistent logging (text + SQLite) — every event, always
            self._session_logger.record(event)

            # Persistent alert store
            self._alert_store.consider(event)

            # Cooldown-aware toast notifications
            if self._alert_history.should_alert(event):
                self._alert_history.record(event)
                if event.severity in (Severity.HIGH, Severity.CRITICAL):
                    self._notifier.toast(
                        f"{event.severity.value} Alert",
                        event.description,
                        event.severity,
                    )

            # Add to model (triggers table refresh)
            self._model.add_event(event)
            self._session_events.append(event)
            processed += 1

        # Update tray icon after processing batch
        if processed > 0:
            self._update_tray()
            self._detail_panel.refresh_alerts()

    # ------------------------------------------------------------------
    # Slots

    @pyqtSlot()
    def _on_filter_changed(self):
        self._proxy.set_filter(self._filter_input.text())

    def _on_quick_filter(self, label: str, severity: Optional[str]):
        if label == "All":
            self._proxy.set_quick_severity(None)
            self._filter_input.clear()
        elif label == "CONN":
            self._proxy.set_quick_severity(None)
            self._filter_input.setText("type:conn")
        elif label == "LOGIN":
            self._proxy.set_quick_severity(None)
            self._filter_input.setText("type:login")
        else:
            self._proxy.set_quick_severity(severity)
            self._filter_input.clear()

    @pyqtSlot()
    def _on_row_selected(self):
        idx = self._table.currentIndex()
        if not idx.isValid():
            return
        source_idx = self._proxy.mapToSource(idx)
        event = self._model.get_event(source_idx.row())
        if event:
            self._detail_panel.show_event(event)

    @pyqtSlot()
    def _maybe_scroll(self):
        if self._auto_scroll:
            self._table.scrollToTop()

    @pyqtSlot()
    def _update_status_bar(self):
        events = self._model.all_events()
        crit   = sum(1 for e in events if e.severity == Severity.CRITICAL)
        high   = sum(1 for e in events if e.severity == Severity.HIGH)

        try:
            conn_count = len([c for c in psutil.net_connections(kind="inet")
                              if c.status == "ESTABLISHED"])
        except Exception:
            conn_count = 0

        try:
            cpu = f"{psutil.cpu_percent(interval=None):.0f}%"
            mem = f"{psutil.virtual_memory().percent:.0f}%"
        except Exception:
            cpu = mem = "—"

        self._st_events.setText(f"Events: {len(events)}")
        self._st_critical.setText(f"CRITICAL: {crit}")
        self._st_critical.setStyleSheet(
            f"color: {'#ff6060' if crit else '#8090a8'}; font-size:12px; padding:0 8px;"
        )
        self._st_high.setText(f"HIGH: {high}")
        self._st_high.setStyleSheet(
            f"color: {'#ffb347' if high else '#8090a8'}; font-size:12px; padding:0 8px;"
        )
        self._st_conns.setText(f"Connections: {conn_count}")
        self._st_cpu.setText(f"CPU: {cpu}")
        self._st_mem.setText(f"MEM: {mem}")

    def _update_tray(self):
        events = self._model.all_events()
        crit   = sum(1 for e in events if e.severity == Severity.CRITICAL)
        high   = sum(1 for e in events if e.severity == Severity.HIGH)
        self._tray.update_status(crit, high, len(events))

    # ------------------------------------------------------------------
    # Toolbar actions

    @pyqtSlot()
    def _start_monitoring(self):
        for m in self._monitors:
            m.start()
        self._start_action.setEnabled(False)
        self._stop_action.setEnabled(True)
        self._st_status.setText("Monitoring")
        self._monitoring = True

    @pyqtSlot()
    def _stop_monitoring(self):
        for m in self._monitors:
            m.stop()
        self._start_action.setEnabled(True)
        self._stop_action.setEnabled(False)
        self._st_status.setText("Stopped")
        self._monitoring = False

    @pyqtSlot()
    def _capture_baseline(self):
        from PyQt6.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            self, "Capture Baseline",
            "Capture a new security baseline snapshot?\n\n"
            "This records current listening ports, services, scheduled tasks,\n"
            "and user accounts as the 'normal' state to compare against.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            from ..baseline import Baseline
            b = Baseline(self._config, self._session_logger._data_dir)
            result = b.capture()
            QMessageBox.information(
                self, "Baseline Captured",
                f"Baseline saved.\n\n"
                f"  Listening ports:  {len(result['listening_ports'])}\n"
                f"  Running services: {len(result['services'])}\n"
                f"  Scheduled tasks:  {len(result['scheduled_tasks'])}\n"
                f"  Local users:      {len(result['local_users'])}",
            )

    @pyqtSlot()
    def _open_history(self):
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QComboBox, QDialogButtonBox
        dlg = QDialog(self)
        dlg.setWindowTitle("Event History Browser")
        dlg.setMinimumSize(1100, 650)
        v = QVBoxLayout(dlg)

        rows = self._session_logger.query_recent(limit=5000)
        if not rows:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No history",
                                    "No events in database yet.")
            return

        # Embed a read-only table
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        tbl = QTableWidget(len(rows), 5)
        tbl.setHorizontalHeaderLabels(
            ["Timestamp", "Severity", "Type", "Source", "Description"]
        )
        tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        tbl.setSortingEnabled(True)

        from PyQt6.QtGui import QColor
        sev_colors = {
            "CRITICAL": QColor("#ff9090"),
            "HIGH":     QColor("#ffb347"),
            "MEDIUM":   QColor("#ffe066"),
            "LOW":      QColor("#66dddd"),
        }
        for r, row in enumerate(rows):
            sev   = row.get("severity", "")
            color = sev_colors.get(sev)
            for c, val in enumerate([
                row.get("timestamp", "")[:19],
                sev,
                row.get("event_type", ""),
                row.get("source", ""),
                row.get("description", ""),
            ]):
                it = QTableWidgetItem(str(val))
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if color:
                    it.setForeground(color)
                tbl.setItem(r, c, it)

        v.addWidget(tbl)
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn.rejected.connect(dlg.reject)
        v.addWidget(btn)
        dlg.exec()

    @pyqtSlot()
    def _acknowledge_all(self):
        self._alert_store.acknowledge_all()
        self._detail_panel.refresh_alerts()
        self._update_tray()

    @pyqtSlot()
    def _open_settings(self):
        dlg = SettingsDialog(self._config, self._config_path, self)
        dlg.exec()

    # ------------------------------------------------------------------
    # Window close / tray behaviour

    def closeEvent(self, event: QCloseEvent):
        close_to_tray = self._config.get("tray", {}).get("close_to_tray", True)
        if close_to_tray and self._tray.isSystemTrayAvailable():
            self.hide()
            event.ignore()
        else:
            self._full_exit()

    @pyqtSlot()
    def show_and_raise(self):
        self.show()
        self.activateWindow()
        self.raise_()

    @pyqtSlot()
    def _full_exit(self):
        """Stop everything, save report, quit."""
        self._queue_timer.stop()
        self._status_timer.stop()
        if self._monitoring:
            for m in self._monitors:
                m.stop()

        events = self._session_events
        if events:
            from pathlib import Path
            reports_dir = self._session_logger._data_dir.parent / "reports"
            reports_dir.mkdir(exist_ok=True)
            report_path = reports_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            report_path.write_text(
                self._notifier._build_html(events, socket.gethostname()),
                encoding="utf-8",
            )
            self._session_logger.write_csv_export(events)

        self._session_logger.close()
        self._tray.hide()
        QApplication.quit()
