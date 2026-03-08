"""
tray_icon.py - System tray icon with dynamic threat-level colour.

Icon colour:
    Green  (#2ecc71) — no unacknowledged HIGH/CRITICAL alerts
    Amber  (#f39c12) — HIGH alerts present
    Red    (#e74c3c) — CRITICAL alerts present

Right-click menu:
    Open Security Commander
    ─────────────────────
    Status: <summary line>
    ─────────────────────
    Acknowledge All Alerts
    ─────────────────────
    Exit
"""

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon


def _make_icon(color: str, size: int = 64) -> QIcon:
    """Draw a filled circle of the given hex colour."""
    px = QPixmap(QSize(size, size))
    px.fill(Qt.GlobalColor.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(QColor("#ffffff"))
    margin = size // 8
    painter.drawEllipse(margin, margin, size - 2 * margin, size - 2 * margin)
    painter.end()
    return QIcon(px)


_ICON_GREEN = _make_icon("#2ecc71")
_ICON_AMBER = _make_icon("#f39c12")
_ICON_RED   = _make_icon("#e74c3c")


class TrayIcon(QSystemTrayIcon):
    open_requested       = pyqtSignal()
    acknowledge_requested = pyqtSignal()
    exit_requested       = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(_ICON_GREEN, parent)
        self.setToolTip("Security Commander — All clear")
        self._build_menu()
        self.activated.connect(self._on_activate)

    # ------------------------------------------------------------------

    def update_status(self, critical: int, high: int, total: int):
        """Call whenever threat counts change."""
        if critical > 0:
            self.setIcon(_ICON_RED)
            self.setToolTip(
                f"Security Commander — {critical} CRITICAL, {high} HIGH alerts"
            )
        elif high > 0:
            self.setIcon(_ICON_AMBER)
            self.setToolTip(f"Security Commander — {high} HIGH alerts")
        else:
            self.setIcon(_ICON_GREEN)
            self.setToolTip(f"Security Commander — All clear ({total} events)")

        self._status_action.setText(
            f"Events: {total}  |  Critical: {critical}  High: {high}"
        )

    # ------------------------------------------------------------------

    def _build_menu(self):
        menu = QMenu()

        open_action = menu.addAction("Open Security Commander")
        open_action.triggered.connect(self.open_requested)

        menu.addSeparator()

        self._status_action = menu.addAction("Events: 0  |  Critical: 0  High: 0")
        self._status_action.setEnabled(False)

        menu.addSeparator()

        ack_action = menu.addAction("Acknowledge All Alerts")
        ack_action.triggered.connect(self.acknowledge_requested)

        menu.addSeparator()

        exit_action = menu.addAction("Exit")
        exit_action.triggered.connect(self.exit_requested)

        self.setContextMenu(menu)

    def _on_activate(self, reason: QSystemTrayIcon.ActivationReason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.open_requested.emit()
