"""
event_model.py - Qt table model for the live event stream.

EventModel      — QAbstractTableModel backed by a deque of SecurityEvent objects.
                  Thread-safe insertions via Qt signal so the view refreshes
                  automatically on the main thread.

EventFilterProxy — QSortFilterProxyModel implementing Wireshark-style filter
                   syntax on top of EventModel.

Filter syntax (case-insensitive, space-separated AND logic):
    chrome                    any column contains "chrome"
    severity:high             severity equals HIGH
    type:conn                 event_type contains "conn"
    source:svchost            source contains "svchost"
    192.168.1.5               any column contains that string
    severity:critical type:threat   combined filter
"""

import re
from collections import deque
from typing import Any, Deque, List, Optional

from PyQt6.QtCore import (
    QAbstractTableModel, QModelIndex, QSortFilterProxyModel,
    Qt, QVariant, pyqtSignal,
)
from PyQt6.QtGui import QColor, QFont

from ..events import SecurityEvent, Severity
from .theme import ROW_COLORS, SELECTED_BG, SELECTED_FG

# Column definitions: (header label, attribute path or callable)
COLUMNS = [
    ("Time",        lambda e: e.timestamp.strftime("%H:%M:%S")),
    ("Date",        lambda e: e.timestamp.strftime("%Y-%m-%d")),
    ("Severity",    lambda e: e.severity.value),
    ("Type",        lambda e: e.event_type.value),
    ("Source",      lambda e: e.source),
    ("Description", lambda e: e.description),
    ("Fixed",       lambda e: "✓" if e.remediated else ""),
]

COL_TIME        = 0
COL_DATE        = 1
COL_SEVERITY    = 2
COL_TYPE        = 3
COL_SOURCE      = 4
COL_DESCRIPTION = 5
COL_FIXED       = 6

MAX_ROWS = 10_000   # Keep memory bounded; oldest rows drop off the top


class EventModel(QAbstractTableModel):
    """
    Append-only table model for SecurityEvent objects.
    Call add_event() from the main thread (connect via signal from worker).
    """

    row_added = pyqtSignal()   # emitted after each insertion (for auto-scroll)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: Deque[SecurityEvent] = deque(maxlen=MAX_ROWS)
        self._mono = QFont("Consolas", 11)

    # ------------------------------------------------------------------
    # Qt interface

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                return COLUMNS[section][0]
            if role == Qt.ItemDataRole.FontRole:
                f = QFont("Segoe UI", 11)
                f.setBold(True)
                return f
        return QVariant()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()

        row = index.row()
        col = index.column()

        # Events stored newest-first for correct display order
        try:
            event: SecurityEvent = list(self._events)[-(row + 1)]
        except IndexError:
            return QVariant()

        if role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[col][1](event)

        if role == Qt.ItemDataRole.BackgroundRole:
            bg, _ = ROW_COLORS.get(event.severity.value, ROW_COLORS["INFO"])
            return bg

        if role == Qt.ItemDataRole.ForegroundRole:
            _, fg = ROW_COLORS.get(event.severity.value, ROW_COLORS["INFO"])
            return fg

        if role == Qt.ItemDataRole.FontRole:
            return self._mono

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (COL_TIME, COL_DATE, COL_SEVERITY, COL_TYPE, COL_FIXED):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        # Expose the raw SecurityEvent for detail panel access
        if role == Qt.ItemDataRole.UserRole:
            return event

        return QVariant()

    # ------------------------------------------------------------------
    # Public API

    def add_event(self, event: SecurityEvent):
        """Must be called on the main thread."""
        # New rows prepend visually (newest at top), so insert at row 0.
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._events.append(event)
        self.endInsertRows()
        self.row_added.emit()

    def get_event(self, visual_row: int) -> Optional[SecurityEvent]:
        """Return the SecurityEvent for a given visual row index."""
        events_list = list(self._events)
        idx = len(events_list) - 1 - visual_row
        if 0 <= idx < len(events_list):
            return events_list[idx]
        return None

    def all_events(self) -> List[SecurityEvent]:
        return list(self._events)

    def clear(self):
        self.beginResetModel()
        self._events.clear()
        self.endResetModel()


# ---------------------------------------------------------------------------
# Filter proxy
# ---------------------------------------------------------------------------

_FIELD_RE = re.compile(r'(\w+):(\S+)')


class EventFilterProxy(QSortFilterProxyModel):
    """
    Wireshark-style display filter. Applied live as text changes.

    Supports:
        bare text        → matches any column (substring, case-insensitive)
        field:value      → severity: type: source: (substring match)
        Multiple terms   → AND logic (all must match)
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""
        self._quick_severity: Optional[str] = None   # set by quick-filter buttons
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setDynamicSortFilter(True)

    def set_filter(self, text: str):
        self._filter_text = text.strip().lower()
        self.invalidateFilter()

    def set_quick_severity(self, severity: Optional[str]):
        """None clears the quick filter."""
        self._quick_severity = severity
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: EventModel = self.sourceModel()
        event = model.get_event(source_row)
        if event is None:
            return False

        # Quick-filter button takes precedence
        if self._quick_severity:
            if event.severity.value != self._quick_severity:
                return False

        if not self._filter_text:
            return True

        # Build searchable fields dict
        fields = {
            "severity": event.severity.value.lower(),
            "type":     event.event_type.value.lower(),
            "source":   event.source.lower(),
            "desc":     event.description.lower(),
            "description": event.description.lower(),
            # detail sub-fields
            "ip":       event.details.get("remote_ip", "").lower(),
            "host":     event.details.get("hostname", "").lower(),
            "process":  event.details.get("process", "").lower(),
        }
        all_text = " ".join(fields.values())

        # Parse terms
        terms = self._filter_text.split()
        for term in terms:
            m = _FIELD_RE.match(term)
            if m:
                field_name, value = m.group(1), m.group(2)
                target = fields.get(field_name, all_text)
                if value not in target:
                    return False
            else:
                # Bare term — match against all fields
                if term not in all_text:
                    return False

        return True
