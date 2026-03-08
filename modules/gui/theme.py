"""
theme.py - Colour palette and Qt stylesheet for Security Commander GUI.

Dark theme tuned for Windows 10/11, high-contrast severity colours that
are readable at a glance (similar to Wireshark's colouring rules).
"""

from PyQt6.QtGui import QColor

# ---------------------------------------------------------------------------
# Severity row colours  (background, foreground)
# ---------------------------------------------------------------------------
ROW_COLORS = {
    "CRITICAL": (QColor("#4a0000"), QColor("#ff9090")),
    "HIGH":     (QColor("#3d2200"), QColor("#ffb347")),
    "MEDIUM":   (QColor("#2e2a00"), QColor("#ffe066")),
    "LOW":      (QColor("#002a2a"), QColor("#66dddd")),
    "INFO":     (QColor("#252535"), QColor("#b0b0c8")),
}

# Selected-row overlay (applied on top of severity colour)
SELECTED_BG = QColor("#4a90d9")
SELECTED_FG = QColor("#ffffff")

# ---------------------------------------------------------------------------
# App-wide stylesheet
# ---------------------------------------------------------------------------
STYLESHEET = """
QMainWindow, QDialog {
    background-color: #1a1a2e;
    color: #e0e0f0;
}

QWidget {
    background-color: #1a1a2e;
    color: #e0e0f0;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}

/* ---- Toolbar ---- */
QToolBar {
    background-color: #16213e;
    border-bottom: 1px solid #0f3460;
    padding: 4px 6px;
    spacing: 6px;
}

QToolButton {
    background-color: #0f3460;
    color: #e0e0f0;
    border: 1px solid #1a5276;
    border-radius: 4px;
    padding: 5px 12px;
    font-weight: 600;
}
QToolButton:hover  { background-color: #1a5276; }
QToolButton:pressed { background-color: #0d2137; }
QToolButton:disabled { color: #555577; background-color: #0d1b2a; }

/* ---- Filter bar ---- */
QLineEdit#filterBar {
    background-color: #0d1b2a;
    color: #e0e0f0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 5px 10px;
    font-family: "Consolas", monospace;
    font-size: 13px;
}
QLineEdit#filterBar:focus { border-color: #4a90d9; }

QPushButton#quickFilter {
    background-color: #0f3460;
    color: #a0a0c0;
    border: 1px solid #1a3a5c;
    border-radius: 3px;
    padding: 4px 10px;
    font-size: 12px;
}
QPushButton#quickFilter:checked {
    background-color: #4a90d9;
    color: #ffffff;
    border-color: #2e6fbf;
}
QPushButton#quickFilter:hover { background-color: #1a5276; }

/* ---- Tables ---- */
QTableView {
    background-color: #1e1e30;
    alternate-background-color: #252535;
    color: #c8c8e0;
    gridline-color: #2a2a40;
    border: none;
    selection-background-color: #4a90d9;
    selection-color: #ffffff;
    font-family: "Consolas", monospace;
    font-size: 12px;
}
QHeaderView::section {
    background-color: #16213e;
    color: #a0b0d0;
    border: none;
    border-right: 1px solid #0f3460;
    border-bottom: 1px solid #0f3460;
    padding: 6px 8px;
    font-weight: 700;
    font-size: 12px;
}
QHeaderView::section:hover { background-color: #1a3a5c; }

/* ---- Tabs ---- */
QTabWidget::pane {
    border: 1px solid #0f3460;
    background-color: #1e1e30;
}
QTabBar::tab {
    background-color: #16213e;
    color: #8090b0;
    border: 1px solid #0f3460;
    border-bottom: none;
    padding: 6px 16px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #1e1e30;
    color: #e0e0f0;
    border-bottom: 2px solid #4a90d9;
}
QTabBar::tab:hover { color: #c0d0f0; }

/* ---- Splitter ---- */
QSplitter::handle {
    background-color: #0f3460;
    height: 3px;
}
QSplitter::handle:hover { background-color: #4a90d9; }

/* ---- Detail / text areas ---- */
QTextEdit, QPlainTextEdit {
    background-color: #0d1b2a;
    color: #c0d0e0;
    border: none;
    font-family: "Consolas", monospace;
    font-size: 12px;
    padding: 8px;
}

/* ---- Status bar ---- */
QStatusBar {
    background-color: #0f1923;
    color: #6080a0;
    font-size: 12px;
    border-top: 1px solid #0f3460;
}
QStatusBar::item { border: none; }
QLabel#statusSep { color: #2a3a50; }

/* ---- Scrollbars ---- */
QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background-color: #2a3a5a;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background-color: #4a90d9; }
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background-color: #1a1a2e;
    height: 10px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background-color: #2a3a5a;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background-color: #4a90d9; }
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal { width: 0; }

/* ---- Dialogs / Settings ---- */
QGroupBox {
    border: 1px solid #0f3460;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
    color: #8090b0;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}

QCheckBox { spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #2a3a5a;
    border-radius: 3px;
    background-color: #0d1b2a;
}
QCheckBox::indicator:checked {
    background-color: #4a90d9;
    border-color: #2e6fbf;
    image: url(none);
}

QComboBox {
    background-color: #0d1b2a;
    border: 1px solid #1a3a5c;
    border-radius: 4px;
    padding: 4px 8px;
    color: #e0e0f0;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background-color: #16213e;
    selection-background-color: #4a90d9;
    border: 1px solid #0f3460;
}

QPushButton {
    background-color: #0f3460;
    color: #e0e0f0;
    border: 1px solid #1a5276;
    border-radius: 4px;
    padding: 6px 16px;
    font-weight: 600;
}
QPushButton:hover  { background-color: #1a5276; }
QPushButton:pressed { background-color: #0d2137; }

QPushButton#dangerBtn {
    background-color: #5c0a0a;
    border-color: #8a1010;
}
QPushButton#dangerBtn:hover { background-color: #7a1010; }

/* ---- Menu ---- */
QMenu {
    background-color: #16213e;
    border: 1px solid #0f3460;
    color: #e0e0f0;
}
QMenu::item:selected { background-color: #4a90d9; }
QMenu::separator { height: 1px; background-color: #0f3460; margin: 3px 0; }
"""
