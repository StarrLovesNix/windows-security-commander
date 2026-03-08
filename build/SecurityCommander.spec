# SecurityCommander.spec - PyInstaller build specification
#
# Run from the project root:
#   pyinstaller build/SecurityCommander.spec
#
# Output: dist/SecurityCommander/  (folder containing the packaged app)
#         dist/SecurityCommander/SecurityCommander.exe  (main executable)

import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent   # project root (one level up from build/)

# Locate PyQt6 plugins dynamically — works regardless of venv/install location
import PyQt6 as _pyqt6
_qt6_plugins = str(Path(_pyqt6.__file__).parent / 'Qt6' / 'plugins')

block_cipher = None

a = Analysis(
    [str(ROOT / 'gui.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        # Ship the example config so first-run setup works
        (str(ROOT / 'config.json.example'), '.'),
        # PyQt6 platform and style plugins (required for windowed apps)
        (_qt6_plugins, 'PyQt6/Qt6/plugins'),
    ],
    hiddenimports=[
        # pywin32 modules loaded at runtime
        'win32evtlog',
        'win32evtlogutil',
        'win32con',
        'pywintypes',
        'win32api',
        # PyQt6 platform plugin
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        # Our modules
        'modules.events',
        'modules.connection_monitor',
        'modules.dns_monitor',
        'modules.process_monitor',
        'modules.event_log_monitor',
        'modules.network_scanner',
        'modules.threat_intel',
        'modules.firewall_manager',
        'modules.remediation',
        'modules.baseline',
        'modules.alert_history',
        'modules.alert_store',
        'modules.notifier',
        'modules.session_logger',
        'modules.gui',
        'modules.gui.main_window',
        'modules.gui.event_model',
        'modules.gui.tray_icon',
        'modules.gui.detail_panel',
        'modules.gui.settings_dialog',
        'modules.gui.theme',
        # Standard library modules that PyInstaller sometimes misses
        'sqlite3',
        'smtplib',
        'email.mime.multipart',
        'email.mime.text',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim unused large packages to keep installer smaller
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'tkinter',
        'unittest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SecurityCommander',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # Compress with UPX if available (reduces size ~30%)
    console=False,      # No black terminal window when launched from desktop
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'assets' / 'icon.ico'),
    version=str(ROOT / 'build' / 'version_info.txt'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SecurityCommander',
)
