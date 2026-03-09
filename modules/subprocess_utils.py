"""
subprocess_utils.py - Hidden-window subprocess helpers for Windows.

Provides a convenience runner that suppresses the console window flash
that otherwise appears every time PowerShell, netsh, arp, or other
console programs are spawned from a GUI application.
"""

import subprocess
import sys
from typing import Any, Dict, List


def hidden_window_kwargs() -> Dict[str, Any]:
    """Return subprocess.run keyword arguments that suppress console windows.

    On Windows, returns creationflags and startupinfo.
    On other platforms, returns an empty dict (no-op).
    """
    if sys.platform != "win32":
        return {}

    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE

    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": si,
    }


def run_hidden(
    args: List[str],
    *,
    capture_output: bool = True,
    text: bool = True,
    timeout: int = 15,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """subprocess.run() wrapper that hides the console window on Windows."""
    merged = {
        "capture_output": capture_output,
        "text": text,
        "timeout": timeout,
    }
    merged.update(hidden_window_kwargs())
    merged.update(kwargs)  # caller overrides win
    return subprocess.run(args, **merged)
