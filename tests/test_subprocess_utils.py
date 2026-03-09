"""Tests for modules.subprocess_utils — hidden-window subprocess helpers."""

import subprocess
import sys

import pytest

from modules.subprocess_utils import hidden_window_kwargs, run_hidden


class TestHiddenWindowKwargs:
    def test_returns_dict(self):
        result = hidden_window_kwargs()
        assert isinstance(result, dict)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_windows_has_creationflags(self):
        kw = hidden_window_kwargs()
        assert "creationflags" in kw
        assert kw["creationflags"] == subprocess.CREATE_NO_WINDOW

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_windows_has_startupinfo(self):
        kw = hidden_window_kwargs()
        assert "startupinfo" in kw
        si = kw["startupinfo"]
        assert si.dwFlags & subprocess.STARTF_USESHOWWINDOW
        assert si.wShowWindow == 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_fresh_startupinfo_each_call(self):
        """Each call must return a new STARTUPINFO to be thread-safe."""
        kw1 = hidden_window_kwargs()
        kw2 = hidden_window_kwargs()
        assert kw1["startupinfo"] is not kw2["startupinfo"]

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_non_windows_returns_empty(self):
        assert hidden_window_kwargs() == {}


class TestRunHidden:
    def test_runs_simple_command(self):
        result = run_hidden([sys.executable, "--version"])
        assert result.returncode == 0
        # Python --version outputs to stdout (3.4+) or stderr (older)
        assert "Python" in (result.stdout + result.stderr)

    def test_captures_stdout(self):
        result = run_hidden(
            [sys.executable, "-c", "print('hello')"],
        )
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_captures_stderr(self):
        result = run_hidden(
            [sys.executable, "-c", "import sys; sys.stderr.write('oops')"],
        )
        assert "oops" in result.stderr

    def test_returns_nonzero_exit_code(self):
        result = run_hidden([sys.executable, "-c", "raise SystemExit(42)"])
        assert result.returncode == 42

    def test_timeout_raises(self):
        with pytest.raises(subprocess.TimeoutExpired):
            run_hidden(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=1,
            )

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            run_hidden(["this_command_does_not_exist_xyz"])

    def test_caller_kwargs_override_defaults(self):
        """Caller should be able to override capture_output, text, etc."""
        result = run_hidden(
            [sys.executable, "-c", "print('test')"],
            capture_output=False,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert "test" in result.stdout

    def test_custom_timeout(self):
        """Explicit timeout should be respected, not the default 15s."""
        result = run_hidden(
            [sys.executable, "-c", "print('fast')"],
            timeout=5,
        )
        assert result.returncode == 0
