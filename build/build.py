"""
build.py - Automated build script for Security Commander.

Produces SecurityCommander-Setup.exe in the dist/ directory.

Steps:
    1. Check Python version and required tools
    2. Install / verify build dependencies (PyInstaller, Pillow)
    3. Generate the application icon (assets/icon.ico)
    4. Run PyInstaller to bundle the app into dist/SecurityCommander/
    5. Run Inno Setup compiler (ISCC.exe) to produce the installer
    6. Print summary with output path and file size

Usage (run from project root):
    python build/build.py

Or from the build/ directory:
    cd build && python build.py

Requirements on the build machine:
    - Python 3.10+
    - Internet access (for pip installs on first run)
    - Inno Setup 6  https://jrsoftware.org/isinfo.php  (for step 5)
      If not installed, step 5 is skipped and a portable folder is produced.
"""

import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).parent
ROOT        = SCRIPT_DIR.parent
ASSETS_DIR  = ROOT / "assets"
DIST_DIR    = ROOT / "dist"
BUILD_WORK  = ROOT / "build_work"   # PyInstaller working directory

SPEC_FILE   = SCRIPT_DIR / "SecurityCommander.spec"
ISS_FILE    = SCRIPT_DIR / "installer.iss"
ICON_FILE   = ASSETS_DIR / "icon.ico"

# Common Inno Setup install locations
ISCC_PATHS = [
    Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
    Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
    Path(r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe"),
    shutil.which("ISCC") and Path(shutil.which("ISCC")),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    print(f"\n  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=check, **kwargs)


def _find_iscc() -> Path | None:
    for p in ISCC_PATHS:
        if p and p.exists():
            return p
    return None


def _pip_install(*packages: str):
    _run([sys.executable, "-m", "pip", "install", "--quiet", *packages])


def _section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Build steps
# ---------------------------------------------------------------------------

def step_check_python():
    _section("Step 1 — Check Python version")
    if sys.version_info < (3, 10):
        print(f"[FAIL] Python 3.10+ required. You have {sys.version}")
        sys.exit(1)
    print(f"[OK] Python {sys.version.split()[0]}")


def step_install_build_deps():
    _section("Step 2 — Install build dependencies")
    _pip_install("pyinstaller", "Pillow")
    print("[OK] PyInstaller and Pillow ready")


def step_install_app_deps():
    _section("Step 2b — Install application dependencies")
    req = ROOT / "requirements.txt"
    _run([sys.executable, "-m", "pip", "install", "--quiet", "-r", str(req)])
    print("[OK] Application dependencies installed")


def step_generate_icon():
    _section("Step 3 — Generate application icon")
    ASSETS_DIR.mkdir(exist_ok=True)
    _run([sys.executable, str(SCRIPT_DIR / "make_icon.py")])
    if not ICON_FILE.exists():
        print("[WARN] Icon not generated — build will use default icon")
    else:
        print(f"[OK] Icon: {ICON_FILE}")


def step_pyinstaller():
    _section("Step 4 — PyInstaller packaging")

    # Clean previous build artefacts
    for d in (DIST_DIR / "SecurityCommander", BUILD_WORK):
        if d.exists():
            shutil.rmtree(d)
            print(f"  Cleaned: {d}")

    _run([
        sys.executable, "-m", "PyInstaller",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_WORK),
        "--noconfirm",
        str(SPEC_FILE),
    ], cwd=str(ROOT))

    bundle = DIST_DIR / "SecurityCommander"
    if not bundle.exists():
        print("[FAIL] PyInstaller did not produce expected output")
        sys.exit(1)

    exe = bundle / "SecurityCommander.exe"
    size_mb = sum(f.stat().st_size for f in bundle.rglob("*") if f.is_file()) / 1_048_576
    print(f"\n[OK] Bundle: {bundle}")
    print(f"     Size:   {size_mb:.1f} MB")
    print(f"     Exe:    {exe}")


def step_inno_setup():
    _section("Step 5 — Inno Setup installer")

    iscc = _find_iscc()
    if not iscc:
        print(
            "[SKIP] Inno Setup not found.\n"
            "       Install from: https://jrsoftware.org/isdl.php\n"
            "       Then re-run this script to produce SecurityCommander-Setup.exe\n"
            "\n"
            "       For now, a portable ZIP is being created instead..."
        )
        _make_portable_zip()
        return

    print(f"  Using ISCC: {iscc}")
    _run([str(iscc), str(ISS_FILE)], cwd=str(ROOT))

    installer = DIST_DIR / "SecurityCommander-Setup.exe"
    if installer.exists():
        size_mb = installer.stat().st_size / 1_048_576
        print(f"\n[OK] Installer: {installer}")
        print(f"     Size:       {size_mb:.1f} MB")
    else:
        print("[WARN] Inno Setup ran but installer not found at expected path")


def _make_portable_zip():
    """Fallback: zip the PyInstaller output as a portable distribution."""
    import zipfile

    src = DIST_DIR / "SecurityCommander"
    zip_path = DIST_DIR / "SecurityCommander-Portable.zip"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in src.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(src.parent))

    size_mb = zip_path.stat().st_size / 1_048_576
    print(f"\n[OK] Portable ZIP: {zip_path}  ({size_mb:.1f} MB)")
    print(
        "     To use: extract anywhere, double-click SecurityCommander.exe\n"
        "     (No installation required — fully portable)"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("\n  Security Commander — Build Script")
    print(f"  Root: {ROOT}\n")

    step_check_python()
    step_install_build_deps()
    step_install_app_deps()
    step_generate_icon()
    step_pyinstaller()
    step_inno_setup()

    _section("Build complete")
    print(
        "\n  Output files are in:  dist/\n"
        "\n  SecurityCommander-Setup.exe   — Windows installer (if Inno Setup found)\n"
        "  SecurityCommander-Portable.zip — Portable version (no install needed)\n"
        "\n  Distribute either file. The installer is recommended for end users."
    )


if __name__ == "__main__":
    main()
