"""
make_icon.py - Generate the Security Commander application icon.

Produces assets/icon.ico (multi-resolution: 16, 32, 48, 64, 128, 256 px).
Requires Pillow: pip install Pillow

The icon is a dark shield with a green centre dot — minimal, professional,
recognisable in both the taskbar and the system tray.
"""

import math
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Pillow not installed. Run: pip install Pillow")
    raise

ASSETS_DIR = Path(__file__).parent.parent / "assets"
ASSETS_DIR.mkdir(exist_ok=True)

OUT_PATH = ASSETS_DIR / "icon.ico"


def _draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(1, size // 10)
    w, h = size - 2 * pad, size - 2 * pad
    cx, cy = size // 2, size // 2

    # Shield body — dark blue polygon
    # Points: top-left, top-right, mid-right, bottom-point, mid-left
    shield = [
        (pad,          pad),
        (size - pad,   pad),
        (size - pad,   pad + h * 55 // 100),
        (cx,           size - pad),
        (pad,          pad + h * 55 // 100),
    ]
    draw.polygon(shield, fill=(22, 33, 62, 230), outline=(74, 144, 217, 255))

    # Inner shield highlight (slightly smaller, slightly lighter)
    inset = max(2, size // 12)
    inner = [
        (pad + inset,         pad + inset),
        (size - pad - inset,  pad + inset),
        (size - pad - inset,  pad + inset + (h * 55 // 100) - inset),
        (cx,                  size - pad - inset * 2),
        (pad + inset,         pad + inset + (h * 55 // 100) - inset),
    ]
    draw.polygon(inner, fill=(26, 45, 80, 200))

    # Green status dot — centre of shield
    r = max(3, size // 9)
    draw.ellipse(
        (cx - r, cy - r // 2 - r // 3,
         cx + r, cy - r // 2 - r // 3 + r * 2),
        fill=(46, 204, 113, 255),
        outline=(39, 174, 96, 255),
    )

    return img


def build_ico():
    sizes = [16, 32, 48, 64, 128, 256]
    frames = [_draw_icon(s) for s in sizes]
    frames[0].save(
        OUT_PATH,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=frames[1:],
    )
    print(f"Icon written: {OUT_PATH}")


if __name__ == "__main__":
    build_ico()
