#!/usr/bin/env python3
"""Draws the tray and application icons (a screen with a check mark) into src/Compliance.Tray/Assets.

The same design as ui/public/brand/logo.svg. Rerun after changing it: python3 scripts/make_tray_icons.py
(needs Pillow).
"""
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parents[1] / "src" / "Compliance.Tray" / "Assets"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
# The management UI's navy (#1f2a5a), check orange and danger red (#e5484d).
NAVY = (31, 42, 90)
CHECK = ((246, 195, 67), (239, 125, 26))
BADGE = (229, 72, 77)
GRAY = (128, 136, 150)
GRAY_CHECK = ((236, 238, 242), (236, 238, 242))


def tile(size: int, badge: bool, base=NAVY, check=CHECK) -> Image.Image:
    scale = 8  # draw large, then shrink for smooth edges
    s = size * scale
    u = s / 64  # the SVG's 64-unit grid
    small = size <= 24
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([2 * u, 2 * u, 62 * u, 62 * u], radius=14 * u, fill=base + (255,))
    # Screen outline and stand; heavier at small sizes so they stay legible.
    line = (5.5 if small else 4) * u
    white = (255, 255, 255, 255)
    if small:
        draw.rounded_rectangle([10 * u, 13 * u, 54 * u, 44 * u], radius=4 * u, outline=white, width=int(line))
        draw.line([(22 * u, 51 * u), (42 * u, 51 * u)], fill=white, width=int(line))
    else:
        draw.rounded_rectangle([12 * u, 15 * u, 52 * u, 42 * u], radius=4 * u, outline=white, width=int(line))
        draw.line([(24 * u, 48 * u), (40 * u, 48 * u)], fill=white, width=int(line))
    # Check mark with an orange gradient from bottom-left to top-right.
    width = (7 if small else 5) * u
    pts = [(22 * u, 28.5 * u), (29 * u, 35 * u), (43 * u, 21 * u)]
    mask = Image.new("L", (s, s), 0)
    md = ImageDraw.Draw(mask)
    md.line(pts, fill=255, width=int(width), joint="curve")
    r = width / 2
    for x, y in (pts[0], pts[-1]):
        md.ellipse([x - r, y - r, x + r, y + r], fill=255)
    gradient = Image.new("RGBA", (s, s))
    gd = ImageDraw.Draw(gradient)
    for i in range(2 * s):
        t = i / (2 * s)
        color = tuple(int(a + (b - a) * t) for a, b in zip(*check)) + (255,)
        gd.line([(i, s), (i - s, 0)], fill=color, width=2)
    img.paste(gradient, (0, 0), mask)
    if badge:
        br = s * 0.22
        cx, cy = s - br - s * 0.01, br + s * 0.01
        ring = s * 0.05
        # Clear a ring around the badge so it reads against the tile.
        clear = Image.new("L", (s, s), 0)
        ImageDraw.Draw(clear).ellipse([cx - br - ring, cy - br - ring, cx + br + ring, cy + br + ring], fill=255)
        img.paste((0, 0, 0, 0), (0, 0), clear)
        ImageDraw.Draw(img).ellipse([cx - br, cy - br, cx + br, cy + br], fill=BADGE + (255,))
    return img.resize((size, size), Image.LANCZOS)


def save(name: str, badge: bool, **colors) -> None:
    images = [tile(size, badge, **colors) for size in SIZES]
    images[-1].save(ASSETS / name, format="ICO", sizes=[(i.width, i.height) for i in images], append_images=images[:-1])


ASSETS.mkdir(parents=True, exist_ok=True)
save("app.ico", badge=False)
save("tray-alert.ico", badge=True)
save("tray-offline.ico", badge=False, base=GRAY, check=GRAY_CHECK)
# Preview sheet for reviewing the design.
sheet = Image.new("RGBA", (600, 140), (255, 255, 255, 255))
x = 10
for badge, colors in ((False, {}), (True, {}), (False, {"base": GRAY, "check": GRAY_CHECK})):
    for size in (16, 24, 32, 48):
        icon = tile(size, badge, **colors)
        sheet.paste(icon, (x, 70 - size // 2), icon)
        x += size + 14
    x += 20
sheet.save(ASSETS.parent / "obj" / "icon-preview.png") if (ASSETS.parent / "obj").exists() else None
