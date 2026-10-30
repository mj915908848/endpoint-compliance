#!/usr/bin/env python3
"""Draws the tray and application icons (a white shield with a check on a blue tile) into src/Compliance.Tray/Assets.

The same design as ui/public/brand/logo.svg. Rerun after changing it: python3 scripts/make_tray_icons.py
(needs Pillow).
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parents[1] / "src" / "Compliance.Tray" / "Assets"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
# The management UI's blue (#2f6bff) and danger red (#e5484d); offline is gray.
BLUE = (47, 107, 255)
BADGE = (229, 72, 77)
GRAY = (128, 136, 150)


def cubic(p0, p1, p2, p3, steps=16):
    return [
        tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t**2 * c + t**3 * d for a, b, c, d in zip(p0, p1, p2, p3))
        for t in (i / steps for i in range(1, steps + 1))
    ]


def tile(size: int, badge: bool, base=BLUE) -> Image.Image:
    scale = 8  # draw large, then shrink for smooth edges
    s = size * scale
    u = s / 64  # the SVG's 64-unit grid
    small = size <= 24
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([2 * u, 2 * u, 62 * u, 62 * u], radius=14 * u, fill=base + (255,))
    white = (255, 255, 255, 255)
    # Heavier lines at small sizes so the shield stays legible.
    line = (6 if small else 4) * u
    # The shield's path from logo.svg, its two curves sampled as cubic Béziers.
    outline = [(32, 13), (46, 19), (46, 29)]
    outline += cubic((46, 29), (46, 38), (40, 45.5), (32, 49))
    outline += cubic((32, 49), (24, 45.5), (18, 38), (18, 29))
    outline += [(18, 19), (32, 13), (46, 19)]
    draw.line([(x * u, y * u) for x, y in outline], fill=white, width=int(line), joint="curve")
    width = (6.5 if small else 4.2) * u
    pts = [(25.5 * u, 31 * u), (30 * u, 35.5 * u), (38.5 * u, 27 * u)]
    draw.line(pts, fill=white, width=int(width), joint="curve")
    r = width / 2
    for x, y in (pts[0], pts[-1]):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=white)
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
save("tray-offline.ico", badge=False, base=GRAY)
# Preview sheet for reviewing the design.
sheet = Image.new("RGBA", (600, 140), (255, 255, 255, 255))
x = 10
for badge, colors in ((False, {}), (True, {}), (False, {"base": GRAY})):
    for size in (16, 24, 32, 48):
        icon = tile(size, badge, **colors)
        sheet.paste(icon, (x, 70 - size // 2), icon)
        x += size + 14
    x += 20
if len(sys.argv) > 1:
    sheet.save(sys.argv[1])
