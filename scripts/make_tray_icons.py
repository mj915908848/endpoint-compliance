#!/usr/bin/env python3
"""Draws the tray and application icons (a shield with a check mark) into src/Compliance.Tray/Assets.

Rerun after changing the design: python3 scripts/make_tray_icons.py (needs Pillow).
"""
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parents[1] / "src" / "Compliance.Tray" / "Assets"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
# The management UI's teal (#1f6f84) and danger red (#c2413b).
TEAL_TOP, TEAL_BOTTOM = (52, 150, 170), (24, 94, 114)
BADGE = (194, 65, 59)
GRAY = ((168, 175, 186), (120, 128, 140))


def shield(size: int, badge: bool, colors=(TEAL_TOP, TEAL_BOTTOM)) -> Image.Image:
    scale = 8  # draw large, then shrink for smooth edges
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # Shield outline: flat top with rounded shoulders, sides curving to a point.
    m = s * 0.08
    top, bottom = s * 0.06, s * 0.96
    left, right = m, s - m
    mid = s / 2
    points = []
    steps = 40
    for i in range(steps + 1):  # right side from the shoulder down to the tip
        t = i / steps
        x = right - (right - mid) * t ** 2.2
        y = top + s * 0.12 + (bottom - top - s * 0.12) * t
        points.append((x, y))
    for i in range(steps + 1):  # left side back up
        t = 1 - i / steps
        x = left + (mid - left) * t ** 2.2
        y = top + s * 0.12 + (bottom - top - s * 0.12) * t
        points.append((x, y))
    # Top edge dips slightly in the middle like a crest.
    points += [(left, top + s * 0.06), (mid, top), (right, top + s * 0.06)]
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).polygon(points, fill=255)
    gradient = Image.new("RGBA", (s, s))
    gd = ImageDraw.Draw(gradient)
    for y in range(s):
        t = y / s
        gd.line(
            [(0, y), (s, y)],
            fill=tuple(int(a + (b - a) * t) for a, b in zip(*colors)) + (255,),
        )
    img.paste(gradient, (0, 0), mask)
    draw = ImageDraw.Draw(img)
    # Check mark; thicker at small sizes so it stays legible.
    width = s * (0.13 if size <= 24 else 0.10)
    check = [(s * 0.29, s * 0.50), (s * 0.44, s * 0.66), (s * 0.72, s * 0.36)]
    draw.line(check, fill=(255, 255, 255, 255), width=int(width), joint="curve")
    r = width / 2
    for x, y in (check[0], check[-1]):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=(255, 255, 255, 255))
    if badge:
        br = s * 0.22
        cx, cy = s - br - s * 0.01, br + s * 0.01
        ring = s * 0.05
        draw.ellipse([cx - br - ring, cy - br - ring, cx + br + ring, cy + br + ring], fill=(0, 0, 0, 0))
        # Clear a ring around the badge so it reads against the shield.
        clear = Image.new("L", (s, s), 0)
        ImageDraw.Draw(clear).ellipse([cx - br - ring, cy - br - ring, cx + br + ring, cy + br + ring], fill=255)
        img.paste((0, 0, 0, 0), (0, 0), clear)
        draw = ImageDraw.Draw(img)
        draw.ellipse([cx - br, cy - br, cx + br, cy + br], fill=BADGE + (255,))
    return img.resize((size, size), Image.LANCZOS)


def save(name: str, badge: bool, colors=(TEAL_TOP, TEAL_BOTTOM)) -> None:
    images = [shield(size, badge, colors) for size in SIZES]
    images[-1].save(ASSETS / name, format="ICO", sizes=[(i.width, i.height) for i in images], append_images=images[:-1])


ASSETS.mkdir(parents=True, exist_ok=True)
save("app.ico", badge=False)
save("tray-alert.ico", badge=True)
save("tray-offline.ico", badge=False, colors=GRAY)
# Preview sheet for reviewing the design.
sheet = Image.new("RGBA", (600, 140), (255, 255, 255, 255))
x = 10
for badge, colors in ((False, (TEAL_TOP, TEAL_BOTTOM)), (True, (TEAL_TOP, TEAL_BOTTOM)), (False, GRAY)):
    for size in (16, 24, 32, 48):
        icon = shield(size, badge, colors)
        sheet.paste(icon, (x, 70 - size // 2), icon)
        x += size + 14
    x += 20
sheet.save(ASSETS.parent / "obj" / "icon-preview.png") if (ASSETS.parent / "obj").exists() else None
