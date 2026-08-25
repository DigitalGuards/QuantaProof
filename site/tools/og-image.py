#!/usr/bin/env python3
"""Render the QuantaStark social card and the raster icons.

Outputs (relative to site/): img/og-image.png (1200x630, the DigitalGuards
family card: dark gradient, mark, wordmark, tagline, domain, ember bar),
favicon.png (512x512) and apple-touch-icon.png (180x180). The mark is the
same geometry as favicon.svg, drawn with Pillow so no SVG rasteriser is needed.

Usage: python3 site/tools/og-image.py [--fonts DIR] [--out site]

Fonts: IBM Plex Sans (the variable file or the static Bold/Regular files) and
IBM Plex Mono Medium. The directory comes from --fonts, then
QUANTASTARK_FONT_DIR, then the usual user and system font directories.
Requires Pillow (with FreeType) and NumPy.
"""

import argparse
import glob
import os
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# Obsidian & Ember tokens (site/assets/css/site.css).
BG_TOP = (13, 11, 16)
BG_MID = (19, 16, 23)
BG_BOTTOM = (9, 9, 12)
EMBER = (250, 118, 30)
CHAMPAGNE = (221, 201, 166)
TEXT_PRIMARY = (245, 243, 240)
TEXT_SECONDARY = (164, 165, 179)
ICON_BG = (15, 16, 20)

SUPERSAMPLE = 4


def font_search_dirs(explicit):
    dirs = []
    if explicit:
        dirs.append(explicit)
    env = os.environ.get('QUANTASTARK_FONT_DIR')
    if env:
        dirs.append(env)
    home = os.path.expanduser('~')
    dirs += [
        os.path.join(home, '.local', 'share', 'fonts'),
        os.path.join(home, '.fonts'),
        '/usr/share/fonts',
        '/usr/local/share/fonts',
    ]
    return [d for d in dirs if os.path.isdir(d)]


def find_font(dirs, patterns):
    for directory in dirs:
        for pattern in patterns:
            hits = sorted(glob.glob(os.path.join(directory, '**', pattern), recursive=True))
            if hits:
                return hits[0]
    return None


def load_sans(dirs, size, weight):
    """IBM Plex Sans at a weight: the variable font if present, else a static file."""
    variable = find_font(dirs, ['IBMPlexSans*wght*.ttf', 'IBMPlexSans-VariableFont*.ttf'])
    if variable:
        font = ImageFont.truetype(variable, size)
        try:
            font.set_variation_by_name(weight)
            return font
        except (OSError, ValueError):
            pass
    static = find_font(dirs, ['IBMPlexSans-%s.ttf' % weight, 'IBMPlexSans-%s.otf' % weight])
    if static:
        return ImageFont.truetype(static, size)
    raise SystemExit(
        'IBM Plex Sans (%s) was not found under %s; pass --fonts DIR or set QUANTASTARK_FONT_DIR'
        % (weight, ', '.join(dirs) or 'the default directories')
    )


def load_mono(dirs, size):
    path = find_font(dirs, ['IBMPlexMono-Medium.ttf', 'IBMPlexMono-Regular.ttf'])
    if not path:
        raise SystemExit('IBM Plex Mono was not found; pass --fonts DIR or set QUANTASTARK_FONT_DIR')
    return ImageFont.truetype(path, size)


def fit_font(loader, size, text, max_width):
    """Largest font at or below `size` whose rendering of `text` fits `max_width`."""
    font = loader(size)
    while size > 12 and font.getlength(text) > max_width:
        size -= 1
        font = loader(size)
    return font


def vertical_gradient(width, height):
    """Three-stop vertical gradient matching the hero background of the site."""
    rows = np.linspace(0.0, 1.0, height)[:, None]
    top = np.array(BG_TOP, dtype=float)
    mid = np.array(BG_MID, dtype=float)
    bottom = np.array(BG_BOTTOM, dtype=float)
    first = np.clip(rows / 0.55, 0.0, 1.0)
    second = np.clip((rows - 0.55) / 0.45, 0.0, 1.0)
    colour = np.where(rows < 0.55, top + (mid - top) * first, mid + (bottom - mid) * second)
    pixels = np.repeat(colour[:, None, :], width, axis=1).astype(np.uint8)
    return Image.fromarray(pixels, 'RGB')


def glow(base, centre, radius, colour, alpha):
    """Soft radial glow composited over the base image."""
    layer = Image.new('RGBA', base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    x, y = centre
    draw.ellipse([x - radius, y - radius, x + radius, y + radius], fill=colour + (alpha,))
    layer = layer.filter(ImageFilter.GaussianBlur(radius * 0.6))
    return Image.alpha_composite(base.convert('RGBA'), layer)


def draw_mark(draw, origin, size, ember=EMBER, star=CHAMPAGNE, scale=1):
    """The favicon geometry (64-unit box) at an origin and size, on an ImageDraw.

    `scale` is the supersampling factor of the draw target; callers pass a draw on a
    canvas that is `scale` times larger than the final image.
    """
    ox, oy = origin[0] * scale, origin[1] * scale
    unit = size * scale / 64.0
    stroke = max(1, int(round(6 * unit)))

    cx, cy, r = ox + 30 * unit, oy + 32 * unit, 15 * unit
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=ember, width=stroke)

    tail = [(ox + 37 * unit, oy + 39 * unit), (ox + 50 * unit, oy + 52 * unit)]
    draw.line(tail, fill=ember, width=stroke)
    cap = stroke / 2.0
    for px, py in tail:
        draw.ellipse([px - cap, py - cap, px + cap, py + cap], fill=ember)

    star_points = [
        (48, 8),
        (50.5, 13.5),
        (56, 16),
        (50.5, 18.5),
        (48, 24),
        (45.5, 18.5),
        (40, 16),
        (45.5, 13.5),
    ]
    draw.polygon([(ox + x * unit, oy + y * unit) for x, y in star_points], fill=star)


def render_mark_layer(canvas_size, origin, size, ember=EMBER, star=CHAMPAGNE, alpha=255):
    """Supersampled RGBA layer holding one mark, for compositing."""
    width, height = canvas_size
    big = Image.new('RGBA', (width * SUPERSAMPLE, height * SUPERSAMPLE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)
    draw_mark(draw, origin, size, ember=ember + (alpha,), star=star + (alpha,), scale=SUPERSAMPLE)
    return big.resize((width, height), Image.LANCZOS)


def render_og(out_dir, dirs):
    width, height = 1200, 630
    image = vertical_gradient(width, height).convert('RGBA')
    image = glow(image, (150, -40), 520, EMBER, 42)
    image = glow(image, (1290, 700), 420, (74, 175, 255), 22)

    # Faint watermark of the mark on the right, like the family cards.
    watermark = render_mark_layer((width, height), (700, 20), 640, alpha=20)
    image = Image.alpha_composite(image, watermark)

    mark = render_mark_layer((width, height), (76, 72), 128)
    image = Image.alpha_composite(image, mark)

    draw = ImageDraw.Draw(image)
    margin = 82
    max_width = width - 2 * margin

    wordmark = fit_font(lambda size: load_sans(dirs, size, 'Bold'), 104, 'QUANTASTARK', max_width)
    draw.text((margin - 4, 214), 'QUANTASTARK', font=wordmark, fill=EMBER)

    lines = [
        ('Post-quantum STARK verifier for QRL 2.0.', TEXT_PRIMARY),
        ('Plonky3 proofs verified on the 512-bit QRVM, hash-based by construction.', TEXT_SECONDARY),
    ]
    longest = max((text for text, _ in lines), key=len)
    tagline = fit_font(lambda size: load_sans(dirs, size, 'Regular'), 36, longest, max_width)
    y = 372
    for text, colour in lines:
        draw.text((margin, y), text, font=tagline, fill=colour)
        y += int(tagline.size * 1.35)

    domain = load_mono(dirs, 30)
    draw.text((margin, 536), 'quantastark.com', font=domain, fill=EMBER)

    draw.rectangle([0, height - 8, width, height], fill=EMBER)

    path = os.path.join(out_dir, 'img', 'og-image.png')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    image.convert('RGB').save(path, 'PNG', optimize=True)
    return path


def render_icon(out_dir, name, size):
    radius = int(round(size * 14 / 64.0))
    big = size * SUPERSAMPLE
    image = Image.new('RGBA', (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([0, 0, big - 1, big - 1], radius=radius * SUPERSAMPLE, fill=ICON_BG)
    draw_mark(draw, (0, 0), size, scale=SUPERSAMPLE)
    image = image.resize((size, size), Image.LANCZOS)
    path = os.path.join(out_dir, name)
    image.save(path, 'PNG', optimize=True)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--fonts', help='directory that holds the IBM Plex font files')
    default_out = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    parser.add_argument('--out', default=default_out, help='site directory (default: site/)')
    args = parser.parse_args()

    dirs = font_search_dirs(args.fonts)
    written = [
        render_og(args.out, dirs),
        render_icon(args.out, 'favicon.png', 512),
        render_icon(args.out, 'apple-touch-icon.png', 180),
    ]
    for path in written:
        print('%s (%d bytes)' % (os.path.relpath(path), os.path.getsize(path)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
