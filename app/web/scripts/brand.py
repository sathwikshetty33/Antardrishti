"""web assets from the brand originals in app/web/brand (dev only, needs pillow and scipy from
app/requirements-dev.txt; the outputs are committed).

  python app/web/scripts/brand.py

writes into app/web/public (vite copies it into the build as-is):
  favicon.ico (16, 32, 48), favicon-32.png, apple-touch-icon.png (180, on the brand navy-black),
  icon-192.png, icon-512.png, site.webmanifest,
  brand/mark-128.png (the ui mark), brand/logo-light.png, brand/logo-dark.png (the dark lockup
  with its background made transparent), brand/og-image.png (1200 x 630 link preview).
"""
import json
from pathlib import Path

import numpy as np
from PIL import Image
from scipy import ndimage

web = Path(__file__).resolve().parents[1]
src = web / "brand"
pub = web / "public"
out = pub / "brand"
navy_black = (15, 23, 42)       # the dark lockup's background, #0F172A


def fit(im, width):
    h = round(im.height * width / im.width)
    return im.resize((width, h), Image.LANCZOS)


def on_background(im, size, color):
    """an icon centred on a solid square (ios renders transparency as black)"""
    bg = Image.new("RGBA", (size, size), color + (255,))
    m = im.resize((round(size * 0.84), round(size * 0.84)), Image.LANCZOS)
    bg.alpha_composite(m, ((size - m.width) // 2, (size - m.height) // 2))
    return bg.convert("RGB")


def transparent(im, bg, tol=3):
    """the solid background of a lockup made transparent: background-coloured pixels become
    clear, and their anti-aliased rim is un-mixed from the background colour (colour to alpha),
    so the edges stay smooth on any dark surface"""
    a = np.asarray(im.convert("RGBA")).astype(float)
    rgb = a[..., :3]
    b = np.array(bg, float)
    # every background-coloured pixel goes, the letter counters included (no brand colour is
    # #0F172A: the hexagon and pupil are #1B2A6B)
    clear = np.abs(rgb - b).max(-1) <= tol
    rim = ndimage.binary_dilation(clear, iterations=2) & ~clear
    hi = np.where(rgb > b, (rgb - b) / (255 - b), 0)
    lo = np.where(rgb < b, (b - rgb) / np.maximum(b, 1), 0)
    alpha = np.clip(np.maximum(hi, lo).max(-1), 0, 1)
    fg = (rgb - (1 - alpha[..., None]) * b) / np.maximum(alpha[..., None], 1e-6)
    res = np.dstack([rgb, np.full(alpha.shape, 255.0)])
    res[rim] = np.dstack([np.clip(fg, 0, 255), alpha * 255])[rim]
    res[clear] = 0
    return Image.fromarray(res.round().astype(np.uint8), "RGBA")


def main():
    out.mkdir(parents=True, exist_ok=True)
    fav = Image.open(src / "favicon-512.png").convert("RGBA")
    fav.save(pub / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    fav.resize((32, 32), Image.LANCZOS).save(pub / "favicon-32.png", optimize=True)
    fav.resize((192, 192), Image.LANCZOS).save(pub / "icon-192.png", optimize=True)
    fav.save(pub / "icon-512.png", optimize=True)
    on_background(fav, 180, navy_black).save(pub / "apple-touch-icon.png", optimize=True)
    fav.resize((128, 128), Image.LANCZOS).save(out / "mark-128.png", optimize=True)
    light = Image.open(src / "logo.png").convert("RGBA")
    fit(light, 720).save(out / "logo-light.png", optimize=True)
    dark = Image.open(src / "logo-dark.png").convert("RGBA")
    fit(transparent(dark, navy_black), 720).save(out / "logo-dark.png", optimize=True)
    og = Image.new("RGB", (1200, 630), navy_black)
    d = dark.convert("RGB").resize((round(dark.width * 590 / dark.height), 590), Image.LANCZOS)
    og.paste(d, ((1200 - d.width) // 2, 20))
    og.save(out / "og-image.png", optimize=True)
    manifest = {"name": "Antardrishti", "short_name": "Antardrishti",
                "description": "See inside the tunnel: passive IPsec VPN analysis.",
                "start_url": "/", "display": "standalone", "background_color": "#0b0e14",
                "theme_color": "#0b0e14",
                "icons": [{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                          {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}]}
    (pub / "site.webmanifest").write_text(json.dumps(manifest, indent=1) + "\n")
    for p in sorted(list(pub.glob("*.*")) + list(out.glob("*"))):
        print(f"{p.relative_to(web)}  {p.stat().st_size:,} B")


if __name__ == "__main__":
    main()
