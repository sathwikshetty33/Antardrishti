"""platform checks that need no database: the runtime stays pure python, the model bundle is
selected by MODEL_BUNDLE and verified, and the design tokens meet wcag aa contrast"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

root = Path(__file__).resolve().parents[2]
css = (root / "app" / "web" / "src" / "index.css").read_text()


def test_runtime_imports_no_heavy_libraries():
    code = ("import sys; import app.api.index, analyzer.cli; "
            "print(sorted(m for m in ('lightgbm','sklearn','pandas','pyarrow','scipy','matplotlib') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=root,
                         env={**os.environ, "PYTHONPATH": str(root)})
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_inference_path_runs_no_binaries():
    files = ["analyzer/parse.py", "analyzer/features.py", "analyzer/aggregate.py", "analyzer/cli.py",
             "analyzer/lgbm.py", "analyzer/calib.py", "analyzer/common.py", "app/api/pipeline.py",
             "app/api/storage.py", "app/api/replay.py", "app/api/index.py"]
    for f in files:
        s = (root / f).read_text()
        assert "subprocess" not in s and "os.system" not in s and "shutil.which" not in s, f


def test_model_bundle_selected_and_verified(tmp_path, monkeypatch):
    from analyzer import bundle as bd
    from app.api import pipeline, settings
    copy = tmp_path / "v1"
    shutil.copytree(settings.bundle_dir, copy)
    monkeypatch.setattr(settings, "bundle_dir", copy)
    pipeline.cached.clear()
    assert pipeline.bundle_info()["version"] == "v1"
    (copy / "presence_voip.txt").write_text((copy / "presence_voip.txt").read_text() + "\n")
    with pytest.raises(ValueError):
        bd.load(copy)
    pipeline.cached.clear()


def tokens(block):
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-f]{6})", block))


def lum(h):
    rgb = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def mix(a, b, t):
    """t of colour a over b (the chip tint: color-mix(a t%, b))"""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * t + y * (1 - t)):02x}" for x, y in zip(ca, cb))


themes = {"dark": tokens(css.split(":root {")[1].split("}")[0]),
          "light": tokens(css.split(':root[data-theme="light"] {')[1].split("}")[0])}


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_text_contrast_aa(theme):
    t = themes[theme]
    for bg in ("bg", "surface", "surface-2"):
        assert ratio(t["text"], t[bg]) >= 7, (theme, "text", bg)
        assert ratio(t["text-2"], t[bg]) >= 4.5, (theme, "text-2", bg)
        assert ratio(t["muted"], t[bg]) >= 3.0, (theme, "muted", bg)   # captions and large text only


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_severity_chips_aa(theme):
    """severity text on its own 14% tint, over a card, keeps 4.5:1"""
    t = themes[theme]
    for sev in ("critical", "high", "medium", "low", "info", "pass"):
        chip = mix(t[sev], t["surface"], 0.14)
        assert ratio(t[sev], chip) >= 4.5, (theme, sev, round(ratio(t[sev], chip), 2))


def test_accent_button_contrast():
    for theme, t in themes.items():
        assert ratio(t["accent-ink"], t["accent"]) >= 4.5, theme
