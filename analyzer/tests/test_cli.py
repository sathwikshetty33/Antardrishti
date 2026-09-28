"""cli end to end on 3 test-split runs (one mixture, one WhatsApp, one edge case): its output
equals the evaluation's predictions. also records the cli speed (seconds per minute of traffic)."""
import json
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from analyzer import common as cm
from analyzer import features as fx

runs = {"mixture": "p1-voip_video_web-21e3e3f0-r1", "whatsapp": "p1-whatsapp-40244c69-r1", "edge": "p0-e18-99a7fdcf-r1"}
tier = {"mixture": "p1", "whatsapp": "p1-whatsapp", "edge": "p0"}
pytestmark = pytest.mark.skipif(not (cm.models / "SHA256SUMS").exists(), reason="models/v1 not built")
speed = {}


def cli(rid, tmp_path):
    d = cm.data / "keep" / rid
    if not (d / "outer.pcap.zst").exists():
        pytest.skip(f"{rid} not kept")
    out = tmp_path / "result.json"
    subprocess.run([sys.executable, "-m", "analyzer.cli", "analyze", str(d / "outer.pcap.zst"), str(d / "ike.pcap.zst"),
                    "--out", str(out)], check=True, cwd=cm.root, capture_output=True)
    return json.loads(out.read_text())


def lab_tunnel(res, rid, t):
    rec = json.loads((cm.feat / t / f"{rid}.json").read_text())
    ids = [x["id"] for x in rec["tunnels"] if x["esp"] and fx.lab_tunnel(x)]
    assert len(ids) == 1
    return rec, next(x for x in res["tunnels"] if x["tunnel"] == ids[0])


@pytest.mark.parametrize("kind", list(runs))
def test_cli_equals_evaluation(kind, tmp_path):
    rid = runs[kind]
    res = cli(rid, tmp_path)
    rec, tun = lab_tunnel(res, rid, tier[kind])
    assert rec["split"] == "test"
    # config: the cli's suite and mode probabilities are the evaluation's
    cp = pd.read_parquet(cm.feat / "config_pred.parquet")
    row = cp[(cp.run_id == rid) & (cp.tunnel == tun["tunnel"])].iloc[0]
    assert row.source == "final"
    for s in cm.suites:
        assert abs(tun["config"]["esp_suite_probabilities"][s] - row[f"p_{s}"]) < 1e-9
    assert tun["handshake_status"] == next(x["status"] for x in rec["tunnels"] if x["id"] == tun["tunnel"])
    speed[rid] = res["timing"]
    if kind == "edge":
        return
    # windows: the cli's per-window presence probabilities are the evaluation's
    wp = pd.read_parquet(cm.feat / "window_pred.parquet")
    wp = wp[(wp.run_id == rid) & (wp.tunnel == tun["tunnel"])].sort_values(["pair", "w"])
    tl = sorted(tun["windows"], key=lambda x: (x["pair"], x["t"]))
    assert len(tl) == len(wp) > 0
    for a in cm.apps:
        mine = np.array([x["presence_probability"][a] for x in tl])
        assert np.allclose(mine, wp[f"p_{a}"].to_numpy(), atol=1e-6), a
    assert abs(sum(tun["byte_share_rounded"].values()) - 100) == 0


def test_zz_speed():
    """seconds of analysis per minute of traffic, over the runs above"""
    if not speed:
        pytest.skip("no cli runs")
    spm = [v["seconds_per_minute"] for v in speed.values() if v["seconds_per_minute"]]
    out = {"runs": speed, "seconds_per_minute": float(np.median(spm)), "min": float(min(spm)), "max": float(max(spm))}
    (cm.feat / "results" / "cli_speed.json").write_text(json.dumps(out, indent=1))
    assert out["seconds_per_minute"] < 60
