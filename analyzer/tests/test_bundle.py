"""bundle loading and schema checks"""
import json

import numpy as np
import pytest

from analyzer import bundle as bd
from analyzer import common as cm

pytestmark = pytest.mark.skipif(not (cm.models / "SHA256SUMS").exists(), reason="models/v1 not built")


def test_loads_and_matches_manifest():
    b = bd.load()
    assert len(b["boosters"]) == 17
    assert {f"presence_{a}" for a in cm.apps} <= set(b["boosters"])
    assert {f"share_{a}" for a in cm.apps} <= set(b["boosters"])
    assert {"config_suite", "config_mode", "config_pfs"} <= set(b["boosters"])


def test_schema():
    b = bd.load()
    s = b["schema"]
    assert s["apps"] == cm.apps and s["suites"] == cm.suites
    for k, bo in b["boosters"].items():
        cols = s["config" if k.startswith("config") else "window"]["columns"]
        assert bo.feature_name() == cols or bo.num_feature() == len(cols)
    # no feature may name an address, port, spi or absolute time
    for cols in (s["config"]["columns"], s["window"]["columns"]):
        for c in cols:
            assert not any(x in c for x in ("addr", "port", "spi", "epoch", "ts_"))


def test_calibration_and_thresholds():
    b = bd.load()
    for k, v in b["calibration"].items():
        cals = v.get("calibration")
        if cals is None:
            continue
        for c in cals if isinstance(cals, list) else [cals]:
            assert np.all(np.diff(c["x"]) >= 0) and np.all(np.diff(c["y"]) >= -1e-12)
            assert 0 <= min(c["y"]) and max(c["y"]) <= 1
        if "threshold" in v:
            assert 0 <= v["threshold"] <= 1


def test_metadata():
    m = json.loads((cm.models / "metadata.json").read_text())
    assert m["seed"] == cm.seed and m["commit"]
    assert {"p0-data", "p0s-data", "p1-data", "p1-whatsapp"} <= set(m["data_releases"])
    assert m["environment"]["libraries"]["lightgbm"]
