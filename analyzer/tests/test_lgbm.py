"""the numpy evaluator (analyzer/lgbm.py) equals lightgbm on every cached window and config row"""
import json

import numpy as np
import pytest

from analyzer import common as cm
from analyzer import lgbm

lgb = pytest.importorskip("lightgbm")
pd = pytest.importorskip("pandas")
need = pytest.mark.skipif(not (cm.feat / "windows.parquet").exists() or not (cm.models / "schema.json").exists(),
                          reason="cached features or bundle missing")


@need
@pytest.mark.parametrize("name", [f"config_{n}" for n in ("suite", "mode", "pfs")]
                         + [f"{k}_{a}" for k in ("presence", "share") for a in cm.apps])
def test_equal_to_lightgbm(name):
    s = json.loads((cm.models / "schema.json").read_text())
    if name.startswith("config"):
        X = pd.read_parquet(cm.feat / "config_rows.parquet")[s["config"]["columns"]].to_numpy(float)
    else:
        X = pd.read_parquet(cm.feat / "windows.parquet")[s["window"]["columns"]].to_numpy(np.float32)
    f = str(cm.models / f"{name}.txt")
    assert np.abs(lgb.Booster(model_file=f).predict(X) - lgbm.booster(f).predict(X)).max() < 1e-9


def test_missing_values_follow_lightgbm():
    f = str(cm.models / "presence_voip.txt")
    X = np.full((3, lgbm.booster(f).num_feature()), np.nan)
    X[1] = 0.0
    assert np.allclose(lgb.Booster(model_file=f).predict(X), lgbm.booster(f).predict(X))
