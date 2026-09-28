"""traffic models (analyzer/CLAUDE.md section 7): per app a presence and a share model.

  python -m analyzer.traffic_models

windows come from the traffic tiers only (section 3: p0s, P1 anchor, mixtures, chat,
realism, WhatsApp; never P0's traffic runs). their config context is the out-of-fold config
prediction (features/config_pred.parquet), never the ground truth. windows unknown for an
app (ambiguous https, section 11) are left out of that app's training.

presence: binary, balanced class weights, early stopping on grouped validation inside each of
5 grouped folds, isotonic calibration on the out-of-fold predictions, a per-app threshold
maximising f1 on them. share: cross_entropy on the byte share. writes features/work/
presence_<app>.* and share_<app>.*, features/windows.parquet and features/window_pred.parquet
(out-of-fold predictions for training windows, final boosters for test windows).
"""
import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from analyzer import common as cm
from analyzer import features as fx
from analyzer import ml

traffic_stages = {"p0s": ("traffic",), "p1": ("anchor", "mixtures", "chat", "realism"), "p1-whatsapp": ("whatsapp",)}
meta_cols = ["run_id", "tier", "stage", "split", "group", "tunnel", "pair", "w", "netem", "capture_start", "mode",
             "shape", "family", "natt", "source", "apps", "esp_bytes", "b_unknown", "timing_valid"]
work = cm.feat / "work"


def label_cols():
    return [f"{k}_{a}" for a in cm.apps for k in ("y", "s", "u", "b")]


def ctx_of(pred, rid, t):
    r = pred.get((rid, t["id"]))
    if r is None:
        return None
    return {**r, "family": t["family"], "natt": t["natt"]}


def build_windows():
    cp = pd.read_parquet(cm.feat / "config_pred.parquet")
    pred = {(r.run_id, int(r.tunnel)): {f"p_{s}": getattr(r, f"p_{s}") for s in cm.suites} | {"p_tunnel": r.p_tunnel}
            for r in cp.itertuples()}
    rows = []
    missing = []
    for tier, stages in traffic_stages.items():
        for jf in sorted((cm.feat / tier).glob("*.json")):
            r = json.loads(jf.read_text())
            if r["stage"] not in stages:
                continue
            tab = pq.read_table(jf.with_suffix(".parquet")).to_pandas()
            cfg = r["config"]
            src = r["replay"]["source"] + ":" + (r["replay"]["scenario"] or "") if r["replay"] else ""
            for t in r["tunnels"]:
                if not t["esp"] or not fx.lab_tunnel(t):
                    continue
                ctx = ctx_of(pred, r["run_id"], t)
                if ctx is None:
                    missing.append((r["run_id"], t["id"]))
                    continue
                sel = tab[tab.tunnel == t["id"]]
                pk = {c: sel[c].to_numpy() for c in ("t", "pair", "dir", "elen", "app", "amb")}
                labs = fx.window_labels(pk)
                for pair, w, f in fx.windows(pk, ctx):
                    lab = labs[(pair, w)]
                    f.update(lab)
                    f.update({"run_id": r["run_id"], "tier": tier, "stage": r["stage"], "split": r["split"],
                              "group": r["group"], "tunnel": t["id"], "pair": pair, "w": w, "netem": r["netem"],
                              "capture_start": r["capture_start"], "mode": cfg["mode"], "shape": r["suite"],
                              "family": t["family"], "natt": int(t["natt"]), "source": src,
                              "apps": "+".join(r["apps"] or []), "timing_valid": bool(r.get("timing_valid"))})
                    rows.append(f)
    df = pd.DataFrame(rows)
    df.to_parquet(cm.feat / "windows.parquet")
    return df, missing


def feature_cols(df):
    skip = set(meta_cols) | set(label_cols()) | {"esp_bytes", "b_unknown"}
    return [c for c in df.columns if c not in skip]


def train_app(df, feats, a):
    """presence and share models of one app -> dict of boosters, calibration, threshold, predictions"""
    usable = df[f"u_{a}"] == 0
    tr = df[(df.split == "train") & usable]
    X = tr[feats].to_numpy(np.float32)
    g = tr.group.to_numpy()
    y = tr[f"y_{a}"].to_numpy()
    p = ml.params("binary")
    b, oofp, rounds, fold = ml.oof(X, y, g, p, w=ml.balanced(y), strat=y)
    cal = ml.iso_fit(oofp, y)
    oc = ml.iso(cal, oofp)
    thr, f1 = ml.best_threshold(oc, y)
    s = tr[f"s_{a}"].to_numpy()
    ps = ml.params("cross_entropy")
    bs, oofs, rounds_s, _ = ml.oof(X, s, g, ps)
    b.save_model(str(work / f"presence_{a}.txt"))
    bs.save_model(str(work / f"share_{a}.txt"))
    meta = {"calibration": cal, "threshold": thr, "oof_f1": f1, "rounds": rounds, "rounds_share": rounds_s,
            "features": feats, "train_rows": int(len(tr)), "positives": int(y.sum())}
    (work / f"presence_{a}.json").write_text(json.dumps(meta))
    return {"presence": b, "share": bs, **meta, "oof_rows": tr.index.to_numpy(), "oof_p": oc, "oof_s": oofs,
            "oof_raw": oofp}


def main():
    work.mkdir(parents=True, exist_ok=True)
    df, missing = build_windows()
    print("windows", len(df), df.groupby(["tier", "stage", "split"]).size().to_dict(), "missing ctx", missing[:5],
          flush=True)
    feats = feature_cols(df)
    (work / "window_features.json").write_text(json.dumps(feats))
    out = df[meta_cols + label_cols()].copy()
    te = df.split == "test"
    Xt = df.loc[te, feats].to_numpy(np.float32)
    for a in cm.apps:
        m = train_app(df, feats, a)
        out[f"p_{a}"] = np.nan
        out[f"q_{a}"] = np.nan
        out.loc[m["oof_rows"], f"p_{a}"] = m["oof_p"]
        out.loc[m["oof_rows"], f"q_{a}"] = m["oof_s"]
        out.loc[te, f"p_{a}"] = ml.iso(m["calibration"], m["presence"].predict(Xt))
        out.loc[te, f"q_{a}"] = m["share"].predict(Xt)
        out[f"thr_{a}"] = m["threshold"]
        print(a, "rows", m["train_rows"], "pos", m["positives"], "thr", round(m["threshold"], 3),
              "oof f1", round(m["oof_f1"], 3), "rounds", m["rounds"], m["rounds_share"], flush=True)
    out.to_parquet(cm.feat / "window_pred.parquet")


if __name__ == "__main__":
    main()
