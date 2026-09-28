"""config models (analyzer/CLAUDE.md section 6): suite, mode and pfs from tunnel evidence.

  python -m analyzer.config_models

rows: every lab tunnel with esp of the four wire shapes, at the 50, 200, 1000 and all
packet evidence sizes, from every tier (section 3). 5 grouped folds give out-of-fold
predictions for the training tunnels (they feed the traffic models), a final booster on all
training rows predicts the test tunnels, isotonic calibration is fitted on the out-of-fold
predictions. writes features/work/config_*.txt|json, features/config_rows.parquet,
features/config_pred.parquet and features/results/config.json.
"""
import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from analyzer import common as cm
from analyzer import features as fx
from analyzer import ml

excluded_edges = ("e15", "e16", "e19")
id_cols = ["run_id", "tier", "stage", "split", "group", "tunnel", "evidence", "combo", "suite", "mode", "pfs",
           "edge_case", "shape_mode"]
work = cm.feat / "work"
results = cm.feat / "results"


def build_rows():
    rows = []
    for tier in cm.tiers:
        for jf in sorted((cm.feat / tier).glob("*.json")):
            r = json.loads(jf.read_text())
            cfg = r["config"]
            if r["edge_case"] in excluded_edges or r["suite"] is None:
                continue
            tab = pq.read_table(jf.with_suffix(".parquet"), columns=["t", "tunnel", "dir", "elen"]).to_pandas()
            for t in r["tunnels"]:
                if not t["esp"] or not fx.lab_tunnel(t):
                    continue
                sel = tab[tab.tunnel == t["id"]]
                pk = {c: sel[c].to_numpy() for c in ("t", "dir", "elen")}
                for e in fx.evidence(pk, t):
                    e.update({"run_id": r["run_id"], "tier": tier, "stage": r["stage"], "split": r["split"],
                              "group": r["group"], "tunnel": t["id"], "suite": r["suite"],
                              "mode": int(cfg["mode"] == "tunnel"), "pfs": int(bool(cfg.get("pfs"))),
                              "edge_case": r["edge_case"] or "",
                              "combo": f"{cfg['mode']}|{r['suite']}|{cfg['outer_family']}|{int(bool(cfg['encap']))}",
                              "shape_mode": f"{cfg['mode']}|{r['suite']}"})
                    rows.append(e)
    df = pd.DataFrame(rows)
    df.to_parquet(cm.feat / "config_rows.parquet")
    return df


def feature_cols(df):
    return [c for c in df.columns if c not in id_cols]


def pfs_rows(df):
    return (df.ccsa_child_n >= 1) | ((df.ike_version == 1) & (df.rekeys >= 1))


def train(df, name, target, mask, nclass=None):
    """-> dict with booster, calibrators, oof and test predictions (calibrated)"""
    feats = feature_cols(df)
    d = df[mask].reset_index(drop=True)
    tr, te = d[d.split == "train"], d[d.split == "test"]
    X, Xt = tr[feats].to_numpy(float), te[feats].to_numpy(float)
    y = tr[target].to_numpy() if not nclass else tr[target].map(cm.suites.index).to_numpy()
    g = tr.group.to_numpy()
    p = ml.params("multiclass", nclass) if nclass else ml.params("binary")
    b, oofp, rounds, fold = ml.oof(X, y, g, p)
    pt = b.predict(Xt)
    if nclass:
        cal = [ml.iso_fit(oofp[:, k], (y == k).astype(int)) for k in range(nclass)]
        oc, tc = ml.iso_multi(cal, oofp), ml.iso_multi(cal, pt)
    else:
        cal = ml.iso_fit(oofp, y)
        oc, tc = ml.iso(cal, oofp), ml.iso(cal, pt)
    b.save_model(str(work / f"config_{name}.txt"))
    (work / f"config_{name}.json").write_text(json.dumps({"calibration": cal, "rounds": rounds, "features": feats}))
    return {"booster": b, "cal": cal, "rounds": rounds, "feats": feats, "train": tr, "test": te,
            "oof": oc, "pred": tc, "oof_raw": oofp, "fold": fold}


def scores(y, p, nclass):
    yhat = p.argmax(1) if nclass else (p >= 0.5).astype(int)
    return {"n": int(len(y)), "accuracy": float(accuracy_score(y, yhat)) if len(y) else None,
            "macro_f1": float(f1_score(y, yhat, average="macro")) if len(y) else None}


def loco(df, m, target, mask, nclass):
    """leave one config out: for each set-a combination with test rows, a booster trained on the
    training rows of the other combinations predicts that combination's test rows"""
    feats = m["feats"]
    d = df[mask]
    out = {}
    tr_all = d[d.split == "train"]
    for combo in sorted(d[d.split == "test"].combo.unique()):
        tr = tr_all[tr_all.combo != combo]
        te = d[(d.split == "test") & (d.combo == combo)]
        y = tr[target].to_numpy() if not nclass else tr[target].map(cm.suites.index).to_numpy()
        yt = te[target].to_numpy() if not nclass else te[target].map(cm.suites.index).to_numpy()
        p = ml.params("multiclass", nclass) if nclass else ml.params("binary")
        b, _ = ml.fit(tr[feats].to_numpy(float), y, tr.group.to_numpy(), p, rounds=m["rounds"])
        pt = b.predict(te[feats].to_numpy(float))
        out[combo] = scores(yt, pt, nclass)
    return out


def report(m, target, nclass):
    te = m["test"]
    yt = te[target].to_numpy() if not nclass else te[target].map(cm.suites.index).to_numpy()
    res = {"overall": scores(yt, m["pred"], nclass), "by_evidence": {}, "rounds": m["rounds"]}
    for ev in fx.sizes:
        k = ev or -1
        sel = (te.evidence == k).to_numpy()
        res["by_evidence"][str(ev or "all")] = scores(yt[sel], m["pred"][sel], nclass)
    yhat = m["pred"].argmax(1) if nclass else (m["pred"] >= 0.5).astype(int)
    res["confusion"] = confusion_matrix(yt, yhat, labels=list(range(nclass or 2))).tolist()
    if nclass:
        conf = m["pred"].max(1)
        res["ece"], res["reliability"] = ml.ece(conf, (yhat == yt).astype(int))
    else:
        res["ece"], res["reliability"] = ml.ece(m["pred"], yt)
    res["ece_uncalibrated_oof"] = None
    res["importance"] = ml.gains(m["booster"], m["feats"])
    res["by_stage"] = {}
    for st in sorted(te.stage.unique()):
        sel = (te.stage == st).to_numpy() & (te.evidence == -1).to_numpy()
        res["by_stage"][st] = scores(yt[sel], m["pred"][sel], nclass)
    return res


def main():
    work.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    df = build_rows()
    print("config rows", len(df), df.groupby(["tier", "split"]).size().to_dict(), flush=True)
    allm = np.ones(len(df), bool)
    ms = {"suite": train(df, "suite", "suite", allm, 4), "mode": train(df, "mode", "mode", allm),
          "pfs": train(df, "pfs", "pfs", pfs_rows(df).to_numpy())}
    res = {"rows": {f"{t}|{s}": int(n) for (t, s), n in df.groupby(["tier", "split"]).size().items()},
           "tunnels": int(df[df.evidence == -1].shape[0])}
    for name, target, nc in (("suite", "suite", 4), ("mode", "mode", None), ("pfs", "pfs", None)):
        res[name] = report(ms[name], target, nc)
        mask = allm if name != "pfs" else pfs_rows(df).to_numpy()
        if name != "pfs":
            res[name]["loco"] = loco(df, ms[name], target, mask, nc)
        print(name, res[name]["overall"], {k: v["accuracy"] for k, v in res[name]["by_evidence"].items()}, flush=True)
    res["pfs"]["rows"] = int(pfs_rows(df).sum())
    # config context per tunnel (all-packet evidence): out-of-fold for training tunnels, the
    # final booster for test tunnels
    pred = []
    for split in ("train", "test"):
        key = "oof" if split == "train" else "pred"
        s = ms["suite"][split]
        mo = ms["mode"][split]
        sel = (s.evidence == -1).to_numpy()
        msel = (mo.evidence == -1).to_numpy()
        ps, pm = ms["suite"][key][sel], ms["mode"][key][msel]
        a = s[sel][["run_id", "tunnel"]].reset_index(drop=True)
        b = mo[msel][["run_id", "tunnel"]].reset_index(drop=True)
        assert (a == b).all().all()
        for k, su in enumerate(cm.suites):
            a[f"p_{su}"] = ps[:, k]
        a["p_tunnel"] = pm
        a["source"] = "oof" if split == "train" else "final"
        pred.append(a)
    pd.concat(pred).to_parquet(cm.feat / "config_pred.parquet")
    (results / "config.json").write_text(json.dumps(res, indent=1, default=float))


if __name__ == "__main__":
    main()
