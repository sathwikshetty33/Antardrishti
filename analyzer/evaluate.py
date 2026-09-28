"""evaluation (analyzer/CLAUDE.md section 8) -> analyzer/REPORT.md and analyzer/report/*.png.

  python -m analyzer.evaluate

every metric below uses the held-out test split. the in-distribution test set is the lab test
windows (p0s, P1 anchor, mixtures, chat); realism and WhatsApp are reported as separate
out-of-distribution rows. also writes features/work/error_table.json (the out-of-fold session
share errors the cli's error bars come from) and features/results/eval.json.
"""
import json
import time
from collections import Counter, defaultdict

import lightgbm as lgb
import matplotlib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from analyzer import aggregate as ag
from analyzer import common as cm
from analyzer import features as fx
from analyzer import ml

work = cm.feat / "work"
results = cm.feat / "results"
colors = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
ink, muted, surface = "#0b0b0b", "#52514e", "#fcfcfb"
bucket_names = ["0-10", "10-50", "50-100"]


# ---------------------------------------------------------------- helpers

def prf(y, yhat):
    y, yhat = np.asarray(y, bool), np.asarray(yhat, bool)
    tp, fp, fn = (y & yhat).sum(), (~y & yhat).sum(), (y & ~yhat).sum()
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * tp / (2 * tp + fp + fn) if y.any() else None
    return {"f1": f, "precision": p, "recall": r, "support": int(y.sum()), "n": int(len(y))}


def fmt(x, pct=False, nd=3):
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "-"
    return f"{x * 100:.1f}%" if pct else f"{x:.{nd}f}"


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def style(ax):
    ax.set_facecolor(surface)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(muted)
    ax.tick_params(colors=muted, labelsize=8)
    ax.yaxis.grid(True, color="#e6e5e0", linewidth=0.6)
    ax.set_axisbelow(True)


def fig(w, h, n=1, m=1):
    f, axs = plt.subplots(m, n, figsize=(w, h), squeeze=False)
    f.patch.set_facecolor(surface)
    for ax in axs.flat:
        style(ax)
    return f, axs


def save(f, name):
    cm.report.mkdir(parents=True, exist_ok=True)
    f.tight_layout()
    f.savefig(cm.report / name, dpi=110, facecolor=surface)
    plt.close(f)


def in_dist(df):
    return (df.split == "test") & ~df.stage.isin(["realism", "whatsapp"])


def present_pred(df):
    return {a: (df[f"p_{a}"] >= df[f"thr_{a}"]).to_numpy() for a in cm.apps}


def run_records():
    out = {}
    for tier in cm.tiers:
        for jf in (cm.feat / tier).glob("*.json"):
            r = json.loads(jf.read_text())
            out[r["run_id"]] = r
    return out


# ---------------------------------------------------------------- sessions

def sessions(df):
    """per (run, tunnel): predicted and true byte shares, the apps excluded (unknown windows)"""
    out = []
    P = df[[f"p_{a}" for a in cm.apps]].to_numpy()
    Q = df[[f"q_{a}" for a in cm.apps]].to_numpy()
    thr = df[[f"thr_{a}" for a in cm.apps]].iloc[0].to_numpy() if len(df) else np.zeros(len(cm.apps))
    for (rid, t), ix in df.groupby(["run_id", "tunnel"]).indices.items():
        d = df.iloc[ix]
        p, q = np.nan_to_num(P[ix]), np.nan_to_num(Q[ix])
        s = ag.session(d.esp_bytes.to_numpy(), p, q, thr)
        true = ag.true_session({a: d[f"b_{a}"].to_numpy() for a in cm.apps}, d.b_unknown.to_numpy(),
                               d.esp_bytes.to_numpy())
        skip = {a for a in cm.apps if d[f"u_{a}"].any() or d[f"p_{a}"].isna().any()}
        out.append({"run_id": rid, "tunnel": t, "stage": d.stage.iloc[0], "tier": d.tier.iloc[0],
                    "source": d.source.iloc[0], "pred": s["byte_share"], "active": s["active_share"],
                    "true": true, "skip": skip, "windows": len(d)})
    return out


def session_mae(ss):
    err = {a: [[] for _ in ag.buckets] for a in cm.apps}
    for s in ss:
        for a in cm.apps:
            if a in s["skip"]:
                continue
            err[a][ag.bucket(s["true"][a])].append(abs(s["pred"][a] - s["true"][a]))
    return {a: [(float(np.mean(e)) if e else None, len(e)) for e in err[a]] for a in cm.apps}


def window_mae(df):
    P = np.nan_to_num(df[[f"p_{a}" for a in cm.apps]].to_numpy())
    Q = np.nan_to_num(df[[f"q_{a}" for a in cm.apps]].to_numpy())
    thr = df[[f"thr_{a}" for a in cm.apps]].iloc[0].to_numpy()
    s, _ = ag.window_shares(P, Q, thr)
    out = {}
    for k, a in enumerate(cm.apps):
        ok = (df[f"u_{a}"] == 0).to_numpy()
        tr = df[f"s_{a}"].to_numpy() * 100
        pr = s[:, k] * 100
        out[a] = []
        for lo, hi in ag.buckets:
            m = ok & (tr >= lo) & (tr < hi)
            out[a].append((float(np.mean(np.abs(pr[m] - tr[m]))) if m.any() else None, int(m.sum())))
    return out


# ---------------------------------------------------------------- label decisions

def label_decisions(recs, win):
    lk = defaultdict(lambda: {"runs": 0, "runs_relabelled": 0, "runs_over_1pct": 0, "esp_bytes": 0,
                              "other_app_bytes": 0, "unknown_bytes": 0, "by_app": Counter()})
    amb = defaultdict(lambda: {"runs": 0, "ambiguous_bytes": 0, "resolved_bytes": 0})
    for r in recs.values():
        L = r["labels"]
        key = f"{r['tier']} {r['stage']}"
        if "relabelled_bytes" in L:
            x = lk[key]
            x["runs"] += 1
            rb = L["relabelled_bytes"]
            tot = sum(rb.values())
            x["esp_bytes"] += L["esp_bytes"]
            x["runs_relabelled"] += int(tot > 0)
            x["runs_over_1pct"] += int(tot > 0.01 * max(L["esp_bytes"], 1))
            x["unknown_bytes"] += rb.get("unknown", 0)
            x["other_app_bytes"] += tot - rb.get("unknown", 0)
            for k, v in rb.items():
                x["by_app"][k] += v
        if "ambiguous_bytes" in L and r["stage"] == "mixtures":
            y = amb[r["scenario"]]
            y["runs"] += 1
            y["ambiguous_bytes"] += L["ambiguous_bytes"]
            y["resolved_bytes"] += L["ambiguous_resolved_bytes"]
    u = win[[f"u_{a}" for a in cm.apps]].to_numpy().astype(bool)
    per_app = {a: {"train": int(u[(win.split == "train").to_numpy(), k].sum()),
                   "test": int(u[(win.split == "test").to_numpy(), k].sum())} for k, a in enumerate(cm.apps)}
    pairs = Counter()
    for k, row in enumerate(u):
        if row.any():
            pairs[("+".join(a for a, f in zip(cm.apps, row) if f), win.split.iloc[k])] += 1
    return {"leaks": {k: {**v, "by_app": dict(v["by_app"])} for k, v in lk.items()}, "ambiguous": dict(amb),
            "excluded_windows": per_app, "excluded_pairs": {f"{k[0]} ({k[1]})": v for k, v in sorted(pairs.items())}}


# ---------------------------------------------------------------- p0 vs p0s

def twins(recs):
    """paired p0 vs p0s comparison of volume and timing, leaked bytes excluded from both"""
    rows = []
    for r in recs.values():
        if r["tier"] != "p0s" or not r.get("recapture_of"):
            continue
        tw = recs.get(r["recapture_of"])
        if not tw:
            continue
        v = {}
        for side, rec in (("p0s", r), ("p0", tw)):
            tab = pq.read_table(cm.feat / rec["tier"] / f"{rec['run_id']}.parquet",
                                columns=["t", "dir", "elen", "app"]).to_pandas()
            ra = cm.apps.index(cm.run_app(rec))
            own = tab[tab.app == ra]
            iat = np.diff(np.sort(own.t.to_numpy()))
            v[side] = {"packets": len(own), "bytes": float(own.elen.sum()), "all_packets": len(tab),
                       "all_bytes": float(tab.elen.sum()), "iat_p50": float(np.median(iat)) if len(iat) else np.nan}
        rows.append({"app": cm.run_app(r), **{f"{s}_{k}": x for s in v for k, x in v[s].items()}})
    df = pd.DataFrame(rows)
    out = {}
    for a, d in df.groupby("app"):
        out[a] = {"pairs": len(d), "packets_ratio": d.p0s_packets.sum() / max(d.p0_packets.sum(), 1),
                  "bytes_ratio": d.p0s_bytes.sum() / max(d.p0_bytes.sum(), 1),
                  "packets_ratio_with_leak": d.p0s_all_packets.sum() / max(d.p0_all_packets.sum(), 1),
                  "median_pair_iat_ratio": float(np.nanmedian(d.p0s_iat_p50 / d.p0_iat_p50))}
    return out


# ---------------------------------------------------------------- loco and ablation

def boost(X, y, rounds, w=None):
    b, _ = ml.fit(X, y, None, ml.params("binary"), w=w, rounds=rounds)
    return b


def traffic_loco(win, pred, feats, meta):
    """one fold per (mode, wire shape): trained on the other training windows, scored on the
    fold's test windows with the main calibration and threshold"""
    out = {}
    te_all = in_dist(win)
    for fold in sorted(win.loc[te_all, ["mode", "shape"]].drop_duplicates().itertuples(index=False)):
        key = f"{fold.mode}|{fold.shape}"
        inf = (win["mode"] == fold.mode) & (win["shape"] == fold.shape)
        te = te_all & inf
        r = {}
        for a in cm.apps:
            tr = (win.split == "train") & ~inf & (win[f"u_{a}"] == 0)
            y = win.loc[tr, f"y_{a}"].to_numpy()
            b = boost(win.loc[tr, feats].to_numpy(np.float32), y, meta[a]["rounds"], ml.balanced(y))
            ok = te & (win[f"u_{a}"] == 0)
            p = ml.iso(meta[a]["calibration"], b.predict(win.loc[ok, feats].to_numpy(np.float32)))
            r[a] = prf(win.loc[ok, f"y_{a}"], p >= meta[a]["threshold"])["f1"]
        out[key] = r
    return out


def ablation(win, feats):
    """size-only vs full features, leave-one-tunnel-out over the anchor set's 8 tunnels"""
    an = win[win.stage == "anchor"].reset_index(drop=True)
    size = [c for c in feats if c in fx.size_cols or c.startswith("ctx_")]
    groups = an.group.to_numpy()
    out = {"tunnels": int(len(np.unique(groups))), "windows": int(len(an)), "size_features": len(size),
           "full_features": len(feats)}
    for name, cols in (("size", size), ("full", feats)):
        X = an[cols].to_numpy(np.float32)
        res = {}
        for a in cm.apps:
            y = an[f"y_{a}"].to_numpy()
            if y.sum() == 0:
                continue
            p = np.zeros(len(y))
            for g in np.unique(groups):
                te = groups == g
                tr = ~te
                if len(np.unique(y[tr])) < 2:
                    continue
                b = boost(X[tr], y[tr], 200, ml.balanced(y[tr]))
                p[te] = b.predict(X[te])
            res[a] = prf(y, p >= 0.5)["f1"]
        out[name] = res
    return out


# ---------------------------------------------------------------- main

def main():
    t_start = time.time()
    results.mkdir(parents=True, exist_ok=True)
    cm.report.mkdir(parents=True, exist_ok=True)
    wp = pd.read_parquet(cm.feat / "window_pred.parquet")
    win = pd.read_parquet(cm.feat / "windows.parquet")
    feats = json.loads((work / "window_features.json").read_text())
    meta = {a: json.loads((work / f"presence_{a}.json").read_text()) for a in cm.apps}
    cfg = json.loads((results / "config.json").read_text())
    recs = run_records()
    R = {"config": cfg}
    pres = present_pred(wp)
    ind = in_dist(wp).to_numpy()
    npres = wp[[f"y_{a}" for a in cm.apps]].sum(1).to_numpy()
    # presence
    P = {}
    for a in cm.apps:
        ok = (wp[f"u_{a}"] == 0).to_numpy() & ind
        y = wp[f"y_{a}"].to_numpy()
        P[a] = {"all": prf(y[ok], pres[a][ok]), "pure": prf(y[ok & (npres <= 1)], pres[a][ok & (npres <= 1)]),
                "mixed": prf(y[ok & (npres >= 2)], pres[a][ok & (npres >= 2)])}
        e, curve = ml.ece(wp.loc[ok, f"p_{a}"], y[ok])
        P[a]["ece"], P[a]["reliability"] = e, curve
        P[a]["threshold"] = meta[a]["threshold"]
    R["presence"] = P
    macro = lambda d: float(np.mean([v for v in d.values() if v is not None])) if d else None
    by = {}
    for col in ("netem", "capture_start", "stage"):
        by[col] = {}
        for v in sorted(wp.loc[ind, col].unique()):
            sel = ind & (wp[col] == v).to_numpy()
            by[col][v] = {a: prf(wp.loc[sel & (wp[f"u_{a}"] == 0).to_numpy(), f"y_{a}"],
                                 pres[a][sel & (wp[f"u_{a}"] == 0).to_numpy()])["f1"] for a in cm.apps}
    R["presence_by"] = by
    # shares
    ss_test = sessions(wp[ind])
    R["share_session"] = session_mae(ss_test)
    R["share_window"] = window_mae(wp[ind])
    R["sessions_test"] = len(ss_test)
    # out-of-fold error table for the cli
    tr = (wp.split == "train").to_numpy()
    ss_oof = sessions(wp[tr])
    et = ag.error_table([(s["pred"], s["true"], s["skip"]) for s in ss_oof])
    (work / "error_table.json").write_text(json.dumps({"buckets": bucket_names, "mae_pp": et,
                                                       "sessions": len(ss_oof)}))
    R["error_table"] = et
    # ood
    ood = {}
    for name, sel in (("realism", (wp.stage == "realism").to_numpy()),
                      ("whatsapp test", ((wp.stage == "whatsapp") & (wp.split == "test")).to_numpy())):
        ood[name] = {a: prf(wp.loc[sel & (wp[f"u_{a}"] == 0).to_numpy(), f"y_{a}"],
                            pres[a][sel & (wp[f"u_{a}"] == 0).to_numpy()]) for a in cm.apps}
        ood[name]["_windows"] = int(sel.sum())
    wa = []
    for s in sessions(wp[(wp.stage == "whatsapp") & (wp.split == "test")]):
        r = recs[s["run_id"]]
        a = cm.run_app(r)
        wa.append({"run": s["run_id"], "source": r["replay"]["source"], "scenario": r["replay"]["scenario"],
                   "device": r["replay"]["device"], "file": r["replay"]["source_file"], "app": a,
                   "true": s["true"][a], "pred": s["pred"][a], "active": s["active"][a],
                   "unknown": s["pred"]["unknown"], "windows": s["windows"]})
    rl = []
    for s in sessions(wp[wp.stage == "realism"]):
        rl.append({"run": s["run_id"], "true_web": s["true"]["web"], "pred_web": s["pred"]["web"],
                   "true_bulk": s["true"]["bulk"], "pred_bulk": s["pred"]["bulk"], "unknown": s["pred"]["unknown"],
                   "top_wrong": max(((a, s["pred"][a]) for a in cm.apps if a not in ("web", "bulk")),
                                    key=lambda x: x[1])})
    R["ood"], R["whatsapp_runs"], R["realism_runs"] = ood, wa, rl
    # label decisions, twins
    R["labels"] = label_decisions(recs, win)
    R["twins"] = twins(recs)
    # loco, ablation
    print("loco", flush=True)
    R["traffic_loco"] = traffic_loco(win, wp, feats, meta)
    print("ablation", flush=True)
    R["ablation"] = ablation(win, feats)
    # importance
    imp = {}
    for kind in ("presence", "share"):
        for a in cm.apps:
            b = lgb.Booster(model_file=str(work / f"{kind}_{a}.txt"))
            imp[f"{kind} {a}"] = ml.gains(b, feats, 10)
    R["importance"] = imp
    R["counts"] = {
        "windows": {f"{t} {s} {sp}": int(n) for (t, s, sp), n in win.groupby(["tier", "stage", "split"]).size().items()},
        "presence_positives": {a: {"train": int(win.loc[win.split == "train", f"y_{a}"].sum()),
                                   "test": int(win.loc[win.split == "test", f"y_{a}"].sum())} for a in cm.apps}}
    R["eval_seconds"] = time.time() - t_start
    (results / "eval.json").write_text(json.dumps(R, indent=1, default=lambda o: sorted(o) if isinstance(o, set) else float(o)))
    plots(R)
    print("eval done", round(time.time() - t_start), "s", flush=True)


def plots(R):
    x = np.arange(len(cm.apps))
    # presence f1, pure vs mixed
    f, ax = fig(7.5, 3.2)
    ax = ax[0, 0]
    for k, (kind, c) in enumerate((("pure", colors[0]), ("mixed", colors[1]))):
        v = [R["presence"][a][kind]["f1"] or 0 for a in cm.apps]
        ax.bar(x + (k - 0.5) * 0.38, v, 0.36, color=c, label=f"{kind} windows", edgecolor=surface, linewidth=2)
    ax.set_xticks(x, cm.apps)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1 (test)", color=muted, fontsize=9)
    ax.set_title("Presence F1 per app, held-out lab test windows", color=ink, fontsize=10, loc="left")
    ax.legend(frameon=False, fontsize=8)
    save(f, "presence_f1.png")
    # reliability, presence
    f, axs = fig(10, 5.2, 4, 2)
    for k, a in enumerate(cm.apps):
        ax = axs.flat[k]
        c = R["presence"][a]["reliability"]
        ax.plot([0, 1], [0, 1], color=muted, linewidth=0.8, linestyle="--")
        ax.plot([p for p, _, _ in c], [o for _, o, _ in c], color=colors[k], linewidth=2, marker="o", markersize=4)
        ax.set_title(f"{a}  ECE {R['presence'][a]['ece']:.3f}", color=ink, fontsize=9, loc="left")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
    ax = axs.flat[7]
    for name, k in (("suite", 0), ("mode", 1), ("pfs", 2)):
        c = R["config"][name]["reliability"]
        ax.plot([p for p, _, _ in c], [o for _, o, _ in c], color=colors[k], linewidth=2, marker="o", markersize=4,
                label=f"{name} {R['config'][name]['ece']:.3f}")
    ax.plot([0, 1], [0, 1], color=muted, linewidth=0.8, linestyle="--")
    ax.set_title("config models (ECE)", color=ink, fontsize=9, loc="left")
    ax.legend(frameon=False, fontsize=7)
    f.supxlabel("predicted probability", color=muted, fontsize=9)
    f.supylabel("observed frequency", color=muted, fontsize=9)
    save(f, "reliability.png")
    # session share mae by true bucket
    f, ax = fig(7.5, 3.2)
    ax = ax[0, 0]
    for k, b in enumerate(bucket_names):
        v = [R["share_session"][a][k][0] or 0 for a in cm.apps]
        ax.bar(x + (k - 1) * 0.27, v, 0.25, color=colors[k], label=f"true share {b}%", edgecolor=surface, linewidth=2)
    ax.set_xticks(x, cm.apps)
    ax.set_ylabel("MAE, percentage points", color=muted, fontsize=9)
    ax.set_title("Session byte-share error per app, by true share", color=ink, fontsize=10, loc="left")
    ax.legend(frameon=False, fontsize=8)
    save(f, "share_mae.png")
    # config accuracy by evidence
    f, ax = fig(5, 3)
    ax = ax[0, 0]
    ev = ["50", "200", "1000", "all"]
    for k, name in enumerate(("suite", "mode")):
        v = [R["config"][name]["by_evidence"][e]["accuracy"] for e in ev]
        ax.plot(ev, v, color=colors[k], linewidth=2, marker="o", markersize=5, label=name)
        ax.annotate(name, (3, v[-1]), textcoords="offset points", xytext=(6, 0), color=ink, fontsize=8, va="center")
    ax.set_ylim(min(0.5, ax.get_ylim()[0]), 1.01)
    ax.set_xlabel("ESP packets of evidence", color=muted, fontsize=9)
    ax.set_ylabel("accuracy (test)", color=muted, fontsize=9)
    ax.set_title("Config accuracy by evidence size", color=ink, fontsize=10, loc="left")
    ax.legend(frameon=False, fontsize=8)
    save(f, "config_evidence.png")
    # ablation
    ab = R["ablation"]
    keys = [a for a in cm.apps if a in ab["full"]]
    f, ax = fig(7.5, 3.2)
    ax = ax[0, 0]
    xx = np.arange(len(keys))
    for k, (name, c) in enumerate((("size", colors[0]), ("full", colors[1]))):
        ax.bar(xx + (k - 0.5) * 0.38, [ab[name].get(a) or 0 for a in keys], 0.36, color=c,
               label="size-only" if name == "size" else "full features", edgecolor=surface, linewidth=2)
    ax.set_xticks(xx, keys)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1, leave-one-tunnel-out", color=muted, fontsize=9)
    ax.set_title("Ablation on the anchor set (8 tunnels)", color=ink, fontsize=10, loc="left")
    ax.legend(frameon=False, fontsize=8)
    save(f, "ablation.png")
    # importance, presence models
    f, axs = fig(12, 6.5, 4, 2)
    for k, a in enumerate(cm.apps):
        ax = axs.flat[k]
        g = R["importance"][f"presence {a}"][:8][::-1]
        ax.barh([n for n, _ in g], [v for _, v in g], color=colors[0], height=0.6)
        ax.set_title(f"presence {a}", color=ink, fontsize=9, loc="left")
        ax.tick_params(axis="y", labelsize=7)
        ax.xaxis.grid(True, color="#e6e5e0", linewidth=0.6)
        ax.yaxis.grid(False)
    axs.flat[7].axis("off")
    f.supxlabel("share of gain", color=muted, fontsize=9)
    save(f, "importance_presence.png")


def write_report(R):
    """analyzer/REPORT.md from eval.json, the environment and the hand-written findings"""
    c, P = R["config"], R["presence"]
    env = json.loads((results / "env.json").read_text()) if (results / "env.json").exists() else {}
    speed = json.loads((results / "cli_speed.json").read_text()) if (results / "cli_speed.json").exists() else None
    findings = (cm.report / "findings.md").read_text() if (cm.report / "findings.md").exists() else ""
    macro_f1 = float(np.mean([P[a]["all"]["f1"] for a in cm.apps if P[a]["all"]["f1"] is not None]))
    ss = R["share_session"]
    allerr = [m for a in cm.apps for m, n in ss[a] if m is not None for _ in range(n)]
    L = ["# Antardrishti analyzer: evaluation report (models/v1)", "",
         "Generated by `python -m analyzer.evaluate` from the held-out test split. Nothing here was tuned on "
         "the test split: thresholds, calibration, early stopping and hyperparameters come from grouped "
         "out-of-fold predictions on the training split only. Spec: `analyzer/CLAUDE.md`.", "",
         "## Headline", "",
         table(["model", "metric", "test"], [
             ["config: ESP suite (4 wire shapes)", "accuracy, all packets", fmt(c["suite"]["by_evidence"]["all"]["accuracy"], True)],
             ["config: ESP suite", "accuracy, first 50 ESP packets", fmt(c["suite"]["by_evidence"]["50"]["accuracy"], True)],
             ["config: mode (tunnel / transport)", "accuracy, all packets", fmt(c["mode"]["by_evidence"]["all"]["accuracy"], True)],
             ["config: PFS (tunnels with a rekey)", "accuracy, all packets", fmt(c["pfs"]["by_evidence"]["all"]["accuracy"], True)],
             ["presence (7 apps)", "macro F1, lab test windows", fmt(macro_f1)],
             ["share (7 apps)", "session byte-share MAE, pp (all apps, all buckets)",
              fmt(float(np.mean(allerr)) if allerr else None, nd=2)]]), "",
         table(["app"] + cm.apps, [["presence F1"] + [fmt(P[a]["all"]["f1"]) for a in cm.apps],
                                   ["precision"] + [fmt(P[a]["all"]["precision"]) for a in cm.apps],
                                   ["recall"] + [fmt(P[a]["all"]["recall"]) for a in cm.apps],
                                   ["test positives"] + [P[a]["all"]["support"] for a in cm.apps]]), "",
         findings, "",
         "## Data and tier usage", "",
         "Traffic models use p0s, P1 anchor, mixtures, chat, realism and WhatsApp; P0's 192 traffic runs are "
         "excluded (parallel capture distorted their timing and volume). Config models use every tier except "
         "e15, e16 and e19. Splits are each run's recorded split (WhatsApp by source file, p0s via its P0 "
         "twin); all 8 realism runs are test-only. CV groups are the config hash.", "",
         "Config evidence rows (tunnels x evidence sizes):", "",
         table(["tier, split", "rows"], [[k, v] for k, v in sorted(c["rows"].items())]), "",
         "Windows (2 s, per tunnel and SPI pair):", "",
         table(["tier stage split", "windows"], [[k, v] for k, v in sorted(R["counts"]["windows"].items())]), "",
         table(["app", "positive windows, train", "positive windows, test"],
               [[a, v["train"], v["test"]] for a, v in R["counts"]["presence_positives"].items()]), "",
         "## Label decisions (analyzer/CLAUDE.md section 11)", "",
         "**Leaked bulk transfers.** Single-app runs take the run's app, except packets whose decrypted header "
         "names another lab app (almost always bulk over ssh), which keep that app. Packets whose header names "
         "no lab app (`other`: in single-app lab runs these are HTTPS or ping flows leaked from an earlier run, "
         "for which no app can be named) count as unknown bytes rather than the run's app. Realism windows take "
         "the run's app, web, whatever the port rule said (the QUIC-as-voip rule is ignored); only bulk keeps "
         "its own label there. Relabelled per tier and stage:", "",
         table(["tier stage", "runs", "runs relabelled", "runs over 1%", "ESP MB", "MB kept as another app",
                "MB unknown", "by app (MB)"],
               [[k, v["runs"], v["runs_relabelled"], v["runs_over_1pct"], f"{v['esp_bytes'] / 1e6:.1f}",
                 f"{v['other_app_bytes'] / 1e6:.1f}", f"{v['unknown_bytes'] / 1e6:.1f}",
                 ", ".join(f"{a} {b / 1e6:.1f}" for a, b in sorted(v["by_app"].items()) if b > 0) or "-"]
                for k, v in sorted(R["labels"]["leaks"].items())]), "",
         "**Ambiguous HTTPS in mixtures.** Where only one candidate app is active in the schedule, the packet "
         "gets that app. Otherwise the window's presence and share are unknown for the candidate apps only "
         "(when the unresolved packets alone would reach the presence rule: 5 packets or 2% of the window's "
         "ESP bytes); those windows are left out of those apps' training and evaluation and out of their "
         "session-share scoring; the other apps' labels in the window stay exact.", "",
         table(["mixture", "runs", "ambiguous MB", "resolved by schedule"],
               [[k, v["runs"], f"{v['ambiguous_bytes'] / 1e6:.1f}",
                 fmt(v["resolved_bytes"] / v["ambiguous_bytes"], True) if v["ambiguous_bytes"] else "-"]
                for k, v in sorted(R["labels"]["ambiguous"].items()) if v["ambiguous_bytes"]]), "",
         "Windows left out, per app:", "",
         table(["app", "train", "test"], [[a, v["train"], v["test"]] for a, v in R["labels"]["excluded_windows"].items()]),
         "", "Windows left out, per unknown app set:", "",
         table(["apps (split)", "windows"], [[k, v] for k, v in R["labels"]["excluded_pairs"].items()]), "",
         "## Config models", "",
         table(["model", "50", "200", "1000", "all"],
               [[m] + [fmt(c[m]["by_evidence"][e]["accuracy"], True) + f" (F1 {fmt(c[m]['by_evidence'][e]['macro_f1'])}, n {c[m]['by_evidence'][e]['n']})"
                       for e in ("50", "200", "1000", "all")] for m in ("suite", "mode", "pfs")]), "",
         "Accuracy (macro-F1, test rows) by evidence size (ESP packets). PFS needs an observed child rekey; "
         f"{c['pfs'].get('rows', '-')} rows qualify, every other tunnel is \"not determinable\".", "",
         "![config accuracy by evidence](report/config_evidence.png)", "",
         "Suite confusion (rows true, columns predicted; " + ", ".join(cm.suites) + "):", "",
         table([""] + cm.suites, [[cm.suites[i]] + row for i, row in enumerate(c["suite"]["confusion"])]), "",
         "Mode confusion (transport, tunnel): " + str(c["mode"]["confusion"]) + "; PFS (off, on): "
         + str(c["pfs"]["confusion"]), "",
         "Leave one config out (32 set-A combinations: mode, wire shape, outer family, NAT-T; each scored on "
         "its test rows by a booster trained on the other combinations):", "",
         table(["combination", "suite acc", "mode acc", "rows"],
               [[k, fmt(c["suite"]["loco"][k]["accuracy"], True), fmt(c["mode"]["loco"].get(k, {}).get("accuracy"), True),
                 c["suite"]["loco"][k]["n"]] for k in sorted(c["suite"]["loco"])]), "",
         f"Calibration (test): ECE suite {c['suite']['ece']:.3f} (top-class confidence), mode {c['mode']['ece']:.3f}, "
         f"PFS {c['pfs']['ece']:.3f}.", "",
         "By stage (all-packet rows):", "",
         table(["stage", "suite acc", "mode acc", "n"],
               [[s, fmt(c["suite"]["by_stage"][s]["accuracy"], True), fmt(c["mode"]["by_stage"].get(s, {}).get("accuracy"), True),
                 c["suite"]["by_stage"][s]["n"]] for s in sorted(c["suite"]["by_stage"])]), "",
         "## Presence", "",
         "Per app on the lab test windows (p0s, anchor, mixtures, live chat), windows unknown for the app left "
         "out. Pure: at most one app present; mixed: two or more.", "",
         table(["app", "threshold", "F1 all", "P", "R", "F1 pure", "F1 mixed", "mixed positives", "ECE"],
               [[a, fmt(P[a]["threshold"]), fmt(P[a]["all"]["f1"]), fmt(P[a]["all"]["precision"]),
                 fmt(P[a]["all"]["recall"]), fmt(P[a]["pure"]["f1"]), fmt(P[a]["mixed"]["f1"]),
                 P[a]["mixed"]["support"], fmt(P[a]["ece"])] for a in cm.apps]), "",
         "![presence F1](report/presence_f1.png)", ""]
    for col, title in (("netem", "By netem profile"), ("capture_start", "By capture start"), ("stage", "By stage")):
        by = R["presence_by"][col]
        L += [f"{title} (F1):", "", table([col] + cm.apps, [[k] + [fmt(v[a]) for a in cm.apps] for k, v in by.items()]), ""]
    lo = R["traffic_loco"]
    L += ["Leave one config out (8 folds, mode x wire shape; trained on the other configs' training windows, "
          "scored on the fold's test windows with the main calibration and threshold):", "",
          table(["fold"] + cm.apps, [[k] + [fmt(v[a]) for a in cm.apps] for k, v in lo.items()]), "",
          "![reliability](report/reliability.png)", "",
          "## Share", "",
          "Mean absolute error in percentage points, bucketed by the true share (count in brackets). Session = "
          "one tunnel of one test run; shares are byte-weighted over the session's windows, absent apps zeroed "
          "and renormalised per window.", "",
          table(["app"] + [f"session {b}%" for b in bucket_names] + [f"window {b}%" for b in bucket_names],
                [[a] + [f"{fmt(m, nd=1)} ({n})" for m, n in R["share_session"][a]]
                 + [f"{fmt(m, nd=1)} ({n})" for m, n in R["share_window"][a]] for a in cm.apps]), "",
          "![share error](report/share_mae.png)", "",
          "Error bars in the CLI output are the out-of-fold session MAE per app and predicted-share bucket "
          f"(training sessions):", "",
          table(["app"] + bucket_names, [[a] + [fmt(v, nd=1) for v in R["error_table"][a]] for a in cm.apps]), "",
          "## Out of distribution", "",
          f"**Realism** (internet, 8 runs, {R['ood']['realism']['_windows']} windows, test-only). Labels: web, "
          "except leaked bulk.", "",
          table(["app", "F1", "P", "R", "positives"],
                [[a, fmt(v["f1"]), fmt(v["precision"]), fmt(v["recall"]), v["support"]]
                 for a, v in R["ood"]["realism"].items() if not a.startswith("_") and v["support"]]), "",
          table(["run", "web true", "web pred", "bulk true", "bulk pred", "unknown pred", "largest wrong app"],
                [[r["run"], fmt(r["true_web"], nd=1), fmt(r["pred_web"], nd=1), fmt(r["true_bulk"], nd=1),
                  fmt(r["pred_bulk"], nd=1), fmt(r["unknown"], nd=1), f"{r['top_wrong'][0]} {r['top_wrong'][1]:.1f}"]
                 for r in R["realism_runs"]]), "",
          "**WhatsApp** (replayed public captures, test runs by source file):", "",
          table(["run", "source", "scenario / device", "file", "app", "true %", "pred %", "active %", "unknown %", "windows"],
                [[r["run"], r["source"], f"{r['scenario']} / {r['device']}", r["file"], r["app"], fmt(r["true"], nd=1),
                  fmt(r["pred"], nd=1), fmt(r["active"], nd=1), fmt(r["unknown"], nd=1), r["windows"]]
                 for r in R["whatsapp_runs"]]), "",
          table(["app", "F1 (WhatsApp test windows)", "P", "R", "positives"],
                [[a, fmt(v["f1"]), fmt(v["precision"]), fmt(v["recall"]), v["support"]]
                 for a, v in R["ood"]["whatsapp test"].items() if not a.startswith("_") and v["support"]]), "",
          "## Ablation", "",
          f"Size-only ({R['ablation']['size_features']} features: sizes, counts, histograms, balance, config "
          f"context) vs full ({R['ablation']['full_features']}: plus inter-arrival, bursts, FFT, deltas), "
          f"leave-one-tunnel-out over the anchor set ({R['ablation']['tunnels']} tunnels, "
          f"{R['ablation']['windows']} windows), 200 rounds, threshold 0.5:", "",
          table(["features"] + [a for a in cm.apps if a in R["ablation"]["full"]],
                [[n] + [fmt(R["ablation"][n].get(a)) for a in cm.apps if a in R["ablation"]["full"]]
                 for n in ("size", "full")]), "",
          "![ablation](report/ablation.png)", "",
          "## Feature importance", "",
          "Top features by share of gain. Config models:", ""]
    for m in ("suite", "mode", "pfs"):
        L.append(f"- **{m}**: " + ", ".join(f"{n} {g:.2f}" for n, g in c[m]["importance"][:8]))
    L += ["", "Traffic models:", ""]
    for k, g in R["importance"].items():
        L.append(f"- **{k}**: " + ", ".join(f"{n} {v:.2f}" for n, v in g[:6]))
    L += ["", "![importance](report/importance_presence.png)", "",
          "## P0 vs p0s (optional)", "",
          "Paired twins, same config, app, netem and noise; only the capture concurrency (3 labs vs 1) and "
          "the run seed differ. Leaked bytes (packets not labelled the run's app) are excluded from both "
          "twins. The earlier \"bulk 2.22x\" packet ratio (`dataset/README.md`) counted leaked transfers too, "
          "so it may be partly due to the leak rather than concurrency alone.", "",
          table(["app", "pairs", "packets p0s/P0", "bytes p0s/P0", "packets p0s/P0 with leaks",
                 "median pair ratio of median IAT"],
                [[a, v["pairs"], f"{v['packets_ratio']:.2f}", f"{v['bytes_ratio']:.2f}",
                  f"{v['packets_ratio_with_leak']:.2f}", f"{v['median_pair_iat_ratio']:.2f}"]
                 for a, v in sorted(R["twins"].items())]), "",
          "## CLI", ""]
    if speed:
        L += [f"`python -m analyzer.cli analyze` on {len(speed['runs'])} test runs: "
              f"{speed['seconds_per_minute']:.2f} s per minute of traffic (median; "
              f"{speed['min']:.2f} to {speed['max']:.2f}).", ""]
    if env:
        L += ["## Environment", "", table(["", ""], [[k, v if not isinstance(v, dict) else
                                                      ", ".join(f"{a} {b}" for a, b in v.items())] for k, v in env.items()]), ""]
    (cm.root / "analyzer" / "REPORT.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["report"]:
        write_report(json.loads((results / "eval.json").read_text()))
    else:
        main()
        write_report(json.loads((results / "eval.json").read_text()))
