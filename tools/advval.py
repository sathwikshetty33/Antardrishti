"""adversarial validation for parallel labs: can a model tell windows captured
with one lab on the machine from windows captured with --labs 3?

  python3 tools/advval.py run [--yes]   avs serially (--labs 1), then avp (--labs 3)
  python3 tools/advval.py analyze       window features -> lightgbm -> auc, writes
                                        dataset/advval.json and the README section

design: tier avs holds the target runs (voip, web, video on 3 set-A configs x 3
reps). tier avp holds the same runs (same seed: config, netem and app seed are
identical, so each avs run has a twin) plus light filler runs, so the targets
share the machine exactly as in p0 (heavy alone on the lane, light work beside).

features come from the analyzer's view only: outer esp packets per 2 s window,
per direction (size and inter-arrival statistics), windows inside app activity.
cross-validation groups twins together (GroupKFold on the twin id), so the model
never sees a session in training and its twin in test.

pre-registered rule: parallel labs pass if the out-of-fold auc < 0.60 and it is
not significantly above chance (paired permutation test, p >= 0.05). otherwise
lower concurrency and retest.
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root / "capture")]
import pcap as pc

raw = root / "dataset" / "raw"
manifest = root / "dataset" / "manifest.jsonl"
out_json = root / "dataset" / "advval.json"
gw_a = {"172.31.1.10", "fd00:a::10"}
auc_max, p_min = 0.60, 0.05


def ip_str(b):
    import ipaddress
    return str(ipaddress.ip_address(bytes(b)))


def stats(xs, pre):
    import numpy as np
    if not xs:
        return {f"{pre}_{k}": 0.0 for k in ("n", "mean", "std", "min", "max", "p10", "p50", "p90")}
    a = np.asarray(xs, dtype=float)
    return {f"{pre}_n": float(len(a)), f"{pre}_mean": a.mean(), f"{pre}_std": a.std(), f"{pre}_min": a.min(),
            f"{pre}_max": a.max(), f"{pre}_p10": np.percentile(a, 10), f"{pre}_p50": np.percentile(a, 50),
            f"{pre}_p90": np.percentile(a, 90)}


def windows(run_dir):
    """feature dicts for the 2 s windows inside the target app's activity"""
    meta = json.loads((run_dir / "meta.json").read_text())
    sched = json.loads((run_dir / "schedule.json").read_text())
    t0 = sched["capture_start_epoch"]
    act = [e for e in sched["entries"] if e.get("event") == "app"]
    if not act:
        return meta, []
    a0, a1 = act[0]["start"], act[0]["stop"]
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        subprocess.run(f"zstd -dqcf {run_dir / 'outer.pcap.zst'} > {tmp.name}", shell=True, check=True)
        pk = defaultdict(lambda: {"up": [], "down": []})
        for ts, m, l3 in pc.packets(tmp.name):
            if m.get("pkttype") == 4 or not pc.esp_payload(l3):
                continue
            rel = ts - t0
            w = int(rel // 2)
            if not (a0 <= 2 * w and 2 * w + 2 <= a1):
                continue
            h = pc.ip(l3)
            d = "up" if ip_str(h[2]) in gw_a else "down"
            pk[w][d].append((ts, m["orig_len"]))
    rows = []
    for w, dd in sorted(pk.items()):
        f = {}
        for d in ("up", "down"):
            ts = sorted(t for t, _ in dd[d])
            f.update(stats([s for _, s in dd[d]], f"{d}_size"))
            f.update(stats([b - a for a, b in zip(ts, ts[1:])], f"{d}_iat"))
        tot_up, tot_dn = sum(s for _, s in dd["up"]), sum(s for _, s in dd["down"])
        f["bytes_ratio"] = tot_up / max(1, tot_up + tot_dn)
        rows.append(f)
    return meta, rows


def latest_ok(tier):
    last = {}
    for l in manifest.read_text().splitlines():
        if l.strip():
            m = json.loads(l)
            if m["tier"] == tier:
                last[m["run_id"]] = m
    return {k: v for k, v in last.items() if v["status"] == "ok" and v["stage"] == "av"}


def cv_auc(X, y, g, seed=0, gains=None):
    import numpy as np
    from lightgbm import LGBMClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupKFold
    p = np.zeros(len(y))
    for tr, te in GroupKFold(n_splits=5).split(X, y, g):
        m = LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=15, min_child_samples=20,
                           subsample=0.8, subsample_freq=1, colsample_bytree=0.8, random_state=seed,
                           importance_type="gain", verbose=-1)
        m.fit(X[tr], y[tr])
        p[te] = m.predict_proba(X[te])[:, 1]
        if gains is not None:
            gains.append(m.feature_importances_)
    return roc_auc_score(y, p), p


def per_app_auc(y, prob, app):
    from sklearn.metrics import roc_auc_score
    return {a: roc_auc_score(y[app == a], prob[app == a]) for a in sorted(set(app)) if len(set(y[app == a])) == 2}


def analyze(n_perm):
    import numpy as np
    from sklearn.metrics import roc_auc_score
    s, p = latest_ok("avs"), latest_ok("avp")
    twin = lambda rid: rid.split("-", 1)[1]
    pairs = sorted(set(map(twin, s)) & set(map(twin, p)))
    rows, y, g, app, conc = [], [], [], [], []
    for t in pairs:
        for tier, lab in (("avs", 0), ("avp", 1)):
            meta, ws = windows(raw / f"{tier}-{t}")
            if lab:
                conc.append(meta.get("concurrency", {}).get("mean", 1))
            for w in ws:
                rows.append(w)
                y.append(lab)
                g.append(t)
                app.append(meta["scenario"])
    if not rows:
        raise SystemExit("no paired avs/avp runs to analyze")
    keys = sorted(rows[0])
    X = np.array([[r[k] for k in keys] for r in rows])
    y, g, app = np.array(y), np.array(g), np.array(app)
    gains = []
    auc, prob = cv_auc(X, y, g, gains=gains)
    per_app = per_app_auc(y, prob, app)
    imp = np.mean(gains, axis=0)
    top = [(keys[i], round(float(imp[i] / imp.sum()), 3)) for i in np.argsort(imp)[::-1][:6]]
    # paired permutation: swap the serial/parallel labels within random twin pairs;
    # the same permutations give a null for the overall auc and for every class
    rng, null, null_app = random.Random(0), [], defaultdict(list)
    for i in range(n_perm):
        flip = {t: rng.random() < 0.5 for t in pairs}
        yp = np.array([1 - v if flip[t] else v for v, t in zip(y, g)])
        a_, p_ = cv_auc(X, yp, g, seed=i + 1)
        null.append(a_)
        for k, v in per_app_auc(yp, p_, app).items():
            null_app[k].append(v)
    pval = (1 + sum(a >= auc for a in null)) / (1 + len(null))
    classes = {}
    for k, v in per_app.items():
        pk = (1 + sum(x >= v for x in null_app[k])) / (1 + len(null_app[k]))
        classes[k] = {"auc": round(v, 3), "p": round(pk, 3),
                      "null_p95": round(float(np.percentile(null_app[k], 95)), 3),
                      "windows": int((app == k).sum()), "pass": bool(v < auc_max and pk >= p_min)}
    res = {"pairs": len(pairs), "windows": int(len(y)), "auc": round(auc, 3), "classes": classes,
           "top_features": top,
           "permutation": {"n": n_perm, "p": round(pval, 3), "null_mean": round(float(np.mean(null)), 3),
                           "null_p95": round(float(np.percentile(null, 95)), 3)},
           "avp_target_concurrency_mean": round(float(np.mean(conc)), 2) if conc else None,
           "rule": f"pass if auc < {auc_max} and permutation p >= {p_min}",
           "pass": bool(auc < auc_max and pval >= p_min and all(c["pass"] for c in classes.values()))}
    out_json.write_text(json.dumps(res, indent=1) + "\n")
    readme(res)
    print(json.dumps(res, indent=1))
    return res


def readme(res):
    import re
    p = root / "dataset" / "README.md"
    s = p.read_text() if p.exists() else "# Antardrishti IPsec dataset\n"
    a, b = "<!-- advval:start -->", "<!-- advval:end -->"
    verdict = "passed" if res["pass"] else "**failed**: concurrency must be lowered and retested"
    body = "\n".join([
        a, "## Parallel labs: adversarial validation", "",
        "Can a model tell traffic captured with one lab on the machine from traffic captured "
        "with three labs side by side? The same 27 target runs (voip, web, video on 3 set-A "
        "configs x 3 reps) were captured serially (tier `avs`) and at full parallelism "
        "(tier `avp`, next to light filler runs), with identical config, netem and app seed per pair. "
        "A LightGBM classifier on outer ESP window features (2 s windows, per-direction size and "
        "inter-arrival statistics) was cross-validated with both twins of a pair in the same fold.", "",
        f"- pairs: {res['pairs']}, windows: {res['windows']}",
        f"- out-of-fold AUC: **{res['auc']}**",
        "", "| class | windows | AUC | permutation p | null 95th pct | verdict |", "|---|---|---|---|---|---|",
        *[f"| {k} | {c['windows']} | {c['auc']} | {c['p']} | {c['null_p95']} | {'pass' if c['pass'] else '**fail**'} |"
          for k, c in res["classes"].items()], "",
        f"- most informative features (share of gain): {', '.join(f'{n} {v}' for n, v in res['top_features'])}",
        f"- paired permutation test ({res['permutation']['n']} permutations): p = {res['permutation']['p']}, "
        f"null mean {res['permutation']['null_mean']}, null 95th percentile {res['permutation']['null_p95']}",
        f"- mean concurrency during the parallel target runs: {res['avp_target_concurrency_mean']}",
        f"- pre-registered rule: {res['rule']} (overall and per class) -> {verdict}",
        "- caveat: the serial half ran before the parallel half (not interleaved), so slow drift of the"
        " host's own load over those hours is confounded with the condition", b])
    s = re.sub(re.escape(a) + ".*?" + re.escape(b), body, s, flags=re.S) if a in s else s.rstrip() + "\n\n" + body + "\n"
    p.write_text(s)


def run(yes):
    flag = ["--yes"] if yes else []
    for tier, labs in (("avs", 1), ("avp", 3)):
        rc = subprocess.run([sys.executable, str(root / "capture" / "run.py"), "--tier", tier,
                             "--labs", str(labs)] + flag).returncode
        if rc:
            raise SystemExit(f"{tier} batch exited {rc}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "analyze"])
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--perm", type=int, default=200)
    a = ap.parse_args()
    if a.cmd == "run":
        run(a.yes)
    else:
        analyze(a.perm)


if __name__ == "__main__":
    main()
