"""aggregation (analyzer/CLAUDE.md section 7): window predictions -> session shares.

per window, absent apps' shares are zeroed and the rest renormalised; a window with no present
app is unknown. the session byte share weights windows by their esp bytes, with unknown
explicit; the active-time share is the share of windows where the app is present; shares are
rounded to 100 by largest remainder; error bars come from the out-of-fold session share error
per app and share bucket.
"""
import numpy as np

from analyzer import common as cm

buckets = [(0, 10), (10, 50), (50, 100.01)]
names = cm.apps + ["unknown"]


def bucket(x):
    for i, (lo, hi) in enumerate(buckets):
        if lo <= x < hi:
            return i
    return len(buckets) - 1


def window_shares(p, q, thr):
    """p, q: (windows, apps) calibrated presence and predicted share; thr: (apps,) -> (windows,
    apps + 1) shares with unknown last, and the presence mask"""
    present = p >= thr
    s = np.where(present, np.maximum(np.clip(q, 0, 1), 1e-6), 0.0)
    tot = s.sum(1, keepdims=True)
    s = np.where(tot > 0, s / np.where(tot > 0, tot, 1), 0.0)
    unk = (~present.any(1)).astype(float)[:, None]
    return np.hstack([s, unk]), present


def session(bytes_, p, q, thr):
    """-> {byte_share, active_share} in percent (unrounded), per name"""
    s, present = window_shares(p, q, thr)
    w = np.asarray(bytes_, float)
    tot = w.sum()
    bs = (s * w[:, None]).sum(0) / tot * 100 if tot > 0 else np.zeros(len(names))
    act = present.mean(0) * 100 if len(present) else np.zeros(len(cm.apps))
    return {"byte_share": dict(zip(names, bs.tolist())), "active_share": dict(zip(cm.apps, act.tolist()))}


def round100(d):
    """largest-remainder rounding of percentages to integers summing to 100"""
    keys = list(d)
    v = np.array([max(d[k], 0.0) for k in keys])
    if v.sum() <= 0:
        return {k: 0 for k in keys}
    v = v / v.sum() * 100
    fl = np.floor(v).astype(int)
    rem = 100 - fl.sum()
    for i in np.argsort(-(v - fl), kind="stable")[:rem]:
        fl[i] += 1
    return dict(zip(keys, fl.tolist()))


def true_session(bytes_by_app, b_unknown, esp_bytes):
    tot = float(np.sum(esp_bytes))
    out = {a: float(np.sum(bytes_by_app[a])) / tot * 100 if tot else 0.0 for a in cm.apps}
    out["unknown"] = max(0.0, 100 - sum(out.values()))
    return out


def error_table(sessions):
    """sessions: [(pred byte shares, true byte shares, excluded apps)] from out-of-fold predictions
    -> {app: [mae per predicted-share bucket]} in percentage points"""
    err = {a: [[] for _ in buckets] for a in cm.apps}
    for pred, true, skip in sessions:
        for a in cm.apps:
            if a in skip:
                continue
            err[a][bucket(pred[a])].append(abs(pred[a] - true[a]))
    return {a: [float(np.mean(e)) if e else None for e in err[a]] for a in cm.apps}


def with_errors(shares, table):
    """byte shares -> {app: {share, error}} using the out-of-fold error of the share's bucket"""
    out = {}
    for k, v in shares.items():
        e = table.get(k, [None] * len(buckets))[bucket(v)] if k in table else None
        out[k] = {"share": v, "error_pp": e}
    return out
