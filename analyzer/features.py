"""features (analyzer/CLAUDE.md section 5).

evidence(pk, tunnel): config evidence rows at the first 50, 200, 1000 and all esp packets.
windows(pk, tunnel, ctx): 2 s window features per tunnel and spi pair, sizes corrected by
the esp overhead estimated from the config context (out-of-fold predictions).
window_labels(pk, ...): presence, byte share and unknown flags per app and window.

nothing here reads an address, port, spi or absolute time: pk holds times relative to
the capture start, directions, esp lengths and the tunnel and pair ids only.
"""
import numpy as np

from analyzer import common as cm

sizes = [50, 200, 1000, 0]    # 0: all packets
win_s = 2.0
bin_s = 0.005
gap_s = 0.05
hist_edges = [0, 80, 160, 320, 640, 1000, 1300, 1e9]
shapes = {"gcm16": (8, 16, 4), "cbc_icv12": (16, 12, 16), "cbc_icv16": (16, 16, 16), "cbc_icv24": (16, 24, 16)}
ke_bytes = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024, 19: 64, 20: 96, 21: 132,
            31: 32, 32: 56}
lab_a = {"172.31.1.10", "172.31.1.11", "fd00:a::10"}
lab_b = {"172.31.2.10", "fd00:b::10"}


def lab_tunnel(t):
    """a tunnel between the lab's two gateways (not one of e18's extra initiators)"""
    return t["initiator"] in lab_a and bool(set(t["responder"]) & lab_b)


def overhead(suite, mode, family, natt=False):
    """esp bytes around the inner payload: spi and seq, iv, mean padding, pad length and next
    header, icv, and the inner ip header in tunnel mode (the esp length excludes nat-t's udp
    header, so nat-t adds nothing)"""
    iv, icv, blk = shapes[suite]
    hdr = (20 if family == 4 else 40) if mode == "tunnel" else 0
    return 8 + iv + (blk - 1) / 2 + 2 + icv + hdr


def overhead_table():
    return {f"{s}|{m}|{f}|{n}": overhead(s, m, f, n) for s in cm.suites for m in ("tunnel", "transport")
            for f in (4, 6) for n in (False, True)}


def expected_overhead(ctx, family):
    """overhead averaged over the predicted suite and mode probabilities"""
    pt = ctx["p_tunnel"]
    return sum(ctx[f"p_{s}"] * ((1 - pt) * overhead(s, "transport", family) + pt * overhead(s, "tunnel", family))
               for s in cm.suites)


def pct(x, q):
    return float(np.percentile(x, q)) if len(x) else np.nan


# ---------------------------------------------------------------- config evidence

def evidence(pk, tun):
    """config evidence rows of one tunnel: pk is the tunnel's esp packets in time order"""
    rows = []
    n_all = len(pk["t"])
    if not n_all:
        return rows
    ike = tun["ike"]
    prop = ike.get("proposal") or {}
    for n in sizes:
        if n and n_all < n:
            continue
        k = n or n_all
        e = pk["elen"][:k]
        d = pk["dir"][:k]
        t_last = pk["t"][k - 1]
        r = {"evidence": n or -1, "evidence_n": k, "family": tun["family"], "natt": int(tun["natt"])}
        for m in (16, 4):
            res = e % m
            c = np.bincount(res, minlength=m)
            r[f"res{m}_n"] = int((c > 0).sum())
            r[f"res{m}_dom"] = int(c.argmax())
            r[f"res{m}_share"] = float(c.max() / k)
        c = np.bincount(e % 16, minlength=16) / k
        for i in range(16):
            r[f"res16_{i}"] = float(c[i])
        for di, dn in ((0, "up"), (1, "down")):
            x = e[d == di]
            for q in (1, 5, 10):
                r[f"{dn}_p{q}"] = pct(x, q)
            r[f"{dn}_min"] = float(x.min()) if len(x) else np.nan
            r[f"{dn}_n"] = len(x)
        r["ike_version"] = ike.get("version") or np.nan
        for f in ("encr", "keylen", "prf", "integ", "dh"):
            v = prop.get(f)
            r[f"ike_{f}"] = v if v is not None else np.nan
        r["ike_ke"] = ike.get("ke") if ike.get("ke") is not None else np.nan
        cc = [x for x in ike.get("ccsa", []) if x["t"] <= t_last]
        for kind, sel in (("child", [x for x in cc if x["child"]]), ("ikesa", [x for x in cc if not x["child"]])):
            r[f"ccsa_{kind}_n"] = len(sel)
            r[f"ccsa_{kind}_req"] = float(np.mean([x["req"] for x in sel])) if sel else np.nan
            rs = [x["resp"] for x in sel if x["resp"]]
            r[f"ccsa_{kind}_resp"] = float(np.mean(rs)) if rs else np.nan
        # a pfs child rekey carries a ke payload of the dh group's size (the group read from
        # IKE_SA_INIT, which set b's pfs reuses)
        # (ikev2: the group id of the ke payload; ikev1: the ke payload's own length)
        if ike.get("version") == 1:
            ke = ike.get("ke") or np.nan
        else:
            g = prop.get("dh") or ike.get("ke")
            ke = ke_bytes.get(g, np.nan)
        r["ke_bytes"] = ke
        r["ccsa_child_minus_ike"] = r["ccsa_child_req"] - r["ccsa_ikesa_req"]
        r["ccsa_child_minus_ke"] = r["ccsa_child_req"] - ke
        r["rekeys"] = len(cc) if ike.get("version") == 2 else ike.get("rekeys", 0)
        r["init_req"] = ike.get("init_req") or np.nan
        r["init_resp"] = ike.get("init_resp") or np.nan
        rows.append(r)
    return rows


# ---------------------------------------------------------------- windows

per_dir = (["n", "bytes", "s_mean", "s_std", "s_min", "s_p10", "s_p50", "s_p90", "s_max"]
           + [f"h{i}" for i in range(7)]
           + ["iat_mean", "iat_std", "iat_min", "iat_p10", "iat_p50", "iat_p90", "iat_max"]
           + ["b_n", "b_pk", "b_bytes", "b_dur", "b_max"])
delta_cols = ["tot_n", "tot_bytes", "up_s_mean", "down_s_mean", "pk_ratio"]
size_cols = ([f"{d}_{c}" for d in ("up", "down") for c in per_dir if not c.startswith(("iat", "b_"))]
             + [f"{m}_{c}" for m in ("max", "min") for c in per_dir if not c.startswith(("iat", "b_"))]
             + ["tot_n", "tot_bytes", "pk_ratio", "byte_ratio"])


def dir_feats(t, s):
    out = {}
    n = len(t)
    out["n"] = n
    out["bytes"] = float(s.sum()) if n else 0.0
    for c, v in (("s_mean", np.mean), ("s_std", np.std), ("s_min", np.min), ("s_max", np.max)):
        out[c] = float(v(s)) if n else np.nan
    for q in (10, 50, 90):
        out[f"s_p{q}"] = pct(s, q)
    h = np.histogram(s, bins=hist_edges)[0] / n if n else np.zeros(7)
    for i in range(7):
        out[f"h{i}"] = float(h[i]) if n else np.nan
    iat = np.diff(t)
    for c, v in (("iat_mean", np.mean), ("iat_std", np.std), ("iat_min", np.min), ("iat_max", np.max)):
        out[c] = float(v(iat)) if len(iat) else np.nan
    for q in (10, 50, 90):
        out[f"iat_p{q}"] = pct(iat, q)
    if n:
        cut = np.nonzero(iat > gap_s)[0] + 1
        starts = np.concatenate([[0], cut])
        ends = np.concatenate([cut, [n]])
        bb = np.add.reduceat(s, starts)
        out["b_n"] = len(starts)
        out["b_pk"] = float(np.mean(ends - starts))
        out["b_bytes"] = float(bb.mean())
        out["b_dur"] = float(np.mean(t[ends - 1] - t[starts]))
        out["b_max"] = float(bb.max())
    else:
        for c in ("b_n", "b_pk", "b_bytes", "b_dur", "b_max"):
            out[c] = 0.0 if c == "b_n" else np.nan
    return out


def fft_feats(t, w0):
    k = int(round(win_s / bin_s))
    c = np.bincount(np.minimum(((t - w0) / bin_s).astype(np.int64), k - 1), minlength=k).astype(float)
    p = np.abs(np.fft.rfft(c - c.mean())) ** 2
    f = np.fft.rfftfreq(k, bin_s)
    p, f = p[1:], f[1:]
    tot = p.sum()
    if tot <= 0:
        return {"fft_peak_hz": np.nan, "fft_peak_ratio": np.nan, "fft_45_55": np.nan}
    i = int(p.argmax())
    band = (f >= 45) & (f <= 55)
    return {"fft_peak_hz": float(f[i]), "fft_peak_ratio": float(p[i] / tot), "fft_45_55": float(p[band].sum() / tot)}


def windows(pk, ctx):
    """window feature rows of one tunnel; pk holds that tunnel's esp packets. ctx: config context
    (p_<suite>, p_tunnel, family, natt). -> list of (pair, w, features)"""
    ov = expected_overhead(ctx, ctx["family"])
    out = []
    if not len(pk["t"]):
        return out
    s_all = pk["elen"].astype(float) - ov
    w_all = np.floor(pk["t"] / win_s).astype(np.int64)
    for pair in np.unique(pk["pair"]).tolist():
        pm = pk["pair"] == pair
        ws = w_all[pm]
        t, s, d = pk["t"][pm], s_all[pm], pk["dir"][pm]
        grid = {}
        order = np.argsort(ws, kind="stable")
        ws, t, s, d = ws[order], t[order], s[order], d[order]
        bounds = np.nonzero(np.diff(ws))[0] + 1
        for a, b in zip(np.concatenate([[0], bounds]), np.concatenate([bounds, [len(ws)]])):
            w = int(ws[a])
            tt, ss, dd = t[a:b], s[a:b], d[a:b]
            f = {}
            per = {}
            for di, dn in ((0, "up"), (1, "down")):
                m = dd == di
                per[dn] = dir_feats(tt[m], ss[m])
                for c, v in per[dn].items():
                    f[f"{dn}_{c}"] = v
            for c in per_dir:
                u, v = per["up"][c], per["down"][c]
                f[f"max_{c}"] = np.nanmax([u, v]) if not (np.isnan(u) and np.isnan(v)) else np.nan
                f[f"min_{c}"] = np.nanmin([u, v]) if not (np.isnan(u) and np.isnan(v)) else np.nan
            f["tot_n"] = len(tt)
            f["tot_bytes"] = float(ss.sum())
            f["pk_ratio"] = per["up"]["n"] / len(tt)
            f["byte_ratio"] = per["up"]["bytes"] / f["tot_bytes"] if f["tot_bytes"] > 0 else np.nan
            f["active_s"] = float(tt[-1] - tt[0])
            f.update(fft_feats(tt, w * win_s))
            grid[w] = f
        empty = {"tot_n": 0, "tot_bytes": 0.0, "up_s_mean": np.nan, "down_s_mean": np.nan, "pk_ratio": np.nan}
        for w, f in grid.items():
            for side, dw in (("prev", -1), ("next", 1)):
                g = grid.get(w + dw, empty)
                for c in delta_cols:
                    f[f"d{side}_{c}"] = f[c] - g[c]
            for k in ("p_" + s_ for s_ in cm.suites):
                f[f"ctx_{k}"] = ctx[k]
            f["ctx_p_tunnel"] = ctx["p_tunnel"]
            f["ctx_family"] = ctx["family"]
            f["ctx_natt"] = int(ctx["natt"])
            f["ctx_overhead"] = ov
            out.append((pair, w, f))
    return out


def window_labels(pk):
    """per (pair, w): esp bytes, and per app present, share, unknown"""
    out = {}
    if not len(pk["t"]):
        return out
    w_all = np.floor(pk["t"] / win_s).astype(np.int64)
    e = pk["elen"].astype(np.int64)
    key = pk["pair"].astype(np.int64) * 1_000_000 + w_all
    uk, inv = np.unique(key, return_inverse=True)
    tot_b = np.bincount(inv, weights=e)
    na = len(cm.apps)
    for a in range(na):
        m = pk["app"] == a
        ab = np.bincount(inv[m], weights=e[m], minlength=len(uk))
        an = np.bincount(inv[m], minlength=len(uk))
        um = (pk["amb"] & (1 << a)) > 0
        ub = np.bincount(inv[um], weights=e[um], minlength=len(uk))
        un = np.bincount(inv[um], minlength=len(uk))
        for i, k in enumerate(uk.tolist()):
            r = out.setdefault(k, {"esp_bytes": float(tot_b[i])})
            r[f"y_{cm.apps[a]}"] = int(an[i] >= 5 or ab[i] >= 0.02 * tot_b[i])
            r[f"s_{cm.apps[a]}"] = float(ab[i] / tot_b[i]) if tot_b[i] else 0.0
            r[f"u_{cm.apps[a]}"] = int(un[i] >= 5 or ub[i] >= 0.02 * tot_b[i])
            r[f"b_{cm.apps[a]}"] = float(ab[i])
    unk = pk["app"] == cm.unknown
    ubytes = np.bincount(inv[unk], weights=e[unk], minlength=len(uk))
    for i, k in enumerate(uk.tolist()):
        out[k]["b_unknown"] = float(ubytes[i])
    return {(k // 1_000_000, k % 1_000_000): v for k, v in out.items()}
