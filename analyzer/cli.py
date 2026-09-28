"""analyzer command line (analyzer/CLAUDE.md section 9).

  python -m analyzer.cli analyze <pcap> [<pcap> ...] --out result.json [--bundle models/v1]

parse -> config inference -> windows -> presence and share -> aggregation, per tunnel:
handshake status, config facts (each with a confidence and a source: "read from IKE",
"observed" or "inferred"), session byte share and active-time share with error bars, and
the window timeline with per-window probabilities.
"""
import argparse
import json
import time

import numpy as np

from analyzer import aggregate as ag
from analyzer import bundle as bd
from analyzer import common as cm
from analyzer import features as fx
from analyzer import calib as ml
from analyzer import parse

# ikev2 transform ids (rfc 7296 / iana) and ikev1 attribute values (rfc 2409): they collide,
# so each version has its own table
encr = {1: "des", 2: "des", 3: "3des", 11: "null", 12: "aes-cbc", 13: "aes-ctr", 14: "aes-ccm8", 18: "aes-gcm8",
        19: "aes-gcm12", 20: "aes-gcm16", 28: "chacha20-poly1305"}
integ = {1: "hmac-md5-96", 2: "hmac-sha1-96", 5: "aes-xcbc-96", 12: "hmac-sha256-128", 13: "hmac-sha384-192",
         14: "hmac-sha512-256"}
prf = {1: "prf-hmac-md5", 2: "prf-hmac-sha1", 4: "prf-aes128-xcbc", 5: "prf-hmac-sha256", 6: "prf-hmac-sha384",
       7: "prf-hmac-sha512"}
dh = {1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 17: "modp6144",
      18: "modp8192", 19: "ecp256", 20: "ecp384", 21: "ecp521", 22: "modp1024s160", 23: "modp2048s224",
      24: "modp2048s256", 31: "curve25519", 32: "curve448"}
encr_v1 = {1: "des", 5: "3des", 7: "aes-cbc"}
hash_v1 = {1: "hmac-md5-96", 2: "hmac-sha1-96", 4: "hmac-sha256-128", 5: "hmac-sha384-192", 6: "hmac-sha512-256"}
auth_v1 = {1: "psk", 2: "dss-sig", 3: "rsa-sig", 4: "rsa-enc", 5: "rsa-rev-enc", 8: "ecdsa-sig", 9: "ecdsa-sig",
           10: "ecdsa-sig", 11: "ecdsa-sig"}
payload_names = {33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ", 39: "AUTH", 40: "Ni/Nr",
                 41: "N", 42: "D", 43: "V", 46: "SK", 53: "SKF"}
suite_names = {"gcm16": "AES-GCM-16 (ICV 16)", "cbc_icv12": "AES-CBC + HMAC-SHA1-96",
               "cbc_icv16": "AES-CBC + HMAC-SHA256-128", "cbc_icv24": "AES-CBC + HMAC-SHA384-192"}


schema_version = "antardrishti.result/1"


def fact(value, confidence, source):
    return {"value": value, "confidence": confidence, "source": source}


def config_infer(b, pk, tun):
    """config probabilities from the all-packet evidence row, and the facts"""
    rows = fx.evidence(pk, tun)
    ike = tun["ike"]
    p = ike.get("proposal") or {}
    facts = {"handshake_status": fact(tun["status"], 1.0, "observed"),
             "outer_family": fact(f"ipv{tun['family']}", 1.0, "observed"),
             "nat_t": fact(bool(tun["natt"]), 1.0, "observed")}
    v = ike.get("version")
    if v:
        facts["ike_version"] = fact(v, 1.0, "read from IKE")
        facts["ike_exchanges"] = fact(ike.get("exchanges", {}), 1.0, "read from IKE")
        facts["ike_retransmissions"] = fact(ike.get("retrans", 0), 1.0, "observed")
    et, ht = (encr_v1, hash_v1) if v == 1 else (encr, integ)
    if p.get("encr") is not None:
        name = et.get(p["encr"], f"id {p['encr']}") + (f"-{p['keylen']}" if p.get("keylen") else "")
        facts["ike_encryption"] = fact(name, 1.0, "read from IKE")
    for k, tab in (("integ", ht), ("prf", prf), ("dh", dh)):
        if p.get(k) is not None:
            facts[f"ike_{k}"] = fact(tab.get(p[k], f"id {p[k]}"), 1.0, "read from IKE")
    if v == 1:
        ex = ike.get("exchanges", {})
        facts["ikev1_mode"] = fact("aggressive" if ex.get("AGGRESSIVE") else "main" if ex.get("MAIN") else "unknown",
                                   1.0, "read from IKE")
        a1 = ike.get("v1", {})
        if a1.get("auth") is not None:
            facts["ikev1_auth"] = fact(auth_v1.get(a1["auth"], f"id {a1['auth']}"), 1.0, "read from IKE")
        if a1.get("life") is not None:
            facts["ike_lifetime_s"] = fact(a1["life"], 1.0, "read from IKE")
    if ike.get("init_payloads"):
        facts["ike_init_payloads"] = fact([payload_names.get(x, str(x)) for x in ike["init_payloads"]], 1.0,
                                          "read from IKE")
    if ike.get("notify"):
        facts["ike_notifies"] = fact(ike["notify"], 1.0, "read from IKE")
    facts["rekeys"] = fact({"child": ike.get("child_rekeys", 0), "ike_sa": ike.get("ike_rekeys", 0)}, 1.0, "observed")
    facts["rekey_times_s"] = fact({"child": [round(x["t"], 3) for x in ike.get("ccsa", []) if x["child"]],
                                   "ike_sa": [round(x["t"], 3) for x in ike.get("ccsa", []) if not x["child"]]},
                                  1.0, "observed")
    facts["spi_first_seen_s"] = fact(tun.get("spi_first_seen", {}), 1.0, "observed")
    facts["capture_span_s"] = fact(round((tun["end"] or 0) - (tun["start"] or 0), 3), 1.0, "observed")
    facts["ah_packets"] = fact(tun.get("ah", 0), 1.0, "observed")
    if tun.get("esp_plaintext_share") is not None:
        facts["esp_plaintext_share"] = fact(round(tun["esp_plaintext_share"], 4), 1.0, "observed")
    facts["esp_duplicate_seq"] = fact(tun.get("esp_duplicates", 0), 1.0, "observed")
    if not rows:
        return None, facts
    r = rows[-1]
    cols = b["schema"]["config"]["columns"]
    x = np.array([[r.get(c, np.nan) for c in cols]], float)
    cal = b["calibration"]
    ps = ml.iso_multi(cal["config_suite"]["calibration"], b["boosters"]["config_suite"].predict(x))[0]
    pt = float(ml.iso(cal["config_mode"]["calibration"], b["boosters"]["config_mode"].predict(x))[0])
    k = int(ps.argmax())
    facts["esp_suite"] = fact(suite_names[cm.suites[k]], float(ps[k]), "inferred")
    facts["esp_suite_probabilities"] = {s: float(v) for s, v in zip(cm.suites, ps)}
    facts["mode"] = fact("tunnel" if pt >= 0.5 else "transport", max(pt, 1 - pt), "inferred")
    if r["ccsa_child_n"] >= 1 or (r["ike_version"] == 1 and r["rekeys"] >= 1):
        pp = float(ml.iso(cal["config_pfs"]["calibration"], b["boosters"]["config_pfs"].predict(x))[0])
        facts["pfs"] = fact(pp >= 0.5, max(pp, 1 - pp), "inferred")
    else:
        facts["pfs"] = fact("not determinable", None, "inferred")
    ctx = {f"p_{s}": float(v) for s, v in zip(cm.suites, ps)}
    ctx.update({"p_tunnel": pt, "family": tun["family"], "natt": tun["natt"]})
    return ctx, facts


def traffic(b, pk, ctx):
    """window rows, calibrated presence, shares -> (timeline, P, Q, bytes)"""
    rows = fx.windows(pk, ctx)
    cols = b["schema"]["window"]["columns"]
    X = np.array([[f.get(c, np.nan) for c in cols] for _, _, f in rows], np.float32)
    cal = b["calibration"]
    P = np.zeros((len(rows), len(cm.apps)))
    Q = np.zeros((len(rows), len(cm.apps)))
    for k, a in enumerate(cm.apps):
        if len(rows):
            P[:, k] = ml.iso(cal[f"presence_{a}"]["calibration"], b["boosters"][f"presence_{a}"].predict(X))
            Q[:, k] = b["boosters"][f"share_{a}"].predict(X)
    thr = np.array([cal[f"presence_{a}"]["threshold"] for a in cm.apps])
    labs = fx.window_labels({**pk, "app": np.zeros(len(pk["t"]), np.int8), "amb": np.zeros(len(pk["t"]), np.uint8)})
    esp = np.array([labs[(pair, w)]["esp_bytes"] for pair, w, _ in rows])
    S, present = ag.window_shares(P, Q, thr)
    tl = []
    for i, (pair, w, f) in enumerate(rows):
        tl.append({"t": w * fx.win_s, "pair": int(pair), "esp_bytes": float(esp[i]), "packets": int(f["tot_n"]),
                   "present": [a for k, a in enumerate(cm.apps) if present[i, k]],
                   "presence_probability": {a: float(P[i, k]) for k, a in enumerate(cm.apps)},
                   "share": {n: float(S[i, k]) for k, n in enumerate(ag.names)}})
    return tl, P, Q, esp, thr


def analyze(paths, bundle=None, progress=None):
    """progress(stage, fraction) is called as the stages advance (optional)"""
    say = progress or (lambda stage, frac: None)
    b = bundle or bd.load()
    t = time.time()
    say("parsing", 0.0)
    r = parse.parse(paths)
    say("inferring", 0.4)
    pkts = r["packets"]
    dur = 0.0
    out = {"schema_version": schema_version, "inputs": [str(p) for p in paths],
           "bundle": b["metadata"].get("commit"), "tunnels": [],
           "counts": r["counts"]}
    for i, tun in enumerate(r["tunnels"]):
        say("inferring", 0.4 + 0.5 * i / max(1, len(r["tunnels"])))
        m = pkts["tunnel"] == tun["id"]
        pk = {k: v[m] for k, v in pkts.items()}
        entry = {"tunnel": tun["id"], "initiator": tun["initiator"], "responder": tun["responder"],
                 "direction_from": tun["direction_from"], "handshake_status": tun["status"],
                 "esp_packets": tun["esp"], "start_s": tun["start"], "end_s": tun["end"]}
        ctx, facts = config_infer(b, pk, tun)
        entry["config"] = facts
        if ctx is not None and len(pk["t"]):
            tl, P, Q, esp, thr = traffic(b, pk, ctx)
            s = ag.session(esp, P, Q, thr)
            err = b["errors"]["mae_pp"]
            entry["byte_share"] = ag.with_errors(s["byte_share"], err)
            entry["byte_share_rounded"] = ag.round100(s["byte_share"])
            entry["active_time_share"] = s["active_share"]
            entry["active_time_share_rounded"] = {a: int(round(v)) for a, v in s["active_share"].items()}
            entry["windows"] = tl
            dur = max(dur, float(pk["t"].max() - pk["t"].min()))
        out["tunnels"].append(entry)
    el = time.time() - t
    out["timing"] = {"seconds": el, "traffic_seconds": dur, "seconds_per_minute": el / (dur / 60) if dur else None}
    return out


def main():
    ap = argparse.ArgumentParser(prog="python -m analyzer.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("pcaps", nargs="+")
    a.add_argument("--out", required=True)
    a.add_argument("--bundle")
    x = ap.parse_args()
    res = analyze(x.pcaps, bd.load(x.bundle) if x.bundle else None)
    open(x.out, "w").write(json.dumps(res, indent=1, default=float) + "\n")
    for t in res["tunnels"]:
        bs = t.get("byte_share_rounded", {})
        print(f"tunnel {t['tunnel']}: {t['handshake_status']}, esp {t['esp_packets']}, "
              + ", ".join(f"{k} {v}%" for k, v in bs.items() if v))
    print(f"{res['timing']['seconds']:.1f} s -> {x.out}")


if __name__ == "__main__":
    main()
