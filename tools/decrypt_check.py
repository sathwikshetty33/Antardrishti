"""decryption spot-check (CLAUDE.md section 8): checks the labels against tshark.

for a seeded sample of ok runs per tier (both modes and both outer families, gcm
and cbc when available), an even sample of the labelled esp packets of each run is
decrypted by tshark with the keys in the run's xfrm_*.txt. outer captures are cut
at 128 bytes and tshark refuses a truncated esp packet, so tshark reads a copy of
the sampled frames zero-padded to their wire length, and only the plaintext whose
ciphertext was captured is used (aes-cbc: whole blocks; aes-gcm: every captured
byte; the icv is not checked). per packet: the app named by tshark's plaintext
header must equal the label's app (app error otherwise; unverifiable when the
captured plaintext stops before the inner ports), a paired inner packet must equal
the plaintext (ttl / hop limit and ipv4 header checksum masked: the gateway
rewrites them), and tshark's plaintext must equal tools/labels.py's own decryption.

usage: python3 tools/decrypt_check.py --tier p0 [--n 5] [--stage s | --not-stage s] [--ids ...]
                                      [--labels labels/<tier>]
labels come from tools/labels.py's output folder.
"""
import argparse
import json
import random
import re
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root / "capture"), str(root / "tools")]
import labels
import pcap as pc

raw = root / "dataset" / "raw"


def uat(run_dir):
    """tshark esp_sa records for the sas in both gateways' xfrm dumps (any address: by spi)"""
    recs = []
    for f in ("xfrm_a.txt", "xfrm_b.txt", "xfrm_a_periodic.txt", "xfrm_b_periodic.txt"):
        if not (run_dir / f).exists():
            continue
        for block in re.split(r"\n(?=src )", (run_dir / f).read_text()):
            m = re.search(r"^src (\S+) dst \S+\s+proto esp spi (0x[0-9a-f]+)", block)
            a = re.search(r"aead rfc4106\(gcm\(aes\)\) 0x([0-9a-f]+) \(\d+ bits\) (\d+)", block)
            e = re.search(r"enc cbc\(aes\) 0x([0-9a-f]+)", block)
            i = re.search(r"auth-trunc \S+ 0x[0-9a-f]+ \(\d+ bits\) (\d+)", block)
            if not m or not (a or (e and i)):
                continue
            fam = "IPv6" if ":" in m.group(1) else "IPv4"
            if a:
                enc, key, auth = f"AES-GCM with {int(a.group(2)) // 8} octet ICV [RFC4106]", a.group(1), "NULL"
            else:
                enc, key, auth = "AES-CBC [RFC3602]", e.group(1), f"ANY {i.group(1)} bit authentication [no checking]"
            recs.append(f'"{fam}","*","*","{m.group(2)}","{enc}","0x{key}","{auth}",""')
    return recs


def tshark_plain(pcap, recs, want, t):
    """(spi, seq) -> esp payload as decrypted by tshark, for the esp frames in want, from a
    copy of those frames zero-padded to their wire length (only the captured part is real)"""
    padded = Path(t) / "padded.pcap"
    with open(pcap, "rb") as f, open(padded, "wb") as g:
        hdr = bytearray(f.read(24))
        end = "<" if struct.unpack("<I", hdr[:4])[0] in (0xa1b2c3d4, 0xa1b23c4d) else ">"
        link = struct.unpack(end + "I", hdr[20:24])[0] & 0x0fffffff
        off = {276: 20, 1: 14, 113: 16}.get(link, 0)
        hdr[16:20] = struct.pack(end + "I", 262144)
        g.write(hdr)
        while len(rec := f.read(16)) == 16:
            sec, frac, incl, orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            e = pc.esp_payload(data[off:])
            if e and (e[0], e[1]) in want:
                g.write(struct.pack(end + "IIII", sec, frac, orig, orig) + data + b"\0" * (orig - incl))
    cmd = ["tshark", "-n", "-r", str(padded), "-o", "esp.enable_encryption_decode:TRUE"]
    for r in recs:
        cmd += ["-o", f"uat:esp_sa:{r}"]
    cmd += ["-Y", "esp.decrypted_data", "-T", "fields", "-E", "occurrence=f",
            "-e", "esp.spi", "-e", "esp.sequence", "-e", "esp.decrypted_data"]
    out = {}
    for line in subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines():
        spi, seq, data = line.split("\t")
        out[(int(spi, 16), int(seq))] = bytes.fromhex(data)
    return out


def flow_of(b, mode, row_proto, src, dst):
    """(proto, sport, dport, src, dst) named by a plaintext prefix, or None when the
    captured part stops before the inner ports"""
    if mode == "tunnel":
        v = b[0] >> 4
        if v == 4 and len(b) >= 20:
            hl, proto, src, dst = (b[0] & 15) * 4, b[9], labels.ip_str(b[12:16]), labels.ip_str(b[16:20])
        elif v == 6 and len(b) >= 40:
            hl, proto, src, dst = 40, b[6], labels.ip_str(b[8:24]), labels.ip_str(b[24:40])
        else:
            return None
    else:
        hl, proto = 0, row_proto
    if proto in (6, 17):
        if len(b) < hl + 4:
            return None
        sp, dp = struct.unpack(">HH", b[hl:hl + 4])
    else:
        sp = dp = None
    return {"proto": proto, "src": src, "sport": sp, "dst": dst, "dport": dp}


def check_run(rid, labdir, limit=300):
    import pyarrow.parquet as pq
    d = raw / rid
    meta = json.loads((d / "meta.json").read_text())
    cfg = meta["config"]
    keys = labels.sas(d)
    lab = pq.read_table(Path(labdir) / rid / "labels.parquet").to_pydict()
    lab.setdefault("label_source", [None] * len(lab["ts"]))   # labels made before method a
    lab.setdefault("paired", lab["matched"])
    with tempfile.TemporaryDirectory() as t:
        # the same packets, in the same order, as the rows of labels.parquet
        op = labels.unzst(d / "outer.pcap.zst", t)
        outer = labels.outer_packets(op)
        inner = {round(p["ts"], 6): p for p in labels.inner_packets(labels.unzst(d / "inner.pcap.zst", t), cfg)}
        rows = [j for j in range(len(lab["ts"])) if lab["kind"][j] == "esp" and lab["matched"][j]
                and outer[j]["spi"] in keys]
        rows = rows[::max(1, len(rows) // limit)][:limit]
        tsh = tshark_plain(op, uat(d), {(outer[j]["spi"], outer[j]["seq"]) for j in rows}, t)
    c = Counter()
    wrong = Counter()
    icv = labels.esp_shape(cfg["esp_proposal"])[2]
    for j in rows:
        o = outer[j]
        sa = keys[o["spi"]]
        real = sa.plain(o["body"], o["esp_len"] - 8 - sa.iv - icv)
        tp = tsh.get((o["spi"], o["seq"]))
        c["checked"] += 1
        c["src:" + str(lab["label_source"][j])] += 1
        if tp is None:
            c["no_tshark"] += 1
            continue
        plain = tp[:len(real)]   # tshark leaves out the icv of a whole packet: compare the overlap
        k = min(len(plain), len(real))
        c["tshark_eq_python"] += plain[:k] == real[:k]
        f = flow_of(plain, cfg["mode"], lab["proto"][j], o["src"], o["dst"])
        if f is None:
            c["app_unverifiable"] += 1
        else:
            app = meta.get("label") or labels.app_of(f, meta["apps"])
            if app == lab["app"][j]:
                c["app_ok"] += 1
            else:
                c["app_error"] += 1
                wrong[f"{lab['app'][j]} labelled, {app} decrypted"] += 1
        if lab["paired"][j]:
            p = inner.get(round(lab["inner_ts"][j], 6))
            if p is not None:
                mine = labels.masked(plain, plain[0] >> 4) if cfg["mode"] == "tunnel" else plain
                n = min(len(mine), len(p["c"]), 64)
                c["paired_checked"] += 1
                c["paired_agree"] += n >= 8 and mine[:n] == p["c"][:n]
    return {"run_id": rid, "stage": meta["stage"], "mode": cfg["mode"], "esp": cfg["esp_proposal"],
            "encap": cfg["encap"], "family": f"{cfg['outer_family']}/{cfg['inner_family']}",
            "label": meta.get("label"), **dict(c), "wrong": dict(wrong)}


traffic = ("traffic", "short", "handshake", "anchor", "mixtures", "chat", "realism", "whatsapp")


def sample(tier, n, seed, labdir, stage=None, not_stage=None):
    """n ok runs (seeded) covering both modes and both outer families, then gcm and
    cbc, from the traffic-like stages that have labels"""
    rs = labels.ok_runs(tier, None, stage, not_stage)
    metas = {r: json.loads((raw / r / "meta.json").read_text()) for r in rs}
    pool = [r for r in rs if metas[r]["stage"] in traffic and (Path(labdir) / r / "labels.parquet").exists()]
    rng = random.Random(seed)
    rng.shuffle(pool)
    want = [(m, f, e) for m in ("tunnel", "transport") for f in ("v4", "v6") for e in ("gcm", "cbc")]
    pick = []
    for mode, fam, enc in [(m, f, None) for m, f, _ in want[::2]] + want:
        for r in pool:
            c = metas[r]["config"]
            if (r not in pick and c["mode"] == mode and c["outer_family"] == fam
                    and (enc is None or ("gcm16" in c["esp_proposal"]) == (enc == "gcm"))):
                pick.append(r)
                break
        if len(pick) >= n:
            break
    for r in pool:
        if len(pick) >= n:
            break
        if r not in pick:
            pick.append(r)
    return pick[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="p0")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=26005)
    ap.add_argument("--ids", nargs="+")
    ap.add_argument("--stage")
    ap.add_argument("--not-stage")
    ap.add_argument("--labels", help="labels folder (default labels/<tier>)")
    ap.add_argument("--out", help="result json (default <labels>/decrypt_check.json)")
    a = ap.parse_args()
    labdir = Path(a.labels or root / "labels" / a.tier)
    rs = a.ids or sample(a.tier, a.n, a.seed, labdir, a.stage, a.not_stage)
    res = [check_run(r, labdir) for r in rs]
    for r in res:
        print(f"{r['run_id']:30} {r['mode']:9} {r['esp']:24} {r['family']:6} encap={r['encap']!s:5} "
              f"checked {r.get('checked', 0):>4}  app ok {r.get('app_ok', 0):>4} error {r.get('app_error', 0):>3} "
              f"unverifiable {r.get('app_unverifiable', 0):>4}  paired {r.get('paired_agree', 0)}/{r.get('paired_checked', 0)}  "
              f"tshark=python {r.get('tshark_eq_python', 0)}  no tshark {r.get('no_tshark', 0)}")
    ok = all(r.get("checked", 0) > 0 and not r.get("no_tshark") and not r.get("app_error")
             and r.get("tshark_eq_python", 0) == r["checked"] and r.get("paired_agree", 0) == r.get("paired_checked", 0)
             for r in res)
    Path(a.out or labdir / "decrypt_check.json").write_text(json.dumps(res, indent=1) + "\n")
    print("decryption spot-check:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
