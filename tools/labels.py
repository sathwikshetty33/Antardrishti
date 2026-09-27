"""per-packet labels (CLAUDE.md section 8).

every outer packet the router saw (ingress copies) gets a kind: esp, ike,
keepalive, ah or other. esp packets of the lab tunnel are matched to the inner
plaintext packet they carry, per direction: the inner packet's ip length fixes
the esp packet's exact length (iv, padding, icv of the run's cipher), and packets
of one length are taken in order inside a time window (up: the inner packet is
captured just before encryption; down: after the router, netem delay, decryption).
a matched esp packet inherits the inner packet's flow and app.

usage: python3 tools/labels.py --tier p0 [--ids ...] [--jobs 3]
writes dataset/raw/<run_id>/labels.parquet and dataset/labels.md, prints the
match rate per run. target: >= 98% of esp packets matched on lan runs; runs below
90% are flagged (not silently used).
"""
import argparse
import ipaddress
import json
import math
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict, deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root / "capture")]
import pcap as pc

raw = root / "dataset" / "raw"
manifest = root / "dataset" / "manifest.jsonl"
target_lan, flag_below = 0.98, 0.90
gw_a = {"172.31.1.10", "172.31.1.11", "fd00:a::10"}   # .11: e12's source nat
gw_b = {"172.31.2.10", "fd00:b::10"}
host_a = {"10.1.0.10", "fd00:1::10"}
https_apps = ("web", "video", "bulk", "web_light", "youtube")


def esp_shape(proposal):
    """(iv, block, icv) bytes on the wire for an esp proposal string"""
    p = proposal.lower()
    integ = {"sha1": 12, "md5": 12, "sha256": 16, "sha384": 24, "sha512": 32}
    icv = next((v for k, v in integ.items() if f"-{k}" in p), 16)
    if "gcm16" in p:
        return 8, 4, 16
    if p.startswith("null"):
        return 0, 4, icv
    if p.startswith("3des"):
        return 8, 8, icv
    return 16, 16, icv


def expected_len(inner_len, inner_hl, cfg):
    """outer ip total length of the esp packet carrying an inner ip packet"""
    iv, blk, icv = esp_shape(cfg["esp_proposal"])
    payload = inner_len if cfg["mode"] == "tunnel" else inner_len - inner_hl
    enc = math.ceil((payload + 2) / blk) * blk
    outer_hl = 20 if cfg["outer_family"] == "v4" else 40
    return outer_hl + (8 if cfg["encap"] else 0) + 8 + iv + enc + icv


def unzst(path, tmpdir):
    out = Path(tmpdir) / path.name.replace(".zst", "")
    subprocess.run(["zstd", "-dqf", str(path), "-o", str(out)], check=True)
    return out


def ports(l3, h):
    """(sport, dport) of tcp/udp when captured, else (None, None)"""
    fam, proto, _, _, hl, _ = h
    if proto in (6, 17) and len(l3) >= hl + 4:
        return struct.unpack(">HH", l3[hl:hl + 4])
    return None, None


def outer_packets(path):
    out = []
    for ts, m, l3 in pc.packets(path):
        if m.get("pkttype") == 4:
            continue
        h = pc.ip(l3)
        if not h:
            continue
        fam, proto, src, dst, hl, total = h
        s, d = ip_str(src), ip_str(dst)
        kind, spi, seq = "other", None, None
        if proto == 50:
            kind = "esp"
        elif proto == 51:
            kind = "ah"
        elif proto == 17 and len(l3) >= hl + 8:
            sp, dp = struct.unpack(">HH", l3[hl:hl + 4])
            body = l3[hl + 8:]
            if 4500 in (sp, dp):
                ulen = struct.unpack(">H", l3[hl + 4:hl + 6])[0]
                if ulen == 9:
                    kind = "keepalive"
                elif body[:4] == b"\0\0\0\0":
                    kind = "ike"
                else:
                    kind = "esp"
            elif 500 in (sp, dp):
                kind = "ike"
        if kind == "esp":
            e = pc.esp_payload(l3)
            if e:
                spi, seq = e[0], e[1]
        direction = "up" if s in gw_a and d in gw_b else "down" if s in gw_b and d in gw_a else "other"
        out.append({"ts": ts, "kind": kind, "dir": direction, "len": total, "spi": spi, "seq": seq,
                    "fam": fam, "src": s, "dst": d})
    return out


def ip_str(b):
    return str(ipaddress.ip_address(bytes(b)))


def inner_packets(path, cfg):
    out = []
    for ts, m, l3 in pc.packets(path):
        h = pc.ip(l3)
        if not h:
            continue
        fam, proto, src, dst, hl, total = h
        s, d = ip_str(src), ip_str(dst)
        if cfg["mode"] == "tunnel":
            if s in host_a:
                direction = "up"
            elif d in host_a:
                direction = "down"
            else:
                continue
        else:
            if s in gw_a:
                direction = "up"
            elif d in gw_a:
                direction = "down"
            else:
                continue
        # neighbour discovery and the like never cross the tunnel
        if proto == 58 and len(l3) > hl and l3[hl] in (133, 134, 135, 136):
            continue
        sp, dp = ports(l3, h)
        out.append({"ts": ts, "dir": direction, "len": total, "hl": hl, "proto": proto,
                    "src": s, "dst": d, "sport": sp, "dport": dp})
    return out


def app_of(p, apps):
    proto, sp, dp = p["proto"], p["sport"], p["dport"]
    ps = {sp, dp}
    if proto in (1, 58):
        return "icmp" if ("icmp" in apps or "icmp_big" in apps) else "other"
    if proto == 17 and (ps & {5060, 5070} or any(x and (10000 <= x <= 20000 or 30000 <= x <= 40000) for x in ps)):
        return "voip"
    if proto == 6:
        if ps & {25, 587, 143, 993}:
            return "email"
        if 5222 in ps:
            return "chat"
        if 22 in ps:
            return "bulk"
        if ps & {443, 80}:
            c = [a for a in apps if a in https_apps]
            return c[0] if len(c) == 1 else ("ambiguous:" + "+".join(c) if c else "other")
    return "other"


def match(outer, inner, cfg):
    """assign inner packets to esp packets; returns match per outer index and stats"""
    win = {"up": (-0.5, 0.05), "down": (-0.05, 3.0)}
    got = {}
    unmatched_inner = Counter()
    for d in ("up", "down"):
        queues = defaultdict(deque)
        for i, p in enumerate(inner):
            if p["dir"] == d:
                queues[expected_len(p["len"], p["hl"], cfg)].append(i)
        lo, hi = win[d]
        for j, o in enumerate(outer):
            if o["kind"] != "esp" or o["dir"] != d:
                continue
            q = queues.get(o["len"])
            while q and inner[q[0]]["ts"] < o["ts"] + lo:
                q.popleft()
                unmatched_inner[d] += 1
            if q and inner[q[0]]["ts"] <= o["ts"] + hi:
                got[j] = q.popleft()
        for q in queues.values():
            unmatched_inner[d] += len(q)
    return got, unmatched_inner


def label_run(rid):
    import pyarrow as pa
    import pyarrow.parquet as pq
    d = raw / rid
    meta = json.loads((d / "meta.json").read_text())
    cfg = meta["config"]
    with tempfile.TemporaryDirectory() as t:
        outer = outer_packets(unzst(d / "outer.pcap.zst", t))
        inner = inner_packets(unzst(d / "inner.pcap.zst", t), cfg)
    got, un_inner = match(outer, inner, cfg)
    rows = defaultdict(list)
    for j, o in enumerate(outer):
        i = got.get(j)
        p = inner[i] if i is not None else None
        for k in ("ts", "kind", "dir", "len", "spi", "seq"):
            rows[k].append(o[k])
        rows["matched"].append(p is not None)
        rows["inner_ts"].append(p["ts"] if p else None)
        rows["inner_len"].append(p["len"] if p else None)
        rows["proto"].append(p["proto"] if p else None)
        rows["flow"].append(f"{p['proto']}:{p['src']}:{p['sport']}>{p['dst']}:{p['dport']}" if p else None)
        rows["app"].append(app_of(p, meta["apps"]) if p else None)
    pq.write_table(pa.table(dict(rows)), d / "labels.parquet")
    esp = {dd: [j for j, o in enumerate(outer) if o["kind"] == "esp" and o["dir"] == dd] for dd in ("up", "down")}
    m = {dd: sum(1 for j in esp[dd] if j in got) for dd in esp}
    n_esp = len(esp["up"]) + len(esp["down"])
    rate = (m["up"] + m["down"]) / n_esp if n_esp else None
    apps = Counter(rows["app"][j] for j in got)
    return {"run_id": rid, "stage": meta["stage"], "scenario": meta["scenario"], "netem": meta["netem"],
            "mode": cfg["mode"], "esp": cfg["esp_proposal"], "encap": cfg["encap"], "esp_packets": n_esp,
            "rate": rate, "rate_up": m["up"] / len(esp["up"]) if esp["up"] else None,
            "rate_down": m["down"] / len(esp["down"]) if esp["down"] else None,
            "inner_unmatched": dict(un_inner), "inner_packets": len(inner), "apps": dict(apps),
            "kinds": dict(Counter(o["kind"] for o in outer))}


def ok_runs(tier, ids):
    last = {}
    for l in manifest.read_text().splitlines():
        if l.strip():
            m = json.loads(l)
            if m["tier"] == tier:
                last[m["run_id"]] = m
    rs = sorted(r for r, m in last.items() if m["status"] == "ok")
    return [r for r in rs if not ids or r in ids]


def verdict(r):
    if r["rate"] is None:
        return "no esp"
    if r["rate"] < flag_below:
        return "FLAG <90%"
    if r["netem"] == "lan" and r["rate"] < target_lan:
        return "below lan target"
    return "ok"


def report(res, tier):
    lines = [f"# Labels ({tier})", "", "Generated by `tools/labels.py`: esp packets matched to their inner "
             "plaintext packet (per direction, exact expected length, order, time window).", "",
             f"Target: >= {target_lan:.0%} matched on lan runs; runs below {flag_below:.0%} are flagged.", ""]
    by = defaultdict(list)
    for r in res:
        if r["rate"] is not None:
            by[(r["netem"])].append(r["rate"])
    lines += ["| netem | runs | mean match | min match |", "|---|---|---|---|"]
    for k, v in sorted(by.items()):
        lines.append(f"| {k} | {len(v)} | {sum(v) / len(v):.2%} | {min(v):.2%} |")
    bad = [r for r in res if verdict(r) not in ("ok",)]
    lines += ["", f"## Runs not meeting the target ({len(bad)})", ""]
    lines += [f"- `{r['run_id']}` ({r['scenario']}, {r['netem']}, {r['mode']}, {r['esp']}): "
              f"{verdict(r)}, match {r['rate']:.2%} (up {r['rate_up'] or 0:.2%}, down {r['rate_down'] or 0:.2%})"
              if r["rate"] is not None else f"- `{r['run_id']}`: no esp" for r in bad] or ["- none"]
    lines += ["", "## Per run", "", "| run | netem | esp packets | match | up | down |", "|---|---|---|---|---|---|"]
    for r in sorted(res, key=lambda r: r["run_id"]):
        f = lambda x: f"{x:.2%}" if x is not None else "-"
        lines.append(f"| {r['run_id']} | {r['netem']} | {r['esp_packets']} | {f(r['rate'])} | {f(r['rate_up'])} | {f(r['rate_down'])} |")
    (root / "dataset" / "labels.md").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="p0")
    ap.add_argument("--ids", nargs="+")
    ap.add_argument("--jobs", type=int, default=3)
    a = ap.parse_args()
    rs = ok_runs(a.tier, a.ids)
    res = []
    with ProcessPoolExecutor(a.jobs) as ex:
        for r in ex.map(label_run, rs):
            res.append(r)
            v = verdict(r)
            rate = f"{r['rate']:.2%}" if r["rate"] is not None else "-"
            print(f"{r['run_id']:30} {r['netem']:10} esp {r['esp_packets']:>8} match {rate:>7}  {v}", flush=True)
    (root / "dataset" / "labels.json").write_text(json.dumps(res, indent=1) + "\n")
    report(res, a.tier)
    bad = [r for r in res if verdict(r) != "ok"]
    print(f"\n{len(res)} runs labelled, {len(bad)} not meeting the target -> dataset/labels.md")


if __name__ == "__main__":
    main()
