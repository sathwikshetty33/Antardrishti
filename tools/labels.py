"""per-packet labels (CLAUDE.md section 8).

every outer packet the router saw (ingress copies) gets a kind: esp, ike,
keepalive, ah or other. an esp packet of the lab tunnel is labelled from its own
decrypted header (method a, owner decision 2026-09-28): the captured start of its
payload (outer captures are cut at 128 bytes) is decrypted with the run's sa keys
from xfrm_*.txt, and the inner header it starts with names the flow. tunnel mode:
the inner ip header and ports. transport mode: the ports, the outer addresses, and
the protocol from the esp trailer when captured, else from the paired inner packet
or the inner capture's flows. the keys only build labels, never model inputs.
an esp packet is paired with the inner packet whose header bytes equal its
decrypted ones (ttl / hop limit and ipv4 checksum masked: the gateway rewrites
them), first inside a time window per direction (up: the inner packet is captured
just before encryption; down: after the router, netem delay, decryption).
fallbacks, flagged per packet in label_source: "prefix" when the captured
plaintext stops before the inner ports (ipv6 in ipv6 with a cbc cipher keeps 32
bytes): the flow comes from the inner packet paired by the decrypted bytes;
"length" when nothing decrypts: the inner packet's ip length fixes the esp
packet's exact length (iv, padding, icv) and packets of one length are taken in
order inside the time window.

usage: python3 tools/labels.py --tier p0 [--stage s | --not-stage s] [--ids ...] [--jobs 4] [--out dir]
writes <out>/<run_id>/labels.parquet (default out: labels/<tier>, never inside a run
folder), <out>/labels.json and <out>/labels.md, and prints the match rate per run.
target: >= 98% of esp packets labelled on lan runs; runs below 90% are flagged (not
silently used). a replayed run with a label (whatsapp chunks: chat or voip) gives
that label to every labelled packet.
"""
import argparse
import ipaddress
import json
import math
import re
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
win = {"up": (-0.5, 0.05), "down": (-0.05, 3.0)}   # inner packet time minus esp packet time, per direction
gw_a = {"172.31.1.10", "172.31.1.11", "fd00:a::10"}   # .11: e12's source nat
gw_b = {"172.31.2.10", "fd00:b::10"}
host_a = {"10.1.0.10", "fd00:1::10"}
https_apps = ("web", "video", "bulk", "web_light", "youtube")
v6_ext = (0, 43, 44, 50, 51, 60, 135, 139, 140)   # ipv6 extension headers: no ports right after the header


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
        body = None
        if kind == "esp":
            e = pc.esp_payload(l3)
            if e:
                spi, seq, body = e
        direction = "up" if s in gw_a and d in gw_b else "down" if s in gw_b and d in gw_a else "other"
        out.append({"ts": ts, "kind": kind, "dir": direction, "len": total, "spi": spi, "seq": seq,
                    "fam": fam, "src": s, "dst": d, "hl": hl, "body": body,
                    "esp_len": total - hl - (8 if proto == 17 else 0)})
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
        b = bytes(l3[:min(total, hl + 64)])
        out.append({"ts": ts, "dir": direction, "len": total, "hl": hl, "proto": proto,
                    "src": s, "dst": d, "sport": sp, "dport": dp,
                    "c": masked(b, fam) if cfg["mode"] == "tunnel" else b[hl:]})
    return out


def masked(b, fam):
    """ttl / hop limit and the ipv4 header checksum zeroed: the gateway rewrites them"""
    b = bytearray(b)
    if fam == 4 and len(b) >= 12:
        b[8] = 0
        b[10:12] = b"\0\0"
    elif fam == 6 and len(b) >= 8:
        b[7] = 0
    return bytes(b)


def xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


class Sa:
    """one esp sa of an xfrm dump: decrypts the captured start of a payload"""

    def __init__(self, cipher, key):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self.cipher = cipher
        self.iv, self.blk = {"gcm": (8, 4), "cbc": (16, 16), "3des": (8, 8), "null": (0, 4)}[cipher]
        if cipher == "gcm":
            self.salt, self.ecb = key[-4:], Cipher(algorithms.AES(key[:-4]), modes.ECB()).encryptor()
        elif cipher == "cbc":
            self.ecb = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        elif cipher == "3des":
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            self.ecb = Cipher(TripleDES(key), modes.ECB()).decryptor()

    def plain(self, body, n):
        """the first n plaintext bytes of body (iv + ciphertext, maybe cut), as far as
        captured: aes-gcm as aes-ctr from counter block 2 (no tag check), cbc by whole blocks"""
        iv, ct = body[:self.iv], bytes(body[self.iv:self.iv + max(n, 0)])
        if self.cipher == "null" or not ct:
            return ct
        if self.cipher == "gcm":
            blocks = b"".join(self.salt + iv + (i + 2).to_bytes(4, "big") for i in range((len(ct) + 15) // 16))
            return xor(ct, self.ecb.update(blocks)[:len(ct)])
        ct = ct[:len(ct) // self.blk * self.blk]
        return xor(self.ecb.update(ct), iv + ct[:-self.blk]) if ct else b""


def sas(run_dir):
    """spi -> Sa for the esp sas in both gateways' xfrm dumps"""
    out = {}
    for f in ("xfrm_a.txt", "xfrm_b.txt", "xfrm_a_periodic.txt", "xfrm_b_periodic.txt"):
        if not (run_dir / f).exists():
            continue
        for block in re.split(r"\n(?=src )", (run_dir / f).read_text()):
            m = re.search(r"proto esp spi (0x[0-9a-f]+)", block)
            a = re.search(r"aead rfc4106\(gcm\(aes\)\) 0x([0-9a-f]+)", block)
            e = re.search(r"enc (cbc\(aes\)|cbc\(des3_ede\)|ecb\(cipher_null\)) ?(?:0x([0-9a-f]+))?", block)
            if m and (a or e):
                cipher = "gcm" if a else {"cbc(aes)": "cbc", "cbc(des3_ede)": "3des", "ecb(cipher_null)": "null"}[e.group(1)]
                out[int(m.group(1), 16)] = Sa(cipher, bytes.fromhex((a.group(1) if a else e.group(2)) or ""))
    return out


def own_header(o, sa, cfg):
    """what an esp packet's decrypted start says, or None when it is not a plausible
    inner packet: {len, proto, src, dst, sport, dport, ports, done, cmp}; done: the flow
    is named (transport mode: once the protocol is known), cmp: the bytes to pair by"""
    icv = esp_shape(cfg["esp_proposal"])[2]
    n = o["esp_len"] - 8 - sa.iv - icv   # payload, padding and trailer on the wire
    pl = sa.plain(o["body"], n)
    if n <= 0 or len(pl) < 4:
        return None
    whole = len(pl) >= n
    if whole:
        pad, nh = pl[n - 2], pl[n - 1]
        if pad > n - 2 or pl[n - 2 - pad:n - 2] != bytes(range(1, pad + 1)):
            return None
        size = n - 2 - pad
    if cfg["mode"] == "tunnel":
        v = pl[0] >> 4
        if v == 4 and len(pl) >= 20:
            hl, total, proto = (pl[0] & 15) * 4, int.from_bytes(pl[2:4], "big"), pl[9]
            src, dst = ip_str(pl[12:16]), ip_str(pl[16:20])
            first = int.from_bytes(pl[6:8], "big") & 0x1fff == 0
        elif v == 6 and len(pl) >= 8:
            hl, total, proto = 40, 40 + int.from_bytes(pl[4:6], "big"), pl[6]
            src = ip_str(pl[8:24]) if len(pl) >= 24 else None
            dst = ip_str(pl[24:40]) if len(pl) >= 40 else None
            first = proto not in v6_ext
        else:
            return None
        if hl < 20 or not 0 <= n - 2 - total < sa.blk or (whole and total != size):
            return None
        has = proto in (6, 17) and first and len(pl) >= hl + 4
        sp, dp = struct.unpack(">HH", pl[hl:hl + 4]) if has else (None, None)
        done = src is not None and dst is not None and first and (has or proto not in (6, 17))
        return {"len": total, "proto": proto, "src": src, "dst": dst, "sport": sp, "dport": dp,
                "ports": has, "done": done, "cmp": masked(pl[:total], v)}
    sp, dp = struct.unpack(">HH", pl[:4])
    return {"len": o["hl"] + size if whole else None, "proto": nh if whole else None, "src": o["src"],
            "dst": o["dst"], "sport": sp, "dport": dp, "ports": True, "done": False,
            "cmp": pl[:size if whole else max(0, n - 1 - sa.blk)]}


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


def v6_sig(b):
    """flow label, next header, source and the captured half of the destination of an ipv6 header"""
    return (b[1] & 15, b[2], b[3], b[6], b[8:32])


def pair_content(outer, inner, cfg, heads):
    """esp packet -> the inner packet with the same header bytes, first in the time window"""
    tunnel = cfg["mode"] == "tunnel"
    k0 = 8 if not tunnel else 20 if cfg["inner_family"] == "v4" else 32
    got = {}
    for d in ("up", "down"):
        lo, hi = win[d]
        index = defaultdict(deque)
        for i, p in enumerate(inner):
            if p["dir"] == d and len(p["c"]) >= k0:
                index[p["c"][:k0]].append(i)
        for j, o in enumerate(outer):
            h = heads.get(j)
            if o["dir"] != d or not h or len(h["cmp"]) < k0:
                continue
            q = index.get(h["cmp"][:k0])
            while q and inner[q[0]]["ts"] < o["ts"] + lo:
                q.popleft()
            for pos, i in enumerate(q or ()):
                if inner[i]["ts"] > o["ts"] + hi:
                    break
                k = min(len(inner[i]["c"]), len(h["cmp"]))
                if inner[i]["c"][:k] == h["cmp"][:k]:
                    got[j] = (i, "content")
                    del q[pos]
                    break
    return got


def pair_length(outer, inner, cfg, heads, got):
    """the fallback for esp packets whose own header names no flow and that no inner packet
    matches by content: exact expected length, order, time window, among unpaired inner packets"""
    used = {i for i, _ in got.values()}
    unmatched_inner = Counter()
    for d in ("up", "down"):
        lo, hi = win[d]
        queues = defaultdict(deque)
        for i, p in enumerate(inner):
            if p["dir"] == d and i not in used:
                queues[expected_len(p["len"], p["hl"], cfg)].append(i)
        for j, o in enumerate(outer):
            h = heads.get(j) or {}
            if o["kind"] != "esp" or o["dir"] != d or j in got or h.get("done") or h.get("flow_of"):
                continue
            q = queues.get(o["len"])
            while q and inner[q[0]]["ts"] < o["ts"] + lo:
                q.popleft()
                unmatched_inner[d] += 1
            if q and inner[q[0]]["ts"] <= o["ts"] + hi:
                got[j] = (q.popleft(), "length")
        for q in queues.values():
            unmatched_inner[d] += len(q)
    return unmatched_inner


def label_run(rid, out=None):
    import pyarrow as pa
    import pyarrow.parquet as pq
    d = raw / rid
    meta = json.loads((d / "meta.json").read_text())
    cfg = meta["config"]
    keys = sas(d)
    with tempfile.TemporaryDirectory() as t:
        outer = outer_packets(unzst(d / "outer.pcap.zst", t))
        inner = inner_packets(unzst(d / "inner.pcap.zst", t), cfg)
    esp = [j for j, o in enumerate(outer) if o["kind"] == "esp" and o["dir"] in ("up", "down")]
    heads = {}
    for j in esp:
        o = outer[j]
        if o["spi"] in keys and o["body"] is not None:
            h = own_header(o, keys[o["spi"]], cfg)
            if h:
                heads[j] = h
    got = pair_content(outer, inner, cfg, heads)
    if cfg["mode"] == "transport":
        # the protocol: esp trailer, else the paired inner packet, else the inner flows
        flows = defaultdict(set)
        for p in inner:
            if p["sport"] is not None:
                flows[(p["src"], p["sport"], p["dst"], p["dport"])].add(p["proto"])
        for j, h in heads.items():
            if h["proto"] is None:
                if j in got:
                    h["proto"] = inner[got[j][0]]["proto"]
                else:
                    f = flows.get((h["src"], h["sport"], h["dst"], h["dport"]), set())
                    h["proto"] = next(iter(f)) if len(f) == 1 else None
            if h["proto"] is not None:
                h["done"] = True
                if h["proto"] not in (6, 17):
                    h["sport"] = h["dport"] = None
                    h["ports"] = False
    elif cfg["inner_family"] == "v6":
        # a readable ipv6 prefix without ports and without a same-bytes inner packet (a
        # segmentation-offload segment): the flow of the inner packets with its flow label,
        # next header and addresses (as far as captured), when that flow is unique
        sig = defaultdict(set)
        for p in inner:
            if len(p["c"]) >= 32:
                sig[v6_sig(p["c"])].add((p["proto"], p["src"], p["sport"], p["dst"], p["dport"]))
        for j, h in heads.items():
            if not h["done"] and j not in got and len(h["cmp"]) >= 32:
                f = sig.get(v6_sig(h["cmp"]), set())
                if len(f) == 1:
                    h["flow_of"] = dict(zip(("proto", "src", "sport", "dst", "dport"), next(iter(f))))
    un_inner = pair_length(outer, inner, cfg, heads, got)
    rows = defaultdict(list)
    src = Counter()
    tcpudp = recovered = 0
    for j, o in enumerate(outer):
        h, g = heads.get(j), got.get(j)
        p = inner[g[0]] if g else None
        if h and h["done"]:
            how, f = "decrypt", h
        elif h and h.get("flow_of"):
            how, f = "prefix", h["flow_of"]
        elif p is not None:
            how, f = ("prefix" if g[1] == "content" else "length"), p
        else:
            how, f = None, None
        if o["kind"] == "esp" and o["dir"] in ("up", "down"):
            src[how or "none"] += 1
            if f and f["proto"] in (6, 17):
                tcpudp += 1
                recovered += bool(h and h["ports"])
        for k in ("ts", "kind", "dir", "len", "spi", "seq"):
            rows[k].append(o[k])
        rows["matched"].append(f is not None)
        rows["label_source"].append(how)
        rows["ports_recovered"].append(bool(h and h["ports"]))
        rows["paired"].append(p is not None)
        rows["inner_ts"].append(p["ts"] if p else None)
        rows["inner_len"].append((h["len"] if how == "decrypt" else None) or (p["len"] if p else None))
        rows["proto"].append(f["proto"] if f else None)
        rows["flow"].append(f"{f['proto']}:{f['src']}:{f['sport']}>{f['dst']}:{f['dport']}" if f else None)
        rows["app"].append((meta.get("label") or app_of(f, meta["apps"])) if f else None)
    dst = Path(out) / rid if out else d
    dst.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(dict(rows)), dst / "labels.parquet")
    by = {dd: [j for j in esp if outer[j]["dir"] == dd] for dd in ("up", "down")}
    m = {dd: sum(1 for j in by[dd] if rows["matched"][j]) for dd in by}
    n_esp = len(esp)
    apps = Counter(rows["app"][j] for j in esp if rows["matched"][j])
    return {"run_id": rid, "stage": meta["stage"], "scenario": meta["scenario"], "netem": meta["netem"],
            "mode": cfg["mode"], "esp": cfg["esp_proposal"], "encap": cfg["encap"],
            "family": f"{cfg['outer_family']}/{cfg['inner_family']}", "esp_packets": n_esp,
            "rate": (m["up"] + m["down"]) / n_esp if n_esp else None,
            "rate_up": m["up"] / len(by["up"]) if by["up"] else None,
            "rate_down": m["down"] / len(by["down"]) if by["down"] else None,
            "sources": dict(src), "paired": sum(1 for j in esp if rows["paired"][j]),
            "decrypted": len(heads), "no_key": sum(1 for j in esp if outer[j]["spi"] not in keys),
            "ports": {"tcpudp": tcpudp, "recovered": recovered},
            "inner_unmatched": dict(un_inner), "inner_packets": len(inner), "apps": dict(apps),
            "kinds": dict(Counter(o["kind"] for o in outer))}


def ok_runs(tier, ids, stage=None, not_stage=None):
    last = {}
    for l in manifest.read_text().splitlines():
        if l.strip():
            m = json.loads(l)
            if m["tier"] == tier and "annotation" not in m:
                last[m["run_id"]] = m
    rs = sorted(r for r, m in last.items() if m["status"] == "ok"
                and (not stage or m["stage"] == stage) and (not not_stage or m["stage"] != not_stage))
    return [r for r in rs if not ids or r in ids]


def verdict(r):
    if r["rate"] is None:
        return "no esp"
    if r["rate"] < flag_below:
        return "FLAG <90%"
    if r["netem"] == "lan" and r["rate"] < target_lan:
        return "below lan target"
    return "ok"


def report(res, tier, out):
    lines = [f"# Labels ({tier})", "", "Generated by `tools/labels.py`: each esp packet labelled from its own "
             "decrypted header (run's sa keys), paired with its inner packet by header content; fallbacks "
             "flagged per packet (prefix: ports beyond the captured plaintext; length: nothing decrypts).", "",
             f"Target: >= {target_lan:.0%} labelled on lan runs; runs below {flag_below:.0%} are flagged.", ""]
    by = defaultdict(list)
    for r in res:
        if r["rate"] is not None:
            by[(r["netem"])].append(r["rate"])
    lines += ["| netem | runs | mean labelled | min labelled |", "|---|---|---|---|"]
    for k, v in sorted(by.items()):
        lines.append(f"| {k} | {len(v)} | {sum(v) / len(v):.2%} | {min(v):.2%} |")
    bad = [r for r in res if verdict(r) not in ("ok",)]
    lines += ["", f"## Runs not meeting the target ({len(bad)})", ""]
    lines += [f"- `{r['run_id']}` ({r['scenario']}, {r['netem']}, {r['mode']}, {r['esp']}): "
              f"{verdict(r)}, labelled {r['rate']:.2%} (up {r['rate_up'] or 0:.2%}, down {r['rate_down'] or 0:.2%})"
              if r["rate"] is not None else f"- `{r['run_id']}`: no esp" for r in bad] or ["- none"]
    lines += ["", "## Per run", "", "| run | netem | esp packets | labelled | up | down | decrypt | prefix | length | paired |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(res, key=lambda r: r["run_id"]):
        f = lambda x: f"{x:.2%}" if x is not None else "-"
        sh = lambda k: f(r["sources"].get(k, 0) / r["esp_packets"]) if r["esp_packets"] else "-"
        lines.append(f"| {r['run_id']} | {r['netem']} | {r['esp_packets']} | {f(r['rate'])} | {f(r['rate_up'])} | "
                     f"{f(r['rate_down'])} | {sh('decrypt')} | {sh('prefix')} | {sh('length')} | "
                     f"{f(r['paired'] / r['esp_packets']) if r['esp_packets'] else '-'} |")
    (Path(out) / "labels.md").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="p0")
    ap.add_argument("--ids", nargs="+")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--stage", help="only this stage")
    ap.add_argument("--not-stage", help="every stage but this one")
    ap.add_argument("--out", help="output folder (default labels/<tier>)")
    a = ap.parse_args()
    out = Path(a.out or root / "labels" / a.tier)
    out.mkdir(parents=True, exist_ok=True)
    rs = ok_runs(a.tier, a.ids, a.stage, a.not_stage)
    res = []
    with ProcessPoolExecutor(a.jobs) as ex:
        for r in ex.map(label_run, rs, [str(out)] * len(rs)):
            res.append(r)
            v = verdict(r)
            rate = f"{r['rate']:.2%}" if r["rate"] is not None else "-"
            print(f"{r['run_id']:30} {r['netem']:10} esp {r['esp_packets']:>8} match {rate:>7}  {v}", flush=True)
    (out / "labels.json").write_text(json.dumps(res, indent=1) + "\n")
    report(res, a.tier, out)
    bad = [r for r in res if verdict(r) != "ok"]
    print(f"\n{len(res)} runs labelled, {len(bad)} not meeting the target -> {out}/labels.md")


if __name__ == "__main__":
    main()
