"""decryption spot-check (CLAUDE.md section 8): proves the ground truth.

for a seeded sample of ok runs per tier (both modes, gcm and cbc when
available), esp packets of the outer capture are decrypted with the keys in the
run's xfrm_*.txt and compared with the inner packet that tools/labels.py matched
them to. outer captures are cut at 128 bytes, so only the start of each payload
is decrypted: aes-gcm as aes-ctr from counter block 2 (no tag check), aes-cbc
block by block from the packet's iv. ttl / hop limit and the ipv4 header
checksum are ignored in the comparison: the gateway rewrites them when it
forwards the packet around the tunnel.

usage: python3 tools/decrypt_check.py --tier p0 [--n 5] [--ids ...]
"""
import argparse
import json
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root / "capture"), str(root / "tools")]
import labels
import pcap as pc

raw = root / "dataset" / "raw"


def sas(run_dir):
    """spi -> (kind, key bytes) from both gateways' xfrm dumps"""
    out = {}
    for f in ("xfrm_a.txt", "xfrm_b.txt"):
        txt = (run_dir / f).read_text()
        for block in re.split(r"\n(?=src )", txt):
            m = re.search(r"proto esp spi (0x[0-9a-f]+)", block)
            if not m:
                continue
            spi = int(m.group(1), 16)
            a = re.search(r"aead rfc4106\(gcm\(aes\)\) 0x([0-9a-f]+)", block)
            e = re.search(r"enc cbc\(aes\) 0x([0-9a-f]+)", block)
            if a:
                out[spi] = ("gcm", bytes.fromhex(a.group(1)))
            elif e:
                out[spi] = ("cbc", bytes.fromhex(e.group(1)))
    return out


def decrypt(kind, key, esp):
    """plaintext prefix of an esp payload (esp = spi..end, possibly truncated)"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    body = esp[8:]
    if kind == "gcm":
        k, salt = key[:-4], key[-4:]
        iv, ct = body[:8], body[8:]
        dec = Cipher(algorithms.AES(k), modes.CTR(salt + iv + b"\0\0\0\x02")).decryptor()
        return dec.update(ct)
    iv, ct = body[:16], body[16:]
    ct = ct[:len(ct) // 16 * 16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct)


def masked(b, fam):
    b = bytearray(b)
    if fam == 4 and len(b) >= 12:
        b[8] = 0
        b[10:12] = b"\0\0"
    elif fam == 6 and len(b) >= 8:
        b[7] = 0
    return bytes(b)


def check_run(rid, limit=300):
    import pyarrow.parquet as pq
    d = raw / rid
    meta = json.loads((d / "meta.json").read_text())
    cfg = meta["config"]
    keys = sas(d)
    lab = pq.read_table(d / "labels.parquet").to_pydict()
    with tempfile.TemporaryDirectory() as t:
        # the same packets, in the same order, as the rows of labels.parquet
        outer = [x for x in pc.packets(labels.unzst(d / "outer.pcap.zst", t))
                 if x[1].get("pkttype") != 4 and pc.ip(x[2])]
        inner = list(pc.packets(labels.unzst(d / "inner.pcap.zst", t)))
    inner_by_ts = {round(ts, 6): l3 for ts, _, l3 in inner}
    n = agree = nokey = 0
    for j in range(len(lab["ts"])):
        if n >= limit:
            break
        if lab["kind"][j] != "esp" or not lab["matched"][j]:
            continue
        ts, m, l3 = outer[j]
        e = pc.esp_payload(l3)
        if not e or e[0] not in keys:
            nokey += 1
            continue
        kind, key = keys[e[0]]
        spi_seq = struct.pack(">II", e[0], e[1])
        plain = decrypt(kind, key, spi_seq + e[2])
        il3 = inner_by_ts.get(round(lab["inner_ts"][j], 6))
        if il3 is None:
            continue
        h = pc.ip(il3)
        want = il3 if cfg["mode"] == "tunnel" else il3[h[4]:]
        k = min(len(plain), len(want), 64)
        if k < 20:
            continue
        n += 1
        fam = h[0]
        a = masked(plain[:k], fam) if cfg["mode"] == "tunnel" else plain[:k]
        b = masked(want[:k], fam) if cfg["mode"] == "tunnel" else want[:k]
        agree += a == b
    return {"run_id": rid, "mode": cfg["mode"], "esp": cfg["esp_proposal"], "encap": cfg["encap"],
            "family": f"{cfg['outer_family']}/{cfg['inner_family']}", "checked": n, "agree": agree,
            "no_key": nokey}


def sample(tier, n, seed):
    """n ok runs covering both modes and gcm and cbc (seeded), traffic-like stages only"""
    rs = labels.ok_runs(tier, None)
    metas = {r: json.loads((raw / r / "meta.json").read_text()) for r in rs}
    pool = [r for r in rs if metas[r]["stage"] in ("traffic", "short", "handshake")
            and (raw / r / "labels.parquet").exists()]
    rng = random.Random(seed)
    rng.shuffle(pool)
    want = [("tunnel", "gcm"), ("transport", "gcm"), ("tunnel", "cbc"), ("transport", "cbc")]
    pick = []
    for mode, enc in want:
        for r in pool:
            c = metas[r]["config"]
            if r not in pick and c["mode"] == mode and (("gcm16" in c["esp_proposal"]) == (enc == "gcm")):
                pick.append(r)
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
    a = ap.parse_args()
    rs = a.ids or sample(a.tier, a.n, a.seed)
    res = [check_run(r) for r in rs]
    for r in res:
        print(f"{r['run_id']:30} {r['mode']:9} {r['esp']:22} {r['family']:6} encap={r['encap']!s:5} "
              f"checked {r['checked']:>4}  agree {r['agree']:>4}  no key {r['no_key']}")
    ok = all(r["checked"] > 0 and r["agree"] == r["checked"] for r in res)
    (root / "dataset" / f"decrypt_check_{a.tier}.json").write_text(json.dumps(res, indent=1) + "\n")
    print("decryption spot-check:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
