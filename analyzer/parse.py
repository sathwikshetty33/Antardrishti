"""outer capture parser (analyzer/CLAUDE.md section 4).

parse(paths) reads one or more pcap / pcapng files (.zst allowed), merges them by time,
drops outgoing copies, reassembles outer ip fragments, classifies every packet (esp,
ike, keepalive, ah, other), joins packets into tunnels and esp sas into spi pairs, sets
the direction (initiator to responder) and reads what ike shows in the clear.

addresses, ports and spis only group packets and set the direction; they are never
features. header fields are read with numpy from a memory map, so a run of millions of
packets costs tens of bytes per packet.
"""
import ipaddress
from array import array
import os
import struct
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import numpy as np

other, esp, ike, keepalive, ah = 0, 1, 2, 3, 4
kinds = ["other", "esp", "ike", "keepalive", "ah"]
exch_names = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
              2: "MAIN", 4: "AGGRESSIVE", 32: "QUICK", 5: "INFO_V1"}
link_hdr = {276: 20, 113: 16, 1: 14, 101: 0, 228: 0, 229: 0, 12: 0, 14: 0, 0: 4, 108: 4}


# ---------------------------------------------------------------- file index

def index(path):
    """(buffer, offsets, caplen, origlen, ts_ns, linktype) of every record of a pcap or pcapng"""
    buf = np.memmap(path, dtype=np.uint8, mode="r")
    if len(buf) < 24:
        z = np.zeros(0, np.int64)
        return buf, z, z, z, z, z
    magic = bytes(buf[:4])
    if magic == b"\x0a\x0d\x0d\x0a":
        return (buf,) + index_ng(buf)
    le = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\x4d\x3c\xb2\xa1": ("<", 1),
          b"\xa1\xb2\xc3\xd4": (">", 1000), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if magic not in le:
        raise ValueError(f"{path}: not a pcap or pcapng file")
    end, mul = le[magic]
    link = struct.unpack_from(end + "I", buf, 20)[0] & 0x0fffffff
    u32 = struct.Struct(end + "I")
    offs = array("q")
    pos, n = 24, len(buf)
    while pos + 16 <= n:
        incl = u32.unpack_from(buf, pos + 8)[0]
        if pos + 16 + incl > n:
            break
        offs.append(pos + 16)
        pos += 16 + incl
    off = np.frombuffer(offs, np.int64).copy()
    h = off - 16
    sec, frac, cap, orig = (word(buf, h + k, end) for k in (0, 4, 8, 12))
    return buf, off, cap, orig, sec * 1_000_000_000 + frac * mul, np.full(len(off), link, np.int64)


def word(buf, i, end):
    """unsigned 32-bit words at offsets i"""
    b = [buf[i + k].astype(np.int64) for k in range(4)]
    if end == "<":
        b = b[::-1]
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def index_ng(buf):
    offs, caps, origs, ts, links = [], [], [], [], []
    ifs = []
    pos, n, end = 0, len(buf), "<"
    while pos + 12 <= n:
        btype = struct.unpack_from(end + "I", buf, pos)[0]
        if btype == 0x0A0D0D0A:
            end = "<" if bytes(buf[pos + 8:pos + 12]) == b"\x4d\x3c\x2b\x1a" else ">"
            ifs = []
        blen = struct.unpack_from(end + "I", buf, pos + 4)[0]
        if blen < 12 or pos + blen > n:
            break
        if btype == 1:
            lt, _, snap = struct.unpack_from(end + "HHI", buf, pos + 8)
            units = 10 ** 6   # ticks per second, default microseconds
            o = pos + 16
            while o + 4 <= pos + blen - 4:
                code, ol = struct.unpack_from(end + "HH", buf, o)
                if code == 0:
                    break
                if code == 9 and ol >= 1:
                    r = int(buf[o + 4])
                    units = 2 ** (r & 0x7f) if r & 0x80 else 10 ** r
                o += 4 + ((ol + 3) & ~3)
            ifs.append((lt, units, snap))
        elif btype == 6:
            iface, hi, lo, cap, orig = struct.unpack_from(end + "IIIII", buf, pos + 8)
            lt, units, _ = ifs[iface]
            offs.append(pos + 28)
            caps.append(cap)
            origs.append(orig)
            ts.append(((hi << 32) | lo) * 10 ** 9 // units)
            links.append(lt)
        elif btype == 3:
            orig = struct.unpack_from(end + "I", buf, pos + 8)[0]
            lt, _, snap = ifs[0]
            offs.append(pos + 12)
            caps.append(min(orig, snap or orig, blen - 16))
            origs.append(orig)
            ts.append(0)
            links.append(lt)
        pos += blen
    return (np.array(offs, np.int64), np.array(caps, np.int64), np.array(origs, np.int64),
            np.array(ts, np.int64), np.array(links, np.int64))


# ---------------------------------------------------------------- header fields

def gather(buf, i, lim):
    """byte buf[i] where i < lim (inside the captured record), else 0"""
    ok = i < lim
    j = np.where(ok, i, 0)
    return np.where(ok, buf[j], 0).astype(np.int64)


def be(buf, i, lim, n):
    v = np.zeros(len(i), np.int64)
    for k in range(n):
        v = (v << 8) | gather(buf, i + k, lim)
    return v


def fields(buf, off, cap, link):
    """per-record header fields of the kept packets (ip, not outgoing)"""
    hdr = np.array([link_hdr.get(int(x), -1) for x in link], np.int64) if len(set(link.tolist())) > 1 \
        else np.full(len(link), link_hdr.get(int(link[0]), -1) if len(link) else 0, np.int64)
    if (hdr < 0).any():
        raise ValueError(f"unsupported link type {sorted(set(link[hdr < 0].tolist()))}")
    lim = off + cap
    eth = link == 1
    if eth.any():
        et = be(buf, off + 12, lim, 2)
        vlan = eth & (et == 0x8100)
        hdr = np.where(vlan, 18, hdr)
        et = np.where(vlan, be(buf, off + 16, lim, 2), et)
    l3 = off + hdr
    v = gather(buf, l3, lim) >> 4
    room = lim - l3
    keep = ((v == 4) & (room >= 20)) | ((v == 6) & (room >= 40))
    if eth.any():
        keep &= ~eth | (et == 0x0800) | (et == 0x86dd)
    keep &= ~((link == 276) & (gather(buf, off + 10, lim) == 4))
    keep &= ~((link == 113) & (be(buf, off, lim, 2) == 4))
    keep &= cap >= hdr
    idx = np.nonzero(keep)[0]
    l3, v, lim = l3[idx], v[idx], lim[idx]
    v4 = v == 4
    ihl = np.where(v4, (gather(buf, l3, lim) & 15) * 4, 40)
    tot = np.where(v4, be(buf, l3 + 2, lim, 2), 40 + be(buf, l3 + 4, lim, 2))
    nh = np.where(v4, gather(buf, l3 + 9, lim), gather(buf, l3 + 6, lim))
    ff = be(buf, l3 + 6, lim, 2)
    fr6 = ~v4 & (nh == 44)
    fo6 = be(buf, l3 + 42, lim, 2)
    proto = np.where(fr6, gather(buf, l3 + 40, lim), nh)
    mf = np.where(v4, (ff >> 13) & 1, np.where(fr6, fo6 & 1, 0))
    foff = np.where(v4, (ff & 0x1fff) * 8, np.where(fr6, (fo6 >> 3) * 8, 0))
    ident = np.where(v4, be(buf, l3 + 4, lim, 2), np.where(fr6, be(buf, l3 + 44, lim, 4), 0))
    l4 = l3 + np.where(fr6, 48, ihl)
    addr = np.zeros((len(idx), 32), np.uint8)
    for k in range(16):
        addr[:, k] = np.where(v4, gather(buf, l3 + 12 + k, lim) if k < 4 else 0, gather(buf, l3 + 8 + k, lim))
        addr[:, 16 + k] = np.where(v4, gather(buf, l3 + 16 + k, lim) if k < 4 else 0, gather(buf, l3 + 24 + k, lim))
    addr[:, 4:16] = np.where(v4[:, None], 0, addr[:, 4:16])
    addr[:, 20:32] = np.where(v4[:, None], 0, addr[:, 20:32])
    return {"idx": idx, "l3": l3, "lim": lim, "fam": np.where(v4, 4, 6), "iphl": np.where(v4, ihl, 40),
            "tot": tot, "proto": proto, "mf": mf, "foff": foff, "ident": ident, "l4": l4, "addr": addr}


def classify(buf, f):
    """kind, spi, seq, esp length, ports and the ike start offset per packet"""
    l4, lim, proto = f["l4"], f["lim"], f["proto"]
    n = len(l4)
    kind = np.zeros(n, np.int8)
    sp = np.where(proto == 17, be(buf, l4, lim, 2), 0)
    dp = np.where(proto == 17, be(buf, l4 + 2, lim, 2), 0)
    ulen = be(buf, l4 + 4, lim, 2)
    first = f["foff"] == 0
    e50 = (proto == 50) & first
    nat = (proto == 17) & first & ((sp == 4500) | (dp == 4500))
    marker = be(buf, l4 + 8, lim, 4)
    ka = nat & (ulen == 9) & (gather(buf, l4 + 8, lim) == 0xff)
    ike4500 = nat & ~ka & (marker == 0) & (lim - l4 >= 12)
    enat = nat & ~ka & ~ike4500 & (lim - l4 >= 16)
    ike500 = (proto == 17) & first & ~nat & ((sp == 500) | (dp == 500))
    kind[e50 | enat] = esp
    kind[ike4500 | ike500] = ike
    kind[ka] = keepalive
    kind[(proto == 51) & first] = ah
    spo = np.where(enat, l4 + 8, l4)
    spi = np.where(kind == esp, be(buf, spo, lim, 4), 0)
    seq = np.where(kind == esp, be(buf, spo + 4, lim, 4), 0)
    ahspi = np.where(kind == ah, be(buf, l4 + 4, lim, 4), 0)
    spi = np.where(kind == ah, ahspi, spi)
    ikeo = np.where(ike4500, l4 + 12, l4 + 8)
    return {"kind": kind, "spi": spi, "seq": seq, "sport": sp, "dport": dp, "ikeo": ikeo, "udp": enat}


# ---------------------------------------------------------------- ike messages

def ike_msg(b):
    """what an ike message shows in the clear: header, and the unencrypted payloads"""
    if len(b) < 28:
        return None
    ispi, rspi, npl, ver, ex, fl, mid, ln = struct.unpack(">8s8sBBBBII", b[:28])
    m = {"ispi": ispi.hex(), "rspi": rspi.hex(), "ver": ver >> 4, "exch": ex, "flags": fl, "msgid": mid,
         "len": ln, "notify": [], "ke": None, "sa": None}
    if m["ver"] == 2:
        pos = 28
        while npl and pos + 4 <= len(b):
            nxt, _, plen = struct.unpack(">BBH", b[pos:pos + 4])
            body = b[pos + 4:pos + plen]
            if plen < 4:
                break
            if npl == 33:
                m["sa"] = sa_v2(body)
            elif npl == 34 and len(body) >= 2:
                m["ke"] = struct.unpack(">H", body[:2])[0]
            elif npl == 41 and len(body) >= 4:
                m["notify"].append(struct.unpack(">H", body[2:4])[0])
            elif npl in (46, 53):
                break
            npl, pos = nxt, pos + plen
    elif m["ver"] == 1 and not fl & 1:
        pos = 28
        while npl and pos + 4 <= len(b):
            nxt, _, plen = struct.unpack(">BBH", b[pos:pos + 4])
            body = b[pos + 4:pos + plen]
            if plen < 4:
                break
            if npl == 1:
                m["sa"] = sa_v1(body)
            elif npl == 4 and m["ke"] is None:
                m["ke"] = len(body)
            elif npl == 11 and len(body) >= 8:
                m["notify"].append(struct.unpack(">H", body[6:8])[0])
            npl, pos = nxt, pos + plen
    return m


def sa_v2(body):
    """the first proposal's transforms: encr, key length, prf, integ, dh"""
    out = {}
    if len(body) < 8:
        return out
    plen, spisz, nt = struct.unpack(">H", body[2:4])[0], body[6], body[7]
    pos = 8 + spisz
    for _ in range(nt):
        if pos + 8 > min(len(body), plen):
            break
        tlen, ttype, tid = struct.unpack(">H", body[pos + 2:pos + 4])[0], body[pos + 4], struct.unpack(">H", body[pos + 6:pos + 8])[0]
        name = {1: "encr", 2: "prf", 3: "integ", 4: "dh", 5: "esn"}.get(ttype)
        if name and name not in out:
            out[name] = tid
            if ttype == 1 and tlen >= 12 and len(body) >= pos + 12 and struct.unpack(">H", body[pos + 8:pos + 10])[0] == 0x800e:
                out["keylen"] = struct.unpack(">H", body[pos + 10:pos + 12])[0]
        pos += max(tlen, 8)
    return out


def sa_v1(body):
    """ikev1 phase 1 attributes of the first transform"""
    out = {}
    if len(body) < 8 + 8:
        return out
    pos = 8   # doi, situation
    pp = body[pos:]
    if len(pp) < 8:
        return out
    spisz = pp[6]
    t = pp[8 + spisz:]
    if len(t) < 8:
        return out
    tlen = struct.unpack(">H", t[2:4])[0]
    a, end = 8, min(tlen, len(t))
    names = {1: "encr", 2: "hash", 3: "auth", 4: "dh", 12: "life", 14: "keylen"}
    while a + 4 <= end:
        at, val = struct.unpack(">HH", t[a:a + 4])
        if at & 0x8000:
            k = names.get(at & 0x7fff)
            if k:
                out[k] = val
            a += 4
        else:
            v = t[a + 4:a + 4 + val]
            k = names.get(at)
            if k:
                out[k] = int.from_bytes(v, "big")
            a += 4 + val
    return out


# ---------------------------------------------------------------- merge, reassembly

def load(paths, tmpdir):
    """per input file: compact per-packet columns (fragments reassembled) and the bytes of its
    ike messages, keyed by the packet's row in its file"""
    out = []
    for fid, p in enumerate(paths):
        p = Path(p)
        tmp = None
        if p.suffix == ".zst":
            tmp = Path(tmpdir) / p.name[:-4]
            subprocess.run(["zstd", "-dqf", str(p), "-o", str(tmp)], check=True)
            p = tmp
        buf, off, cap, orig, ts, link = index(p)
        f = fields(buf, off, cap, link)
        del off, cap, orig, link
        f["ts"] = ts[f["idx"]]
        del ts
        f.update(classify(buf, f))
        f["fidx"] = np.arange(len(f["idx"]), dtype=np.int32)
        keep, k = reassemble(f)
        ikes = {}
        for r in np.nonzero(keep & (f["kind"] == ike))[0].tolist():
            ikes[int(f["fidx"][r])] = bytes(buf[int(f["ikeo"][r]):int(f["lim"][r])])
        c = {"ts": f["ts"], "fam": f["fam"].astype(np.uint8), "iphl": f["iphl"].astype(np.uint8),
             "tot": f["tot"].astype(np.int32), "proto": f["proto"].astype(np.uint8), "addr": f["addr"],
             "kind": f["kind"], "spi": f["spi"].astype(np.uint32), "seq": f["seq"].astype(np.uint32),
             "sport": f["sport"].astype(np.uint16), "dport": f["dport"].astype(np.uint16),
             "udp": f["udp"].astype(bool), "fidx": f["fidx"]}
        rows = len(f["idx"])
        del f
        c = {k_: v[keep] for k_, v in c.items()}
        c["fid"] = np.full(len(c["ts"]), fid, np.int8)
        out.append({"cols": c, "ike": ikes, "rows": rows, "reassembled": k})
        del buf
        if tmp is not None:
            tmp.unlink()
    return out


def reassemble(f):
    """outer ip fragments -> one packet with the first fragment's time and bytes and the summed
    length; returns the kept row mask (non-first fragments and orphans dropped)"""
    frag = (f["mf"] == 1) | (f["foff"] > 0)
    keep = np.ones(len(frag), bool)
    rows = np.nonzero(frag)[0]
    if not len(rows):
        return keep, 0
    groups = defaultdict(list)
    for r in rows:
        key = (bytes(f["addr"][r]), int(f["ident"][r]), int(f["proto"][r]), int(f["fam"][r]))
        groups[key].append(r)
    n = 0
    for rs in groups.values():
        firsts = [r for r in rs if f["foff"][r] == 0]
        hl = f["iphl"][rs[0]]
        if not firsts:
            keep[rs] = False
            continue
        head = firsts[0]
        pay = sum(int(f["tot"][r] - (f["l4"][r] - f["l3"][r])) for r in rs)
        f["tot"][head] = hl + pay
        for r in rs:
            if r != head:
                keep[r] = False
        n += 1
    return keep, n


def keyhash(ts_us, tot, proto, a):
    h = ts_us.astype(np.uint64) * np.uint64(0x9E3779B97F4A7C15)
    h ^= tot.astype(np.uint64) * np.uint64(0xC2B2AE3D27D4EB4F)
    h ^= proto.astype(np.uint64) << np.uint64(56)
    w = np.ascontiguousarray(a).view(np.uint64)
    for k in range(w.shape[1]):
        h ^= (w[:, k] + np.uint64(k + 1)) * np.uint64(0x165667B19E3779F9)
        h = (h << np.uint64(13)) | (h >> np.uint64(51))
    return h


# ---------------------------------------------------------------- tunnels

class uf:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def join(self, a, b):
        self.p[self.find(a)] = self.find(b)


def addr_str(a16, fam):
    return str(ipaddress.ip_address(bytes(a16[:4]) if fam == 4 else bytes(a16)))


def parse(paths, tmpdir=None):
    """-> {"t0": ns, "packets": {...esp arrays}, "tunnels": [...], "counts": {...}}"""
    own = tmpdir is None
    td = tempfile.mkdtemp(prefix="antar-") if own else tmpdir
    try:
        return parse_in(paths, td)
    finally:
        if own:
            for x in Path(td).iterdir():
                x.unlink()
            os.rmdir(td)


def parse_in(paths, td):
    files = load(paths, td)
    parts = [f["cols"] for f in files]
    ikes = {(i, k): v for i, f in enumerate(files) for k, v in f["ike"].items()}
    # the same packet in several files (outer cut at 128 bytes, ike full): keep the first
    # file's row, read ike from the longest copy
    if len(parts) > 1:
        hs = [keyhash(p["ts"] // 1000, p["tot"], p["proto"], p["addr"]) for p in parts]
        o0 = np.argsort(hs[0])
        h0 = hs[0][o0]
        seen = {}
        for fid in range(1, len(parts)):
            p, h = parts[fid], hs[fid]
            j = np.minimum(np.searchsorted(h0, h), max(len(h0) - 1, 0))
            hit = (h0[j] == h) if len(h0) else np.zeros(len(h), bool)
            drop = np.zeros(len(h), bool)
            for r in range(len(h)):
                if hit[r]:
                    t = (0, int(parts[0]["fidx"][o0[j[r]]]))
                else:
                    t = seen.get(int(h[r]))
                    if t is None:
                        seen[int(h[r])] = (fid, int(p["fidx"][r]))
                        continue
                drop[r] = True
                mine = ikes.get((fid, int(p["fidx"][r])))
                if mine is not None and len(mine) > len(ikes.get(t, b"")):
                    ikes[t] = mine
            parts[fid] = {c: v[~drop] for c, v in p.items()}
    a = {c: np.concatenate([p[c] for p in parts]) for c in parts[0]}
    del parts
    o = np.lexsort((a["fidx"], a["fid"], a["ts"]))
    a = {c: v[o] for c, v in a.items()}
    n = len(a["ts"])
    t0 = int(a["ts"][0]) if n else 0
    counts = {kinds[k]: int((a["kind"] == k).sum()) for k in range(5)}
    counts["reassembled"] = sum(f["reassembled"] for f in files)
    counts["packets"] = n
    counts["rows"] = [f["rows"] for f in files]
    ipsec = np.nonzero(a["kind"] > 0)[0]
    # addresses -> ids
    uaddr, aid = np.unique(a["addr"][ipsec].reshape(-1, 16), axis=0, return_inverse=True)
    aid = aid.reshape(-1, 2)
    src, dst = aid[:, 0], aid[:, 1]
    fam = a["fam"][ipsec]
    kind = a["kind"][ipsec]
    isudp = (a["proto"][ipsec] == 17)
    sp, dp = a["sport"][ipsec].astype(np.int64), a["dport"][ipsec].astype(np.int64)
    lo, hi = np.minimum(src, dst), np.maximum(src, dst)
    plo = np.where(isudp, np.where(src < dst, sp, dp), 0)
    phi = np.where(isudp, np.where(src < dst, dp, sp), 0)
    ckey = np.stack([lo, hi, plo, phi], 1)
    uconv, conv = np.unique(ckey, axis=0, return_inverse=True)
    conv = conv.reshape(-1)
    # ike messages
    msgs = {}
    for j in np.nonzero(kind == ike)[0].tolist():
        r = ipsec[j]
        m = ike_msg(ikes.get((int(a["fid"][r]), int(a["fidx"][r])), b""))
        if m:
            m.update({"row": j, "t": (int(a["ts"][r]) - t0) / 1e9, "src": int(src[j]), "dst": int(dst[j]),
                      "sport": int(sp[j]), "dport": int(dp[j])})
            msgs[j] = m
    # conversations -> tunnels
    u = uf()
    for c in range(len(uconv)):
        u.find(c)
    by_ispi = defaultdict(set)
    for j, m in msgs.items():
        by_ispi[m["ispi"]].add(int(conv[j]))
    for cs in by_ispi.values():
        cs = sorted(cs)
        for c in cs[1:]:
            u.join(c, cs[0])
    ikeconv = {int(conv[j]) for j in msgs}
    for c, (l, h_, p1, p2) in enumerate(uconv.tolist()):
        if p1 == 0 and p2 == 0:
            cands = [d for d in ikeconv if tuple(uconv[d][:2]) == (l, h_) and uconv[d][2] == uconv[d][3]]
            for d in cands:
                u.join(c, d)
    spi_conv = defaultdict(set)
    ej = np.nonzero((kind == esp) | (kind == ah))[0]
    for s_, c in set(zip(a["spi"][ipsec][ej].tolist(), conv[ej].tolist())):
        spi_conv[s_].add(c)
    for cs in spi_conv.values():
        cs = sorted(cs)
        for c in cs[1:]:
            u.join(c, cs[0])
    roots = sorted({u.find(c) for c in range(len(uconv))}, key=lambda r: min(
        c for c in range(len(uconv)) if u.find(c) == r))
    tid_of_conv = np.array([roots.index(u.find(c)) for c in range(len(uconv))], np.int64)
    tun = tid_of_conv[conv] if len(conv) else np.zeros(0, np.int64)
    rel = (a["ts"][ipsec] - t0) / 1e9
    tunnels = []
    for t in range(len(roots)):
        rows = np.nonzero(tun == t)[0]
        tunnels.append(tunnel_info(t, rows, msgs, kind, src, dst, sp, dp, fam, isudp, rel, a, ipsec, uaddr))
    # esp packet table
    ej = np.nonzero(kind == esp)[0]
    r = ipsec[ej]
    init = np.array([tt["init_id"] for tt in tunnels], np.int64)
    pdir = (src[ej] != init[tun[ej]]).astype(np.int8)
    elen = a["tot"][r] - a["iphl"][r] - np.where(a["udp"][r], 8, 0)
    pair = np.zeros(len(ej), np.int16)
    for tt in tunnels:
        for s_, pid in tt["pair_of"].items():
            pair[(tun[ej] == tt["id"]) & (a["spi"][r] == s_)] = pid
    packets = {"t": rel[ej], "tunnel": tun[ej].astype(np.int16), "pair": pair, "dir": pdir,
               "elen": elen.astype(np.int32), "fid": a["fid"][r].astype(np.int8),
               "fidx": a["fidx"][r].astype(np.int64), "seq": a["seq"][r].astype(np.uint32)}
    for tt in tunnels:
        tt.pop("pair_of")
        tt.pop("init_id")
    return {"t0": t0, "packets": packets, "tunnels": tunnels, "counts": counts}


def tunnel_info(t, rows, msgs, kind, src, dst, sp, dp, fam, isudp, rel, a, ipsec, uaddr):
    ms = sorted((msgs[j] for j in rows.tolist() if j in msgs), key=lambda m: m["t"])
    er = rows[kind[rows] == esp]
    ahr = rows[kind[rows] == ah]
    pr = rows[(kind[rows] == esp) | (kind[rows] == ah) | (kind[rows] == ike) | (kind[rows] == keepalive)]
    ends = sorted({int(x) for x in np.concatenate([src[pr], dst[pr]]).tolist()})
    # direction
    init, how = None, "lower address"
    if ms:
        m = ms[0]
        if m["ver"] == 2:
            init = m["src"] if m["flags"] & 0x08 else m["dst"]
            how = "ike I flag"
        else:
            v1 = [x for x in ms if x["exch"] in (2, 4) and x["rspi"] == "0" * 16]
            init = (v1[0] if v1 else m)["src"]
            how = "ikev1 first message"
    elif len(er) and isudp[er].any():
        j = er[isudp[er]][0]
        if (sp[j] == 4500) != (dp[j] == 4500):
            init = int(src[j]) if sp[j] != 4500 else int(dst[j])
            how = "nat-t port"
    if init is None:
        init = min(ends, key=lambda x: bytes(uaddr[x])) if ends else -1
    other_end = [x for x in ends if x != init]
    tf = int(fam[pr[0]]) if len(pr) else 4
    # spi pairs by first appearance per direction
    up, down = [], []
    for j in er.tolist():
        s_ = int(a["spi"][ipsec[j]])
        lst = up if src[j] == init else down
        if s_ not in lst and s_ not in up and s_ not in down:
            lst.append(s_)
    pair_of = {}
    for i, s_ in enumerate(up):
        pair_of[s_] = i
    for i, s_ in enumerate(down):
        pair_of[s_] = i
    exch = {m["exch"] for m in ms}
    v = ms[0]["ver"] if ms else None
    initial = (34 in exch) if v == 2 else bool(exch & {2, 4}) if v == 1 else False
    has_esp = bool(len(er) or len(ahr))
    if initial:
        status = "full" if has_esp and (35 in exch or v == 1) else "failed"
    elif 36 in exch:
        status = "rekey-only"
    elif has_esp:
        status = "esp-only"
    else:
        status = "ike-only"
    info = ike_summary(ms, init, er, rel, a, ipsec, v)
    return {"id": t, "family": tf, "natt": bool(isudp[er].any()) if len(er) else bool(
        any(m["sport"] == 4500 or m["dport"] == 4500 for m in ms)),
            "initiator": addr_str(uaddr[init], tf) if init >= 0 else None,
            "responder": [addr_str(uaddr[x], tf) for x in other_end], "direction_from": how,
            "status": status, "esp": int(len(er)), "ah": int(len(ahr)),
            "keepalive": int((kind[rows] == keepalive).sum()), "ike_packets": len(ms),
            "spis": {"up": [f"{x:08x}" for x in up], "down": [f"{x:08x}" for x in down]},
            "ike": info, "pair_of": pair_of, "init_id": init,
            "start": float(rel[rows].min()) if len(rows) else None,
            "end": float(rel[rows].max()) if len(rows) else None}


def ike_summary(ms, init, er, rel, a, ipsec, v):
    out = {"version": v, "proposal": {}, "ke": None, "notify": [], "init_req": None, "init_resp": None,
           "retrans": 0, "ccsa": [], "child_rekeys": 0, "ike_rekeys": 0, "rekeys": 0, "exchanges": {},
           "v1": {}, "quick": 0}
    if not ms:
        return out
    seen = set()
    for m in ms:
        name = exch_names.get(m["exch"], str(m["exch"]))
        out["exchanges"][name] = out["exchanges"].get(name, 0) + 1
        k = (m["ispi"], m["msgid"], m["exch"], m["flags"] & 0x20, m["src"], m["len"])
        if k in seen:
            out["retrans"] += 1
        seen.add(k)
        out["notify"] += [n for n in m["notify"] if n not in out["notify"]]
        resp = bool(m["flags"] & 0x20)
        if v == 2 and m["exch"] == 34:
            if not resp and out["init_req"] is None:
                out["init_req"] = m["len"]
            if resp and out["init_resp"] is None:
                out["init_resp"] = m["len"]
                if m["sa"]:
                    out["proposal"] = m["sa"]
            if m["ke"] is not None and (resp or out["ke"] is None):
                out["ke"] = m["ke"]
        if v == 1 and m["exch"] in (2, 4):
            if m["sa"] and (m["rspi"] != "0" * 16 or not out["v1"]):
                out["v1"] = m["sa"]
            if out["init_req"] is None and m["src"] == init:
                out["init_req"] = m["len"]
            if out["init_resp"] is None and m["src"] != init:
                out["init_resp"] = m["len"]
        if v == 1 and m["exch"] == 32 and m["src"] == init:
            out["quick"] += 1
    if v == 1:
        p = out["v1"]
        out["proposal"] = {"encr": p.get("encr"), "keylen": p.get("keylen"), "integ": p.get("hash"),
                           "dh": p.get("dh")}
        out["rekeys"] = max(0, len({m["msgid"] for m in ms if m["exch"] == 32}) // 1 - 1)
        out["child_rekeys"] = out["rekeys"]
        return out
    # create_child_sa exchanges: request / response by message id and requester
    reqs = {}
    for m in ms:
        if m["exch"] != 36:
            continue
        k = (m["ispi"], m["msgid"], m["flags"] & 0x08)
        if not m["flags"] & 0x20:
            reqs.setdefault(k, {"t": m["t"], "req": m["len"], "resp": None, "t_resp": None})
        elif k in reqs and reqs[k]["resp"] is None:
            reqs[k]["resp"], reqs[k]["t_resp"] = m["len"], m["t"]
    et = rel[er]
    espi = a["spi"][ipsec[er]]
    first_seen = {}
    for tt, s_ in zip(et.tolist(), espi.tolist()):
        first_seen.setdefault(s_, tt)
    news = sorted(first_seen.values())
    for x in sorted(reqs.values(), key=lambda x: x["t"]):
        end = (x["t_resp"] or x["t"]) + 5.0
        x["child"] = any(x["t"] - 0.5 <= s_ <= end for s_ in news)
        out["ccsa"].append(x)
    out["child_rekeys"] = sum(1 for x in out["ccsa"] if x["child"])
    out["ike_rekeys"] = len(out["ccsa"]) - out["child_rekeys"]
    out["rekeys"] = len(out["ccsa"])
    return out
