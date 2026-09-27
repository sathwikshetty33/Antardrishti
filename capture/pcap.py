"""minimal pcap reader (no dependencies) for the link types the lab writes:
sll2 (tcpdump -i any), ethernet, raw ip and nflog (transport-mode inner).

yields (ts, meta, l3) where l3 starts at the ip header and meta holds the
sll2 packet type / interface when present.
"""
import struct

sll2, en10mb, raw, raw4, raw6, nflog = 276, 1, 101, 228, 229, 239


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            end = "<"
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            end = ">"
            magic = struct.unpack(">I", hdr[:4])[0]
        else:
            raise ValueError(f"{path}: not a pcap file")
        nano = magic == 0xa1b23c4d
        link = struct.unpack(end + "I", hdr[20:24])[0] & 0x0fffffff
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            ts = sec + frac / (1e9 if nano else 1e6)
            meta = {"orig_len": orig}
            if link == sll2:
                if len(data) < 20:
                    continue
                meta["ifindex"] = struct.unpack(">I", data[4:8])[0]
                meta["pkttype"] = data[10]
                l3 = data[20:]
            elif link == en10mb:
                et = struct.unpack(">H", data[12:14])[0]
                off = 14
                if et == 0x8100:
                    et, off = struct.unpack(">H", data[16:18])[0], 18
                if et not in (0x0800, 0x86dd):
                    continue
                l3 = data[off:]
            elif link in (raw, raw4, raw6):
                l3 = data
            elif link == nflog:
                l3 = nflog_payload(data)
                if l3 is None:
                    continue
            else:
                raise ValueError(f"{path}: unsupported link type {link}")
            yield ts, meta, l3


def nflog_payload(data):
    """nflog: 4-byte header, then tlvs (little-endian len/type, 4-byte aligned); payload is type 9"""
    off = 4
    while off + 4 <= len(data):
        tlen, ttype = struct.unpack("<HH", data[off:off + 4])
        if tlen < 4:
            return None
        if ttype & 0x7fff == 9:
            return data[off + 4:off + tlen]
        off += (tlen + 3) & ~3
    return None


def ip(l3):
    """-> (family, proto, src, dst, header_len, total_len) or None"""
    if len(l3) < 20:
        return None
    v = l3[0] >> 4
    if v == 4:
        ihl = (l3[0] & 15) * 4
        return 4, l3[9], l3[12:16], l3[16:20], ihl, struct.unpack(">H", l3[2:4])[0]
    if v == 6 and len(l3) >= 40:
        return 6, l3[6], l3[8:24], l3[24:40], 40, 40 + struct.unpack(">H", l3[4:6])[0]
    return None


def esp_payload(l3):
    """(spi, seq, bytes after the esp header) for esp or esp-in-udp, else None"""
    h = ip(l3)
    if not h:
        return None
    fam, proto, _, _, hl, _ = h
    p = l3[hl:]
    if proto == 17 and len(p) >= 16:
        sport, dport = struct.unpack(">HH", p[:4])
        if 4500 not in (sport, dport) or p[8:12] == b"\0\0\0\0" or len(p) < 17:
            return None
        p = p[8:]
    elif proto != 50:
        return None
    if len(p) < 8:
        return None
    spi, seq = struct.unpack(">II", p[:8])
    return spi, seq, p[8:]


def plausible_inner(b, room):
    """does b start with an inner ip header whose length fits the esp payload?"""
    h = ip(b)
    if not h:
        return False
    fam, proto, _, _, hl, total = h
    if fam == 4 and (hl < 20 or b[0] & 15 < 5):
        return False
    return hl <= total <= room and proto in (1, 6, 17, 58, 50, 47)
