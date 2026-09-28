"""build the demo captures from kept test-split runs (dev only; the results are committed).

  python -m app.api.demo.make

each demo is one pcap: the router's outer capture (cut at 128 bytes), with every truncated
IKE packet replaced by its full copy from ike.pcap (same packet: same microsecond and length),
zstd-compressed. the analyzer reads it exactly as it reads outer.pcap.zst + ike.pcap.zst.
"""
import json
import struct
from pathlib import Path

import zstandard

here = Path(__file__).resolve().parent
keep = Path.home() / "antar-data" / "keep"
demos = [
    {"name": "mixture", "run": "p1-voip_video_web-21e3e3f0-r1", "title": "Three-app mixture (mid-stream)",
     "description": "voip + video + web over one transport-mode tunnel (AES-CBC, HMAC-SHA256), captured "
                    "mid-stream: the IKE setup happened before the capture, so IKE facts are not determinable."},
    {"name": "whatsapp", "run": "p1-whatsapp-40244c69-r1", "title": "WhatsApp voice call (replayed)",
     "description": "a public ITC-Net-Audio-5 WhatsApp call (CC BY 4.0) replayed through an IKEv2 tunnel with "
                    "AES-CBC and HMAC-SHA1; the capture includes IKE_SA_INIT."},
    {"name": "ikev1-aggressive", "run": "p0-e14-c468d4c1-r1", "title": "IKEv1 aggressive mode (edge case)",
     "description": "edge case e14: IKEv1 aggressive mode with a pre-shared key, then ping traffic."},
]


def read(path):
    raw = zstandard.ZstdDecompressor().stream_reader(open(path, "rb")).read()
    magic = raw[:4]
    end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    recs, pos = [], 24
    while pos + 16 <= len(raw):
        sec, frac, incl, orig = struct.unpack_from(end + "IIII", raw, pos)
        recs.append((sec, frac if nano else frac * 1000, orig, raw[pos + 16:pos + 16 + incl]))
        pos += 16 + incl
    return raw[:24], end, recs


def build(d):
    head, end, outer = read(keep / d["run"] / "outer.pcap.zst")
    _, _, ike = read(keep / d["run"] / "ike.pcap.zst")
    full = {(s, ns // 1000, o): data for s, ns, o, data in ike}
    used = set()
    out = []
    for s, ns, o, data in outer:
        k = (s, ns // 1000, o)
        if k in full and len(full[k]) > len(data):
            data = full[k]
            used.add(k)
        out.append((s, ns, o, data))
    for s, ns, o, data in ike:
        if (s, ns // 1000, o) not in used and not any((s, ns // 1000, o) == (a, b // 1000, c) for a, b, c, _ in outer):
            out.append((s, ns, o, data))
    out.sort(key=lambda r: (r[0], r[1]))
    nano_head = struct.pack(end + "I", 0xa1b23c4d) + head[4:16] + struct.pack(end + "I", 262144) + head[20:24]
    body = b"".join(struct.pack(end + "IIII", s, ns, len(data), o) + data for s, ns, o, data in out)
    dst = here / f"{d['name']}.pcap.zst"
    dst.write_bytes(zstandard.ZstdCompressor(level=19).compress(nano_head + body))
    return {**d, "file": dst.name, "bytes": dst.stat().st_size, "packets": len(out),
            "duration_s": round((out[-1][0] + out[-1][1] / 1e9) - (out[0][0] + out[0][1] / 1e9), 3)}


def main():
    meta = [build(d) for d in demos]
    (here / "demos.json").write_text(json.dumps(meta, indent=1) + "\n")
    for x in meta:
        print(x["file"], x["bytes"], x["packets"], x["duration_s"])


if __name__ == "__main__":
    main()
