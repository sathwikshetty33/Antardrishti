"""demo replay: a stored demo capture fed to the api in successive 5 s chunks.

live capture can't run on vercel, so the replay stands in for it. each step appends the next
chunk (the pcap records of the next 5 s) to replay_chunks in postgres, rebuilds the capture so
far from those chunks, analyses it and replaces the analysis' tunnels, facts, findings and
scores: the evidence accumulates across requests and confidence rises as it grows.
"""
import json
import struct
from pathlib import Path

import zstandard

from app.api import models as m
from app.api import settings

cache = {}


def demos():
    return json.loads((settings.demo_dir / "demos.json").read_text())


def demo(name):
    d = next((x for x in demos() if x["name"] == name), None)
    if d is None:
        raise KeyError(name)
    return d


def records(name):
    """(pcap header, [(t, record bytes)]) of a demo capture, t in seconds from its first packet"""
    if name not in cache:
        raw = zstandard.ZstdDecompressor().stream_reader(open(settings.demo_dir / demo(name)["file"], "rb")).read()
        end = "<" if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = raw[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        out, pos, t0 = [], 24, None
        while pos + 16 <= len(raw):
            sec, frac, incl, _ = struct.unpack_from(end + "IIII", raw, pos)
            t = sec + frac / (1e9 if nano else 1e6)
            t0 = t if t0 is None else t0
            out.append((t - t0, raw[pos:pos + 16 + incl]))
            pos += 16 + incl
        cache[name] = (raw[:24], out)
    return cache[name]


def steps(name):
    _, recs = records(name)
    return int(recs[-1][0] // settings.replay_chunk_s) + 1 if recs else 0


def chunk(name, k):
    """the records of step k: [5k, 5k + 5) seconds"""
    _, recs = records(name)
    lo, hi = k * settings.replay_chunk_s, (k + 1) * settings.replay_chunk_s
    part = [r for t, r in recs if lo <= t < hi]
    return b"".join(part), len(part), hi


def append_next(s, a):
    """store the next chunk; -> (path of the capture so far, step) or None when finished"""
    name = a.replay["demo"]
    k = s.query(m.replay_chunk).filter(m.replay_chunk.analysis_id == a.id).count()
    if k >= a.replay["steps"]:
        return None
    data, n, t_end = chunk(name, k)
    s.add(m.replay_chunk(analysis_id=a.id, idx=k, t_end=t_end, packets=n, data=data))
    s.commit()
    head, _ = records(name)
    rows = s.query(m.replay_chunk).filter(m.replay_chunk.analysis_id == a.id).order_by(m.replay_chunk.idx).all()
    p = Path(settings.tmp_dir) / f"replay-{a.id}.pcap"
    with open(p, "wb") as f:
        f.write(head)
        for r in rows:
            f.write(r.data)
    return p, k + 1, t_end, sum(r.packets for r in rows)
