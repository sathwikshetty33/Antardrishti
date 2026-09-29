"""live capture sessions: a sensor agent posts successive capture chunks (an esp/ah pcap,
plus an optional ike pcap). each chunk is appended to the session's growing esp and ike
captures and the whole thing is reanalysed with the same in-request pipeline as an upload --
exactly like demo replay reprocesses its growing capture (replay.py) -- so config facts,
findings and shares strengthen as evidence accumulates, every analysed window stays a full
window except the current tail, and instant events (handshake facts) show up as soon as the
chunk that carries them is processed. no background work: expiry is settled lazily, whenever
a session is read.
"""
import hashlib
import hmac
import secrets
import struct
import time
from pathlib import Path

import zstandard
from sqlalchemy import delete

from app.api import models as m
from app.api import settings

le_magic = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")


def new_key():
    return secrets.token_urlsafe(24)


def key_hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def check_key(sess, key):
    return bool(key) and hmac.compare_digest(key_hash(key), sess.key_hash)


def count_records(header, records):
    """number of pcap records in a header-less record blob (records taken from a capture with
    the given global header, for its endianness)"""
    if not records:
        return 0
    end = "<" if header[:4] in le_magic else ">"
    n, pos, ln = 0, 0, len(records)
    while pos + 16 <= ln:
        incl = struct.unpack_from(end + "I", records, pos + 8)[0]
        pos += 16 + incl
        n += 1
    return n


def effective_status(sess, t=None):
    """the session's status as of t (default now), without writing anything. total duration
    and capture size are not judged lazily here: check_caps settles those right after each
    chunk, since only a chunk arriving can grow either of them."""
    t = t if t is not None else time.time()
    if sess.status in ("stopped", "completed"):
        return sess.status
    # 20 minutes without a chunk, counted from the last chunk or, before the first, from creation
    last = (sess.last_chunk_at or sess.created_at).timestamp()
    if sess.status in ("waiting", "live") and t - last > settings.live_idle_timeout_s:
        return "expired"
    return sess.status


def check_caps(sess, esp_bytes):
    """-> a completion note once a chunk has pushed the session past its total-duration or
    accumulated-capture-size cap, else None. reprocessing the whole capture on every chunk
    (module docstring) makes each chunk slower as the session grows, so both caps bound that
    growth instead of letting a session run and reprocess without limit."""
    age = (m.now() - sess.created_at).total_seconds()
    if age >= settings.live_max_duration_s:
        return f"reached the {settings.live_max_duration_s / 60:.0f}-minute cap on a live session"
    if esp_bytes >= settings.live_max_esp_mb * 2 ** 20:
        return f"reached the {settings.live_max_esp_mb:.0f} MB cap on a live session's capture"
    return None


def release(s, sess):
    """a session that takes no more chunks keeps its analysis but not its capture: the stored
    chunks only serve to reanalyse the next chunk, and neon's free plan has 512 mb per branch"""
    s.execute(delete(m.live_chunk).where(m.live_chunk.analysis_id == sess.analysis_id))


def finish(s, sess, status, note=""):
    """completed, stopped or expired: no more chunks"""
    sess.status = status
    if note:
        sess.note = note
    release(s, sess)
    s.commit()


def refresh_status(s, sess):
    """settle an expired session's stored status (no worker does this, so every read does)"""
    eff = effective_status(sess)
    if eff != sess.status:
        finish(s, sess, eff)
    return eff


def active_count(s, ip):
    rows = s.query(m.live_session).filter(m.live_session.creator_ip == ip,
                                          m.live_session.status.in_(("waiting", "live"))).all()
    return sum(1 for r in rows if refresh_status(s, r) in ("waiting", "live"))


def store_chunk(s, sess, seq, esp_raw, ike_raw):
    """validate and persist one chunk. -> packets in this chunk. raises ValueError on a bad pcap"""
    if len(esp_raw) < 24:
        raise ValueError("the esp chunk is not a valid pcap")
    if ike_raw is not None and len(ike_raw) < 24:
        raise ValueError("the ike chunk is not a valid pcap")
    if sess.esp_header is None:
        sess.esp_header = esp_raw[:24]
    if ike_raw and sess.ike_header is None:
        sess.ike_header = ike_raw[:24]
    n = count_records(sess.esp_header, esp_raw[24:]) + (count_records(sess.ike_header, ike_raw[24:]) if ike_raw else 0)
    z = zstandard.ZstdCompressor(level=6)
    s.add(m.live_chunk(analysis_id=sess.analysis_id, seq=seq, esp_data=z.compress(esp_raw[24:]),
                       ike_data=z.compress(ike_raw[24:]) if ike_raw else None, packets=n))
    sess.last_seq = seq
    sess.chunks += 1
    sess.total_bytes += len(esp_raw) + (len(ike_raw) if ike_raw else 0)
    sess.last_chunk_at = m.now()
    sess.status = "live"
    s.commit()
    return n


def unpack(b):
    b = bytes(b)
    return zstandard.ZstdDecompressor().decompress(b) if b[:4] == b"\x28\xb5\x2f\xfd" else b


def rebuild(s, sess):
    """the capture so far, as (esp path, ike path or None); the caller deletes both when done"""
    rows = s.query(m.live_chunk).filter(m.live_chunk.analysis_id == sess.analysis_id).order_by(m.live_chunk.seq).all()
    esp_path = Path(settings.tmp_dir) / f"live-{sess.analysis_id}-esp.pcap"
    with open(esp_path, "wb") as f:
        f.write(sess.esp_header)
        for r in rows:
            f.write(unpack(r.esp_data))
    ike_path = None
    if sess.ike_header and any(r.ike_data for r in rows):
        ike_path = Path(settings.tmp_dir) / f"live-{sess.analysis_id}-ike.pcap"
        with open(ike_path, "wb") as f:
            f.write(sess.ike_header)
            for r in rows:
                if r.ike_data:
                    f.write(unpack(r.ike_data))
    return esp_path, ike_path
