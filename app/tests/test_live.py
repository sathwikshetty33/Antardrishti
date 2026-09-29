"""live capture session tests: two sessions fed chunks concurrently keep separate tunnels,
findings and alerts; a key for one session is rejected by another; sequence and rate rules;
carry-over windows stay full 2 s; instant events fire on the chunk with the ike packet;
limits and expiry; the agent's own multipart chunk format parses"""
import gzip
import importlib.util
import struct
import time
import uuid
from pathlib import Path

import pytest
import sqlalchemy
import zstandard

from analyzer import parse
from app.api import settings

settings.storage = "local"
from fastapi.testclient import TestClient  # noqa: E402

from app.api import db  # noqa: E402
from app.api import models as m  # noqa: E402
from app.api.index import app  # noqa: E402

pytestmark = pytest.mark.skipif(
    not __import__("app.tests.test_api", fromlist=["db_up"]).db_up(), reason="local postgres not running")
c = TestClient(app)

agent_path = Path(__file__).resolve().parent.parent / "api" / "agent" / "antardrishti-agent.py"
spec = importlib.util.spec_from_file_location("antardrishti_agent", agent_path)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


# ---------------------------------------------------------------- test fixtures: a real demo capture split

def split_demo(name):
    """(header, esp-only records, ike-only records) of a demo capture, each ready to write as
    a standalone pcap (header + records)"""
    d = settings.demo_dir / next(x["file"] for x in __import__("json").loads(
        (settings.demo_dir / "demos.json").read_text()) if x["name"] == name)
    raw = zstandard.ZstdDecompressor().stream_reader(open(d, "rb")).read()
    tmp = Path(f"/tmp/antar-test-{uuid.uuid4().hex}.pcap")
    tmp.write_bytes(raw)
    try:
        buf, off, cap, orig, ts, link = parse.index(tmp)
        f = parse.fields(buf, off, cap, link)
        cl = parse.classify(buf, f)
        idx = f["idx"]
        off2, cap2 = off[idx], cap[idx]
        is_ike = cl["kind"] == parse.ike

        def build(mask):
            out = []
            for o, cp in zip(off2[mask], cap2[mask]):
                o = int(o)
                cp = int(cp)
                out.append(bytes(buf[o - 16:o]) + bytes(buf[o:o + cp]))
            return b"".join(out)

        header = bytes(buf[:24])
        return header, build(~is_ike), build(is_ike)
    finally:
        tmp.unlink(missing_ok=True)


le_magic = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")


def chunks_of(records, header, n):
    """split a records blob into n chunks, each a whole number of pcap records, in order:
    record i goes to bucket floor(i * n / total), so the earliest records land in chunk 0"""
    end = "<" if header[:4] in le_magic else ">"
    bounds, pos = [0], 0
    while pos + 16 <= len(records):
        incl = struct.unpack_from(end + "I", records, pos + 8)[0]
        pos += 16 + incl
        bounds.append(pos)
    total = len(bounds) - 1
    out = [b""] * n
    for i in range(total):
        b = min(i * n // total, n - 1)
        out[b] += records[bounds[i]:bounds[i + 1]]
    return out


@pytest.fixture(scope="module")
def mixture_parts():
    header, esp, ike = split_demo("mixture")
    return header, chunks_of(esp, header, 4), chunks_of(ike, header, 4)


@pytest.fixture(scope="module")
def aggr_parts():
    """the ikev1-aggressive edge case: its ike packets land in the first chunk"""
    header, esp, ike = split_demo("ikev1-aggressive")
    return header, chunks_of(esp, header, 3), chunks_of(ike, header, 3)


def post_chunk(sid, key, seq, header, esp_records, ike_records):
    files = {"esp": ("esp.pcap.gz", gzip.compress(header + esp_records), "application/gzip")}
    if ike_records:
        files["ike"] = ("ike.pcap.gz", gzip.compress(header + ike_records), "application/gzip")
    return c.post(f"/api/live/{sid}/chunks", data={"seq": seq}, files=files, headers={"x-sensor-key": key})


def create_session(name="test"):
    r = c.post("/api/live", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(autouse=True)
def many_sessions_per_client(monkeypatch):
    """the test client always presents the same ip; only test_limits_and_expiry checks the cap"""
    monkeypatch.setattr(settings, "live_max_sessions_per_ip", 1000)


# ---------------------------------------------------------------- tests

def test_two_sessions_stay_separate(mixture_parts, aggr_parts):
    header, esp_a, ike_a = mixture_parts
    header2, esp_b, ike_b = aggr_parts
    a = create_session("session-a")
    b = create_session("session-b")
    for seq in range(3):
        assert post_chunk(a["id"], a["key"], seq, header, esp_a[seq], ike_a[seq]).status_code == 200
        assert post_chunk(b["id"], b["key"], seq, header2, esp_b[seq], ike_b[seq]).status_code == 200
        time.sleep(1.01)
    ta = c.get(f"/api/analyses/{a['id']}/tunnels").json()
    tb = c.get(f"/api/analyses/{b['id']}/tunnels").json()
    assert ta and tb
    # the aggressive-mode tunnel is IKEv1; the mixture tunnel never gets that fact
    assert tb[0]["facts"].get("ike_version", {}).get("value") == 1
    assert ta[0]["facts"].get("ike_version") is None
    la = c.get(f"/api/live/{a['id']}").json()
    lb = c.get(f"/api/live/{b['id']}").json()
    assert la["chunks"] == 3 and lb["chunks"] == 3
    assert la["id"] != lb["id"]


def test_foreign_key_rejected(mixture_parts):
    header, esp, ike = mixture_parts
    a = create_session("owner")
    b = create_session("other")
    ok = post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0])
    assert ok.status_code == 200
    wrong = post_chunk(a["id"], b["key"], 1, header, esp[1], ike[1])
    assert wrong.status_code == 403
    missing = c.post(f"/api/live/{a['id']}/chunks", data={"seq": 1}, files={"esp": ("e.pcap.gz", b"x", "application/gzip")})
    assert missing.status_code == 403
    assert c.post(f"/api/live/{a['id']}/stop", headers={"x-sensor-key": b["key"]}).status_code == 403
    assert c.post(f"/api/live/{a['id']}/stop", headers={"x-sensor-key": a["key"]}).status_code == 200


def test_sequence_and_rate_rules(mixture_parts, monkeypatch):
    header, esp, ike = mixture_parts
    a = create_session()
    assert post_chunk(a["id"], a["key"], 1, header, esp[0], ike[0]).status_code == 409  # must start at 0
    assert post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0]).status_code == 200
    assert post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0]).status_code == 409  # duplicate
    assert post_chunk(a["id"], a["key"], 2, header, esp[1], ike[1]).status_code == 409  # out of order
    # force the rate check to trip regardless of how long the previous chunks' analyses took
    monkeypatch.setattr(settings, "live_min_chunk_interval_s", 1e9)
    fast = post_chunk(a["id"], a["key"], 1, header, esp[1], ike[1])
    assert fast.status_code == 429
    monkeypatch.setattr(settings, "live_min_chunk_interval_s", 0.0)
    assert post_chunk(a["id"], a["key"], 1, header, esp[1], ike[1]).status_code == 200


def test_instant_events_on_the_ike_chunk(aggr_parts):
    header, esp, ike = aggr_parts
    a = create_session()
    r0 = post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0])
    assert r0.status_code == 200
    findings0 = c.get(f"/api/analyses/{a['id']}/findings").json()
    assert any(f["check_id"] == "IKEV1-AGGR" for f in findings0), "the handshake is in chunk 0"
    alerts0 = c.get(f"/api/live/{a['id']}/alerts").json()
    assert any(f["check_id"] == "IKEV1-AGGR" for f in alerts0)
    assert all(f["severity"] in ("critical", "high") for f in alerts0)


def test_full_windows_across_chunks(mixture_parts):
    header, esp, ike = mixture_parts
    a = create_session()
    last_windows = None
    for seq in range(4):
        r = post_chunk(a["id"], a["key"], seq, header, esp[seq], ike[seq])
        assert r.status_code == 200
        time.sleep(1.01)
    tunnels = c.get(f"/api/analyses/{a['id']}/tunnels").json()
    main = max(tunnels, key=lambda t: t["esp_packets"])
    detail = c.get(f"/api/analyses/{a['id']}/tunnels/{main['idx']}").json()
    ts = sorted(w["t"] for w in detail["windows"])
    assert ts, "there should be at least one full window by the last chunk"
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    assert all(abs(g - 2.0) < 1e-6 for g in gaps), "every window but the tail is a full 2 s"


def test_limits_and_expiry(mixture_parts, monkeypatch):
    header, esp, ike = mixture_parts
    a = create_session()
    monkeypatch.setattr(settings, "live_max_chunk_mb", 0.0001)
    big = post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0])
    assert big.status_code == 413
    monkeypatch.setattr(settings, "live_max_chunk_mb", 3.0)

    monkeypatch.setattr(settings, "live_max_sessions_per_ip", 0)
    assert c.post("/api/live", json={"name": "capped"}).status_code == 429
    monkeypatch.setattr(settings, "live_max_sessions_per_ip", 1000)

    b = create_session()
    from datetime import timedelta

    from app.api import live
    with db.session() as s:
        sess = s.get(m.live_session, b["id"])
        sess.status = "live"
        sess.last_chunk_at = m.now() - timedelta(seconds=10)  # recent enough not to trip the rate limit below
        s.commit()
        assert live.effective_status(sess, t=time.time() + settings.live_idle_timeout_s + 1) == "expired"
    still_live = post_chunk(b["id"], b["key"], 0, header, esp[0], ike[0])
    # not actually idle yet at the real clock (we only checked the pure function above)
    assert still_live.status_code == 200


def test_overview_scoped_to_one_session(mixture_parts):
    header, esp, ike = mixture_parts
    a = create_session()
    post_chunk(a["id"], a["key"], 0, header, esp[0], ike[0])
    ov = c.get(f"/api/overview?session={a['id']}").json()
    assert all(x["analysis_id"] == a["id"] for x in ov["inventory"])
    assert len(ov["recent"]) == 1 and ov["recent"][0]["id"] == a["id"]


# ---------------------------------------------------------------- agent script

def test_agent_arg_parsing_and_clamping():
    ns = agent.build_parser().parse_args(["--api", "http://x", "--session", "s", "--key", "k",
                                          "--chunk-seconds", "1"])
    assert ns.api == "http://x" and ns.chunk_seconds == 1
    assert agent.clamp_chunk_seconds(1) == agent.MIN_CHUNK_S
    assert agent.clamp_chunk_seconds(99) == agent.MAX_CHUNK_S
    assert agent.clamp_chunk_seconds(5) == 5


def test_agent_chunk_format_parses(mixture_parts):
    header, esp, ike = mixture_parts
    a = create_session()
    body = agent.build_multipart_body("BOUNDARY123", 0, gzip.compress(header + esp[0]), gzip.compress(header + ike[0]))
    r = c.post(f"/api/live/{a['id']}/chunks", data=body,
              headers={"content-type": "multipart/form-data; boundary=BOUNDARY123", "x-sensor-key": a["key"]})
    assert r.status_code == 200, r.text
    assert r.json()["packets_in_chunk"] > 0


def test_agent_no_ike_when_chunk_empty():
    body = agent.build_multipart_body("B", 0, gzip.compress(b"\0" * 24), None)
    assert b'name="ike"' not in body
    assert b'name="esp"' in body
