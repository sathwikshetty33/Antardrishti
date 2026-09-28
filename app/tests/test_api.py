"""api tests against a local postgres (docker compose up) with local storage: upload -> analysis
-> findings on the 3 demo captures, the replay, the access key, limits and the blob token"""
import base64
import hashlib
import hmac
import json
import uuid

import pytest
import sqlalchemy

from app.api import settings, storage

settings.storage = "local"
from fastapi.testclient import TestClient  # noqa: E402

from app.api import db  # noqa: E402
from app.api.index import app  # noqa: E402


def db_up():
    try:
        with db.session() as s:
            s.execute(sqlalchemy.text("select 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not db_up(), reason="local postgres not running (docker compose up -d)")
c = TestClient(app)
demos = json.loads((settings.demo_dir / "demos.json").read_text())
expect = {"mixture": {"apps": {"voip", "video"}, "fail": set()},
          "whatsapp": {"apps": {"voip"}, "fail": set()},
          "ikev1-aggressive": {"apps": {"icmp"}, "fail": {"IKEV1-AGGR", "IKE-VERSION"}}}


def test_health_model_config():
    h = c.get("/api/health").json()
    assert h["ok"] and h["db"] == "ok" and h["bundle"] == "v1"
    mo = c.get("/api/model").json()
    assert mo["version"] == "v1" and mo["commit"].startswith("a88b2a4") and mo["models"] == 17
    assert c.get("/api/config").json()["upload_limit_mb"] == settings.upload_limit_mb


@pytest.mark.parametrize("d", demos, ids=[d["name"] for d in demos])
def test_upload_analysis_findings(d):
    data = (settings.demo_dir / d["file"]).read_bytes()
    assert len(data) < settings.upload_limit_mb * 2 ** 20
    up = c.put(f"/api/uploads/local/{d['file']}", content=data)
    assert up.status_code == 200
    aid = str(uuid.uuid4())
    assert c.get(f"/api/analyses/{aid}").json()["status"] == "pending"
    r = c.post("/api/analyses", json={"id": aid, "uploads": [{"url": up.json()["url"], "name": d["file"]}]}).json()
    assert r["status"] == "done", r["error"]
    assert r["bundle_version"].startswith("v1@") and r["schema_version"] == "antardrishti.result/1"
    tunnels = c.get(f"/api/analyses/{aid}/tunnels").json()
    main = max(tunnels, key=lambda t: t["esp_packets"])
    detail = c.get(f"/api/analyses/{aid}/tunnels/{main['idx']}").json()
    assert detail["windows"] and sum(x["byte_rounded"] for x in detail["shares"]) == 100
    top = {x["app"] for x in detail["shares"] if x["byte_rounded"] >= 5}
    assert expect[d["name"]]["apps"] <= top | {"unknown"}
    fs = c.get(f"/api/analyses/{aid}/findings").json()
    assert fs and all(set(f) >= {"check_id", "verdict", "severity", "standard", "evidence", "confidence"} for f in fs)
    fails = {f["check_id"] for f in fs if f["verdict"] == "fail"}
    assert expect[d["name"]]["fail"] <= fails
    th = c.get(f"/api/analyses/{aid}/threats").json()["threats"]
    assert all(1 <= t["likelihood"] <= 5 for t in th)
    rep = c.get(f"/api/analyses/{aid}/report").json()
    assert rep["overall"]["score"] == r["risk"] and rep["model"]["version"] == "v1"


def test_demo_one_click_and_list():
    r = c.post("/api/analyses", json={"demo": "ikev1-aggressive"}).json()
    assert r["status"] == "done" and r["source"] == "demo" and r["risk"] >= 30
    assert any(a["id"] == r["id"] for a in c.get("/api/analyses").json())
    ov = c.get("/api/overview").json()
    assert ov["inventory"] and ov["recent"]


def test_replay_accumulates():
    rp = c.post("/api/replays", json={"demo": "whatsapp"}).json()
    assert rp["status"] == "replaying" and rp["replay"]["steps"] > 3
    seen = []
    for _ in range(4):
        x = c.post(f"/api/replays/{rp['id']}/next").json()
        seen.append(x["replay"]["packets"])
    assert seen == sorted(seen) and seen[-1] > seen[0]
    t = c.get(f"/api/analyses/{rp['id']}/tunnels").json()
    assert t and t[0]["esp_packets"] > 0


def test_access_key(monkeypatch):
    monkeypatch.setattr(settings, "access_key", "k-test")
    assert c.post("/api/analyses", json={"demo": "whatsapp"}).status_code == 401
    ok = c.post("/api/analyses", json={"demo": "ikev1-aggressive"}, headers={"x-access-key": "k-test"})
    assert ok.status_code == 200


def test_limits(monkeypatch):
    monkeypatch.setattr(settings, "max_pcap_mb", 0.01)
    r = c.post("/api/analyses", json={"demo": "whatsapp"}).json()
    assert r["status"] == "failed" and r["stage"] == "rejected" and "300 s" in r["error"]
    monkeypatch.setattr(settings, "upload_limit_mb", 0.001)
    big = c.put("/api/uploads/local/x.pcap", content=b"\0" * 5000)
    assert big.status_code == 413


def test_rejects_foreign_urls():
    r = c.post("/api/analyses", json={"uploads": [{"url": "https://example.com/x.pcap", "name": "x.pcap"}]})
    assert r.status_code == 400
    assert c.put("/api/uploads/local/notes.txt", content=b"x").status_code == 400


def test_blob_client_token(monkeypatch):
    tok = "vercel_blob_rw_AbCdEf123_secretpart"
    monkeypatch.setattr(settings, "blob_token", tok)
    monkeypatch.setattr(settings, "storage", "blob")
    r = c.post("/api/uploads", json={"type": "blob.generate-client-token",
                                     "payload": {"pathname": "cap.pcap", "clientPayload": None, "multipart": False}})
    assert r.status_code == 200
    ct = r.json()["clientToken"]
    assert ct.startswith("vercel_blob_client_AbCdEf123_")
    sig, payload = base64.b64decode(ct.split("_", 4)[4]).decode().split(".", 1)
    assert hmac.new(tok.encode(), payload.encode(), hashlib.sha256).hexdigest() == sig
    body = json.loads(base64.b64decode(payload))
    assert body["pathname"] == "captures/cap.pcap" and body["maximumSizeInBytes"] == int(settings.upload_limit_mb * 2 ** 20)
    bad = c.post("/api/uploads", json={"type": "blob.generate-client-token", "payload": {"pathname": "x.exe"}})
    assert bad.status_code == 400
    assert storage.is_blob_url("https://abcdef123.private.blob.vercel-storage.com/captures/cap-x.pcap")
