"""rule engine unit tests: one case per check (pass and fail where the check can fail), the
confidence wording, "not determinable" findings, risk scores and the threat matrix"""
import pytest

from app.api.rules import engine
from app.api.rules import table as tb


def fact(v, conf=1.0, src="read from IKE"):
    return {"value": v, "confidence": conf, "source": src}


def tunnel(**facts):
    cfg = {"handshake_status": fact("full", 1.0, "observed")}
    cfg.update(facts)
    return {"tunnel": 0, "config": cfg}


def windows(app, p, share=100.0):
    ws = [{"present": [app], "presence_probability": {app: p}} for _ in range(5)]
    bs = {a: {"share": 0.0, "error_pp": None} for a in ["voip", "video", "web", "email", "icmp", "bulk", "chat"]}
    bs[app] = {"share": share, "error_pp": 1.0}
    bs["unknown"] = {"share": 100 - share, "error_pp": None}
    return {"windows": ws, "byte_share": bs}


def find(t, check):
    fs = [f for f in engine.evaluate(t) if f["check_id"] == check]
    assert len(fs) == 1, (check, fs)
    return fs[0]


cases = [
    ("IKE-ENC", {"ike_encryption": fact("aes-gcm16-256")}, "pass", "info"),
    ("IKE-ENC", {"ike_encryption": fact("3des")}, "fail", "high"),
    ("IKE-ENC", {"ike_encryption": fact("des")}, "fail", "critical"),
    ("IKE-ENC", {"ike_encryption": fact("null")}, "fail", "critical"),
    ("IKE-KEYLEN", {"ike_encryption": fact("aes-cbc-256")}, "pass", "info"),
    ("IKE-KEYLEN", {"ike_encryption": fact("aes-cbc-64")}, "fail", "high"),
    ("IKE-INTEG", {"ike_integ": fact("hmac-sha256-128")}, "pass", "info"),
    ("IKE-INTEG", {"ike_integ": fact("hmac-sha1-96")}, "warn", "low"),
    ("IKE-INTEG", {"ike_integ": fact("hmac-md5-96")}, "fail", "high"),
    ("IKE-PRF", {"ike_prf": fact("prf-hmac-sha256")}, "pass", "info"),
    ("IKE-PRF", {"ike_prf": fact("prf-hmac-md5")}, "fail", "high"),
    ("IKE-DH", {"ike_dh": fact("ecp256")}, "pass", "info"),
    ("IKE-DH", {"ike_dh": fact("modp2048")}, "pass", "info"),
    ("IKE-DH", {"ike_dh": fact("modp1024")}, "fail", "high"),
    ("IKE-DH", {"ike_dh": fact("modp768")}, "fail", "critical"),
    ("IKE-DH", {"ike_dh": fact("modp1536")}, "fail", "medium"),
    ("ESP-SUITE", {"esp_suite": fact("AES-GCM-16 (ICV 16)", 0.99, "inferred")}, "pass", "info"),
    ("ESP-SUITE", {"esp_suite": fact("AES-CBC + HMAC-SHA1-96", 0.95, "inferred")}, "warn", "low"),
    ("ESP-NULL", {"esp_plaintext_share": fact(1.0, 1.0, "observed")}, "fail", "critical"),
    ("ESP-NULL", {"esp_plaintext_share": fact(0.001, 1.0, "observed")}, "pass", "info"),
    ("AH-ONLY", {"ah_packets": fact(94, 1.0, "observed")}, "fail", "high"),
    ("AH-ONLY", {"ah_packets": fact(0, 1.0, "observed")}, "pass", "info"),
    ("PFS", {"pfs": fact(True, 0.97, "inferred")}, "pass", "info"),
    ("PFS", {"pfs": fact(False, 0.95, "inferred")}, "fail", "medium"),
    ("IKE-VERSION", {"ike_version": fact(2)}, "pass", "info"),
    ("IKE-VERSION", {"ike_version": fact(1)}, "fail", "medium"),
    ("IKEV1-AGGR", {"ike_version": fact(1), "ikev1_mode": fact("aggressive")}, "fail", "high"),
    ("IKEV1-AGGR", {"ike_version": fact(1), "ikev1_mode": fact("main")}, "pass", "info"),
    ("AUTH", {"ikev1_auth": fact("psk")}, "warn", "low"),
    ("AUTH", {"ikev1_auth": fact("rsa-sig")}, "pass", "info"),
    ("MODE", {"mode": fact("tunnel", 0.99, "inferred")}, "pass", "info"),
    ("MODE", {"mode": fact("transport", 0.99, "inferred")}, "warn", "low"),
    ("LIFETIME-CHILD", {"rekey_times_s": fact({"child": [40.0, 100.0, 160.0], "ike_sa": []}, 1.0, "observed")},
     "pass", "info"),
    ("LIFETIME-CHILD", {"rekey_times_s": fact({"child": [10.0, 30.0], "ike_sa": []}, 1.0, "observed")}, "warn", "low"),
    ("LIFETIME-IKE", {"ike_lifetime_s": fact(28800)}, "pass", "info"),
    ("LIFETIME-IKE", {"ike_lifetime_s": fact(172800)}, "warn", "low"),
    ("REPLAY", {"esp_duplicate_seq": fact(40, 1.0, "observed")}, "fail", "medium"),
    ("REPLAY", {"esp_duplicate_seq": fact(0, 1.0, "observed")}, "info", "info"),
    ("NEGOTIATION", {"handshake_status": fact("failed", 1.0, "observed"), "ike_version": fact(2),
                     "ike_notifies": fact([14])}, "fail", "medium"),
    ("NEGOTIATION", {}, "pass", "info"),
    ("NOTIFY", {"ike_version": fact(2), "ike_notifies": fact([24])}, "warn", "low"),
    ("NOTIFY", {"ike_version": fact(2), "ike_notifies": fact([16388, 17])}, "pass", "info"),
    ("COOKIE", {"ike_version": fact(2), "ike_notifies": fact([16390])}, "warn", "low"),
    ("COOKIE", {"ike_version": fact(2), "ike_notifies": fact([])}, "pass", "info"),
    ("RETRANSMIT", {"ike_retransmissions": fact(8, 1.0, "observed")}, "warn", "low"),
    ("RETRANSMIT", {"ike_retransmissions": fact(0, 1.0, "observed")}, "pass", "info"),
]


@pytest.mark.parametrize("check,facts,verdict,severity", cases, ids=[f"{c[0]}-{c[2]}-{i}" for i, c in
                                                                    enumerate(cases)])
def test_check(check, facts, verdict, severity):
    f = find(tunnel(**facts), check)
    assert (f["verdict"], f["severity"]) == (verdict, severity), f["text"]
    assert f["standard"] and f["title"]
    if verdict in ("fail", "warn"):
        assert f["recommendation"] and f["evidence"] and f["threats"]
        assert all(set(e) >= {"fact", "value", "source"} for e in f["evidence"])


def test_every_check_has_a_case():
    tested = {c[0] for c in cases} | {"ESP-KEYLEN", "REPLAY-WINDOW", "METADATA"}
    assert tested == {r["id"] for r in tb.checks}


def test_metadata_exposure():
    t = tunnel(**{})
    t.update(windows("voip", 0.97))
    f = find(t, "METADATA")
    assert f["verdict"] == "warn" and f["severity"] == "medium" and "voip" in f["text"]
    assert f["confidence"] == pytest.approx(0.97)
    t.update(windows("voip", 0.6))
    assert find(t, "METADATA")["verdict"] == "pass"


@pytest.mark.parametrize("check,facts", [
    ("PFS", {"pfs": fact("not determinable", None, "inferred")}),
    ("PFS", {}),
    ("ESP-KEYLEN", {}),
    ("REPLAY-WINDOW", {"esp_duplicate_seq": fact(0, 1.0, "observed")}),
    ("IKE-DH", {}),
    ("AUTH", {"ike_version": fact(2)}),
    ("LIFETIME-CHILD", {"rekey_times_s": fact({"child": [45.0], "ike_sa": []}, 1.0, "observed")}),
    ("METADATA", {}),
])
def test_not_determinable(check, facts):
    f = find(tunnel(**facts), check)
    assert f["verdict"] == "not determinable" and f["severity"] == "info" and f["confidence"] is None
    assert "likely" not in f["text"].lower()


def test_likely_wording_below_confidence():
    low = find(tunnel(esp_suite=fact("AES-CBC + HMAC-SHA1-96", 0.62, "inferred")), "ESP-SUITE")
    assert low["text"].startswith("Likely (62% confidence)") and low["confidence"] == pytest.approx(0.62)
    high = find(tunnel(esp_suite=fact("AES-CBC + HMAC-SHA1-96", 0.93, "inferred")), "ESP-SUITE")
    assert "likely" not in high["text"].lower()


def test_score_weights_and_critical_floor():
    assert engine.score([]) == 0
    med = [{"verdict": "fail", "severity": "medium", "confidence": 1.0}]
    assert engine.score(med) == tb.weights["medium"]
    crit = [{"verdict": "fail", "severity": "critical", "confidence": 1.0}]
    assert engine.score(crit) == tb.critical_floor
    weak = [{"verdict": "fail", "severity": "critical", "confidence": 0.5}]
    assert engine.score(weak) == 20
    many = [{"verdict": "fail", "severity": "high", "confidence": 1.0}] * 9
    assert engine.score(many) == 100


def test_assess_and_threats():
    bad = tunnel(ike_version=fact(1), ikev1_mode=fact("aggressive"), ike_dh=fact("modp1024"))
    bad["tunnel"] = 1
    good = tunnel(ike_version=fact(2), ike_dh=fact("ecp256"), ike_encryption=fact("aes-gcm16-256"))
    a = engine.assess({"tunnels": [good, bad]})
    assert a["tunnels"][1]["score"] > a["tunnels"][0]["score"]
    assert a["overall"]["score"] == a["tunnels"][1]["score"]
    ids = {t["threat_id"] for t in a["threats"]}
    assert "T-KEY" in ids and all(t["tunnels"] == [1] for t in a["threats"])
    for t in a["threats"]:
        assert 1 <= t["likelihood"] <= 5 and 1 <= t["impact"] <= 5 and t["findings"]


def test_table_is_consistent():
    for r in tb.checks:
        assert set(r) >= {"id", "title", "standard", "fact", "outcomes", "missing", "threats", "fix"}
        assert all(t in tb.threats for t in r["threats"])
        for verdict, sev, _ in list(r["outcomes"].values()) + [r["missing"]]:
            assert verdict in ("pass", "fail", "warn", "info", "not determinable")
            assert sev in tb.weights
