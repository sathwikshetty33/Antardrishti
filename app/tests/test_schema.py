"""the contract (app/schema) against real analyzer.cli output of the kept test captures"""
import json
from pathlib import Path

import jsonschema
import pytest

from analyzer import cli
from app.schema import v1

keep = Path.home() / "antar-data" / "keep"
runs = ["p1-voip_video_web-21e3e3f0-r1", "p1-whatsapp-40244c69-r1", "p0-e18-99a7fdcf-r1", "p0-e14-c468d4c1-r1",
        "p0-e03-e47151a8-r1", "p0-e10-74abf847-r1", "p1-e19-eb5a846a-r1", "p1-e25-99a7fdcf-r1"]
schema_file = Path(v1.__file__).with_name("result.v1.json")
cache = {}


def result(rid):
    if rid not in cache:
        d = keep / rid
        if not (d / "outer.pcap.zst").exists():
            pytest.skip(f"{rid} not kept")
        cache[rid] = json.loads(json.dumps(cli.analyze([d / "outer.pcap.zst", d / "ike.pcap.zst"]), default=float))
    return cache[rid]


@pytest.mark.parametrize("rid", runs)
def test_pydantic(rid):
    r = v1.validate(result(rid))
    assert r.schema_version == v1.schema_version
    for t in r.tunnels:
        for name in t.config.facts():
            assert name in v1.known_facts, name


@pytest.mark.parametrize("rid", runs)
def test_json_schema(rid):
    jsonschema.validate(result(rid), json.loads(schema_file.read_text()))


def test_schema_file_is_current():
    s = json.loads(schema_file.read_text())
    fresh = v1.result.model_json_schema()
    assert s["$defs"] == fresh["$defs"] and s["properties"] == fresh["properties"]


def test_traffic_parts():
    """a mixture has shares with error bars, a timeline and per-window probabilities"""
    r = v1.validate(result("p1-voip_video_web-21e3e3f0-r1"))
    t = max(r.tunnels, key=lambda t: t.esp_packets)
    assert sum(t.byte_share_rounded.values()) == 100
    assert set(t.active_time_share) == set(v1.apps)
    assert t.windows and set(t.windows[0].presence_probability) == set(v1.apps)
    f = t.config.facts()
    assert f["esp_suite"].source == "inferred" and 0 < f["esp_suite"].confidence <= 1
    assert f["outer_family"].source == "observed"


def test_rejects_bad_output():
    bad = json.loads(json.dumps(result("p1-whatsapp-40244c69-r1")))
    bad["tunnels"][0]["config"]["mode"]["source"] = "guessed"
    with pytest.raises(Exception):
        v1.validate(bad)
    bad = json.loads(json.dumps(result("p1-whatsapp-40244c69-r1")))
    bad["tunnels"][0]["handshake_status"] = "maybe"
    with pytest.raises(Exception):
        v1.validate(bad)
