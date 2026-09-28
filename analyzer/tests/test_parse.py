"""parser known-answer cases, checked against tshark on dataset runs (kept in ~/antar-data/keep)"""
import shutil
import subprocess
from collections import Counter

import pytest

from analyzer import common as cm
from analyzer import parse

keep = cm.data / "keep"
cases = ["p1-e25-99a7fdcf-r1", "p0-e13-2b102005-r1", "p0-e18-99a7fdcf-r1", "p0-e12-258e9a88-r1",
         "p0-e08-fb7d05a0-r1", "p1-e23-99a7fdcf-r1", "p1-voip_video_web-21e3e3f0-r1", "p0-e06-c3d4406b-r1"]
need = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark missing")


def run_dir(rid):
    d = keep / rid
    if not (d / "outer.pcap.zst").exists():
        pytest.skip(f"{rid} not kept")
    return d


def tshark(path, filt, fields):
    out = subprocess.run(["tshark", "-r", str(path), "-Y", filt, "-T", "fields", "-E", "separator=|"]
                         + sum((["-e", f] for f in fields), []), capture_output=True, text=True, check=True).stdout
    return [l.split("|") for l in out.splitlines() if l]


@need
@pytest.mark.parametrize("rid", cases)
def test_esp_against_tshark(rid, tmp_path):
    d = run_dir(rid)
    o = tmp_path / "outer.pcap"
    subprocess.run(["zstd", "-dqf", str(d / "outer.pcap.zst"), "-o", str(o)], check=True)
    r = parse.parse([o])
    ts = tshark(o, "sll.pkttype != 4 && esp",
                ["esp.spi", "esp.sequence"])
    theirs = Counter((int(s, 16), int(q)) for s, q in ts)
    mine = Counter(zip(pk_spis(r), r["packets"]["seq"].tolist()))
    assert sum(mine.values()) == r["counts"]["esp"]
    assert mine == theirs


def pk_spis(r):
    """spi per esp packet, from the tunnels' pair ids (pair ids are shared by up and down)"""
    import numpy as np
    pk = r["packets"]
    out = np.zeros(len(pk["t"]), np.int64)
    for t in r["tunnels"]:
        for side, dv in (("up", 0), ("down", 1)):
            for i, s in enumerate(t["spis"][side]):
                m = (pk["tunnel"] == t["id"]) & (pk["dir"] == dv) & (pk["pair"] == i)
                out[m] = int(s, 16)
    return out.tolist()


@need
@pytest.mark.parametrize("rid", cases)
def test_ike_against_tshark(rid, tmp_path):
    d = run_dir(rid)
    o, k = tmp_path / "outer.pcap", tmp_path / "ike.pcap"
    subprocess.run(["zstd", "-dqf", str(d / "outer.pcap.zst"), "-o", str(o)], check=True)
    subprocess.run(["zstd", "-dqf", str(d / "ike.pcap.zst"), "-o", str(k)], check=True)
    r = parse.parse([o, k])
    ts = tshark(k, "sll.pkttype != 4 && isakmp", ["isakmp.version", "isakmp.exchangetype",
                                                  "isakmp.key_exchange.dh_group"])
    theirs = Counter(int(e.split(",")[0]) for _, e, _ in ts)
    mine = Counter()
    for t in r["tunnels"]:
        for name, n in t["ike"]["exchanges"].items():
            code = {v: k_ for k_, v in parse.exch_names.items()}.get(name, name)
            mine[int(code)] += n
    assert mine == theirs
    groups = {int(g.split(",")[0]) for _, _, g in ts if g}
    got = {t["ike"]["ke"] for t in r["tunnels"] if t["ike"]["version"] == 2 and t["ike"]["ke"]}
    assert got <= groups


def test_statuses():
    """handshake status per edge case, as designed (dataset/CLAUDE.md section 6)"""
    want = {"p0-e07-99a7fdcf-r1": {"esp-only"}, "p0-e08-fb7d05a0-r1": {"rekey-only"}, "p0-e10-74abf847-r1": {"ike-only"},
            "p0-e03-e47151a8-r1": {"failed"}, "p0-e13-2b102005-r1": {"full"}, "p0-e14-c468d4c1-r1": {"full"}}
    for rid, st in want.items():
        d = run_dir(rid)
        r = parse.parse([d / "outer.pcap.zst", d / "ike.pcap.zst"])
        assert {t["status"] for t in r["tunnels"]} == st, rid


def test_multiple_tunnels_and_children():
    """e18: four tunnels (two behind one nat, told apart by nat-t ports); e23: two spi pairs"""
    d = run_dir("p0-e18-99a7fdcf-r1")
    r = parse.parse([d / "outer.pcap.zst", d / "ike.pcap.zst"])
    assert len([t for t in r["tunnels"] if t["esp"]]) == 4
    d = run_dir("p1-e23-99a7fdcf-r1")
    r = parse.parse([d / "outer.pcap.zst", d / "ike.pcap.zst"])
    t = max(r["tunnels"], key=lambda t: t["esp"])
    assert len(t["spis"]["up"]) >= 2 and len(t["spis"]["down"]) >= 2


def test_ikev1():
    d = run_dir("p0-e13-2b102005-r1")
    r = parse.parse([d / "outer.pcap.zst", d / "ike.pcap.zst"])
    t = max(r["tunnels"], key=lambda t: t["esp"])
    assert t["ike"]["version"] == 1 and t["ike"]["exchanges"].get("MAIN") == 6 and t["ike"]["exchanges"].get("QUICK")
    assert t["direction_from"] == "ikev1 first message"


def test_truncated_ike_replaced():
    """outer.pcap cuts ike at 128 bytes; merged with ike.pcap the full IKE_SA_INIT proposal is read"""
    d = run_dir("p1-whatsapp-40244c69-r1")
    alone = parse.parse([d / "outer.pcap.zst"])
    both = parse.parse([d / "outer.pcap.zst", d / "ike.pcap.zst"])
    assert both["counts"]["packets"] == alone["counts"]["packets"]
    t = max(both["tunnels"], key=lambda t: t["esp"])
    assert t["ike"]["proposal"].get("encr") and t["ike"]["ke"]
