"""phase 2 acceptance: each class runs 30 s through a live tunnel and must show
recognisable traffic in the inner capture (host_a eth0, plaintext).

usage: python3 gen/smoke.py [class ...] [--mode tunnel|transport] [--fam v4|v6]
"""
import importlib
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

here = Path(__file__).resolve().parent
sys.path[:0] = [str(here), str(here.parent / "lab")]
import common
import topo
from lab import dx, sh

classes = ["icmp", "voip", "email", "bulk", "chat", "web_light", "web", "video"]
# what "recognisable" means for each class, on the inner plaintext capture
sig = {"icmp": lambda s: s["icmp"] >= 20,
       "voip": lambda s: s["sip"] >= 2 and s["rtp_udp"] >= 500,
       "email": lambda s: s["tcp/587"] + s["tcp/143"] >= 20,
       "bulk": lambda s: s["bytes"] >= 10e6,
       "chat": lambda s: s["tcp/5222"] >= 20,
       "web_light": lambda s: s["tcp/443"] >= 10,
       "web": lambda s: s["tcp/443"] >= 100,
       "video": lambda s: s["tcp/443"] >= 500 and s["bytes"] >= 2e6}
base = {"ike_version": 2, "ike_proposal": "aes256-sha256-ecp256", "esp_proposal": "aes128gcm16-ecp256",
        "pfs": True, "dh": "ecp256", "encap": False, "auth": "psk", "aggressive": False, "esn": False,
        "replay_window": 32, "ike_rekey_s": 14400, "child_rekey_s": 3600, "dpd_delay_s": 0,
        "fragmentation": "yes"}


def stats(pcap):
    out = sh(f"tshark -r {pcap} -T fields -e frame.len -e ip.proto -e ipv6.nxt -e tcp.srcport -e tcp.dstport "
             f"-e udp.srcport -e udp.dstport -e sip.Method", timeout=300)[1]
    s = Counter()
    for line in out.splitlines():
        f = (line.split("\t") + [""] * 8)[:8]
        s["packets"] += 1
        s["bytes"] += int(f[0] or 0)
        pr = f[1] or f[2]
        if pr in ("1", "58"):
            s["icmp"] += 1
        for p in (f[3], f[4]):
            if p and int(p) in (443, 587, 143, 5222, 22):
                s[f"tcp/{p}"] += 1
                break
        if f[5] and f[6]:
            u = {int(f[5]), int(f[6])}
            if 5060 in u:
                s["sip"] += 1
            elif any(10000 <= x <= 40000 for x in u):
                s["rtp_udp"] += 1
        if f[7]:
            s["sip_methods"] += 1
    return s


def run(cls, cfg, dur=30):
    mod = importlib.import_module(common.module(cls))
    ctx = topo.gen_ctx(cfg)
    cap = topo.c["host_a"] if cfg["mode"] == "tunnel" else topo.c["gw_a"]
    dx(cap, "pkill tcpdump; rm -f /tmp/inner.pcap; true")
    if cfg["mode"] == "tunnel":
        dx(cap, "tcpdump -i eth0 -s 96 -w /tmp/inner.pcap not arp >/dev/null 2>&1", detach=True)
    else:
        dx(cap, "tcpdump -i nflog:7 -s 0 -w /tmp/inner.pcap >/dev/null 2>&1", detach=True)
    time.sleep(1)
    ev = mod.start(dur, 1234, ctx)
    time.sleep(1)
    dx(cap, "pkill tcpdump; sleep 0.5; true")
    local = f"/tmp/smoke-{cls}.pcap"
    sh(f"docker cp {cap}:/tmp/inner.pcap {local}")
    s = stats(local)
    app = [e for e in ev if e["event"] == "app"][0]
    ok = sig[cls](s) and app["rc"] == 0
    keys = {k: v for k, v in s.items() if k not in ("packets", "bytes") and v}
    print(f"[{'ok  ' if ok else 'FAIL'}] {cls:10} pkts={s['packets']:<6} bytes={s['bytes'] / 1e6:7.2f}MB "
          f"events={len(ev) - 1:<3} {json.dumps(keys)}", flush=True)
    if not ok:
        print("   ", app.get("err", "")[-400:], [e for e in ev if e["event"] != "app"][:3])
    return ok


def main():
    want = [a for a in sys.argv[1:] if a in classes] or classes
    mode = sys.argv[sys.argv.index("--mode") + 1] if "--mode" in sys.argv else "tunnel"
    fam = sys.argv[sys.argv.index("--fam") + 1] if "--fam" in sys.argv else "v4"
    cfg = {**base, "mode": mode, "outer_family": fam, "inner_family": fam}
    topo.up()
    topo.deploy(cfg)
    topo.initiate()
    topo.nflog(mode == "transport")
    res = [run(c, cfg) for c in want]
    topo.stop_ipsec()
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    main()
