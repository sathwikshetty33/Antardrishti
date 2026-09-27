"""phase 1 acceptance: one set-A config per mode and family establishes
and passes traffic, with esp (and only esp) for the inner flow at the router.

usage: python3 lab/smoke.py [--keep]
"""
import re
import sys
import time

import topo
from lab import dx

base = {"ike_version": 2, "ike_proposal": "aes256-sha256-ecp256", "pfs": True,
        "dh": "ecp256", "encap": False, "auth": "psk", "aggressive": False,
        "esn": False, "replay_window": 32, "ike_rekey_s": 14400, "child_rekey_s": 3600,
        "dpd_delay_s": 0, "fragmentation": "yes"}
cases = [
    {"mode": "tunnel", "outer_family": "v4", "inner_family": "v4", "esp_proposal": "aes128gcm16-ecp256"},
    {"mode": "tunnel", "outer_family": "v6", "inner_family": "v6", "esp_proposal": "aes256-sha256-ecp256", "encap": True},
    {"mode": "transport", "outer_family": "v4", "inner_family": "v4", "esp_proposal": "aes128-sha1-ecp256", "auth": "cert", "cert_key": "ecdsa"},
    {"mode": "transport", "outer_family": "v6", "inner_family": "v6", "esp_proposal": "aes256gcm16-ecp256", "auth": "cert"},
]


def one(cfg):
    cli, srv, ip = topo.endpoints(cfg)
    r = topo.c["router"]
    topo.deploy(cfg)
    dx(srv, "pkill -f [h]ttp.server; true")
    dx(srv, "cd /tmp && head -c 3000000 /dev/urandom > blob && python3 -m http.server --bind :: 8080 >/dev/null 2>&1", detach=True)
    dx(r, "pkill tcpdump; rm -f /tmp/s.pcap; tcpdump -i any -s 128 -w /tmp/s.pcap >/dev/null 2>&1", detach=True)
    time.sleep(1.5)
    topo.initiate()
    url = f"http://[{ip}]:8080/blob" if ":" in ip else f"http://{ip}:8080/blob"
    dx(cli, f"ping -c5 -i0.2 -W2 {ip}")
    _, got = dx(cli, f"curl -s -m 20 -o /dev/null -w '%{{size_download}}' {url}")
    time.sleep(0.5)
    dx(r, "pkill tcpdump; sleep 0.5; true")
    _, out = dx(r, "tcpdump -nr /tmp/s.pcap 2>/dev/null")
    esp = len(re.findall(r"ESP\(spi", out))
    udp = bool(re.search(r"\.4500[ :]", out))
    # plaintext leak: inner addresses or the http port visible outside esp
    leak = len([l for l in out.splitlines() if ("8080" in l or " 10.1.0." in l or "fd00:1::" in l) and "ESP" not in l])
    _, sa = dx(topo.c["gw_a"], "swanctl --list-sas")
    enc = re.search(r"(ESP|AH):.*", sa)
    ok = esp > 50 and int(got) == 3000000 and leak == 0
    tag = f"{cfg['mode']}/{cfg['outer_family']}"
    print(f"[{'ok  ' if ok else 'FAIL'}] {tag:14} {cfg['esp_proposal']:22} auth={cfg['auth']:4} "
          f"esp={esp} http={got}B leak={leak} natt={'y' if udp else 'n'} | {enc.group(0).strip() if enc else '?'}")
    topo.stop_ipsec()
    return ok


def main():
    topo.up()
    res = [one({**base, **k}) for k in cases]
    if "--keep" not in sys.argv:
        topo.down()
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    main()
