"""phase 0: probe what this codespace kernel and docker can do.

writes dataset/env.json (read by the orchestrator) and the
environment section of dataset/README.md.
"""
import json
import platform
import re
import sys
import time

from lab import bridge_off, dx, put, render, root, sh

pre = "pf"
nets = {"a": ("172.30.1", "fd00:30:1:"), "b": ("172.30.2", "fd00:30:2:")}
results = {}


def check(name, fn):
    try:
        detail = fn()
        results[name] = {"ok": True, "detail": detail or ""}
    except Exception as e:
        results[name] = {"ok": False, "detail": str(e).strip().splitlines()[-1][:300]}
    mark = "ok  " if results[name]["ok"] else "FAIL"
    print(f"[{mark}] {name}: {results[name]['detail']}")
    return results[name]["ok"]


def cleanup():
    for c in ("gw_a", "gw_b", "router"):
        sh(f"docker rm -f {pre}_{c}", check=False)
    for n in nets:
        sh(f"docker network rm {pre}_{n}", check=False)


def build():
    for img in ("gw", "router"):
        sh(f"docker build -q -t antar/{img} {root}/lab/images/{img}", timeout=900)


def pinned():
    """the lab images and media are the digests in lab/images.lock (lab/images.sh
    pull, pull-media): never a local build, runs on those are rejected at merge"""
    lock = root / "lab" / "images.lock"
    if not lock.exists():
        build()
        return "no lab/images.lock: gw and router built locally"
    bad, n = [], 0
    for line in lock.read_text().splitlines():
        name, ref = line.split()
        n += 1
        if name == "media":
            f = root / "lab" / "media" / ".digest"
            if not f.exists() or f.read_text().strip() != ref:
                bad.append("media")
            continue
        _, have = sh(f"docker image inspect -f '{{{{join .RepoDigests \" \"}}}}' antar/{name}", check=False)
        if ref not in have.split():
            bad.append(name)
    if bad:
        raise RuntimeError(f"not the pinned digests: {', '.join(bad)} (run lab/images.sh pull / pull-media)")
    return f"{n} digests of lab/images.lock: gw, router, host, services, noise, media"


def topo():
    for n, (v4, v6) in nets.items():
        sh(f"docker network create --internal --ipv6 --subnet {v4}.0/24 "
           f"--subnet {v6}:/64 {pre}_{n}")
    run = "docker run -d --privileged --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0"
    sh(f"{run} --name {pre}_gw_a --network {pre}_a --ip 172.30.1.10 --ip6 fd00:30:1::10 antar/gw")
    sh(f"{run} --name {pre}_gw_b --network {pre}_b --ip 172.30.2.10 --ip6 fd00:30:2::10 antar/gw")
    sh(f"{run} --name {pre}_router --network {pre}_a --ip 172.30.1.254 --ip6 fd00:30:1::254 antar/router")
    sh(f"docker network connect --ip 172.30.2.254 --ip6 fd00:30:2::254 {pre}_b {pre}_router")
    time.sleep(1)
    dx(f"{pre}_gw_a", "ip route replace 172.30.2.0/24 via 172.30.1.254 && ip -6 route replace fd00:30:2::/64 via fd00:30:1::254")
    dx(f"{pre}_gw_b", "ip route replace 172.30.1.0/24 via 172.30.2.254 && ip -6 route replace fd00:30:1::/64 via fd00:30:2::254")
    dx(f"{pre}_gw_a", "ping -c2 -W2 172.30.2.10 && ping -6 -c2 -W2 fd00:30:2::10")
    return "privileged siblings up, v4+v6 routed through router"


def xfrm():
    g = f"{pre}_gw_a"
    dx(g, "ip xfrm state add src 1.1.1.1 dst 2.2.2.2 proto esp spi 0x100 mode tunnel "
          "aead 'rfc4106(gcm(aes))' 0x0102030405060708091011121314151617181920 128")
    dx(g, "ip xfrm state flush")
    return "ip xfrm state add/flush works in gateway"


def veth():
    dx(f"{pre}_router", "ip link add pfva type veth peer name pfvb && ip link del pfva")
    return "veth create/delete"


def v6fwd():
    _, out = dx(f"{pre}_router", "sysctl -n net.ipv6.conf.all.forwarding")
    if out.strip() != "1":
        raise RuntimeError(f"forwarding={out}")
    dx(f"{pre}_gw_a", "ping -6 -c1 -W2 fd00:30:2::10")
    return "router forwards ipv6"


def netem():
    r = f"{pre}_router"
    dx(r, "tc qdisc add dev eth0 root netem delay 60ms 20ms loss 1%")
    dx(r, "tc qdisc replace dev eth0 root netem delay 120ms 40ms loss 2% rate 5mbit")
    dx(r, "tc qdisc del dev eth0 root")
    return "delay/jitter/loss/rate"


def nflog():
    g = f"{pre}_gw_a"
    dx(g, "iptables -A OUTPUT -m policy --pol ipsec --dir out -j NFLOG --nflog-group 5")
    dx(g, "iptables -A INPUT -m policy --pol ipsec --dir in -j NFLOG --nflog-group 5")
    rc, out = dx(g, "timeout 2 tcpdump -i nflog:5 -c1 2>&1", check=False)
    if "link-type NFLOG" not in out:
        raise RuntimeError(out)
    return "NFLOG + policy match, tcpdump -i nflog:5"


def nft_raw():
    dx(f"{pre}_router", "nft add table inet pft && nft add chain inet pft c "
       "'{ type filter hook forward priority 0; }' && "
       "nft add rule inet pft c udp dport 500 @th,208,8 35 drop && nft delete table inet pft")
    return "raw payload match for ike exchange type"


def tunnel_conf(me, peer, fam):
    lo, re_ = (f"172.30.{me}.10", f"172.30.{peer}.10") if fam == "v4" else \
              (f"fd00:30:{me}::10", f"fd00:30:{peer}::10")
    conn = {"name": "pf", "ike_version": 2, "local_addr": lo, "remote_addr": re_,
            "ike_proposal": "aes256-sha256-ecp256", "ike_rekey_s": 14400,
            "dpd_delay_s": 0, "encap": False, "aggressive": False,
            "fragmentation": "yes", "auth": "psk",
            "local_id": f"gw{me}", "remote_id": f"gw{peer}",
            "children": [{"name": "t", "mode": "tunnel", "local_ts": "dynamic",
                          "remote_ts": "dynamic", "ah_proposals": None,
                          "esp_proposal": "aes128gcm16-ecp256", "child_rekey_s": 3600,
                          "replay_window": 32, "start_action": "none"}]}
    sec = [{"id1": "gw1", "id2": "gw2", "psk": "preflight-throwaway"}]
    return render("swanctl.conf.j2", conns=[conn], secrets=sec), re_


def charon(g, backend):
    put(g, "/etc/strongswan.conf", render("strongswan.conf.j2", backend=backend))
    dx(g, "pkill charon; rm -f /var/run/charon.*; true")
    dx(g, "/usr/lib/ipsec/charon >/dev/null 2>&1", detach=True)
    for _ in range(40):
        if dx(g, "test -S /var/run/charon.vici", check=False)[0] == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("charon did not open vici socket")


def strongswan(fam, backend="kernel"):
    a, b, r = f"{pre}_gw_a", f"{pre}_gw_b", f"{pre}_router"
    for g, me, peer in ((a, 1, 2), (b, 2, 1)):
        conf, _ = tunnel_conf(me, peer, fam)
        put(g, "/etc/swanctl/swanctl.conf", conf)
        charon(g, backend)
        dx(g, "swanctl --load-all --noprompt")
    dx(r, "rm -f /tmp/pf.pcap; tcpdump -i any -s 128 -w /tmp/pf.pcap esp or udp port 500 or udp port 4500 >/dev/null 2>&1", detach=True)
    time.sleep(1)
    dx(a, "swanctl --initiate --child t --timeout 20", timeout=40)
    peer = "172.30.2.10" if fam == "v4" else "fd00:30:2::10"
    dx(a, f"ping -c5 -i0.2 -W2 {peer}")
    time.sleep(0.5)
    dx(r, "pkill tcpdump; sleep 0.5; true")
    _, out = dx(r, "tcpdump -nr /tmp/pf.pcap 2>/dev/null")
    esp = len(re.findall(r"ESP\(spi", out))
    ike = len(re.findall(r"isakmp", out))
    if esp < 10:
        raise RuntimeError(f"only {esp} esp packets seen on router ({ike} ike)")
    dx(a, "swanctl --terminate --ike pf --timeout 10", check=False)
    return f"backend={backend}: {ike} ike + {esp} esp packets seen at router"


def algs():
    _, out = dx(f"{pre}_gw_a", "swanctl --list-algs")
    sec, got = None, {}
    for line in out.splitlines():
        if line and not line.startswith(" "):
            sec = line.strip().rstrip(":")
            got[sec] = []
        elif sec:
            got[sec] += [re.sub(r"\[.*", "", w) for w in line.split()]
    results["_algs"] = got
    return ", ".join(f"{k}:{len(v)}" for k, v in got.items())


def kernel_algs():
    """algorithms the kernel xfrm accepts, tested directly"""
    g, ok, bad = f"{pre}_gw_a", [], []
    k16 = "0x" + "11" * 16
    k32 = "0x" + "11" * 32
    tests = {
        "aes128gcm16": "aead 'rfc4106(gcm(aes))' 0x" + "11" * 20 + " 128",
        "aes256gcm16": "aead 'rfc4106(gcm(aes))' 0x" + "11" * 36 + " 128",
        "aes-cbc+sha256": f"enc 'cbc(aes)' {k16} auth-trunc 'hmac(sha256)' {k32} 128",
        "aes-cbc+sha1": f"enc 'cbc(aes)' {k16} auth-trunc 'hmac(sha1)' 0x{'11' * 20} 96",
        "aes-cbc+sha384": f"enc 'cbc(aes)' {k32} auth-trunc 'hmac(sha384)' 0x{'11' * 48} 192",
        "3des+sha1": f"enc 'cbc(des3_ede)' 0x{'11' * 24} auth-trunc 'hmac(sha1)' 0x{'11' * 20} 96",
        "3des+md5": f"enc 'cbc(des3_ede)' 0x{'11' * 24} auth-trunc 'hmac(md5)' {k16} 96",
        "null+sha256": f"enc 'ecb(cipher_null)' '' auth-trunc 'hmac(sha256)' {k32} 128",
        "chacha20poly1305": "aead 'rfc7539esp(chacha20,poly1305)' 0x" + "11" * 36 + " 128",
    }
    for i, (n, spec) in enumerate(tests.items()):
        rc, _ = dx(g, f"ip xfrm state add src 1.1.1.1 dst 2.2.2.{i + 2} proto esp spi {0x200 + i} {spec}", check=False)
        (ok if rc == 0 else bad).append(n)
    rc, _ = dx(g, f"ip xfrm state add src 1.1.1.1 dst 2.2.3.1 proto ah spi 0x300 auth-trunc 'hmac(sha256)' {k32} 128", check=False)
    (ok if rc == 0 else bad).append("ah-sha256")
    dx(g, "ip xfrm state flush")
    results["_kernel_algs"] = {"ok": ok, "unsupported": bad}
    return f"unsupported: {', '.join(bad) or 'none'}"


def env_section(env):
    r = env["checks"]
    lines = ["## Environment", "",
             f"Probed by `lab/preflight.py` on {env['date']}.", "",
             f"- host kernel: `{env['kernel']}`",
             f"- docker: `{env['docker']}`",
             f"- strongSwan: `{env['strongswan_version']}`",
             f"- ipsec backend: **{env['ipsec_backend']}**",
             f"- netem available: **{'yes' if env['netem'] else 'no - every run is `lan`; this is a dataset weakness'}**",
             f"- kernel xfrm algorithms not available: {', '.join(env['kernel_algs']['unsupported']) or 'none'}",
             "", "| check | result | detail |", "|---|---|---|"]
    for k, v in r.items():
        lines.append(f"| {k} | {'ok' if v['ok'] else 'FAIL'} | {v['detail']} |")
    return "\n".join(lines) + "\n"


def write_readme(section):
    p = root / "dataset" / "README.md"
    s = p.read_text() if p.exists() else "# Antardrishti IPsec dataset\n\n"
    a, b = "<!-- env:start -->", "<!-- env:end -->"
    block = f"{a}\n{section}{b}"
    s = re.sub(re.escape(a) + ".*?" + re.escape(b), block, s, flags=re.S) if a in s \
        else s.rstrip() + "\n\n" + block + "\n"
    p.write_text(s)


def main():
    cleanup()
    check("docker", lambda: sh("docker info --format '{{.ServerVersion}} {{.Driver}}'")[1])
    check("pinned images", pinned)
    check("bridge netfilter off", bridge_off)
    if not check("privileged sibling containers", topo):
        cleanup()
        sys.exit("cannot build the topology; nothing else can be probed")
    has_xfrm = check("kernel xfrm", xfrm)
    check("veth", veth)
    check("ipv6 forwarding", v6fwd)
    has_netem = check("netem", netem)
    check("nflog policy match", nflog)
    check("nft raw payload match", nft_raw)
    backend = "kernel" if has_xfrm else "libipsec"
    tun4 = check(f"strongswan tunnel v4 ({backend})", lambda: strongswan("v4", backend))
    if not tun4 and backend == "kernel":
        backend = "libipsec"
        tun4 = check("strongswan tunnel v4 (libipsec)", lambda: strongswan("v4", backend))
    check(f"strongswan tunnel v6 ({backend})", lambda: strongswan("v6", backend))
    check("swanctl --list-algs", algs)
    if has_xfrm:
        check("kernel xfrm algorithms", kernel_algs)
    _, ver = dx(f"{pre}_gw_a", "swanctl --version | head -1", check=False)
    algs_ = results.pop("_algs", {})
    kalgs = results.pop("_kernel_algs", {"ok": [], "unsupported": []})
    env = {"date": time.strftime("%Y-%m-%d"), "kernel": platform.release(),
           "docker": sh("docker version --format '{{.Server.Version}}'")[1],
           "strongswan_version": ver.strip(), "ipsec_backend": backend,
           "netem": has_netem, "kernel_algs": kalgs, "swanctl_algs": algs_,
           "checks": results}
    (root / "dataset" / "env.json").write_text(json.dumps(env, indent=2) + "\n")
    write_readme(env_section(env))
    cleanup()
    bad = [k for k, v in results.items() if not v["ok"]]
    print(f"\nbackend={backend} netem={has_netem} failed={bad or 'none'}")
    print("wrote dataset/env.json and dataset/README.md (environment)")
    sys.exit(1 if not tun4 else 0)


if __name__ == "__main__":
    main()
