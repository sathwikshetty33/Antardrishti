"""lab topology control: up/down, routes, netem, pki, strongswan deploy.

addresses mirror lab/compose.yaml. the orchestrator imports this module.
"""
import time

from lab import bridge_off, dx, put, render, root, sh

compose = f"docker compose -f {root}/lab/compose.yaml"
c = {n: f"antar_{n}" for n in ("gw_a", "gw_b", "router", "host_a", "host_b",
                               "cli_gw", "svc_gw", "noise_a", "noise_b")}

lan = {"a": {"v4": "10.1.0.0/24", "v6": "fd00:1::/64"},
       "b": {"v4": "10.2.0.0/24", "v6": "fd00:2::/64"}}
wan = {"a": {"v4": "172.31.1.0/24", "v6": "fd00:a::/64"},
       "b": {"v4": "172.31.2.0/24", "v6": "fd00:b::/64"}}
gw = {"a": {"v4": "172.31.1.10", "v6": "fd00:a::10"},
      "b": {"v4": "172.31.2.10", "v6": "fd00:b::10"}}
gw_lan = {"a": {"v4": "10.1.0.254", "v6": "fd00:1::254"},
          "b": {"v4": "10.2.0.254", "v6": "fd00:2::254"}}
rtr = {"a": {"v4": "172.31.1.254", "v6": "fd00:a::254"},
       "b": {"v4": "172.31.2.254", "v6": "fd00:b::254"}}
host = {"a": {"v4": "10.1.0.10", "v6": "fd00:1::10"},
        "b": {"v4": "10.2.0.10", "v6": "fd00:2::10"}}
anyn = {"v4": "0.0.0.0/0", "v6": "::/0"}
psk = "antardrishti-lab-throwaway-psk"
pki = root / "lab" / "pki"


def route(name, net, via):
    v6 = "-6" if ":" in via else ""
    dx(name, f"ip {v6} route replace {net} via {via}")


def routes():
    for f in ("v4", "v6"):
        for s in "ab":
            route(c[f"host_{s}"], "default", gw_lan[s][f])
        route(c["gw_a"], wan["b"][f], rtr["a"][f])
        route(c["gw_b"], wan["a"][f], rtr["b"][f])
        route(c["noise_a"], wan["b"][f], rtr["a"][f])
        route(c["noise_b"], wan["a"][f], rtr["b"][f])
        # inner subnets are routed toward the peer; only xfrm policy lets them
        # out, and the router guard drops any plaintext that escapes
        route(c["gw_a"], lan["b"][f], rtr["a"][f])
        route(c["gw_b"], lan["a"][f], rtr["b"][f])


def guard():
    """gateways never send plaintext onto the wan: only esp/ah, ike, nd/pmtu icmp
    and ipsec-protected packets leave. a tunnel that is down (or never came up,
    as in the failure edge cases) must not leak inner traffic into outer captures.
    the router has no inner routes either, but tcpdump there sees ingress first."""
    for s_ in "ab":
        g = c[f"gw_{s_}"]
        dev = iface(g, gw[s_]["v4"])
        for ipt, icmp in (("iptables", "-p icmp --icmp-type fragmentation-needed"),
                          ("ip6tables", "")):
            dx(g, f"{ipt} -N wanguard 2>/dev/null; {ipt} -F wanguard")
            rules = ["-p esp -j RETURN", "-p ah -j RETURN",
                     "-p udp -m multiport --ports 500,4500 -j RETURN",
                     "-m policy --dir out --pol ipsec -j RETURN"]
            if ipt == "iptables":
                rules.append(f"{icmp} -j RETURN")
            else:
                rules += [f"-p ipv6-icmp --icmpv6-type {t} -j RETURN"
                          for t in ("packet-too-big", "133", "134", "135", "136")]
            rules.append("-j DROP")
            for r in rules:
                dx(g, f"{ipt} -A wanguard {r}")
            for ch in ("OUTPUT", "FORWARD"):
                dx(g, f"{ipt} -D {ch} -o {dev} -j wanguard 2>/dev/null; {ipt} -I {ch} -o {dev} -j wanguard")


def nat(on):
    """gw_b masquerades tunnelled lan_a traffic to the internet (realism tier)"""
    dx(c["gw_b"], "iptables -t nat -F POSTROUTING")
    if on:
        _, dev = dx(c["gw_b"], "ip -o route show default | awk '{print $5}'")
        dx(c["gw_b"], f"iptables -t nat -A POSTROUTING -s {lan['a']['v4']} -o {dev.split()[0]} -j MASQUERADE")


def iface(name, ip):
    _, out = dx(name, f"ip -o addr show | awk '$4 ~ /^{ip}\\// {{print $2}}'")
    return out.split()[0]


def rtr_ifaces():
    return [iface(c["router"], rtr[s]["v4"]) for s in "ab"]


def netem(prof):
    """prof: dict from capture/netem.yaml, or None for lan. applied on both router egresses"""
    for dev in rtr_ifaces():
        dx(c["router"], f"tc qdisc del dev {dev} root 2>/dev/null; true")
        if prof and prof.get("args"):
            dx(c["router"], f"tc qdisc add dev {dev} root netem {prof['args']}")


def up(build=False):
    bridge_off()
    sh(f"{compose} up -d {'--build' if build else ''} --remove-orphans", timeout=1800)
    time.sleep(1)
    routes()
    guard()
    ensure_pki()
    for g in ("gw_a", "gw_b"):
        for d in ("x509", "x509ca", "private"):
            dx(c[g], f"mkdir -p /etc/swanctl/{d}")
        put(c[g], "/etc/swanctl/x509ca/ca.pem", (pki / "ca.pem").read_text())
        for k in ("rsa", "ecdsa"):
            put(c[g], f"/etc/swanctl/x509/{g}-{k}.pem", (pki / f"{g}-{k}.pem").read_text())
            put(c[g], f"/etc/swanctl/private/{g}-{k}.key", (pki / f"{g}-{k}.key").read_text())
    ssh_keys()
    for n in ("host_b", "svc_gw"):
        for _ in range(120):
            if dx(c[n], "test -f /tmp/ready", check=False)[0] == 0:
                break
            rc, why = dx(c[n], "cat /tmp/failed", check=False)
            if rc == 0:
                raise RuntimeError(f"services on {n}: {why}")
            time.sleep(1)
        else:
            raise RuntimeError(f"services on {n} not ready")
    return "lab up"


def ssh_keys():
    """throwaway key for scp/rsync bulk transfers: clients -> user lab on servers"""
    k = pki / "ssh_lab"
    if not k.exists():
        sh(f"ssh-keygen -q -t ed25519 -N '' -C antardrishti-lab -f {k}")
    for n in ("host_a", "cli_gw"):
        dx(c[n], "mkdir -p /root/.ssh && chmod 700 /root/.ssh")
        put(c[n], "/root/.ssh/id_lab", k.read_text())
        dx(c[n], "chmod 600 /root/.ssh/id_lab")
    for n in ("host_b", "svc_gw"):
        put(c[n], "/home/lab/.ssh/authorized_keys", (pki / "ssh_lab.pub").read_text())
        dx(c[n], "chown -R lab /home/lab/.ssh && chmod 600 /home/lab/.ssh/authorized_keys")


def down():
    sh(f"{compose} down --remove-orphans -t 2", check=False, timeout=300)


def ensure_pki():
    """throwaway lab ca + rsa and ecdsa certs per gateway; never reuse elsewhere"""
    if (pki / "ca.pem").exists():
        return
    pki.mkdir(exist_ok=True)
    g = c["gw_a"]
    cmds = ["cd /tmp && rm -rf pki && mkdir pki && cd pki",
            "pki --gen --type rsa --size 3072 --outform pem > ca.key",
            "pki --self --ca --lifetime 3650 --in ca.key --dn 'CN=antardrishti lab ca' --outform pem > ca.pem"]
    for gname, fq in (("gw_a", "gw-a.lab"), ("gw_b", "gw-b.lab")):
        for k, opt in (("rsa", "--type rsa --size 2048"), ("ecdsa", "--type ecdsa --size 256")):
            cmds += [f"pki --gen {opt} --outform pem > {gname}-{k}.key",
                     f"pki --pub --in {gname}-{k}.key | pki --issue --lifetime 3650 --cacert ca.pem "
                     f"--cakey ca.key --dn 'CN={fq}' --san {fq} --outform pem > {gname}-{k}.pem"]
    dx(g, " && ".join(cmds), timeout=120)
    for f in ["ca.pem", "ca.key"] + [f"{a}-{k}.{e}" for a in ("gw_a", "gw_b")
                                      for k in ("rsa", "ecdsa") for e in ("pem", "key")]:
        _, txt = dx(g, f"cat /tmp/pki/{f}")
        (pki / f).write_text(txt + "\n")


def conn_ctx(cfg, side, over=None):
    """template context for one gateway. side 'a' initiates, 'b' responds."""
    over = over or {}
    me, peer = side, "b" if side == "a" else "a"
    of, inf = cfg["outer_family"], cfg["inner_family"]
    tunnel = cfg["mode"] == "tunnel"
    if tunnel and cfg.get("internet"):
        lts = lan["a"][inf] if me == "a" else anyn[inf]
        rts = anyn[inf] if me == "a" else lan["a"][inf]
    elif tunnel:
        lts, rts = lan[me][inf], lan[peer][inf]
    else:
        lts = rts = "dynamic"
    # responder rekeys later so the initiator drives rekeys deterministically
    k = 1.0 if me == "a" else 1.3
    child = {"name": "t", "mode": cfg["mode"], "local_ts": lts, "remote_ts": rts,
             "ah_proposals": cfg.get("ah_proposal"),
             "esp_proposal": cfg["esp_proposal"], "child_rekey_s": int(cfg["child_rekey_s"] * k),
             "replay_window": cfg["replay_window"], "start_action": "none"}
    auth = cfg["auth"]
    kt = cfg.get("cert_key", "rsa")
    conn = {"name": "lab", "ike_version": cfg["ike_version"],
            "local_addr": gw[me][of], "remote_addr": gw[peer][of],
            "ike_proposal": cfg["ike_proposal"], "ike_rekey_s": int(cfg["ike_rekey_s"] * k),
            "dpd_delay_s": cfg["dpd_delay_s"], "encap": cfg["encap"],
            "aggressive": cfg["aggressive"], "fragmentation": cfg["fragmentation"],
            "auth": "psk" if auth == "psk" else "cert",
            "local_cert": f"gw_{me}-{kt}.pem",
            "local_id": f"gw-{me}.lab", "remote_id": f"gw-{peer}.lab",
            "children": [child]}
    conn.update(over.get("conn", {}))
    for i, ch in enumerate(over.get("children", [])):
        if i < len(conn["children"]):
            conn["children"][i] = {**conn["children"][i], **ch}
        else:
            conn["children"].append({**child, **ch})
    key = over.get("psk", {}).get(me, psk)
    secrets = [{"id1": "gw-a.lab", "id2": "gw-b.lab", "psk": key}] if auth == "psk" else []
    return {"conns": [conn], "secrets": secrets}


def charon_start(name, sconf):
    put(name, "/etc/strongswan.conf", sconf)
    dx(name, "pkill -x charon; sleep 0.3; pkill -9 -x charon; rm -f /var/run/charon.*; true")
    dx(name, "ip xfrm state flush; ip xfrm policy flush; : > /var/log/charon.log")
    dx(name, "/usr/lib/ipsec/charon >/dev/null 2>&1", detach=True)
    for _ in range(60):
        if dx(name, "test -S /var/run/charon.vici", check=False)[0] == 0:
            return
        time.sleep(0.25)
    raise RuntimeError(f"charon on {name} did not start")


def deploy(cfg, over=None, backend="kernel"):
    """render + load swanctl on both gateways. returns rendered confs {a, b}"""
    over = over or {}
    out = {}
    for s in "ab":
        g = c[f"gw_{s}"]
        sconf = render("strongswan.conf.j2", backend=backend, **over.get("charon", {}).get(s, {}))
        swan = render("swanctl.conf.j2", **conn_ctx(cfg, s, over))
        put(g, "/etc/swanctl/swanctl.conf", swan)
        charon_start(g, sconf)
        dx(g, "swanctl --load-all --noprompt")
        out[s] = swan
    return out


def initiate(timeout=20, check=True):
    return dx(c["gw_a"], f"swanctl --initiate --child t --timeout {timeout}",
              check=check, timeout=timeout + 15)


def stop_ipsec():
    for s in "ab":
        dx(c[f"gw_{s}"], "pkill -x charon; sleep 0.3; ip xfrm state flush; ip xfrm policy flush; true", check=False)


def nflog(on, group=7, size=96):
    """transport-mode inner capture on gw_a: plaintext of ipsec-protected packets
    in both directions. tcpdump must read nflog:<group> with -s 0; truncation is
    done by --nflog-size so the nflog tlvs stay intact, and threshold 1 delivers
    each packet at once (the kernel default batches up to 1 s, ruining timing)."""
    g = c["gw_a"]
    for ipt in ("iptables", "ip6tables"):
        _, old = dx(g, f"{ipt} -S | grep -- '--nflog-group {group}' || true")
        for r in old.splitlines():
            dx(g, f"{ipt} {r.replace('-A ', '-D ', 1)}")
        for ch, d in (("OUTPUT", "out"), ("INPUT", "in")):
            if on:
                dx(g, f"{ipt} -A {ch} -m policy --pol ipsec --dir {d} -j NFLOG --nflog-group {group} "
                      f"--nflog-size {size} --nflog-threshold 1")


def gen_ctx(cfg, run_dir=None):
    """what a generator needs to know about where it runs"""
    cli, srv, ip = endpoints(cfg)
    f = cfg["inner_family"]
    return {"cli": cli, "srv": srv, "ip": ip, "fam": f, "mode": cfg["mode"],
            "a_ip": host["a"][f] if cfg["mode"] == "tunnel" else gw["a"][f],
            "gw_a": c["gw_a"], "gw_b": c["gw_b"],
            "gw_a_lan": iface(c["gw_a"], gw_lan["a"]["v4"]),
            "gw_b_lan": iface(c["gw_b"], gw_lan["b"]["v4"]),
            "run_dir": str(run_dir) if run_dir else None}


def endpoints(cfg):
    """(client container, server container, server ip) for a config"""
    if cfg["mode"] == "transport":
        return c["cli_gw"], c["svc_gw"], gw["b"][cfg["outer_family"]]
    return c["host_a"], c["host_b"], host["b"][cfg["inner_family"]]
