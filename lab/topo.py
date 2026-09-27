"""lab topology control: up/down, wiring, routes, netem, pki, strongswan deploy.

several labs can run side by side on one machine (ANTAR_LAB=0,1,...). each lab
has its own containers (gateways, router, hosts, services, noise) and its own
switch network namespace. links are veth pairs into bridges in that namespace,
so every lab uses the same addresses and mac addresses (derived from the ip):
runs from different labs are indistinguishable on the wire. labs share only
images and read-only mounts (media, generators, external pcaps).
"""
import os
import time

from lab import bridge_off, dx, put, render, root, sh

lab_id = int(os.environ.get("ANTAR_LAB", "0"))
prefix = f"antar{lab_id}"
os.environ["ANTAR_PREFIX"] = prefix
# only gw_b's internet uplink (realism tier) is a docker network; it never
# crosses the router, so a per-lab subnet there is invisible in captures
os.environ["ANTAR_INET"] = f"192.168.{100 + lab_id}.0/24"
compose = f"docker compose -p {prefix} -f {root}/lab/compose.yaml"
swns = f"{prefix}sw"
c = {n: f"{prefix}_{n}" for n in ("gw_a", "gw_b", "router", "host_a", "host_b", "cli_gw",
                                  "svc_gw", "noise_a", "noise_b", "gw_c", "nat_n", "gw_d", "gw_e")}

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
# gateway cert kinds: bigchain is e22's (ca -> rsa 4096 intermediate -> rsa 4096 cert)
cert_keys = ("rsa", "ecdsa", "bigchain")


# lab links: segment -> [(container, interface, ipv4/prefix, ipv6/prefix or None)]
links = {
    "lan_a": [("host_a", "eth0", "10.1.0.10/24", "fd00:1::10/64"),
              ("gw_a", "lan0", "10.1.0.254/24", "fd00:1::254/64")],
    "wan_a": [("gw_a", "wan0", "172.31.1.10/24", "fd00:a::10/64"),
              ("router", "wan_a", "172.31.1.254/24", "fd00:a::254/64"),
              ("noise_a", "eth0", "172.31.1.20/24", "fd00:a::20/64")],
    "wan_b": [("router", "wan_b", "172.31.2.254/24", "fd00:b::254/64"),
              ("gw_b", "wan0", "172.31.2.10/24", "fd00:b::10/64"),
              ("noise_b", "eth0", "172.31.2.20/24", "fd00:b::20/64")],
    "lan_b": [("gw_b", "lan0", "10.2.0.254/24", "fd00:2::254/64"),
              ("host_b", "eth0", "10.2.0.10/24", "fd00:2::10/64")],
}
# e18 only (compose profile multi)
multi_links = {
    "wan_a": [("gw_c", "eth0", "172.31.1.30/24", None), ("nat_n", "wan0", "172.31.1.40/24", None)],
    "nat_lan": [("nat_n", "lan0", "172.31.5.254/24", None), ("gw_d", "eth0", "172.31.5.10/24", None),
                ("gw_e", "eth0", "172.31.5.11/24", None)],
}


def mac(ip4):
    """locally administered mac from the ipv4 address: the same in every lab"""
    return "02:00:" + ":".join(f"{int(x):02x}" for x in ip4.split("/")[0].split("."))


def pid(name):
    return sh(f"docker inspect -f '{{{{.State.Pid}}}}' {name}")[1].strip()


def wire(multi_only=False):
    """idempotent: bridges in this lab's switch namespace, one veth per member.
    containers restarted (or a restarted codespace) simply get new veths."""
    if sh(f"sudo ip netns exec {swns} true", check=False)[0]:
        # a restart can leave a stale /run/netns entry behind
        sh(f"sudo ip netns del {swns}", check=False)
        sh(f"sudo ip netns add {swns}")
        sh(f"sudo ip netns exec {swns} ip link set lo up")
    # bridges and their ports are pure l2 plumbing: no ipv6 on them, or they send
    # router solicitations (with random macs) into every lab segment
    sh(f"sudo ip netns exec {swns} sh -c 'sysctl -qw net.ipv6.conf.all.disable_ipv6=1 "
       f"net.ipv6.conf.default.disable_ipv6=1; for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do echo 1 > $f; done'")
    segs = multi_links if multi_only else links
    n = 0
    for seg, members in segs.items():
        br = f"br_{seg}"
        if sh(f"sudo ip netns exec {swns} ip link show {br}", check=False)[0]:
            sh(f"sudo ip netns exec {swns} ip link add {br} type bridge")
            sh(f"sudo ip netns exec {swns} ip link set {br} up")
        for cont, dev, a4, a6 in members:
            name = c[cont]
            if dx(name, f"ip link show {dev}", check=False)[0] == 0:
                continue
            n += 1
            inside, outside = f"a{lab_id}x{seg[:5]}{n}", f"b{lab_id}x{seg[:5]}{n}"
            sh(f"sudo ip link add {inside} type veth peer name {outside}")
            sh(f"sudo ip link set {outside} netns {swns}")
            sh(f"sudo ip netns exec {swns} ip link set {outside} master {br} up")
            sh(f"sudo ip link set {inside} netns {pid(name)}")
            cmds = [f"ip link set {inside} name {dev}", f"ip link set {dev} address {mac(a4)}",
                    f"ip addr add {a4} dev {dev}"]
            if a6:
                cmds.append(f"ip -6 addr add {a6} dev {dev} nodad")
            cmds.append(f"ip link set {dev} up")
            dx(name, " && ".join(cmds))
    return n


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
        wan_guard(c[f"gw_{s_}"], gw[s_]["v4"])


def wan_guard(g, wan_ip, v6=True):
    dev = iface(g, wan_ip)
    fams = (("iptables", "v4"), ("ip6tables", "v6")) if v6 else (("iptables", "v4"),)
    for ipt, fam in fams:
        dx(g, f"{ipt} -N wanguard 2>/dev/null; {ipt} -F wanguard")
        rules = ["-p esp -j RETURN", "-p ah -j RETURN",
                 "-p udp -m multiport --ports 500,4500 -j RETURN",
                 "-m policy --dir out --pol ipsec -j RETURN"]
        if fam == "v4":
            rules.append("-p icmp --icmp-type fragmentation-needed -j RETURN")
        else:
            rules += [f"-p ipv6-icmp --icmpv6-type {t} -j RETURN"
                      for t in ("packet-too-big", "133", "134", "135", "136")]
        rules.append("-j DROP")
        for r in rules:
            dx(g, f"{ipt} -A wanguard {r}")
        for ch in ("OUTPUT", "FORWARD"):
            dx(g, f"{ipt} -D {ch} -o {dev} -j wanguard 2>/dev/null; {ipt} -I {ch} -o {dev} -j wanguard")


def nat(on):
    """gw_b masquerades tunnelled lan_a traffic to the internet (realism tier).
    touches only its own rule: docker's embedded dns lives in the same nat table.
    a remote selector of 0.0.0.0/0 also covers gw_a's own lan_a, so while it is on
    gw_a keeps lan_a out of the tunnel, as strongswan's bypass-lan would: lan_a
    stays in main (the tunnel route in table 220 is looked up first and would send
    the replies to lan_a back onto the wan), and a bypass policy lets gw_a's own
    packets to lan_a (icmp frag-needed: path mtu discovery) reach it in clear"""
    _, dev = dx(c["gw_b"], "ip -o route show default | awk '{print $5}'")
    rule = f"POSTROUTING -s {lan['a']['v4']} -o {dev.split()[0]} -j MASQUERADE"
    dx(c["gw_b"], f"while iptables -t nat -D {rule} 2>/dev/null; do :; done")
    for f, ip in (("v4", "ip"), ("v6", "ip -6")):
        n = lan["a"][f]
        dx(c["gw_a"], f"while {ip} rule del to {n} lookup main priority 100 2>/dev/null; do :; done; "
                      f"ip xfrm policy delete src {n} dst {n} dir out 2>/dev/null; "
                      f"ip xfrm policy delete src {n} dst {n} dir in 2>/dev/null; true")
        if on:
            dx(c["gw_a"], f"{ip} rule add to {n} lookup main priority 100 && "
                          f"ip xfrm policy update src {n} dst {n} dir out priority 100 && "
                          f"ip xfrm policy update src {n} dst {n} dir in priority 100")
    if on:
        dx(c["gw_b"], f"iptables -t nat -A {rule}")


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


def no_dns(names):
    """the lab has no dns: lookups must fail at once. docker leaves the host's
    resolver in /etc/resolv.conf, unreachable from an isolated lab, so every lookup
    (sip, smtp reverse lookups, ...) would hang until it times out"""
    for n in names:
        dx(c[n], "printf 'nameserver 127.0.0.1\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf", check=False)


def inet_dns(on):
    """realism tier: host_a resolves through the tunnel and gw_b's nat with this
    machine's upstream resolvers (codespaces drop queries to public resolvers such
    as 1.1.1.1; the azure resolver answers). every other run keeps the lab without
    dns (no_dns). returns the resolvers in use"""
    if not on:
        no_dns(["host_a"])
        return []
    ns = [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")
          and not l.split()[1].startswith("127.")] or ["1.1.1.1", "8.8.8.8"]
    txt = "".join(f"nameserver {n}\\n" for n in ns)
    dx(c["host_a"], f"printf '{txt}options timeout:2 attempts:2\\n' > /etc/resolv.conf")
    return ns


def up(build=False):
    bridge_off()
    sh(f"{compose} up -d {'--build' if build else ''} --remove-orphans", timeout=1800)
    time.sleep(1)
    wire()
    no_dns([n for n in ("gw_a", "gw_b", "router", "host_a", "host_b", "cli_gw", "svc_gw", "noise_a", "noise_b")])
    routes()
    guard()
    ensure_keys()
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
    for n in ("host_a", "cli_gw"):
        dx(c[n], "mkdir -p /root/.ssh && chmod 700 /root/.ssh")
        put(c[n], "/root/.ssh/id_lab", k.read_text())
        dx(c[n], "chmod 600 /root/.ssh/id_lab")
    for n in ("host_b", "svc_gw"):
        put(c[n], "/home/lab/.ssh/authorized_keys", (pki / "ssh_lab.pub").read_text())
        dx(c[n], "chown -R lab /home/lab/.ssh && chmod 600 /home/lab/.ssh/authorized_keys")


def down():
    sh(f"{compose} --profile multi down --remove-orphans -t 2", check=False, timeout=300)
    sh(f"sudo ip netns del {swns}", check=False)


def pki_ok():
    """every gateway cert must chain to the ca on disk"""
    if not (pki / "ca.pem").exists() or not (pki / "int.pem").exists():
        return False
    for g in ("gw_a", "gw_b"):
        for k in cert_keys:
            f = pki / f"{g}-{k}.pem"
            if not f.exists() or sh(f"openssl verify -CAfile {pki}/ca.pem -untrusted {pki}/int.pem {f}", check=False)[0]:
                return False
    return (pki / "ssh_lab").exists() and (pki / "ssh_lab.pub").exists()


def ensure_keys():
    """throwaway lab pki + ssh key, generated once per checkout under a lock.
    parallel lab workers must never generate them concurrently: interleaved
    writes leave certs that do not chain to the ca (authentication failures)"""
    import fcntl
    pki.mkdir(exist_ok=True)
    with open(pki / ".lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        if not pki_ok():
            for f in pki.glob("*"):
                if f.name != ".lock":
                    f.unlink()
            ensure_pki()
            sh(f"ssh-keygen -q -t ed25519 -N '' -C antardrishti-lab -f {pki / 'ssh_lab'}")
            if not pki_ok():
                raise RuntimeError("lab pki does not verify after regeneration")
        fcntl.flock(lk, fcntl.LOCK_UN)


def ensure_pki():
    """throwaway lab ca + rsa and ecdsa certs per gateway, and e22's big chain: an rsa
    4096 cert under an rsa 4096 intermediate, so ike_auth cannot fit one packet;
    never reuse elsewhere"""
    if (pki / "ca.pem").exists():
        return
    pki.mkdir(exist_ok=True)
    g = c["gw_a"]
    cmds = ["cd /tmp && rm -rf pki && mkdir pki && cd pki",
            "pki --gen --type rsa --size 3072 --outform pem > ca.key",
            "pki --self --ca --lifetime 3650 --in ca.key --dn 'CN=antardrishti lab ca' --outform pem > ca.pem",
            "pki --gen --type rsa --size 4096 --outform pem > int.key",
            "pki --pub --in int.key | pki --issue --ca --lifetime 3650 --cacert ca.pem --cakey ca.key "
            "--dn 'CN=antardrishti lab intermediate ca' --outform pem > int.pem"]
    for gname, fq in (("gw_a", "gw-a.lab"), ("gw_b", "gw-b.lab")):
        for k, opt, ca in (("rsa", "--type rsa --size 2048", "ca"), ("ecdsa", "--type ecdsa --size 256", "ca"),
                           ("bigchain", "--type rsa --size 4096", "int")):
            cmds += [f"pki --gen {opt} --outform pem > {gname}-{k}.key",
                     f"pki --pub --in {gname}-{k}.key | pki --issue --lifetime 3650 --cacert {ca}.pem "
                     f"--cakey {ca}.key --dn 'CN={fq}' --san {fq} --outform pem > {gname}-{k}.pem"]
    dx(g, " && ".join(cmds), timeout=600)
    for f in ["ca.pem", "ca.key", "int.pem", "int.key"] + [f"{a}-{k}.{e}" for a in ("gw_a", "gw_b")
                                                          for k in cert_keys for e in ("pem", "key")]:
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
    conn.update({k: v for k, v in over.get("conn", {}).items() if k != "proposals"})
    if "proposals" in over.get("conn", {}):
        conn["ike_proposal"] = over["conn"]["proposals"]
    for i, ch in enumerate(over.get("children", [])):
        if i < len(conn["children"]):
            conn["children"][i] = {**conn["children"][i], **ch}
        else:
            conn["children"].append({**child, **ch})
    key = over.get("psk", psk) if isinstance(over.get("psk"), str) else psk
    secrets = [{"id1": "gw-a.lab", "id2": "gw-b.lab", "psk": key}] if auth == "psk" else []
    conns = [conn]
    for x in over.get("extra_conns", []):
        conns.append(x)
        secrets.append({"id1": x["local_id"], "id2": x["remote_id"], "psk": psk})
    return {"conns": conns, "secrets": secrets}


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


def big_chain(on):
    """e22's credentials (the big chain) sit on the gateways only during e22 runs: a
    loaded intermediate ca would add its hash to the certificate requests, and so
    change the ike sizes, of every other run"""
    for g in ("gw_a", "gw_b"):
        files = {"/etc/swanctl/x509ca/int.pem": "int.pem", f"/etc/swanctl/x509/{g}-bigchain.pem": f"{g}-bigchain.pem",
                 f"/etc/swanctl/private/{g}-bigchain.key": f"{g}-bigchain.key"}
        if on:
            for dst, src in files.items():
                put(c[g], dst, (pki / src).read_text())
        else:
            dx(c[g], "rm -f " + " ".join(files), check=False)


def deploy(cfg, over=None, backend="kernel"):
    """render + load swanctl on both gateways. over = {"a": {...}, "b": {...}}
    with per-side conn / children / psk / charon / extra_conns overrides.
    returns rendered confs {a, b}"""
    over = over or {}
    out = {}
    big_chain(cfg.get("cert_key") == "bigchain")
    for s in "ab":
        g = c[f"gw_{s}"]
        o = over.get(s, {})
        sconf = render("strongswan.conf.j2", backend=backend, **o.get("charon", {}))
        swan = render("swanctl.conf.j2", **conn_ctx(cfg, s, o))
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
    return {"cli": cli, "srv": srv, "ip": ip, "fam": f, "mode": cfg["mode"], "internet": bool(cfg.get("internet")),
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


# e18: extra initiators toward gw_b. gw_c is direct, gw_d / gw_e sit behind nat_n
multi = {"gw_c": {"ip": "172.31.1.30", "via": "172.31.1.254", "encap": False},
         "gw_d": {"ip": "172.31.5.10", "via": "172.31.5.254", "encap": True},
         "gw_e": {"ip": "172.31.5.11", "via": "172.31.5.254", "encap": True}}


def multi_conn(name, side):
    """conn dict for an extra initiator (side 'i') or its responder twin on gw_b ('r')"""
    x = name[-1]
    child = {"name": "t", "mode": "tunnel", "local_ts": "dynamic", "remote_ts": "dynamic",
             "ah_proposals": None, "esp_proposal": "aes128gcm16-ecp256", "child_rekey_s": 3600,
             "replay_window": 32, "start_action": "none"}
    base_ = {"ike_version": 2, "ike_proposal": "aes256-sha256-ecp256", "ike_rekey_s": 14400,
             "dpd_delay_s": 0, "aggressive": False, "fragmentation": "yes", "auth": "psk",
             "local_cert": "", "children": [child]}
    if side == "i":
        return {**base_, "name": "lab", "local_addr": multi[name]["ip"], "remote_addr": gw["b"]["v4"],
                "encap": multi[name]["encap"], "local_id": f"gw-{x}.lab", "remote_id": "gw-b.lab"}
    # behind nat the initiator proposes its private address; on the responder
    # "dynamic" would mean the nat's public one (ts unacceptable), so accept the lan
    rchild = {**child, "remote_ts": "172.31.5.0/24"} if multi[name]["encap"] else child
    return {**base_, "name": f"peer_{x}", "local_addr": gw["b"]["v4"], "remote_addr": "%any",
            "encap": multi[name]["encap"], "local_id": "gw-b.lab", "remote_id": f"gw-{x}.lab",
            "children": [rchild]}


def multi_up():
    sh(f"{compose} --profile multi up -d gw_c nat_n gw_d gw_e", timeout=600)
    time.sleep(1)
    wire(multi_only=True)
    no_dns(["gw_c", "nat_n", "gw_d", "gw_e"])
    n = c["nat_n"]
    dx(n, "ip route replace 172.31.2.0/24 via 172.31.1.254")
    _, dev = dx(n, "ip -o addr show | awk '$4 ~ /^172.31.1.40\\// {print $2}'")
    dx(n, f"iptables -t nat -F POSTROUTING; iptables -t nat -A POSTROUTING -s 172.31.5.0/24 -o {dev.split()[0]} -j MASQUERADE")
    for g, m in multi.items():
        dx(c[g], f"ip route replace 172.31.2.0/24 via {m['via']}")
    route(c["gw_b"], "172.31.5.0/24", rtr["b"]["v4"])
    return [f"gw-{g[-1]}.lab" for g in multi]


def multi_start(duration=50):
    """charon + conn on every extra initiator, initiate all, then ping gw_b through
    each tunnel for duration seconds. returns {name: initiate rc}"""
    res = {}
    for g in multi:
        name = c[g]
        swan = render("swanctl.conf.j2", conns=[multi_conn(g, "i")],
                      secrets=[{"id1": f"gw-{g[-1]}.lab", "id2": "gw-b.lab", "psk": psk}])
        put(name, "/etc/swanctl/swanctl.conf", swan)
        charon_start(name, render("strongswan.conf.j2", backend="kernel"))
        dx(name, "swanctl --load-all --noprompt")
    for g in multi:
        name = c[g]
        wan_guard(name, multi[g]["ip"], v6=False)
        res[g] = dx(name, "swanctl --initiate --child t --timeout 20", check=False, timeout=40)[0]
        # light traffic per tunnel, so each one shows esp for tunnel grouping
        dx(name, f"ping -q -i 0.5 -w {duration} {gw['b']['v4']} >/dev/null 2>&1", detach=True)
    return res


def multi_down():
    sh(f"{compose} --profile multi rm -sf gw_c nat_n gw_d gw_e", check=False, timeout=300)
    # their bridge ports died with the containers; nothing else to clean


def versions():
    """what actually ran: images are rebuilt after every codespace restart, so
    package versions can drift within a dataset. recorded in every run's meta"""
    q = {"strongswan": (c["gw_a"], "/usr/lib/ipsec/charon --version 2>&1 | grep -m1 -i strongswan"),
         "kernel_ipsec": (c["gw_a"], "uname -r"),
         "nginx": (c["host_b"], "nginx -v 2>&1"),
         "asterisk": (c["host_b"], "asterisk -V"),
         "postfix": (c["host_b"], "postconf -h mail_version"),
         "dovecot": (c["host_b"], "dovecot --version"),
         "prosody": (c["host_b"], "prosodyctl about 2>/dev/null | grep -m1 -i '^prosody'"),
         "chrome": (c["host_a"], "google-chrome --version"),
         "baresip": (c["host_a"], "baresip -h 2>&1 | head -1"),
         "tcpdump": (c["router"], "tcpdump --version 2>&1 | head -1")}
    out = {k: dx(n, cmd, check=False)[1].strip()[:80] for k, (n, cmd) in q.items()}
    for n in ("gw_a", "router", "host_a", "host_b", "noise_a"):
        out[f"image_{n}"] = sh(f"docker inspect -f '{{{{.Image}}}}' {c[n]}", check=False)[1][:19]
    # registry digests when the images came from ghcr (lab/images.sh pull); empty for local builds
    for img in ("gw", "router", "host", "services", "noise"):
        _, d = sh(f"docker image inspect -f '{{{{join .RepoDigests \" \"}}}}' antar/{img}", check=False)
        reg = [x for x in d.split() if x.startswith("ghcr.io/")]
        out[f"digest_{img}"] = reg[0] if reg else ""
    # the media snapshot served by the labs (lab/images.sh pull-media); empty for a local crawl
    mark = root / "lab" / "media" / ".digest"
    out["digest_media"] = mark.read_text().strip() if mark.exists() else ""
    return out
