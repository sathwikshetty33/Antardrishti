"""replay of real captures (whatsapp from the test phone, public non-vpn pcaps).

host side only. per pcap: split by direction around the client address,
rewrite ips (client -> host_a, every server -> host_b) and macs with
tcprewrite, then replay client->server from host_a and server->client from
host_b at the same moment with tcpreplay, preserving timing.

replayed packets hit no real sockets, so both hosts drop inbound traffic
from each other during the replay (no rst / icmp unreachable pollution).
tunnel mode only: tcpreplay injects raw frames, which bypass xfrm.
runs are always marked replayed: true.
"""
import random
import subprocess
import time
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent.parent


def sh(cmd, timeout=600):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{cmd}: {p.stderr[-400:]}")
    return p.stdout


def private(ip):
    return ip.startswith(("10.", "192.168.")) or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)


def client_ip(pcap):
    """the capturing device: most frequent private source address"""
    out = sh(f"tshark -r '{pcap}' -T fields -e ip.src -e ip.dst")
    c = Counter(x for line in out.splitlines() for x in line.split("\t") if x and private(x))
    if not c:
        raise RuntimeError(f"no private client address in {pcap}")
    return c.most_common(1)[0][0]


def mac(container, dev="eth0"):
    return subprocess.run(f"docker exec {container} cat /sys/class/net/{dev}/address", shell=True,
                          capture_output=True, text=True).stdout.strip()


def prepare(pcap, work, cli, a_mac, gw_a_mac, b_mac, gw_b_mac, a_ip, b_ip):
    work.mkdir(parents=True, exist_ok=True)
    for d, flt, smac, dmac in (("c2s", f"ip.src=={cli}", a_mac, gw_a_mac),
                               ("s2c", f"ip.dst=={cli}", b_mac, gw_b_mac)):
        sh(f"tshark -r '{pcap}' -Y '{flt}' -F pcap -w {work}/{d}.raw.pcap")
        # raw-ip captures (pcapdroid) get an ethernet header; then map addresses
        sh(f"tcprewrite --dlt=enet --enet-smac={smac} --enet-dmac={dmac} "
           f"--pnat={cli}/32:{a_ip}/32,0.0.0.0/0:{b_ip}/32 --fixcsum --mtu-trunc "
           f"-i {work}/{d}.raw.pcap -o {work}/{d}.pcap")
    return work / "c2s.pcap", work / "s2c.pcap"


def start(duration, seed, ctx, source="whatsapp"):
    """ctx needs cli/srv containers, gw containers, host ips and run_dir"""
    files = sorted(p for p in (root / "dataset" / "external" / source).glob("*")
                   if p.suffix in (".pcap", ".pcapng"))
    if not files:
        return [{"app": source, "event": "skipped", "start": time.time(), "stop": time.time(),
                 "reason": f"no pcaps in dataset/external/{source}"}]
    rng = random.Random(seed)
    pcap = rng.choice(files)
    cli = client_ip(pcap)
    work = Path(ctx["run_dir"]) / "replay"
    c2s, s2c = prepare(pcap, work, cli, mac(ctx["cli"]), mac(ctx["gw_a"], ctx["gw_a_lan"]),
                       mac(ctx["srv"]), mac(ctx["gw_b"], ctx["gw_b_lan"]), ctx["a_ip"], ctx["ip"])
    for c, f in ((ctx["cli"], c2s), (ctx["srv"], s2c)):
        sh(f"docker cp {f} {c}:/tmp/{f.name}")
    for c, peer in ((ctx["cli"], ctx["ip"]), (ctx["srv"], ctx["a_ip"])):
        sh(f"docker exec {c} iptables -I INPUT -s {peer} -j DROP")
    at = time.time() + 3
    procs = []
    for c, f in ((ctx["cli"], c2s), (ctx["srv"], s2c)):
        cmd = (f"docker exec {c} sh -c 'sleep $(python3 -c \"import time;print(max(0,{at}-time.time()))\"); "
               f"timeout {int(duration)} tcpreplay -q -i eth0 /tmp/{f.name}'")
        procs.append(subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    outs = [p.communicate(timeout=duration + 60) for p in procs]
    for c, peer in ((ctx["cli"], ctx["ip"]), (ctx["srv"], ctx["a_ip"])):
        sh(f"docker exec {c} iptables -D INPUT -s {peer} -j DROP")
    return [{"app": source, "event": "replay", "start": at, "stop": time.time(), "pcap": pcap.name,
             "client_ip": cli, "replayed": True, "rc": [p.returncode for p in procs],
             "tcpreplay": [o[0][-300:] + o[1][-300:] for o in outs]}]
