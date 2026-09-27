"""noise_a: random dns / ntp / http / icmp toward noise_b until killed.

usage: noise.py <seed> [v4|v6|both]
"""
import random
import subprocess
import sys
import time

seed = int(sys.argv[1]) if len(sys.argv) > 1 else 0
fam = sys.argv[2] if len(sys.argv) > 2 else "both"
rng = random.Random(seed)
srv = {"v4": "172.31.2.20", "v6": "fd00:b::20"}


def run(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


while True:
    ip = srv[rng.choice(["v4", "v6"]) if fam == "both" else fam]
    host = ip if ":" not in ip else f"[{ip}]"
    kind = rng.choices(["dns", "ntp", "http", "icmp"], [5, 1, 3, 2])[0]
    if kind == "dns":
        run(f"dig +time=2 +tries=1 @{ip} h{rng.randint(1, 40)}.lab.test {rng.choice(['A', 'AAAA'])}")
    elif kind == "ntp":
        run(f"ntpdate -q {ip}")
    elif kind == "http":
        run(f"curl -s -m 10 -o /dev/null http://{host}/p{rng.randint(1, 20)}.txt")
    else:
        run(f"ping -c {rng.randint(1, 5)} -s {rng.choice([56, 120, 500, 1000])} -i 0.3 {ip}")
    time.sleep(rng.expovariate(1 / 1.5))
