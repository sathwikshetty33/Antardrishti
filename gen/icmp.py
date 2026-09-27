"""icmp: ping bursts with varied intervals (0.2-1 s) and payload sizes."""
import random
import subprocess
import time

from common import args, emit, launch, left, nap


def start(duration, seed, ctx, big=False):
    return launch(ctx, "icmp", duration, seed, "--big" if big else "")


def main():
    a = args({"--big": {"action": "store_true", "help": "sizes above path mtu (e25)"}})
    rng = random.Random(a.seed)
    six = "-6" if a.fam == "v6" else ""
    while left(a) > 1:
        n = rng.randint(5, 30)
        iv = round(rng.uniform(0.2, 1.0), 2)
        size = rng.choice([2000, 3000, 4500, 8000]) if a.big else \
            rng.choice([16, 56, 64, 120, 256, 512, 1000, 1200, 1400])
        n = max(1, min(n, int(left(a) / iv)))
        t = time.time()
        p = subprocess.run(f"ping {six} -q -c {n} -i {iv} -s {size} -W 2 {a.ip}",
                           shell=True, capture_output=True, text=True, timeout=n * iv + 30)
        got = p.stdout.strip().splitlines()[-2:] if p.stdout else []
        emit("icmp", "burst", t, count=n, interval=iv, size=size, summary=" | ".join(got))
        nap(a, rng.uniform(0, 3))


if __name__ == "__main__":
    main()
