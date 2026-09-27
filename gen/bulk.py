"""bulk: scp / rsync / curl transfers of 10-200 MB incompressible files.

about 40% of runs are rate-limited (seeded). some transfers are uploads.
"""
import os
import random
import subprocess
import time

from common import args, emit, launch, left, nap

sizes = [10, 25, 50, 100, 200]
ssh = "ssh -i /root/.ssh/id_lab -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"


def start(duration, seed, ctx):
    return launch(ctx, "bulk", duration, seed)


def main():
    a = args()
    rng = random.Random(a.seed)
    limit = rng.choice([2, 5, 10, 20]) if rng.random() < 0.4 else None  # mbit/s
    while left(a) > 3:
        tool = rng.choice(["scp", "rsync", "curl"])
        size = rng.choice(sizes)
        up = tool != "curl" and rng.random() < 0.3
        dst = f"/tmp/bulk-{time.time_ns()}"
        rem = f"lab@{a.host}:bulk/f{size}.bin"
        if tool == "scp":
            lim = f"-l {limit * 1000}" if limit else ""
            cmd = f"scp -q {lim} -i /root/.ssh/id_lab -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " + \
                  (f"/tmp/up{size}.bin lab@{a.host}:/tmp/up.bin" if up else f"{rem} {dst}")
        elif tool == "rsync":
            lim = f"--bwlimit={limit * 125}" if limit else ""
            cmd = f"rsync -q --inplace {lim} -e '{ssh}' " + \
                  (f"/tmp/up{size}.bin lab@{a.host}:/tmp/up.bin" if up else f"{rem} {dst}")
        else:
            lim = f"--limit-rate {limit * 125}k" if limit else ""
            cmd = f"curl -sk {lim} -o {dst} https://{a.host}/bulk/f{size}.bin"
        if up and not os.path.exists(f"/tmp/up{size}.bin"):
            subprocess.run(f"head -c {size}M /dev/urandom > /tmp/up{size}.bin", shell=True)
        t = time.time()
        try:
            p = subprocess.run(cmd, shell=True, timeout=max(1, left(a)), capture_output=True, text=True)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = "cut at deadline"
        emit("bulk", "transfer", t, tool=tool, size_mb=size, direction="up" if up else "down",
             limit_mbit=limit, rc=rc)
        subprocess.run(f"rm -f {dst}", shell=True)
        nap(a, rng.uniform(0.5, 4))


if __name__ == "__main__":
    main()
