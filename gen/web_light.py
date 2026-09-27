"""web_light: small curl fetches for handshake runs (keeps esp flowing lightly)."""
import random
import subprocess
import time

from common import args, emit, launch, left, nap


def start(duration, seed, ctx):
    return launch(ctx, "web_light", duration, seed)


def main():
    a = args()
    rng = random.Random(a.seed)
    lst = subprocess.run(f"curl -sk https://{a.host}/sites/index.txt", shell=True,
                         capture_output=True, text=True).stdout.split() or ["/player.html"]
    while left(a) > 1:
        path = rng.choice(lst)
        t = time.time()
        p = subprocess.run(f"curl -sk -m {max(1, int(left(a)))} -o /dev/null -w '%{{size_download}}' https://{a.host}{path}",
                           shell=True, capture_output=True, text=True)
        emit("web_light", "get", t, path=path, bytes=int(p.stdout or 0))
        nap(a, rng.uniform(2, 8))


if __name__ == "__main__":
    main()
