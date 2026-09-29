"""the largest supported capture (MAX_PCAP_MB of uncompressed pcap, cut from the largest kept
test capture: 1.8 M esp packets of lan bulk, the worst case per byte) finishes well under
vercel hobby's 300 s on a 2 gb budget.

the analysis runs in a child process with its address space capped at 2 gb (RLIMIT_AS, a
harder limit than resident memory) and one thread, like vercel's single vcpu. vercel's vcpu
is assumed up to 3x slower than this machine's core, so the test asks for 3x the measured
time to stay under 300 s. writes features/results/timing.json for DEPLOY.md.
"""
import json
import os
import resource
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
import zstandard

from app.api import settings

root = Path(__file__).resolve().parents[2]
src = Path.home() / "antar-data" / "keep" / "p0s-bulk-0b569375-r1" / "outer.pcap.zst"
work = Path.home() / "antar-data" / "tmp"
slowdown = 3.0
budget = 2 * 2 ** 30


def cut(dst, limit):
    """the first `limit` bytes of whole pcap records of the source capture"""
    r = zstandard.ZstdDecompressor().stream_reader(open(src, "rb"))
    head = r.read(24)
    end = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    size, n = 24, 0
    with open(dst, "wb") as f:
        f.write(head)
        while True:
            h = r.read(16)
            if len(h) < 16:
                break
            incl = struct.unpack(end + "IIII", h)[2]
            body = r.read(incl)
            if size + 16 + incl > limit:
                break
            f.write(h + body)
            size += 16 + incl
            n += 1
    return size, n


child = """
import json, resource, sys, time
from pathlib import Path
from analyzer import cli
from app.api import pipeline
t = time.time()
r = cli.analyze([Path(sys.argv[1])], pipeline.bundle())
el = time.time() - t
print(json.dumps({"seconds": el, "rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                  "esp": sum(x["esp_packets"] for x in r["tunnels"]), "packets": r["counts"]["packets"],
                  "windows": sum(len(x.get("windows") or []) for x in r["tunnels"])}))
"""


def limit_as():
    resource.setrlimit(resource.RLIMIT_AS, (budget, budget))
    os.nice(10)


@pytest.mark.skipif(not src.exists(), reason="the largest kept capture is not in ~/antar-data/keep")
def test_largest_supported_capture_fits():
    work.mkdir(parents=True, exist_ok=True)
    pcap = work / "timing-largest.pcap"
    size, records = cut(pcap, int(settings.max_pcap_mb * 2 ** 20))
    try:
        env = {**os.environ, "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1",
               "PYTHONPATH": str(root)}
        t = time.time()
        p = subprocess.run([sys.executable, "-c", child, str(pcap)], capture_output=True, text=True, env=env,
                           preexec_fn=limit_as, cwd=root, timeout=600)
        wall = time.time() - t
        assert p.returncode == 0, p.stderr[-2000:]
        m = json.loads(p.stdout.strip().splitlines()[-1])
    finally:
        pcap.unlink(missing_ok=True)
    out = {"max_pcap_mb": settings.max_pcap_mb, "pcap_bytes": size, "records": records, "analysis_s": m["seconds"],
           "process_s": wall, "peak_rss_mb": m["rss_mb"], "esp_packets": m["esp"], "windows": m["windows"],
           "address_space_limit_gb": budget / 2 ** 30, "assumed_vercel_slowdown": slowdown,
           "vercel_estimate_s": wall * slowdown}
    (root / "features" / "results").mkdir(parents=True, exist_ok=True)
    (root / "features" / "results" / "timing.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    assert wall * slowdown < 300 * 0.5, out          # well under the limit: half of it with the slowdown
    assert m["rss_mb"] < 1536, out
