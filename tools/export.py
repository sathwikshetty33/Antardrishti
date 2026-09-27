"""pack ok runs for hand-back or release: run folders + their manifest lines.

usage: python3 tools/export.py --tier p0 [--slice i/n] [--out dataset/export]

writes <out>/<tier>[-slice-i-of-n]-<code>.tar.zst and a .sha256 next to it.
only runs whose latest manifest entry is ok are packed; each run folder is
checked against its meta.json checksums first (tools/checkmeta.py).
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root / "capture"), str(root / "tools")]
import checkmeta
import plan

raw = root / "dataset" / "raw"
manifest = root / "dataset" / "manifest.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", required=True)
    ap.add_argument("--slice")
    ap.add_argument("--out", default=str(root / "dataset" / "export"))
    a = ap.parse_args()
    runs = plan.build(a.tier)
    tag = a.tier
    if a.slice:
        i, n = (int(x) for x in a.slice.split("/"))
        runs = plan.deal(runs, i, n) if a.tier not in plan.legacy else plan.slice_units(runs, i, n)
        tag += f"-slice-{i}-of-{n}"
    want = {r["run_id"] for r in runs}
    base = {r["run_id"] for r in plan.build(a.tier)}
    last, lines = {}, []
    for l in manifest.read_text().splitlines():
        if l.strip():
            m = json.loads(l)
            # extra edge reps (--fill-gaps) are not in the plan: a slice packs the ones it captured
            extra = m.get("edge_case") and m["run_id"] not in base and (not a.slice or (raw / m["run_id"]).exists())
            if m["tier"] == a.tier and (m["run_id"] in want or extra):
                if "annotation" not in m:
                    last[m["run_id"]] = m["status"]
                lines.append(l)
    ok = sorted(r for r, s in last.items() if s == "ok")
    bad = [(r, checkmeta.check(raw / r)) for r in ok]
    bad = [(r, b) for r, b in bad if b]
    if bad:
        for r, b in bad[:20]:
            print(f"FAIL {r}: {'; '.join(b)}")
        sys.exit("some run folders fail checkmeta: fix before exporting")
    code = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    dst = out / f"{tag}-{code}.tar.zst"
    with tempfile.TemporaryDirectory() as t:
        (Path(t) / "manifest.jsonl").write_text("\n".join(lines) + "\n")
        lst = Path(t) / "files"
        lst.write_text("\n".join(f"dataset/raw/{r}" for r in ok) + "\n")
        subprocess.run(f"tar -C {root} -cf - -T {lst} -C {t} manifest.jsonl | zstd -q -T0 -10 -o {dst} -f",
                       shell=True, check=True)
    digest = hashlib.sha256(dst.read_bytes()).hexdigest()
    (dst.parent / (dst.name + ".sha256")).write_text(f"{digest}  {dst.name}\n")
    print(f"{dst}: {len(ok)} ok runs, {dst.stat().st_size / 1e9:.2f} GB, sha256 {digest[:16]}...")


if __name__ == "__main__":
    main()
