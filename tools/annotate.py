"""append annotations to the manifest: a field set on runs after their capture,
for example timing_valid=false on the p0 traffic runs (captured with 3 labs).

usage: python3 tools/annotate.py --tier p0 --stage traffic --set timing_valid=false --reason "..."

append-only: an annotation line never edits an attempt. readers merge it into
its run's latest attempt recorded before it; a later attempt stands on its own.
only runs whose latest attempt is ok are annotated, and a run that already
carries the same annotation is skipped, so a rerun appends nothing.
"""
import argparse
import fcntl
import json
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent
manifest = root / "dataset" / "manifest.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--set", required=True, nargs="+", help="key=value, value in json (false, 3, \"x\")")
    ap.add_argument("--reason", required=True)
    a = ap.parse_args()
    fields = {k: json.loads(v) for k, _, v in (kv.partition("=") for kv in a.set)}
    last, have = {}, set()
    for line in manifest.read_text().splitlines():
        if line.strip():
            m = json.loads(line)
            if "annotation" in m:
                if m["annotation"] == fields:
                    have.add(m["run_id"])
            elif m["tier"] == a.tier and m["stage"] == a.stage:
                last[m["run_id"]] = m
    todo = sorted(r for r, m in last.items() if m["status"] == "ok" and r not in have)
    ts = round(time.time(), 3)
    with open(manifest, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        for r in todo:
            f.write(json.dumps({"annotation": fields, "run_id": r, "tier": a.tier, "stage": a.stage,
                                "reason": a.reason, "ts": ts}, sort_keys=True) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)
    print(f"annotated {len(todo)} {a.tier} {a.stage} runs with {fields} ({len(have & set(last))} already had it)")


if __name__ == "__main__":
    main()
