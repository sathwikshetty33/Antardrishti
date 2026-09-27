"""orchestrator: plan -> run -> validate -> record.

usage: python3 capture/run.py --tier p0 [--scenario voip ...] [--resume]
                              [--fill-gaps] [--dry-run] [--limit N]
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan

root = plan.root
manifest = root / "dataset" / "manifest.jsonl"


def done_ids():
    """run_ids whose latest manifest entry is ok"""
    last = {}
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                last[m["run_id"]] = m["status"]
    return {k for k, v in last.items() if v == "ok"}


def select(args):
    runs = plan.build(args.tier)
    if args.scenario:
        runs = [r for r in runs if r["scenario"] in args.scenario or r["stage"] in args.scenario]
    return runs


def hms(s):
    return f"{int(s // 3600)}h{int(s % 3600 // 60):02d}m"


def dry_run(runs, todo):
    cores = os.cpu_count()
    by = defaultdict(list)
    for r in runs:
        by[r["stage"]].append(r)
    print(f"{'stage':<11}{'runs':>6}{'todo':>6}{'skip':>6}{'est':>9}   scenarios")
    total = 0
    for st, rs in by.items():
        t = [r for r in rs if r["run_id"] in todo and not r.get("skip")]
        est = sum(plan.cost(r) for r in t)
        total += est
        sk = sum(1 for r in rs if r.get("skip"))
        sc = Counter(r["scenario"] for r in rs)
        print(f"{st:<11}{len(rs):>6}{len(t):>6}{sk:>6}{hms(est):>9}   "
              + ", ".join(f"{k}:{v}" for k, v in sc.items()))
    skipped = {r["scenario"]: r["skip"] for r in runs if r.get("skip")}
    for k, v in skipped.items():
        print(f"  skip {k}: {v}")
    split = Counter(r["split"] for r in runs)
    nm = Counter(r.get("netem") for r in runs if r["stage"] != "edge")
    mid = sum(r.get("capture_start") == "mid_stream" for r in runs)
    print(f"\nsplit: {dict(split)}  netem (non-edge): {dict(nm)}  mid_stream: {mid}")
    print(f"estimate: {hms(total)} wall clock on this {cores}-core machine = "
          f"{total / 3600 * cores:.1f} core-hours (free quota: 120/month)")
    if total > 2 * 3600:
        print("more than 2 hours: ask before starting (CLAUDE.md section 1)")
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", required=True, choices=sorted(plan.matrix["tiers"]))
    ap.add_argument("--scenario", nargs="*", help="scenario or stage names")
    ap.add_argument("--resume", action="store_true", help="skip runs already ok (default)")
    ap.add_argument("--fill-gaps", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--list", action="store_true", help="print run ids")
    args = ap.parse_args()
    runs = select(args)
    ok = done_ids()
    todo = {r["run_id"] for r in runs if r["run_id"] not in ok}
    if args.list:
        for r in runs:
            print(r["run_id"], r["split"], r.get("netem"), r.get("capture_start"), r.get("skip") or "")
    if args.dry_run:
        dry_run(runs, todo)
        return
    sys.exit("execution lands in phase 3")


if __name__ == "__main__":
    main()
