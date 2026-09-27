"""merge manifests from several codespaces (slices of one plan) into one.

usage: python3 tools/merge.py SRC [SRC ...] [-o dataset/manifest.jsonl] [--strict]
  SRC is a manifest file, or git:<ref> for dataset/manifest.jsonl on a branch
  (e.g. git:origin/alice after `git fetch`).

every attempt line is kept (deduplicated), ordered by capture time. checks:
  - each run's config matches this checkout's plan (shards built the same plan)
  - one image digest set per tier (all shards pulled the same lab images)
  - no run ended ok on two shards (duplicate work is reported, both kept)
--strict turns any finding into a non-zero exit.
"""
import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "capture"))
import plan


def read(src):
    if src.startswith("git:"):
        ref = src[4:]
        p = subprocess.run(["git", "-C", str(root), "show", f"{ref}:dataset/manifest.jsonl"],
                           capture_output=True, text=True)
        if p.returncode:
            raise SystemExit(f"{src}: {p.stderr.strip()}")
        text = p.stdout
    else:
        text = Path(src).read_text()
    return [json.loads(l) for l in text.splitlines() if l.strip()]


def key(m):
    return (m["run_id"], m.get("attempt"), m.get("capture_start_epoch"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="+")
    ap.add_argument("-o", "--out", default=str(root / "dataset" / "manifest.jsonl"))
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    seen, lines, origin = {}, [], defaultdict(set)
    problems = []
    for src in args.src:
        rows = read(src)
        n_ok = sum(m["status"] == "ok" for m in rows)
        print(f"{src}: {len(rows)} attempts, {n_ok} ok")
        for m in rows:
            k = key(m)
            if k in seen:
                if json.dumps(seen[k], sort_keys=True) != json.dumps(m, sort_keys=True):
                    problems.append(f"conflicting records for {k[0]} attempt {k[1]}")
                continue
            seen[k] = m
            lines.append(m)
            origin[m["run_id"]].add(src)
    # plan consistency: the same run_id must carry the same config everywhere
    planned = {}
    for t in {m["tier"] for m in lines}:
        if t in plan.matrix["tiers"]:
            planned.update({r["run_id"]: r for r in plan.build(t)})
    for m in lines:
        p = planned.get(m["run_id"])
        if p is None:
            if not m.get("edge_case"):  # extra edge reps (fill-gaps) are not in the base plan
                problems.append(f"{m['run_id']}: not in this checkout's plan")
        elif json.dumps(p["config"], sort_keys=True) != json.dumps(m["config"], sort_keys=True):
            problems.append(f"{m['run_id']}: config differs from the plan (different matrix version?)")
    # one image digest set per tier
    digests = defaultdict(set)
    for m in lines:
        d = tuple(sorted((k, v) for k, v in (m.get("images") or {}).items() if k.startswith("digest_")))
        digests[m["tier"]].add(d)
    for t, ds in digests.items():
        if len(ds) > 1:
            problems.append(f"tier {t}: {len(ds)} different image digest sets across shards")
        if any(not v.startswith("ghcr.io/") for d in ds for _, v in d):
            problems.append(f"tier {t}: some runs used locally built images (no ghcr.io digest)")
    # duplicate work
    ok_by = defaultdict(list)
    for m in lines:
        if m["status"] == "ok":
            ok_by[m["run_id"]].append(m)
    for rid, ms in ok_by.items():
        if len(ms) > 1:
            problems.append(f"{rid}: ok on {len(ms)} attempts ({', '.join(sorted(origin[rid]))})")
    lines.sort(key=lambda m: (m.get("capture_start_epoch") or 0, m["run_id"], m.get("attempt") or 0))
    Path(args.out).write_text("".join(json.dumps(m, sort_keys=True, default=list) + "\n" for m in lines))
    last = {}
    for m in lines:
        last[m["run_id"]] = m["status"]
    print(f"merged: {len(lines)} attempts, {len(last)} runs, {sum(v == 'ok' for v in last.values())} ok -> {args.out}")
    for p in problems[:50]:
        print("  !", p)
    if len(problems) > 50:
        print(f"  ! ... {len(problems) - 50} more")
    sys.exit(1 if problems and args.strict else 0)


if __name__ == "__main__":
    main()
