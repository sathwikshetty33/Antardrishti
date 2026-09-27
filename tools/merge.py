"""merge manifests from several codespaces (slices of one plan) into one.

usage: python3 tools/merge.py SRC [SRC ...] [-o dataset/manifest.jsonl] [--strict]
  SRC is a manifest file, or git:<ref> for dataset/manifest.jsonl on a branch
  (e.g. git:origin/alice after `git fetch`).

every attempt line is kept (deduplicated), ordered by capture time.

a shard is rejected (nothing is written, exit 1) when it differs from this
checkout or from the other shards in:
  - plan: a run's config differs from this checkout's plan, or a run is unknown
  - seed / design: plan.tier_seed or plan.design_sha differs
  - images: a different image digest set, or images that were not pulled from
    ghcr (local builds cannot be proven identical)
duplicate work (a run ok on two shards) is only reported; both lines are kept.
--force writes the merge anyway (for inspection, never for the dataset).
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
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    seen, lines, origin = {}, [], defaultdict(set)
    problems, warnings = [], []
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
    # seed and design fingerprint: the same for every shard, and equal to this checkout's
    here = plan.design_sha()
    for m in lines:
        pl = m.get("plan") or {}
        if pl.get("design_sha") != here:
            problems.append(f"{m['run_id']}: design {pl.get('design_sha')} != this checkout's {here}")
        if pl.get("tier_seed") != plan.matrix["seeds"].get(m["tier"]):
            problems.append(f"{m['run_id']}: tier seed {pl.get('tier_seed')} != {plan.matrix['seeds'].get(m['tier'])}")
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
            warnings.append(f"{rid}: ok on {len(ms)} attempts ({', '.join(sorted(origin[rid]))})")
    for w in warnings[:20]:
        print("  warning:", w)
    if problems and not args.force:
        for p in problems[:50]:
            print("  REJECT", p)
        if len(problems) > 50:
            print(f"  REJECT ... {len(problems) - 50} more")
        print("merge rejected: nothing written (fix the shard, or --force for inspection only)")
        sys.exit(1)
    lines.sort(key=lambda m: (m.get("capture_start_epoch") or 0, m["run_id"], m.get("attempt") or 0))
    Path(args.out).write_text("".join(json.dumps(m, sort_keys=True, default=list) + "\n" for m in lines))
    last = {}
    for m in lines:
        last[m["run_id"]] = m["status"]
    print(f"merged: {len(lines)} attempts, {len(last)} runs, {sum(v == 'ok' for v in last.values())} ok -> {args.out}")
    for p in problems[:50]:
        print("  forced past:", p)


if __name__ == "__main__":
    main()
