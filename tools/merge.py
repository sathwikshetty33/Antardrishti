"""merge manifests from several codespaces (slices of one plan) into one.

usage: python3 tools/merge.py SRC [SRC ...] [-o dataset/manifest.jsonl] [--tier t] [--force]
  SRC is a manifest file, or git:<ref> for dataset/manifest.jsonl on a branch
  (e.g. git:origin/alice after `git fetch`).

every attempt line is kept (deduplicated), ordered by capture time; annotation
lines (tools/annotate.py) are kept after the attempts they annotate.
--tier t merges only tier t's lines of the sources and keeps every other line of
the output file as it is (the way a tier is merged once earlier tiers are in).

a shard is rejected (nothing is written, exit 1) when it differs from this
checkout or from the other shards in:
  - plan: a run's config differs from this checkout's plan, or a run is unknown
  - seed / design / plan: plan.tier_seed, plan.design_sha or plan.plan_sha differs
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
    if "annotation" in m:
        return (m["run_id"], "annotation", json.dumps(m["annotation"], sort_keys=True), m.get("ts"))
    return (m["run_id"], m.get("attempt"), m.get("capture_start_epoch"))


def when(m):
    return m.get("capture_start_epoch") or m.get("ts") or 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="+")
    ap.add_argument("-o", "--out", default=str(root / "dataset" / "manifest.jsonl"))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--tier", help="merge only this tier's lines; keep the output's other lines")
    args = ap.parse_args()
    seen, lines, origin = {}, [], defaultdict(set)
    problems, warnings = [], []
    keep = []
    if args.tier and Path(args.out).exists():
        keep = [m for m in read(args.out) if m["tier"] != args.tier]
    for src in args.src:
        rows = [m for m in read(src) if not args.tier or m["tier"] == args.tier]
        n_ok = sum(m.get("status") == "ok" for m in rows)
        n_ann = sum("annotation" in m for m in rows)
        print(f"{src}: {len(rows) - n_ann} attempts, {n_ok} ok" + (f", {n_ann} annotations" if n_ann else ""))
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
    runs = {m["run_id"] for m in lines if "annotation" not in m} | {m["run_id"] for m in keep}
    ann = [m for m in lines if "annotation" in m]
    problems += [f"{m['run_id']}: annotation for a run with no attempt" for m in ann if m["run_id"] not in runs]
    lines_a = [m for m in lines if "annotation" not in m]
    for m in lines_a:
        p = planned.get(m["run_id"])
        if p is None:
            if not m.get("edge_case"):  # extra edge reps (fill-gaps) are not in the base plan
                problems.append(f"{m['run_id']}: not in this checkout's plan")
        elif json.dumps(p["config"], sort_keys=True) != json.dumps(m["config"], sort_keys=True):
            problems.append(f"{m['run_id']}: config differs from the plan (different matrix version?)")
    # seed and design fingerprint: the same for every shard, and equal to this checkout's
    here = plan.design_sha()
    for m in lines_a:
        pl = m.get("plan") or {}
        if pl.get("design_sha") != here:
            problems.append(f"{m['run_id']}: design {pl.get('design_sha')} != this checkout's {here}")
        if pl.get("tier_seed") != plan.matrix["seeds"].get(m["tier"]):
            problems.append(f"{m['run_id']}: tier seed {pl.get('tier_seed')} != {plan.matrix['seeds'].get(m['tier'])}")
    # one plan fingerprint per tier (runs from before plan_sha existed carry none)
    shas = defaultdict(set)
    for m in lines_a:
        if (m.get("plan") or {}).get("plan_sha"):
            shas[m["tier"]].add(m["plan"]["plan_sha"])
    for t, ss in shas.items():
        if len(ss) > 1:
            problems.append(f"tier {t}: {len(ss)} different plans ({', '.join(sorted(ss))})")
    # one image digest set per tier
    digests = defaultdict(set)
    for m in lines_a:
        d = tuple(sorted((k, v) for k, v in (m.get("images") or {}).items() if k.startswith("digest_")))
        digests[m["tier"]].add(d)
    for t, ds in digests.items():
        if len(ds) > 1:
            problems.append(f"tier {t}: {len(ds)} different image digest sets across shards")
        if any(not v.startswith("ghcr.io/") for d in ds for _, v in d):
            problems.append(f"tier {t}: some runs used locally built images (no ghcr.io digest)")
    # duplicate work
    ok_by = defaultdict(list)
    for m in lines_a:
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
    lines.sort(key=lambda m: (when(m), m["run_id"], m.get("attempt") or 0))
    Path(args.out).write_text("".join(json.dumps(m, sort_keys=True, default=list) + "\n" for m in keep + lines))
    last = {}
    for m in lines:
        if "annotation" not in m:
            last[m["run_id"]] = m["status"]
    print(f"merged: {len(lines_a)} attempts, {len(last)} runs, {sum(v == 'ok' for v in last.values())} ok"
          + (f" of tier {args.tier} (+{len(keep)} other lines kept)" if args.tier else "") + f" -> {args.out}")
    for p in problems[:50]:
        print("  forced past:", p)


if __name__ == "__main__":
    main()
