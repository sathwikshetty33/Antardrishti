"""sufficiency targets (CLAUDE.md section 7). counts ok runs, not just windows.

usage: python3 tools/coverage.py [--tier p0|p1|p2]   (default: every tier)
prints target vs actual, lists the exact missing runs, writes dataset/coverage.md,
exits non-zero when any p0 target is unmet.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "capture"))
import plan

manifest = root / "dataset" / "manifest.jsonl"
apps6 = plan.matrix["apps"]


def latest():
    """latest manifest entry per run_id"""
    last = {}
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                last[m["run_id"]] = m
    return last


def akey(cfg):
    """set-A config = esp wire shape (not key size) x mode x family x encap"""
    return (cfg["mode"], cfg.get("esp_shape", cfg["esp_proposal"]), cfg["outer_family"], bool(cfg["encap"]))


def app_targets(tiers):
    """p0 runs one tunnel group per set-A config (32 runs per app; 8 test tunnels,
    one per shape x mode pair, so 8 test runs per app); the p2 second rep brings
    every app back to the original 40 / 1500"""
    if "p2" in tiers:
        return {"runs": 40, "windows": 1500, "test": 8}
    return {"runs": 32, "windows": 1400, "test": 8}


def bkey(cfg):
    return (cfg["dh"], bool(cfg["pfs"]), cfg["auth"])


def row(rows, level, what, target, actual, ok, missing=()):
    rows.append({"level": level, "what": what, "target": target, "actual": actual, "ok": ok,
                 "missing": list(missing)})


def evaluate(tiers):
    last = latest()
    planned = {t: plan.build(t) for t in tiers}
    allrun = [r for t in tiers for r in planned[t]]
    ok = [m for m in last.values() if m["status"] == "ok" and m["tier"] in tiers]
    tg = app_targets(tiers)
    notok = lambda rs: [r["run_id"] for r in rs if last.get(r["run_id"], {}).get("status") != "ok" and not r.get("skip")]
    rows = []
    env = json.loads((root / "dataset" / "env.json").read_text()) if (root / "dataset" / "env.json").exists() else {}

    single = [m for m in ok if len(m["apps"]) == 1 and m["stage"] in ("traffic", "chat", "whatsapp")]
    classes = apps6 + (["chat"] if "p1" in tiers else [])
    na = len(plan.cross(plan.matrix["set_a"]))
    for a in classes:
        rs = [m for m in single if m["apps"][0] in (a, "whatsapp" if a == "chat" else a)]
        win = sum((m["observed"].get("windows_2s") or {}).get(m["apps"][0], 0) for m in rs)
        cfgs = {akey(m["config"]) for m in rs}
        lvl = "p0" if a in apps6 else "p1"
        pr = [r for r in allrun if r["apps"] == [a] and r["stage"] in ("traffic", "chat")]
        row(rows, lvl, f"app {a}: ok runs", f">= {tg['runs']}", len(rs), len(rs) >= tg["runs"], notok(pr))
        row(rows, lvl, f"app {a}: 2 s windows", f">= {tg['windows']}", win, win >= tg["windows"])
        row(rows, lvl, f"app {a}: set-A configs covered", f">= 90% of {na}", f"{len(cfgs)}/{na}", len(cfgs) >= 0.9 * na)
        test = [m for m in rs if m["split"] == "test"]
        row(rows, lvl, f"app {a}: test runs", f">= {tg['test']}", len(test), len(test) >= tg["test"])

    traffic = [m for m in ok if m["stage"] == "traffic"]
    per = Counter(akey(m["config"]) for m in traffic)
    space = plan.cross(plan.matrix["set_a"])
    short = [k for k in space if per[(k["mode"], k["esp"], k["outer_family"], k["encap"])] < 5]
    row(rows, "p0", "each set-A config: ok runs", f">= 5 (all {na})", f"{na - len(short)}/{na} configs meet it",
        not short, [f"{k['mode']}/{k['esp']}/{k['outer_family']}/encap={k['encap']}: "
                    f"{per[(k['mode'], k['esp'], k['outer_family'], k['encap'])]}" for k in short])

    if "p1" in tiers:
        mix = [m for m in ok if m["stage"] == "mixtures"]
        for combo in plan.matrix["tiers"]["p1"][0]["combos"]:
            sc = "_".join(combo)
            n = sum(m["scenario"] == sc for m in mix)
            row(rows, "p1", f"mixture {sc}", ">= 8", n, n >= 8, notok([r for r in allrun if r["scenario"] == sc]))

    tun = Counter(akey(m["config"]) for m in ok if m["stage"] in ("traffic", "short") and m.get("group_pos", 0) == 0)
    tshort = [k for k in space if tun[(k["mode"], k["esp"], k["outer_family"], k["encap"])] < 3]
    row(rows, "p0", "each set-A config: tunnels (traffic + short)", f">= 3 (all {na})",
        f"{na - len(tshort)}/{na} configs meet it", not tshort,
        [f"{k['mode']}/{k['esp']}/{k['outer_family']}/encap={k['encap']}: "
         f"{tun[(k['mode'], k['esp'], k['outer_family'], k['encap'])]}" for k in tshort])

    hs = [m for m in ok if m["stage"] == "handshake" and m["observed"].get("child_rekeys", 0) >= 1]
    hper = Counter(bkey(m["config"]) for m in hs)
    bshort = [c for c in plan.b_configs() if hper[(c["dh"], c["pfs"], c["auth"])] < 3]
    row(rows, "p0", "each set-B combo: ok runs with a child rekey", ">= 3 (all 20)",
        f"{20 - len(bshort)}/20 combos meet it", not bshort,
        [f"{c['dh']}/pfs={c['pfs']}/{c['auth']}: {hper[(c['dh'], c['pfs'], c['auth'])]}" for c in bshort])

    algs = {a for v in env.get("swanctl_algs", {}).values() for a in v}
    for lvl in ("p0", "p1"):
        if lvl not in tiers:
            continue
        for eid, e in plan.edges[lvl].items():
            miss = [n for n in e.get("needs", []) if algs and n not in algs]
            if miss:
                row(rows, lvl, f"edge {eid} {e['scenario']}", ">= 3 ok", "unsupported: " + ", ".join(miss), True)
                continue
            rs = [m for m in ok if m.get("edge_case") == eid]
            mm = sum(1 for m in last.values() if m.get("edge_case") == eid and m["status"] == "mismatch")
            test = sum(m["split"] == "test" for m in rs)
            row(rows, lvl, f"edge {eid} {e['scenario']}", ">= 3 ok, in test",
                f"{len(rs)} ok ({mm} mismatch), {test} test", len(rs) >= 3 and test >= 1,
                notok([r for r in allrun if r.get("edge_case") == eid]))

    if traffic:
        mid = sum(m["capture_start"] == "mid_stream" for m in traffic)
        row(rows, "p0", "mid-stream (esp-only) captures", ">= 15% of traffic runs",
            f"{mid}/{len(traffic)} = {mid / len(traffic):.0%}", mid >= 0.15 * len(traffic))
    nonedge = [m for m in ok if not m.get("edge_case")]
    if nonedge:
        nc = Counter(m["netem"] for m in nonedge)
        for p in sorted(plan.netems):
            row(rows, "p0", f"netem {p}", ">= 15% of runs", f"{nc[p]}/{len(nonedge)} = {nc[p] / len(nonedge):.0%}",
                nc[p] >= 0.15 * len(nonedge))

    gaps = []
    for r in allrun:
        if r.get("skip"):
            gaps.append(f"{r['stage']} {r['scenario']}: {r['skip']}")
    return rows, sorted(set(gaps)), ok, last


def datasheet_numbers(ok):
    n = len(ok)
    rep = sum(bool(m.get("replayed")) for m in ok)
    inet = sum(bool(m.get("internet")) for m in ok)
    return n, n - rep - inet, inet, rep


def write_md(rows, gaps, ok, tiers):
    n, lab, inet, rep = datasheet_numbers(ok)
    lines = ["# Coverage", "", f"Generated by `tools/coverage.py` for tiers {', '.join(tiers)}.", "",
             f"ok runs: {n} (lab {lab}, internet {inet}, replayed {rep})", "",
             "| level | target | minimum | actual | met |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['level']} | {r['what']} | {r['target']} | {r['actual']} | {'yes' if r['ok'] else '**no**'} |")
    lines += ["", "## Gaps", ""]
    lines += [f"- {g}" for g in gaps] or ["- none"]
    miss = [r for r in rows if r["missing"] and not r["ok"]]
    if miss:
        lines += ["", "## Missing runs", ""]
        for r in miss:
            lines.append(f"### {r['what']}")
            lines += [f"- `{x}`" for x in r["missing"][:200]]
            if len(r["missing"]) > 200:
                lines.append(f"- ... {len(r['missing']) - 200} more")
    (root / "dataset" / "coverage.md").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", choices=sorted(plan.matrix["tiers"]))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    tiers = [args.tier] if args.tier else sorted(plan.matrix["tiers"])
    rows, gaps, ok, _ = evaluate(tiers)
    w = max(len(r["what"]) for r in rows)
    print(f"{'lvl':<4}{'target':<{w + 2}}{'minimum':<24}{'actual':<32}met")
    for r in rows:
        print(f"{r['level']:<4}{r['what']:<{w + 2}}{r['target']:<24}{str(r['actual']):<32}{'yes' if r['ok'] else 'NO'}")
        if not r["ok"] and r["missing"] and not args.quiet:
            for x in r["missing"][:8]:
                print(f"      missing: {x}")
            if len(r["missing"]) > 8:
                print(f"      ... {len(r['missing']) - 8} more (see coverage.md)")
    for g in gaps:
        print(f"gap: {g}")
    write_md(rows, gaps, ok, tiers)
    print("wrote dataset/coverage.md")
    p0_bad = [r for r in rows if r["level"] == "p0" and not r["ok"]]
    sys.exit(1 if p0_bad else 0)


if __name__ == "__main__":
    main()
