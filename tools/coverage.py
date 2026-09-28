"""sufficiency targets (CLAUDE.md section 7). counts ok runs, not just windows.

usage: python3 tools/coverage.py [--tier p0|p1|p2]   (default: every tier with runs)
prints target vs actual, lists the exact missing runs, and writes each tier's
section of dataset/coverage.md (the other sections are kept). exits non-zero
when a target of the given tier is unmet (without --tier: any p0 target).
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "capture"))
import plan

manifest = root / "dataset" / "manifest.jsonl"
apps6 = plan.matrix["apps"]
# p1 minimums for 60 s runs: p0's windows target is 35/36 of the most a run can
# give (1400 of 32 x 45), so the same share of 8 x 30 (anchor) and 32 x 30 (chat);
# chat: 920 (owner, 2026-09-28): each chat run's own ike setup costs it windows, by design
p1_anchor_windows = 230
p1_chat_windows = 920


def latest():
    """latest attempt per run_id, with the annotations recorded after it merged in
    (tools/annotate.py: annotation lines are not attempts)"""
    last = {}
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                if "annotation" in m:
                    if m["run_id"] in last:
                        last[m["run_id"]] = {**last[m["run_id"]], **m["annotation"]}
                    continue
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


def win(m):
    return (m["observed"].get("windows_2s") or {}).get(m["apps"][0], 0)


def evaluate(tier):
    """the rows of one tier's section; p2 counts together with p0 (its second rep)"""
    last = latest()
    tiers = ["p0", "p2"] if tier == "p2" else [tier]
    allrun = [r for t in tiers for r in plan.build(t)]
    ok = [m for m in last.values() if m["status"] == "ok" and m["tier"] in tiers]
    notok = lambda rs: [r["run_id"] for r in rs if last.get(r["run_id"], {}).get("status") != "ok" and not r.get("skip")]
    env = json.loads((root / "dataset" / "env.json").read_text()) if (root / "dataset" / "env.json").exists() else {}
    rows = []
    if tier == "p1":
        p1_rows(rows, ok, allrun, notok)
    else:
        p0_rows(rows, ok, allrun, notok, tiers)
    level = "p1" if tier == "p1" else "p0"
    algs = {a for v in env.get("swanctl_algs", {}).values() for a in v}
    for eid, e in plan.edges[level].items():
        miss = [n for n in e.get("needs", []) if algs and n not in algs]
        if miss:
            row(rows, level, f"edge {eid} {e['scenario']}", ">= 3 ok", "unsupported: " + ", ".join(miss), True)
            continue
        rs = [m for m in ok if m.get("edge_case") == eid]
        mm = sum(1 for m in last.values() if m.get("edge_case") == eid and m["tier"] in tiers and m["status"] == "mismatch")
        test = sum(m["split"] == "test" for m in rs)
        row(rows, level, f"edge {eid} {e['scenario']}", ">= 3 ok, in test",
            f"{len(rs)} ok ({mm} mismatch), {test} test", len(rs) >= 3 and test >= 1,
            notok([r for r in allrun if r.get("edge_case") == eid]))
    traffic = [m for m in ok if m["stage"] == "traffic"] if tier != "p1" else [m for m in ok if m.get("timed")]
    if traffic:
        mid = sum(m["capture_start"] == "mid_stream" for m in traffic)
        row(rows, level, "mid-stream (esp-only) captures", ">= 15% of traffic runs",
            f"{mid}/{len(traffic)} = {mid / len(traffic):.0%}", mid >= 0.15 * len(traffic))
    nonedge = [m for m in ok if not m.get("edge_case")]
    if nonedge:
        nc = Counter(m["netem"] for m in nonedge)
        for p in sorted(plan.netems):
            row(rows, level, f"netem {p}", ">= 15% of runs", f"{nc[p]}/{len(nonedge)} = {nc[p] / len(nonedge):.0%}",
                nc[p] >= 0.15 * len(nonedge))
    gaps = []
    for r in allrun:
        if r.get("skip"):
            gaps.append(f"{r['stage']} {r['scenario']}: {r['skip']}")
    blocked = Counter(a for m in ok for a in (m["observed"].get("blocked") or {}))
    for a, n in sorted(blocked.items()):
        runs = sum(1 for m in ok if a in m["apps"])
        gaps.append(f"{a}: blocked in {n} of {runs} ok runs (recorded, never worked around)")
    return rows, sorted(set(gaps)), ok, last


def p0_rows(rows, ok, allrun, notok, tiers):
    """p0 (and p2 with it): single apps on set A, tunnels per config, set B"""
    tg = app_targets(tiers)
    single = [m for m in ok if len(m["apps"]) == 1 and m["stage"] == "traffic"]
    na = len(plan.cross(plan.matrix["set_a"]))
    for a in apps6:
        rs = [m for m in single if m["apps"][0] == a]
        w = sum(win(m) for m in rs)
        cfgs = {akey(m["config"]) for m in rs}
        pr = [r for r in allrun if r["apps"] == [a] and r["stage"] == "traffic"]
        row(rows, "p0", f"app {a}: ok runs", f">= {tg['runs']}", len(rs), len(rs) >= tg["runs"], notok(pr))
        row(rows, "p0", f"app {a}: 2 s windows", f">= {tg['windows']}", w, w >= tg["windows"])
        row(rows, "p0", f"app {a}: set-A configs covered", f">= 90% of {na}", f"{len(cfgs)}/{na}", len(cfgs) >= 0.9 * na)
        test = [m for m in rs if m["split"] == "test"]
        row(rows, "p0", f"app {a}: test runs", f">= {tg['test']}", len(test), len(test) >= tg["test"])

    traffic = [m for m in ok if m["stage"] == "traffic"]
    per = Counter(akey(m["config"]) for m in traffic)
    space = plan.cross(plan.matrix["set_a"])
    short = [k for k in space if per[(k["mode"], k["esp"], k["outer_family"], k["encap"])] < 5]
    row(rows, "p0", "each set-A config: ok runs", f">= 5 (all {na})", f"{na - len(short)}/{na} configs meet it",
        not short, [f"{k['mode']}/{k['esp']}/{k['outer_family']}/encap={k['encap']}: "
                    f"{per[(k['mode'], k['esp'], k['outer_family'], k['encap'])]}" for k in short])

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


def p1_rows(rows, ok, allrun, notok):
    """p1: timing-valid anchors, mixtures, live chat and realism, each traffic run
    captured alone on its machine"""
    st = {s["stage"]: s for s in plan.matrix["tiers"]["p1"]}
    a8 = {(c["mode"], c["esp"], c["outer_family"], c["encap"]) for c, _ in plan.set_a(st["anchor"]["set"])}
    for a in st["anchor"]["apps"]:
        rs = [m for m in ok if m["stage"] == "anchor" and m["apps"] == [a]]
        w = sum(win(m) for m in rs)
        cfgs = {akey(m["config"]) for m in rs} & a8
        test = [m for m in rs if m["split"] == "test"]
        pr = [r for r in allrun if r["stage"] == "anchor" and r["apps"] == [a]]
        row(rows, "p1", f"anchor {a}: ok runs", f">= {len(a8)}", len(rs), len(rs) >= len(a8), notok(pr))
        row(rows, "p1", f"anchor {a}: 2 s windows", f">= {p1_anchor_windows}", w, w >= p1_anchor_windows)
        row(rows, "p1", f"anchor {a}: a8 configs covered", f"all {len(a8)}", f"{len(cfgs)}/{len(a8)}", len(cfgs) == len(a8))
        row(rows, "p1", f"anchor {a}: test runs", ">= 2", len(test), len(test) >= 2)

    mix = [m for m in ok if m["stage"] == "mixtures"]
    for combo in st["mixtures"]["combos"]:
        sc = "_".join(combo)
        rs = [m for m in mix if m["scenario"] == sc]
        test = sum(m["split"] == "test" for m in rs)
        row(rows, "p1", f"mixture {sc}", ">= 8 ok, in test", f"{len(rs)} ok, {test} test", len(rs) >= 8 and test >= 1,
            notok([r for r in allrun if r["scenario"] == sc]))

    # live chat (xmpp, 60 s runs) and the whatsapp replay runs labelled chat count
    # together as the chat class (whatsapp call chunks are labelled voip)
    na = len(plan.cross(plan.matrix["set_a"]))
    rs = [m for m in ok if m["stage"] == "chat" or (m["stage"] == "whatsapp" and m.get("label") == "chat")]
    w = sum(win(m) for m in rs)
    cfgs = {akey(m["config"]) for m in rs}
    test = [m for m in rs if m["split"] == "test"]
    pr = [r for r in allrun if r["stage"] == "chat"]
    row(rows, "p1", "app chat: ok runs", f">= {na}", len(rs), len(rs) >= na, notok(pr))
    row(rows, "p1", "app chat: 2 s windows", f">= {p1_chat_windows}", w, w >= p1_chat_windows)
    row(rows, "p1", "app chat: set-A configs covered", f">= 90% of {na}", f"{len(cfgs)}/{na}", len(cfgs) >= 0.9 * na)
    row(rows, "p1", "app chat: test runs", ">= 8", len(test), len(test) >= 8)

    pr = [r for r in allrun if r["stage"] == "whatsapp" and not r.get("skip")]
    if pr:
        rs = [m for m in ok if m["stage"] == "whatsapp"]
        lab = Counter(m.get("label") for m in rs)
        test = Counter(m.get("label") for m in rs if m["split"] == "test")
        want = Counter(r["replay_label"] for r in pr)
        prov = [m for m in rs if m.get("source") and all((m.get("replay") or {}).get(k) is not None
                                                          for k in ("doi", "source_file", "start_s", "end_s", "sha256"))]
        row(rows, "p1", "whatsapp replay: ok runs", f"{len(pr)} ({want['chat']} chat, {want['voip']} voip)",
            f"{len(rs)} ({lab['chat']} chat, {lab['voip']} voip)", len(rs) >= len(pr) and lab == want, notok(pr))
        row(rows, "p1", "whatsapp replay: test runs", ">= 1 chat, >= 1 voip", f"{test['chat']} chat, {test['voip']} voip",
            test["chat"] >= 1 and test["voip"] >= 1)
        row(rows, "p1", "whatsapp replay: provenance recorded", "all", f"{len(prov)}/{len(rs)}", len(prov) == len(rs))

    pr = [r for r in allrun if r["stage"] == "realism"]
    rs = [m for m in ok if m["stage"] == "realism"]
    row(rows, "p1", "realism (internet): ok runs", f">= {len(pr)}", len(rs), len(rs) >= len(pr), notok(pr))

    timed = [m for m in ok if m.get("timed")]
    bad = [m["run_id"] for m in timed if not m.get("timing_valid")]
    row(rows, "p1", "traffic runs captured alone (timing_valid)", "all", f"{len(timed) - len(bad)}/{len(timed)}",
        not bad, bad)


def datasheet_numbers(ok):
    n = len(ok)
    rep = sum(bool(m.get("replayed")) for m in ok)
    inet = sum(bool(m.get("internet")) for m in ok)
    return n, n - rep - inet, inet, rep


def section(rows, gaps, ok, tier):
    n, lab, inet, rep = datasheet_numbers(ok)
    lines = [f"<!-- {tier}:start -->", f"## {tier.upper()}", "",
             f"ok runs: {n} (lab {lab}, internet {inet}, replayed {rep})", "",
             "| level | target | minimum | actual | met |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['level']} | {r['what']} | {r['target']} | {r['actual']} | {'yes' if r['ok'] else '**no**'} |")
    lines += ["", "### Gaps", ""]
    lines += [f"- {g}" for g in gaps] or ["- none"]
    miss = [r for r in rows if r["missing"] and not r["ok"]]
    if miss:
        lines += ["", "### Missing runs", ""]
        for r in miss:
            lines.append(f"#### {r['what']}")
            lines += [f"- `{x}`" for x in r["missing"][:200]]
            if len(r["missing"]) > 200:
                lines.append(f"- ... {len(r['missing']) - 200} more")
    return "\n".join(lines) + f"\n<!-- {tier}:end -->"


def write_md(text, tier):
    """replace this tier's section of coverage.md, keep the others in tier order"""
    p = root / "dataset" / "coverage.md"
    old = p.read_text() if p.exists() else ""
    secs = {m.group(1): m.group(0) for m in re.finditer(r"<!-- (\w+):start -->.*?<!-- \1:end -->", old, flags=re.S)}
    secs[tier] = text
    head = ["# Coverage", "", "Generated by `tools/coverage.py`, one section per tier "
            "(`python3 tools/coverage.py --tier <t>` rewrites that tier's section).", ""]
    p.write_text("\n".join(head) + "\n" + "\n\n".join(secs[t] for t in sorted(secs)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", choices=sorted(plan.matrix["tiers"]))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    have = {m["tier"] for m in latest().values()}
    tiers = [args.tier] if args.tier else [t for t in ("p0", "p1", "p2") if t in have]
    bad = []
    for tier in tiers:
        rows, gaps, ok, _ = evaluate(tier)
        w = max(len(r["what"]) for r in rows)
        print(f"== {tier}")
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
        write_md(section(rows, gaps, ok, tier), tier)
        bad += [r for r in rows if not r["ok"] and (args.tier or r["level"] == "p0")]
    print("wrote dataset/coverage.md")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
