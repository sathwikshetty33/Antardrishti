"""phase a: every run of a tier, one at a time -> cached packet table and tunnel rows.

  python -m analyzer.prep --tier p1-whatsapp [--ids ...]

streams the tier's verified release archives (~/antar-data/dl/<release>/*.tar.zst),
extracts one run's outer and ike captures, parses them (analyzer/parse.py), joins the
per-packet labels (labels/<tier>/<run_id>/labels.parquet), applies the label decisions
of analyzer/CLAUDE.md section 11, writes features/<tier>/<run_id>.parquet (esp packets)
and .json (meta, tunnels, counts), then deletes the extracted run. cached runs are
skipped, so an interrupted pass resumes. the edge runs and a few test runs are kept
(outer and ike only) in ~/antar-data/keep for the parser and cli tests.
"""
import argparse
import json
import resource
import shutil
import sys
import tarfile
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard

from analyzer import common as cm
from analyzer import parse

wanted = ("outer.pcap.zst", "ike.pcap.zst", "meta.json", "schedule.json")
raw_other, raw_amb, raw_none = 7, 8, 9


def mem_used():
    info = {}
    for l in Path("/proc/meminfo").read_text().splitlines():
        k, v = l.split(":")
        info[k] = int(v.split()[0])
    return 1 - info["MemAvailable"] / info["MemTotal"]


def keep_list(rs):
    """runs whose captures stay for the tests: every edge run, the first test mixture with
    three apps, the first test whatsapp run and the first test p0s run"""
    keep = {r for r, m in rs.items() if m["stage"] == "edge"}
    for stage, pre in (("mixtures", "p1-voip_video_web"), ("whatsapp", "p1-whatsapp"), ("traffic", "p0s-")):
        c = sorted(r for r, m in rs.items() if m["stage"] == stage and m["split"] == "test" and r.startswith(pre))
        keep |= set(c[:1])
    return keep


def stream(archive, dest):
    """extract an archive run by run; yields each run_id once its files are written"""
    cur = None
    with open(archive, "rb") as fh, zstandard.ZstdDecompressor().stream_reader(fh) as rd:
        tf = tarfile.open(fileobj=rd, mode="r|")
        for mem in tf:
            parts = Path(mem.name).parts
            if "raw" not in parts or len(parts) < parts.index("raw") + 3:
                continue
            i = parts.index("raw")
            rid = parts[i + 1]
            if rid != cur:
                if cur:
                    yield cur
                cur = rid
            if not mem.isfile() or len(parts) != i + 3 or parts[i + 2] not in wanted:
                continue
            out = dest / rid / parts[i + 2]
            out.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(mem) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        if cur:
            yield cur


def intervals(sched, shift):
    """app -> [(start, stop)] relative to the first packet"""
    out = {}
    for e in sched.get("entries", []):
        if e.get("event") == "app" and e.get("app"):
            a = cm.alias.get(e["app"], e["app"])
            out.setdefault(a, []).append((e["start"] + shift, e["stop"] + shift))
    return out


def raw_codes(lab_app):
    """per dictionary value of the labels' app column -> raw code, and candidate apps"""
    codes, cands = [], []
    for v in lab_app.dictionary.to_pylist():
        if v is None:
            codes.append(raw_none)
            cands.append([])
        elif v.startswith("ambiguous:"):
            codes.append(raw_amb)
            cands.append([cm.apps.index(cm.alias.get(x, x)) for x in v.split(":", 1)[1].split("+")
                          if cm.alias.get(x, x) in cm.apps])
        else:
            a = cm.alias.get(v, v)
            codes.append(cm.apps.index(a) if a in cm.apps else raw_other)
            cands.append([])
    return np.array(codes, np.int8), cands


def labels_for(m, pk, t0, sched, lab, rows0):
    """raw and final app codes per esp packet, the unresolved ambiguity mask, and stats"""
    n = len(pk["t"])
    raw = np.full(n, raw_none, np.int8)
    amb_of = np.zeros(n, np.int16) - 1
    check = {"rows": int(lab.num_rows) if lab is not None else None, "parsed_rows": rows0}
    if lab is not None and lab.num_rows == rows0:
        col = lab.column("app").combine_chunks()
        if not hasattr(col, "dictionary"):
            col = pa.array([None] * len(col), pa.string()).dictionary_encode()
        codes, cands = raw_codes(col)
        ix = col.indices.fill_null(0).to_numpy(zero_copy_only=False).astype(np.int64)
        valid = col.is_valid().to_numpy(zero_copy_only=False)
        mine = pk["fid"] == 0
        sel = pk["fidx"][mine]
        r = np.where(valid[sel], codes[np.where(valid[sel], ix[sel], 0)], raw_none)
        raw[mine] = r
        amb_of[mine] = np.where(valid[sel] & (r == raw_amb), ix[sel], -1)
        kind = lab.column("kind").to_numpy(zero_copy_only=False)[sel]
        check["esp_kind_agree"] = float((kind == "esp").mean()) if len(sel) else None
        dr = lab.column("dir").to_numpy(zero_copy_only=False)[sel]
        both = (dr == "up") | (dr == "down")
        check["dir_agree"] = float(((dr[both] == "up") == (pk["dir"][mine][both] == 0)).mean()) if both.any() else None
    else:
        cands = []
        check["mismatch"] = True
    final = np.full(n, cm.unknown, np.int8)
    amb = np.zeros(n, np.uint8)
    elen = pk["elen"].astype(np.int64)
    stats = {"esp_bytes": int(elen.sum())}
    if m["stage"] in cm.single:
        ra = cm.apps.index(cm.run_app(m))
        final[:] = ra
        if m["stage"] == "realism":
            final[raw == cm.apps.index("bulk")] = cm.apps.index("bulk")
        else:
            oth = (raw < raw_other) & (raw != ra)
            final[oth] = raw[oth]
            final[raw == raw_other] = cm.unknown
        moved = final != ra
        stats["run_app"] = cm.apps[ra]
        stats["relabelled_bytes"] = {cm.apps[a] if a < cm.unknown else "unknown": int(elen[moved & (final == a)].sum())
                                     for a in np.unique(final[moved]).tolist()}
        stats["relabelled_packets"] = int(moved.sum())
    else:
        ok = raw < raw_other
        final[ok] = raw[ok]
        am = np.nonzero(raw == raw_amb)[0]
        iv = intervals(sched, (m.get("cse", 0.0)) - t0)
        res = 0
        for dv in np.unique(amb_of[am]).tolist():
            rows = am[amb_of[am] == dv]
            cand = cands[dv]
            t = pk["t"][rows]
            act = np.zeros((len(cand), len(rows)), bool)
            for k, c in enumerate(cand):
                for s, e in iv.get(cm.apps[c], []):
                    act[k] |= (t >= s) & (t <= e)
            one = act.sum(0) == 1
            pick = np.array(cand)[act.argmax(0)] if cand else np.zeros(len(rows), int)
            final[rows[one]] = pick[one]
            res += int(elen[rows[one]].sum())
            bits = sum(1 << c for c in cand)
            amb[rows[~one]] = bits
        stats["ambiguous_bytes"] = int(elen[am].sum())
        stats["ambiguous_resolved_bytes"] = res
    return raw, final, amb, stats, check


def do_run(rid, m, d, tier, out):
    t = time.time()
    meta = json.loads((d / "meta.json").read_text())
    sched = json.loads((d / "schedule.json").read_text()) if (d / "schedule.json").exists() else {}
    files = [d / "outer.pcap.zst"] + ([d / "ike.pcap.zst"] if (d / "ike.pcap.zst").exists() else [])
    r = parse.parse(files, str(cm.data / "tmp"))
    pk = r["packets"]
    t0 = r["t0"] / 1e9
    lf = cm.data / "labels" / tier / rid / "labels.parquet"
    lab = pq.read_table(lf, columns=["kind", "dir", "app"], read_dictionary=["kind", "dir", "app"]) if lf.exists() else None
    info = {"cse": sched.get("capture_start_epoch", t0)}
    mm = {**m, **info}
    raw, final, amb, stats, check = labels_for(mm, pk, t0, sched, lab, r["counts"]["rows"][0])
    split = "test" if m["stage"] == "realism" else m["split"]
    cfg = m["config"]
    row = {"run_id": rid, "tier": tier, "stage": m["stage"], "scenario": m.get("scenario"), "split": split,
           "recorded_split": m["split"], "group": cm.group(rid), "tunnel_group": m.get("group"),
           "config": cfg, "suite": cm.suite_of(cfg), "apps": m.get("apps"), "label": m.get("label"),
           "netem": m.get("netem"), "capture_start": m.get("capture_start"), "noise": m.get("noise"),
           "replayed": m.get("replayed"), "internet": m.get("internet"), "edge_case": m.get("edge_case"),
           "timing_valid": m.get("timing_valid"), "recapture_of": meta.get("recapture_of"),
           "replay": {"source": meta.get("source"), **{k: meta["replay"].get(k) for k in (
               "scenario", "device", "source_file", "split")}} if meta.get("replay") else None,
           "duration_s": m.get("duration_s"), "t0": r["t0"], "cse": info["cse"],
           "schedule": intervals(sched, info["cse"] - t0), "tunnels": r["tunnels"], "counts": r["counts"],
           "labels": {**stats, **check}}
    table = pa.table({"t": pk["t"], "tunnel": pk["tunnel"], "pair": pk["pair"], "dir": pk["dir"],
                      "elen": pk["elen"], "raw": raw, "app": final, "amb": amb})
    out.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, out / f"{rid}.parquet", compression="zstd")
    (out / f"{rid}.json").write_text(json.dumps(row, default=int) + "\n")
    return len(pk["t"]), time.time() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", required=True, choices=list(cm.tiers))
    ap.add_argument("--ids", nargs="+")
    a = ap.parse_args()
    rs = {r: m for r, m in cm.runs().items() if cm.label_tier(m) == a.tier}
    if a.ids:
        rs = {r: m for r, m in rs.items() if r in a.ids}
    out = cm.feat / a.tier
    done = {p.stem for p in out.glob("*.json")} if out.exists() else set()
    keep = keep_list(rs)
    work = cm.data / "raw" / a.tier
    (cm.data / "tmp").mkdir(parents=True, exist_ok=True)
    log = open(cm.feat / f"prep-{a.tier}.log", "a")
    todo = set(rs) - done
    print(f"{a.tier}: {len(rs)} runs, {len(done & set(rs))} cached, {len(todo)} to do", flush=True)
    t_all = time.time()
    for rel in cm.tiers[a.tier]:
        if not todo:
            break
        for arc in sorted((cm.data / "dl" / rel).glob("*.tar.zst")):
            for rid in stream(arc, work):
                d = work / rid
                if rid in todo:
                    if mem_used() > 0.80:
                        print(f"memory at {mem_used():.0%}: stopping (resume later)", flush=True)
                        sys.exit(2)
                    n, s = do_run(rid, rs[rid], d, a.tier, out)
                    todo.discard(rid)
                    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                    line = f"{rid:34} esp {n:>8} {s:6.1f}s peak rss {rss:6.0f} MB, system {mem_used():.0%}"
                    print(line, flush=True)
                    log.write(line + "\n")
                    log.flush()
                    if rid in keep:
                        k = cm.data / "keep" / rid
                        k.mkdir(parents=True, exist_ok=True)
                        for f in wanted:
                            if (d / f).exists():
                                shutil.copy(d / f, k / f)
                if d.exists():
                    shutil.rmtree(d)
    print(f"done in {time.time() - t_all:.0f}s, {len(todo)} runs missing: {sorted(todo)[:10]}", flush=True)


if __name__ == "__main__":
    main()
