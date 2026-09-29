"""one analysis, inside one request: fetch -> size gate -> analyzer -> contract -> rules -> postgres.

progress is committed to the analyses row as the stages advance, so other requests can poll
it. there is no background work: when this returns, the analysis is done or failed.
"""
import shutil
import tempfile
import time
import traceback
from pathlib import Path

import zstandard
from sqlalchemy import delete, insert

from analyzer import bundle as bd
from analyzer import cli
from app.api import models as m
from app.api import settings, storage
from app.api.rules import assess
from app.schema import v1

cached = {}


def bundle():
    """the model bundle selected by MODEL_BUNDLE, checksum-verified once per warm instance"""
    key = str(settings.bundle_dir)
    if key not in cached:
        cached[key] = bd.load(settings.bundle_dir)
    return cached[key]


def bundle_info():
    b = bundle()
    md = b["metadata"]
    return {"version": md.get("bundle", "v1"), "commit": md.get("commit"), "dir": str(settings.bundle_dir.name),
            "seed": md.get("seed"), "models": len(b["boosters"]), "apps": b["schema"]["apps"],
            "suites": b["schema"]["suites"], "results": md.get("results"),
            "data_releases": sorted((md.get("data_releases") or {}).keys())}


def limit_error(mb):
    return (f"the capture is {mb:.0f} MB uncompressed; the hosted analyzer accepts up to {settings.max_pcap_mb:.0f} MB "
            "so that the analysis finishes inside Vercel's 300 s function limit. Split the capture (editcap -c) or run "
            "the analyzer locally: python -m analyzer.cli analyze <pcap> --out result.json")


def unpack(p, limit):
    """a .zst input is decompressed (the uncompressed size counts against the limit)"""
    if p.suffix != ".zst":
        return p
    out = p.with_suffix("")
    size = 0
    with open(p, "rb") as src, open(out, "wb") as dst:
        r = zstandard.ZstdDecompressor().stream_reader(src)
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            size += len(b)
            if size > limit:
                raise storage.too_large(limit_error(size / 2 ** 20))
            dst.write(b)
    p.unlink()
    return out


def set_state(s, a, **kw):
    for k, v in kw.items():
        setattr(a, k, v)
    s.commit()


def run(s, a, inputs):
    """inputs: [(url or local path, name)]. updates a (an analysis row) and returns it"""
    t0 = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="antar-", dir=settings.tmp_dir))
    timings = {}
    try:
        set_state(s, a, status="running", stage="fetching", progress=0.02)
        paths = []
        up_limit = int(settings.upload_limit_mb * 2 ** 20)
        pcap_limit = int(settings.max_pcap_mb * 2 ** 20)
        total = 0
        raw = 0
        # one file at a time: download, decompress, drop the compressed copy, so /tmp (about 512 mb
        # on vercel) holds at most the captures so far plus one upload
        for i, (src, name) in enumerate(inputs):
            dest = tmp / f"{i}-{storage.safe_name(name)}"
            if isinstance(src, Path):
                shutil.copy(src, dest)
                total += dest.stat().st_size
            else:
                total += storage.fetch(src, dest, up_limit)
            q = unpack(dest, pcap_limit - raw)
            raw += q.stat().st_size
            if raw > pcap_limit:
                raise storage.too_large(limit_error(raw / 2 ** 20))
            paths.append(q)
        timings["fetch_s"] = round(time.time() - t0, 3)
        a.size_bytes = int(total)
        t1 = time.time()
        last = [0.0]

        def progress(stage, frac):
            if time.time() - last[0] > 1.0 or frac == 0:
                last[0] = time.time()
                set_state(s, a, stage=stage, progress=round(0.05 + 0.8 * frac, 3))

        res = cli.analyze(paths, bundle(), progress=progress)
        timings["analyze_s"] = round(time.time() - t1, 3)
        res["inputs"] = [n for _, n in inputs]
        doc = v1.validate(res).model_dump(mode="json", exclude_none=False)
        set_state(s, a, stage="rules", progress=0.88)
        t2 = time.time()
        found = assess(doc)
        timings["rules_s"] = round(time.time() - t2, 3)
        set_state(s, a, stage="saving", progress=0.93)
        t3 = time.time()
        persist(s, a, doc, found)
        timings["save_s"] = round(time.time() - t3, 3)
        timings["total_s"] = round(time.time() - t0, 3)
        timings["traffic_s"] = res["timing"]["traffic_seconds"]
        set_state(s, a, status="done", stage="done", progress=1.0, timings=timings, finished_at=m.now(), error=None)
    except storage.too_large as e:
        s.rollback()
        set_state(s, a, status="failed", stage="rejected", error=str(e), finished_at=m.now(), timings=timings)
    except Exception as e:
        s.rollback()
        traceback.print_exc()
        set_state(s, a, status="failed", stage="error", error=f"{type(e).__name__}: {e}", finished_at=m.now(),
                  timings=timings)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return a


def clear(s, aid):
    """remove an analysis' derived rows (a replay step replaces them)"""
    tids = [t.id for t in s.query(m.tunnel.id).filter(m.tunnel.analysis_id == aid)]
    for tab in (m.config_fact, m.window, m.session_share):
        if tids:
            s.execute(delete(tab).where(tab.tunnel_id.in_(tids)))
    for tab in (m.tunnel, m.finding, m.risk_score, m.threat):
        s.execute(delete(tab).where(tab.analysis_id == aid))


def persist(s, a, doc, found):
    clear(s, a.id)
    for t in doc["tunnels"]:
        cfg = dict(t["config"])
        probs = cfg.pop("esp_suite_probabilities", None)
        row = m.tunnel(analysis_id=a.id, idx=t["tunnel"], initiator=t["initiator"], responder=t["responder"],
                       direction_from=t["direction_from"], status=t["handshake_status"], esp_packets=t["esp_packets"],
                       start_s=t["start_s"], end_s=t["end_s"], has_traffic=bool(t.get("windows")),
                       esp_suite_probabilities=probs)
        s.add(row)
        s.flush()
        facts = [{"tunnel_id": row.id, "name": k, "value": v["value"], "confidence": v.get("confidence"),
                  "source": v["source"]} for k, v in cfg.items() if isinstance(v, dict) and "source" in v]
        if facts:
            s.execute(insert(m.config_fact), facts)
        ws = [{"tunnel_id": row.id, "t": w["t"], "pair": w["pair"], "esp_bytes": w["esp_bytes"],
               "packets": w["packets"], "present": w["present"], "probabilities": w["presence_probability"],
               "shares": w["share"]} for w in t.get("windows") or []]
        if ws:
            s.execute(insert(m.window), ws)
        if t.get("byte_share"):
            act, actr = t.get("active_time_share") or {}, t.get("active_time_share_rounded") or {}
            s.execute(insert(m.session_share), [
                {"tunnel_id": row.id, "app": k, "byte_share": v["share"], "error_pp": v["error_pp"],
                 "byte_rounded": t["byte_share_rounded"][k], "active_share": act.get(k),
                 "active_rounded": actr.get(k)} for k, v in t["byte_share"].items()])
    if found["findings"]:
        s.execute(insert(m.finding), [
            {"analysis_id": a.id, "tunnel_idx": f["tunnel"], "check_id": f["check_id"], "title": f["title"],
             "verdict": f["verdict"], "severity": f["severity"], "standard": f["standard"],
             "evidence": f["evidence"], "confidence": f["confidence"], "text": f["text"],
             "recommendation": f["recommendation"], "threats": f["threats"]} for f in found["findings"]])
    rows = [{"analysis_id": a.id, "tunnel_idx": k, "score": v["score"], "band": v["band"], "breakdown": v["counts"]}
            for k, v in found["tunnels"].items()]
    rows.append({"analysis_id": a.id, "tunnel_idx": None, "score": found["overall"]["score"],
                 "band": found["overall"]["band"], "breakdown": {"rule": found["overall"]["rule"]}})
    s.execute(insert(m.risk_score), rows)
    if found["threats"]:
        s.execute(insert(m.threat), [{"analysis_id": a.id, **{k: x[k] for k in ("threat_id", "threat", "likelihood",
                                                                               "impact", "tunnels", "findings")}}
                                     for x in found["threats"]])
    a.result = {**doc, "tunnels": [{k: v for k, v in t.items() if k != "windows"} for t in doc["tunnels"]]}
    a.counts = doc["counts"]
    a.schema_version = doc["schema_version"]
    a.bundle_version = f"{bundle_info()['version']}@{(doc['bundle'] or '')[:7]}"
    a.risk = found["overall"]["score"]
    a.risk_band = found["overall"]["band"]
