"""antardrishti api (fastapi). on vercel this module is the python function (pyproject.toml
tool.vercel.entrypoint); locally: uvicorn app.api.index:app --reload --port 8000"""
import re
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import db, pipeline, replay, settings, storage
from app.api import models as m
from app.api.rules import table as rules_table
from app.schema import v1

app = FastAPI(title="Antardrishti API", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(GZipMiddleware, minimum_size=2048)
capture_ext = re.compile(r"\.(pcap|pcapng|cap)(\.zst)?$", re.I)
sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def guard(x_access_key: str | None = Header(None)):
    """mutating endpoints need APP_ACCESS_KEY when it is set"""
    if settings.access_key and x_access_key != settings.access_key:
        raise HTTPException(401, "missing or wrong access key (x-access-key)")


# ---------------------------------------------------------------- serializers

def summary(a):
    return {"id": a.id, "created_at": a.created_at.isoformat() if a.created_at else None,
            "finished_at": a.finished_at.isoformat() if a.finished_at else None, "status": a.status,
            "progress": a.progress, "stage": a.stage, "error": a.error, "source": a.source, "name": a.name,
            "size_bytes": a.size_bytes, "bundle_version": a.bundle_version, "schema_version": a.schema_version,
            "timings": a.timings, "risk": a.risk, "risk_band": a.risk_band, "replay": a.replay or None,
            "tunnel_count": len((a.result or {}).get("tunnels", [])), "packets": (a.counts or {}).get("packets")}


def facts_of(s, tid):
    return {f.name: {"value": f.value, "confidence": f.confidence, "source": f.source}
            for f in s.query(m.config_fact).filter(m.config_fact.tunnel_id == tid)}


def shares_of(s, tid):
    rows = s.query(m.session_share).filter(m.session_share.tunnel_id == tid).all()
    order = v1.share_names
    rows.sort(key=lambda r: order.index(r.app) if r.app in order else 99)
    return [{"app": r.app, "byte_share": r.byte_share, "byte_rounded": r.byte_rounded, "error_pp": r.error_pp,
             "active_share": r.active_share, "active_rounded": r.active_rounded} for r in rows]


def finding_dict(f):
    return {"id": f.id, "tunnel": f.tunnel_idx, "check_id": f.check_id, "title": f.title, "verdict": f.verdict,
            "severity": f.severity, "standard": f.standard, "evidence": f.evidence, "confidence": f.confidence,
            "text": f.text, "recommendation": f.recommendation, "threats": f.threats}


def findings_of(s, aid, tunnel=None):
    q = s.query(m.finding).filter(m.finding.analysis_id == aid)
    if tunnel is not None:
        q = q.filter(m.finding.tunnel_idx == tunnel)
    out = [finding_dict(f) for f in q]
    rank = {"fail": 0, "warn": 1, "not determinable": 2, "info": 3, "pass": 4}
    return sorted(out, key=lambda f: (rank.get(f["verdict"], 5), sev_order.get(f["severity"], 5), f["check_id"]))


def risks_of(s, aid):
    return {r.tunnel_idx: {"score": r.score, "band": r.band, "breakdown": r.breakdown}
            for r in s.query(m.risk_score).filter(m.risk_score.analysis_id == aid)}


def tunnel_dict(s, t, risks, full=False):
    d = {"idx": t.idx, "initiator": t.initiator, "responder": t.responder, "direction_from": t.direction_from,
         "handshake_status": t.status, "esp_packets": t.esp_packets, "start_s": t.start_s, "end_s": t.end_s,
         "has_traffic": t.has_traffic, "esp_suite_probabilities": t.esp_suite_probabilities,
         "facts": facts_of(s, t.id), "shares": shares_of(s, t.id), "risk": risks.get(t.idx)}
    if full:
        ws = s.query(m.window).filter(m.window.tunnel_id == t.id).order_by(m.window.pair, m.window.t).all()
        d["windows"] = [{"t": w.t, "pair": w.pair, "esp_bytes": w.esp_bytes, "packets": w.packets,
                         "present": w.present, "presence_probability": w.probabilities, "share": w.shares} for w in ws]
    return d


def get_analysis(s, aid):
    a = s.get(m.analysis, aid)
    if a is None:
        raise HTTPException(404, "no such analysis")
    return a


# ---------------------------------------------------------------- service

@app.get("/api/health")
def health():
    out = {"ok": True, "storage": settings.storage, "vercel": settings.on_vercel}
    try:
        with db.session() as s:
            s.execute(text("select 1"))
        out["db"] = "ok"
    except Exception as e:
        out["ok"], out["db"] = False, f"error: {type(e).__name__}"
    try:
        out["bundle"] = pipeline.bundle_info()["version"]
    except Exception as e:
        out["ok"], out["bundle"] = False, f"error: {e}"
    return out


@app.get("/api/model")
def model():
    return {**pipeline.bundle_info(), "schema_version": v1.schema_version,
            "rules": [{"id": r["id"], "title": r["title"], "standard": r["standard"]} for r in rules_table.checks],
            "weights": rules_table.weights, "critical_floor": rules_table.critical_floor,
            "confident": rules_table.confident, "threats": rules_table.threats}


@app.get("/api/config")
def config():
    return {"storage": settings.storage, "upload_limit_mb": settings.upload_limit_mb,
            "max_pcap_mb": settings.max_pcap_mb, "access_key_required": bool(settings.access_key),
            "blob_access": settings.blob_access, "replay_chunk_s": settings.replay_chunk_s,
            "schema_version": v1.schema_version}


# ---------------------------------------------------------------- uploads

@app.post("/api/uploads", dependencies=[Depends(guard)])
async def uploads(request: Request):
    """the @vercel/blob client-upload handshake (handleUploadUrl)"""
    body = await request.json()
    kind = body.get("type")
    if kind == "blob.generate-client-token":
        path = (body.get("payload") or {}).get("pathname", "")
        if not capture_ext.search(path):
            raise HTTPException(400, "only .pcap, .pcapng or .cap captures (optionally .zst) are accepted")
        if settings.storage != "blob":
            raise HTTPException(400, "this deployment stores uploads locally: use PUT /api/uploads/local/{name}")
        token = storage.client_token(f"captures/{storage.safe_name(path)}", settings.upload_limit_mb * 2 ** 20)
        return {"type": kind, "clientToken": token}
    if kind == "blob.upload-completed":
        return {"type": kind, "response": "ok"}
    raise HTTPException(400, "unknown upload event")


@app.put("/api/uploads/local/{name}", dependencies=[Depends(guard)])
async def upload_local(name: str, request: Request):
    if settings.storage != "local":
        raise HTTPException(400, "local uploads are disabled (STORAGE=blob)")
    if not capture_ext.search(name):
        raise HTTPException(400, "only .pcap, .pcapng or .cap captures (optionally .zst) are accepted")

    chunks = [b async for b in request.stream()]
    try:
        url, size = storage.save_local(name, chunks, int(settings.upload_limit_mb * 2 ** 20))
    except storage.too_large as e:
        raise HTTPException(413, str(e))
    return {"url": url, "pathname": name, "size": size}


# ---------------------------------------------------------------- analyses

class upload_ref(BaseModel):
    url: str
    name: str = "capture.pcap"


class start(BaseModel):
    id: str | None = None
    uploads: list[upload_ref] = []
    demo: str | None = None
    name: str | None = None


@app.post("/api/analyses", dependencies=[Depends(guard)])
def create(req: start, s: Session = Depends(db.dep)):
    """start an analysis and run it in this request (the ui polls GET /api/analyses/{id})"""
    aid = req.id or str(uuid.uuid4())
    try:
        uuid.UUID(aid)
    except ValueError:
        raise HTTPException(400, "id must be a uuid")
    if s.get(m.analysis, aid):
        raise HTTPException(409, "analysis id already exists")
    if req.demo:
        try:
            d = replay.demo(req.demo)
        except KeyError:
            raise HTTPException(404, "no such demo")
        inputs = [(settings.demo_dir / d["file"], d["file"])]
        source, name = "demo", req.name or d["title"]
    else:
        if not req.uploads:
            raise HTTPException(400, "give uploads (blob urls) or a demo")
        for u in req.uploads:
            if not (u.url.startswith("local:") or storage.is_blob_url(u.url)):
                raise HTTPException(400, f"not a blob url of this deployment: {u.url[:80]}")
        inputs = [(u.url, u.name) for u in req.uploads]
        source, name = "upload", req.name or ", ".join(u.name for u in req.uploads)
    a = m.analysis(id=aid, source=source, name=name[:200], urls=[str(x[0]) if not isinstance(x[0], Path) else
                                                                 f"demo:{req.demo}" for x in inputs])
    s.add(a)
    s.commit()
    pipeline.run(s, a, inputs)
    return summary(a)


@app.get("/api/analyses")
def list_analyses(limit: int = 30, s: Session = Depends(db.dep)):
    q = s.query(m.analysis).order_by(m.analysis.created_at.desc()).limit(max(1, min(limit, 200)))
    return [summary(a) for a in q]


@app.get("/api/analyses/{aid}")
def get_one(aid: str, s: Session = Depends(db.dep)):
    a = s.get(m.analysis, aid)
    if a is None:
        return {"id": aid, "status": "pending", "progress": 0.0, "stage": "waiting"}
    return summary(a)


@app.get("/api/analyses/{aid}/tunnels")
def tunnels(aid: str, s: Session = Depends(db.dep)):
    get_analysis(s, aid)
    risks = risks_of(s, aid)
    rows = s.query(m.tunnel).filter(m.tunnel.analysis_id == aid).order_by(m.tunnel.idx).all()
    return [tunnel_dict(s, t, risks) for t in rows]


@app.get("/api/analyses/{aid}/tunnels/{idx}")
def tunnel_detail(aid: str, idx: int, s: Session = Depends(db.dep)):
    get_analysis(s, aid)
    t = s.query(m.tunnel).filter(m.tunnel.analysis_id == aid, m.tunnel.idx == idx).first()
    if t is None:
        raise HTTPException(404, "no such tunnel")
    d = tunnel_dict(s, t, risks_of(s, aid), full=True)
    d["findings"] = findings_of(s, aid, idx)
    return d


@app.get("/api/analyses/{aid}/findings")
def findings(aid: str, s: Session = Depends(db.dep)):
    get_analysis(s, aid)
    return findings_of(s, aid)


@app.get("/api/analyses/{aid}/threats")
def threats(aid: str, s: Session = Depends(db.dep)):
    get_analysis(s, aid)
    rows = s.query(m.threat).filter(m.threat.analysis_id == aid).all()
    return {"threats": [{"threat_id": r.threat_id, "threat": r.threat, "likelihood": r.likelihood, "impact": r.impact,
                         "tunnels": r.tunnels, "findings": r.findings} for r in rows],
            "scale": {"likelihood": [1, 5], "impact": [1, 5]}}


@app.get("/api/analyses/{aid}/report")
def report(aid: str, s: Session = Depends(db.dep)):
    """everything the executive and technical reports show, in one response"""
    a = get_analysis(s, aid)
    risks = risks_of(s, aid)
    rows = s.query(m.tunnel).filter(m.tunnel.analysis_id == aid).order_by(m.tunnel.idx).all()
    return {"analysis": summary(a), "overall": risks.get(None), "tunnels": [tunnel_dict(s, t, risks, full=True)
                                                                            for t in rows],
            "findings": findings_of(s, aid), "threats": threats(aid, s)["threats"], "model": model(),
            "counts": a.counts, "inputs": (a.result or {}).get("inputs", [])}


@app.get("/api/overview")
def overview(s: Session = Depends(db.dep)):
    """recent analyses, the latest finished analysis' tunnels and risk, and critical alerts"""
    recent = s.query(m.analysis).order_by(m.analysis.created_at.desc()).limit(8).all()
    done = s.query(m.analysis).filter(m.analysis.status == "done").order_by(m.analysis.created_at.desc()).limit(20).all()
    inventory, alerts = [], []
    for a in done:
        risks = risks_of(s, a.id)
        for t in s.query(m.tunnel).filter(m.tunnel.analysis_id == a.id).order_by(m.tunnel.idx):
            f = facts_of(s, t.id)
            inventory.append({"analysis_id": a.id, "analysis": a.name, "created_at": a.created_at.isoformat(),
                              "idx": t.idx, "initiator": t.initiator, "responder": t.responder,
                              "handshake_status": t.status, "esp_packets": t.esp_packets,
                              "esp_suite": f.get("esp_suite"), "mode": f.get("mode"),
                              "ike_version": f.get("ike_version"), "risk": risks.get(t.idx)})
        for x in findings_of(s, a.id):
            if x["verdict"] == "fail" and x["severity"] in ("critical", "high"):
                alerts.append({**x, "analysis_id": a.id, "analysis": a.name})
    alerts.sort(key=lambda x: sev_order[x["severity"]])
    worst = max((a.risk or 0 for a in done), default=None) if done else None
    return {"recent": [summary(a) for a in recent], "inventory": inventory[:60], "alerts": alerts[:12],
            "overall": {"score": worst, "rule": "worst tunnel over the last 20 finished analyses"},
            "analyses_done": len(done)}


# ---------------------------------------------------------------- demos and replay

@app.get("/api/demos")
def list_demos():
    return [{k: d[k] for k in ("name", "title", "description", "bytes", "packets", "duration_s")} |
            {"steps": replay.steps(d["name"])} for d in replay.demos()]


class replay_start(BaseModel):
    demo: str


@app.post("/api/replays", dependencies=[Depends(guard)])
def replay_create(req: replay_start, s: Session = Depends(db.dep)):
    try:
        d = replay.demo(req.demo)
    except KeyError:
        raise HTTPException(404, "no such demo")
    a = m.analysis(source="replay", name=f"Replay: {d['title']}", urls=[f"demo:{d['name']}"], status="replaying",
                   stage="waiting", replay={"demo": d["name"], "step": 0, "steps": replay.steps(d["name"]), "t": 0.0,
                                            "packets": 0})
    s.add(a)
    s.commit()
    return summary(a)


@app.post("/api/replays/{aid}/next", dependencies=[Depends(guard)])
def replay_next(aid: str, s: Session = Depends(db.dep)):
    a = get_analysis(s, aid)
    if a.source != "replay":
        raise HTTPException(400, "not a replay")
    t = time.time()
    got = replay.append_next(s, a)
    if got is None:
        return summary(a)
    path, step, t_end, packets = got
    try:
        pipeline.run(s, a, [(path, f"{a.replay['demo']}-replay.pcap")])
    finally:
        path.unlink(missing_ok=True)
    a.replay = {**a.replay, "step": step, "t": t_end, "packets": packets, "step_s": round(time.time() - t, 3)}
    if step < a.replay["steps"] and a.status == "done":
        a.status = "replaying"
    s.commit()
    return summary(a)
