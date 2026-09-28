"""shared names, paths and manifest reading for the analyzer"""
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parent.parent
data = Path(os.environ.get("ANTAR_DATA", Path.home() / "antar-data"))
feat = root / "features"
models = root / "models" / "v1"
report = root / "analyzer" / "report"
seed = 26006
apps = ["voip", "video", "web", "email", "icmp", "bulk", "chat"]
unknown = len(apps)
suites = ["gcm16", "cbc_icv12", "cbc_icv16", "cbc_icv24"]
shape_of = {"gcm16": "gcm16", "sha1": "cbc_icv12", "sha256": "cbc_icv16", "sha384": "cbc_icv24"}
alias = {"web_light": "web", "youtube": "video"}
tiers = {"p0": ["p0-data"], "p0s": ["p0s-data"], "p1": ["p1-data"], "p1-whatsapp": ["p1-whatsapp"]}
single = ("traffic", "anchor", "chat", "realism", "whatsapp")


def suite_of(cfg):
    """wire shape class of a run's esp proposal, or None outside the four shapes"""
    s = cfg.get("esp_shape")
    if s in shape_of:
        return shape_of[s]
    p = cfg.get("esp_proposal", "").lower()
    if p.startswith(("3des", "null")) or "md5" in p or "sha512" in p:
        return None
    if "gcm16" in p:
        return "gcm16"
    for k in ("sha384", "sha256", "sha1"):
        if f"-{k}" in p:
            return shape_of[k]
    return None


def runs():
    """run_id -> latest ok attempt, annotations merged (dataset/CLAUDE.md section 4)"""
    last = {}
    for l in (root / "dataset" / "manifest.jsonl").read_text().splitlines():
        if not l.strip():
            continue
        m = json.loads(l)
        if "annotation" in m:
            if m["run_id"] in last:
                last[m["run_id"]].update(m["annotation"])
            continue
        if m["status"] == "ok":
            last[m["run_id"]] = m
    return {r: m for r, m in last.items() if m["tier"] in ("p0", "p0s", "p1")}


def label_tier(m):
    """the folder of a run's labels and cached features"""
    return "p1-whatsapp" if m["stage"] == "whatsapp" else m["tier"]


def group(rid):
    """cv group: the config hash, the third field of the run_id"""
    return rid.split("-")[-2]


def run_app(m):
    """the app of a single-app run"""
    if m["stage"] == "realism":
        return "web"
    if m.get("label"):
        return m["label"]
    return alias.get(m["apps"][0], m["apps"][0])
