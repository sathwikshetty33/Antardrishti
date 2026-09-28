"""rule engine: an analyzer result (app/schema v1) -> findings, risk scores, threat matrix.

each check is a row of table.py. a finding's confidence is the lowest confidence of the facts
it rests on (observed and read-from-IKE facts count as 1.0); below table.confident its text
says "likely". facts that are not observable give "not determinable" findings.
"""
import re

from app.api.rules import table as tb

neutral = ("pass", "info", "not determinable")


def fact_map(t):
    """fact name -> {value, confidence, source}, with the derived facts the table reads"""
    cfg = dict(t.get("config") or {})
    cfg.pop("esp_suite_probabilities", None)
    f = {k: {"value": v["value"], "confidence": v.get("confidence"), "source": v["source"]}
         for k, v in cfg.items() if isinstance(v, dict) and "source" in v}
    enc = f.get("ike_encryption")
    if enc:
        m = re.search(r"-(\d{2,3})$", str(enc["value"]))
        if m:
            f["_ike_key_bits"] = {"value": int(m.group(1)), "confidence": 1.0, "source": "read from IKE"}
    times = (f.get("rekey_times_s") or {}).get("value") or {}
    child = sorted(times.get("child", []))
    if len(child) >= 2:
        f["_child_lifetime_s"] = {"value": max(b - a for a, b in zip(child, child[1:])), "confidence": 1.0,
                                  "source": "observed"}
    ikes = sorted(times.get("ike_sa", []))
    if "ike_lifetime_s" in f:
        f["_ike_lifetime_s"] = dict(f["ike_lifetime_s"])
    elif len(ikes) >= 2:
        f["_ike_lifetime_s"] = {"value": max(b - a for a, b in zip(ikes, ikes[1:])), "confidence": 1.0,
                                "source": "observed"}
    if "ike_version" in f:
        ns = (f.get("ike_notifies") or {}).get("value") or []
        errs = [tb.notify_names.get(n, f"notify {n}") for n in ns if n < 16384 and n not in tb.benign_errors]
        f["_error_notifies"] = {"value": ", ".join(errs) or "none", "confidence": 1.0, "source": "read from IKE"}
        f["_cookie"] = {"value": tb.cookie in ns, "confidence": 1.0, "source": "read from IKE"}
    ids = identifiable(t)
    if ids is not None:
        f["_identifiable"] = ids
    return f


def identifiable(t):
    """apps a passive observer can pick out: byte share and mean presence probability where present"""
    ws, bs = t.get("windows"), t.get("byte_share")
    if not ws or not bs:
        return None
    found = []
    for a, v in bs.items():
        if a == "unknown" or v["share"] < tb.identifiable["min_share_pct"]:
            continue
        ps = [w["presence_probability"][a] for w in ws if a in w["present"]]
        if ps and sum(ps) / len(ps) >= tb.identifiable["min_probability"]:
            found.append((a, sum(ps) / len(ps), v["share"]))
    if not found:
        return {"value": "none", "confidence": 1.0, "source": "inferred"}
    found.sort(key=lambda x: -x[2])
    text = ", ".join(f"{a} ({s:.0f}% of bytes, presence {p:.0%})" for a, p, s in found)
    return {"value": text, "confidence": min(p for _, p, _ in found), "source": "inferred", "apps": found}


def applies(row, f):
    for k, want in (row.get("when") or {}).items():
        v = (f.get(k) or {}).get("value")
        if v is None:
            return False
        if not any(v == w or (isinstance(v, str) and isinstance(w, str) and v.startswith(w)) for w in want):
            return False
    return True


def pick(row, v):
    out = row["outcomes"]
    kind = row.get("match", "exact")
    if kind == "range":
        for (lo, hi), o in out.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v < hi:
                return o
    elif kind == "prefix":
        for k in sorted((k for k in out if k != "*"), key=len, reverse=True):
            if isinstance(v, str) and v.startswith(k):
                return out[k]
    else:
        for k, o in out.items():
            if k != "*" and k == v and type(k) is type(v):
                return o
    return out.get("*")


def wording(text, conf, verdict):
    if verdict != "not determinable" and conf is not None and conf < tb.confident:
        return f"Likely ({conf:.0%} confidence): {text[0].lower() + text[1:]}"
    return text[0].upper() + text[1:]


def evaluate(t):
    """findings of one tunnel result"""
    f = fact_map(t)
    out = []
    for row in tb.checks:
        if not applies(row, f):
            continue
        x = f.get(row["fact"])
        if x is None or x["value"] is None:
            verdict, sev, text = row["missing"]
            conf, ev = None, []
        else:
            o = pick(row, x["value"])
            if o is None:
                continue
            verdict, sev, text = o
            conf = 1.0 if x["confidence"] is None else float(x["confidence"])
            if verdict == "not determinable":
                conf = None
            ev = [{"fact": row["fact"].lstrip("_"), "value": x["value"], "source": x["source"],
                   "confidence": x["confidence"]}]
            notes = ""
            if row["id"] == "NEGOTIATION" and f.get("_error_notifies", {}).get("value", "none") != "none":
                notes = f" (notified: {f['_error_notifies']['value']})"
            try:
                text = text.format(value=x["value"], notes=notes)
            except (ValueError, KeyError):
                text = text.replace("{value}", str(x["value"])).replace("{notes}", notes)
        if verdict in neutral:
            sev = "info"
        out.append({"check_id": row["id"], "title": row["title"], "tunnel": t.get("tunnel"), "verdict": verdict,
                    "severity": sev, "standard": row["standard"], "evidence": ev, "confidence": conf,
                    "text": wording(text or row["title"], conf, verdict),
                    "recommendation": row["fix"] if verdict in ("fail", "warn") else "",
                    "threats": row["threats"] if verdict in ("fail", "warn") else []})
    return out


def score(findings):
    """0-100: severity weights times confidence, capped; a confident critical sets the floor"""
    s = 0.0
    floor = 0
    for x in findings:
        if x["verdict"] not in ("fail", "warn"):
            continue
        c = x["confidence"] if x["confidence"] is not None else 1.0
        s += tb.weights[x["severity"]] * c
        if x["severity"] == "critical" and x["verdict"] == "fail" and c >= tb.confident:
            floor = tb.critical_floor
    return int(round(min(100.0, max(s, floor))))


def band(s):
    return "critical" if s >= 90 else "high" if s >= 60 else "medium" if s >= 30 else "low" if s > 0 else "none"


def threat_matrix(findings):
    """threat -> likelihood (from its linked findings' severity and confidence), impact, tunnels"""
    out = []
    for tid, th in tb.threats.items():
        linked = [x for x in findings if tid in x["threats"]]
        if not linked:
            continue
        lk = max(max(1, min(5, round(tb.likelihood[x["severity"]] * (x["confidence"] if x["confidence"] is not None
                                                                     else 1.0)))) for x in linked)
        out.append({"threat_id": tid, "threat": th["threat"], "likelihood": int(lk), "impact": th["impact"],
                    "tunnels": sorted({x["tunnel"] for x in linked}),
                    "findings": [f"{x['check_id']}#{x['tunnel']}" for x in linked]})
    return sorted(out, key=lambda x: -(x["likelihood"] * x["impact"]))


def assess(result):
    """-> {findings, tunnels: {tunnel: {score, band}}, overall: {score, band}, threats}"""
    findings = []
    tunnels = {}
    for t in result.get("tunnels", []):
        fs = evaluate(t)
        findings += fs
        s = score(fs)
        tunnels[t["tunnel"]] = {"score": s, "band": band(s),
                                "counts": {v: sum(1 for x in fs if x["verdict"] == v)
                                           for v in ("fail", "warn", "pass", "info", "not determinable")}}
    overall = max((v["score"] for v in tunnels.values()), default=0)
    return {"findings": findings, "tunnels": tunnels, "overall": {"score": overall, "band": band(overall),
                                                                  "rule": "worst tunnel"},
            "threats": threat_matrix(findings)}
