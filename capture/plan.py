"""build the deterministic run plan for a tier from matrix.yaml + edge.yaml.

every random choice uses an rng seeded from (tier seed, stage, config key, rep),
so the plan is identical across machines and independent of ordering.
"""
import hashlib
import itertools
import json
import random
from pathlib import Path

import yaml

here = Path(__file__).resolve().parent
root = here.parent
matrix = yaml.safe_load((here / "matrix.yaml").read_text())
edges = yaml.safe_load((here / "edge.yaml").read_text())
netems = yaml.safe_load((here / "netem.yaml").read_text())


def h(s, n=8):
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def confighash(cfg):
    return h(json.dumps(cfg, sort_keys=True))


def cross(space):
    keys = ["mode", "esp", "outer_family", "encap"]
    return [dict(zip(keys, v)) for v in itertools.product(*(space[k] for k in keys))]


def set_a(name="a"):
    space = matrix["set_a"] if name == "a" else matrix["subsets"][name]
    return [(c, space.get("inner_family")) for c in cross(space)]


def base():
    d = dict(matrix["defaults"])
    d.pop("inner_family")
    return d


def a_config(c, rng, inner=None):
    s = matrix["set_a"]["sample"]
    dh, pfs, auth = rng.choice(s["dh"]), rng.choice(s["pfs"]), rng.choice(s["auth"])
    cfg = {**base(), "ike_proposal": f"{rng.choice(s['ike_enc'])}-{dh}",
           "esp_proposal": c["esp"] + (f"-{dh}" if pfs else ""), "pfs": pfs, "dh": dh,
           "mode": c["mode"], "outer_family": c["outer_family"],
           "inner_family": inner or c["outer_family"], "encap": c["encap"], "auth": auth}
    if auth == "cert":
        cfg["cert_key"] = rng.choice(s["cert_key"])
    if c["mode"] == "transport":
        cfg["inner_family"] = c["outer_family"]
    return cfg


def b_configs():
    b = matrix["set_b"]
    return [dict(zip(("dh", "pfs", "auth"), v)) for v in itertools.product(b["dh"], b["pfs"], b["auth"])]


def b_config(c, rng, rep):
    b = matrix["set_b"]
    fam = rng.choice(b["sample"]["outer_family"])
    cfg = {**base(), "ike_proposal": f"{rng.choice(b['sample']['ike_enc'])}-{c['dh']}",
           "esp_proposal": rng.choice(b["sample"]["esp"]) + (f"-{c['dh']}" if c["pfs"] else ""),
           "pfs": c["pfs"], "dh": c["dh"], "mode": "tunnel", "outer_family": fam,
           "inner_family": fam, "encap": False, "auth": c["auth"],
           "child_rekey_s": rng.randint(*b["child_rekey_s"]),
           "ike_rekey_s": rng.randint(*b["ike_rekey_s"])}
    if c["auth"] == "cert":
        cfg["cert_key"] = b["cert_key_by_rep"][(rep - 1) % len(b["cert_key_by_rep"])]
    return cfg


def edge_base():
    return {**base(), "ike_proposal": "aes256-sha256-ecp256", "esp_proposal": "aes128gcm16-ecp256",
            "pfs": True, "dh": "ecp256", "mode": "tunnel", "outer_family": "v4",
            "inner_family": "v4", "encap": False, "auth": "psk"}


def randomize(rng, run, allow_mid=True):
    r = matrix["randomize"]
    run["netem"] = rng.choice(sorted(netems))
    mid = allow_mid and rng.random() < r["mid_stream"]
    run["capture_start"] = "mid_stream" if mid else "before_tunnel"
    run["capture_delay_s"] = rng.randint(*r["mid_stream_delay_s"]) if mid else 0
    run["noise"] = rng.random() < r["noise"]


def mk(tier, stage, scenario, cfg, rep, seed, apps, duration, **kw):
    run_id = f"{tier}-{scenario}-{confighash(cfg)}-r{rep}"
    return {"run_id": run_id, "tier": tier, "stage": stage, "scenario": scenario,
            "rep": rep, "seed": seed, "config": cfg, "apps": apps,
            "duration_s": duration, "edge_case": None, "replayed": False,
            "internet": False, **kw}


def ext_files(sub):
    d = root / "dataset" / sub
    return sorted(p for p in d.glob("*") if p.suffix in (".pcap", ".pcapng")) if d.exists() else []


def algs_ok(needs):
    env = root / "dataset" / "env.json"
    if not needs:
        return None
    if not env.exists():
        return "run lab/preflight.py first"
    have = {a for v in json.loads(env.read_text())["swanctl_algs"].values() for a in v}
    miss = [n for n in needs if n not in have]
    return f"unsupported: {', '.join(miss)}" if miss else None


def build(tier):
    seed = matrix["seeds"][tier]
    runs = []
    for st in matrix["tiers"][tier]:
        stage = st["stage"]
        rep0 = st.get("rep_offset", 0)
        if stage == "edge":
            for eid, e in edges[st["level"]].items():
                for rep in range(1, st["reps"] + 1):
                    runs.append(edge_run(tier, eid, e, rep, seed))
            continue
        if stage == "handshake":
            for c in b_configs():
                for rep in range(1, st["reps"] + 1):
                    rng = random.Random(f"{seed}:{stage}:{json.dumps(c, sort_keys=True)}:{rep}")
                    cfg = b_config(c, rng, rep)
                    r = mk(tier, stage, "handshake", cfg, rep, rng.randrange(2**31), st["apps"],
                           st["duration_s"])
                    randomize(rng, r, allow_mid=False)
                    runs.append(r)
            continue
        skip = None
        if st.get("needs") and not ext_files(st["needs"]):
            skip = f"no pcaps in dataset/{st['needs']}"
        combos = st.get("combos") or [[a] for a in st["apps"]]
        if stage == "realism":
            combos = [st["apps"]]
        for apps in combos:
            scen = "_".join(apps) if stage != "realism" else "inet"
            for c, inner in set_a(st["set"]):
                for rep in range(1 + rep0, st["reps"] + 1 + rep0):
                    key = json.dumps(c, sort_keys=True)
                    rng = random.Random(f"{seed}:{stage}:{scen}:{key}:{rep}")
                    cfg = a_config(c, rng, inner)
                    if stage == "realism":
                        cfg["internet"] = True
                    r = mk(tier, stage, scen, cfg, rep, rng.randrange(2**31), apps, st["duration_s"],
                           replayed=stage in ("whatsapp", "public"), internet=stage == "realism",
                           skip=skip)
                    randomize(rng, r)
                    runs.append(r)
    assign_split(runs)
    return runs


def edge_run(tier, eid, e, rep, seed):
    """one edge-case run; variants cycle by rep. late-capture cases are mid-stream"""
    cfg = {**edge_base(), **e.get("config", {})}
    vs = e.get("variants")
    if vs:
        cfg.update(vs[(rep - 1) % len(vs)])
    rng = random.Random(f"{seed}:edge:{eid}:{rep}")
    after = max([int(x.split("_")[-1]) for x in e.get("setup", []) if x.startswith("capture_after_")] or [0])
    return mk(tier, "edge", eid, cfg, rep, rng.randrange(2**31), e["apps"], e["duration_s"],
              edge_case=eid, netem="lan", capture_start="mid_stream" if after else "before_tunnel",
              capture_delay_s=after, noise=False, setup=e.get("setup", []),
              over={"a": e.get("a", {}), "b": e.get("b", {})}, expect=e["expect"],
              app_len_s=e.get("app_len_s"), skip=algs_ok(e.get("needs")))


def assign_split(runs, test=0.2):
    """per run, stratified by (tier, stage, scenario): the 20% of runs with the
    lowest hash(run_id) in each stratum go to test. stable across machines."""
    groups = {}
    for r in runs:
        groups.setdefault((r["tier"], r["stage"], r["scenario"]), []).append(r)
    for g in groups.values():
        g.sort(key=lambda r: h(r["run_id"], 16))
        n = round(len(g) * test)
        for i, r in enumerate(g):
            r["split"] = "test" if i < n else "train"


def cost(run):
    return run["duration_s"] + run.get("capture_delay_s", 0) + matrix["overhead_s"]
