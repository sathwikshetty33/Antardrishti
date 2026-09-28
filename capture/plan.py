"""build the deterministic run plan for a tier from matrix.yaml + edge.yaml.

every random choice uses an rng seeded from (tier seed, stage, config key, rep),
so the plan is identical across machines and independent of ordering.

traffic-like stages (traffic, mixtures, chat, whatsapp, realism, public) are
built as tunnel groups: the runs of one set-A config share one tunnel. the
group's first run is before_tunnel, the others are mid_stream.
"""
import hashlib
import itertools
import json
import random
from collections import Counter
from pathlib import Path

import yaml

here = Path(__file__).resolve().parent
root = here.parent
matrix = yaml.safe_load((here / "matrix.yaml").read_text())
edges = yaml.safe_load((here / "edge.yaml").read_text())
netems = yaml.safe_load((here / "netem.yaml").read_text())

# scheduling classes: heavy apps load cpu (chrome decode, gbit esp + ssh); at most
# one heavy run per machine, and voip never runs next to a heavy one
heavy = {"video", "web", "bulk", "youtube"}
# timing-sensitive stages: each run is captured alone on its machine (placement)
# and records timing_valid. parallel labs bias packet timing (dataset/advval.json);
# edge, handshake and short runs may share a machine
timed = {"traffic", "anchor", "mixtures", "chat", "whatsapp", "realism", "public"}
# tiers sliced with the round-robin dealer (slice_units) and its split tie-break:
# p0 and the adversarial tiers were captured with them, so they stay reproducible
legacy = {"p0", "avs", "avp"}


def h(s, n=8):
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def confighash(cfg):
    return h(json.dumps(cfg, sort_keys=True))


def cross(space):
    keys = ["mode", "esp", "outer_family", "encap"]
    return [dict(zip(keys, v)) for v in itertools.product(*(space[k] for k in keys))]


def set_a(name="a"):
    space = matrix["set_a"] if name == "a" else matrix["subsets"][name]
    cs = cross(space)
    if "pick" in space:
        cs = [cs[i] for i in space["pick"]]
    return [(c, space.get("inner_family")) for c in cs]


def base():
    d = dict(matrix["defaults"])
    d.pop("inner_family")
    return d


def esp_suite(shape, bits):
    """wire shape + key size -> strongswan esp proposal (without dh)"""
    return f"aes{bits}gcm16" if shape == "gcm16" else f"aes{bits}-{shape}"


def a_config(c, rng, inner=None):
    s = matrix["set_a"]["sample"]
    bits = rng.choice(matrix["set_a"]["aes_bits"])
    dh, pfs, auth = rng.choice(s["dh"]), rng.choice(s["pfs"]), rng.choice(s["auth"])
    cfg = {**base(), "ike_proposal": f"{rng.choice(s['ike_enc'])}-{dh}",
           "esp_proposal": esp_suite(c["esp"], bits) + (f"-{dh}" if pfs else ""),
           "esp_shape": c["esp"], "esp_aes_bits": bits, "pfs": pfs, "dh": dh,
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


def randomize(rng, run):
    """per-run draws: netem profile and background noise (the tunnel is shared)"""
    run["netem"] = rng.choice(sorted(netems))
    run["noise"] = rng.random() < matrix["randomize"]["noise"]


def mk(tier, stage, scenario, cfg, rep, seed, apps, duration, **kw):
    run_id = f"{tier}-{scenario}-{confighash(cfg)}-r{rep}"
    return {"run_id": run_id, "tier": tier, "stage": stage, "scenario": scenario,
            "rep": rep, "seed": seed, "config": cfg, "apps": apps,
            "duration_s": duration, "edge_case": None, "replayed": False,
            "internet": False, "group": None, "group_pos": 0, "group_size": 1,
            "capture_start": "before_tunnel", "capture_delay_s": 0, "timed": stage in timed,
            "cls": "heavy" if set(apps) & heavy else ("voip" if "voip" in apps else "light"), **kw}


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
                           st["duration_s"], cls="light")
                    randomize(rng, r)
                    runs.append(r)
            continue
        skip = None
        if st.get("needs") and not ext_files(st["needs"]):
            skip = f"no pcaps in dataset/{st['needs']}"
        combos = st.get("combos") or [[a] for a in st["apps"]]
        if stage in ("realism", "short"):
            combos = [st["apps"]]  # one run carrying all the stage's apps
        for c, inner in set_a(st["set"]):
            for rep in range(1 + rep0, st["reps"] + 1 + rep0):
                key = json.dumps(c, sort_keys=True)
                # one tunnel per (config, rep): drawn once, shared by every app run on it
                rng = random.Random(f"{seed}:{stage}:{key}:{rep}")
                cfg = a_config(c, rng, inner)
                if stage == "realism":
                    cfg["internet"] = True
                group = f"{tier}-{stage}-{confighash(cfg)}-r{rep}"
                order = list(range(len(combos)))
                rng.shuffle(order)
                for pos, i in enumerate(order):
                    apps = combos[i]
                    scen = {"realism": "inet", "short": "short"}.get(stage, "_".join(apps))
                    r_rng = random.Random(f"{seed}:{stage}:{scen}:{key}:{rep}")
                    r = mk(tier, stage, scen, cfg, rep, r_rng.randrange(2**31), apps, st["duration_s"],
                           replayed=stage in ("whatsapp", "public"), internet=stage == "realism",
                           skip=skip, group=group, group_pos=pos, group_size=len(combos),
                           capture_start="before_tunnel" if pos == 0 else "mid_stream")
                    randomize(r_rng, r)
                    runs.append(r)
    assign_split(runs)
    replay_labels(runs)
    return runs


def replay_labels(runs):
    """whatsapp replay runs (owner decision 2026-09-28): half replay chat chunks, half
    voip (call) chunks, two of each per wire shape, the test runs split evenly.
    replay_rank numbers the runs of one (label, split), so each takes another source
    file (gen/replay.py). no design change: these fields are outside plan_sha"""
    wa = [r for r in runs if r["stage"] == "whatsapp"]
    for i, shape in enumerate(sorted({r["config"]["esp_shape"] for r in wa})):
        rs = sorted((r for r in wa if r["config"]["esp_shape"] == shape),
                    key=lambda r: (r["split"] != "test", r["config"]["outer_family"], r["config"]["encap"]))
        pattern = ["chat", "voip"] if i % 2 == 0 else ["voip", "chat"]
        for j, r in enumerate(rs):
            r["replay_label"] = pattern[j % 2]
    rank = Counter()
    for r in sorted(wa, key=lambda r: r["run_id"]):
        k = (r["replay_label"], r["split"])
        r["replay_rank"] = rank[k]
        rank[k] += 1


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
              app_len_s=e.get("app_len_s"), skip=algs_ok(e.get("needs")), cls="light")


def units(runs):
    """scheduling units: a tunnel group (its runs share a tunnel), or a single run"""
    out = {}
    for r in runs:
        out.setdefault(r["group"] or r["run_id"], []).append(r)
    for u in out.values():
        u.sort(key=lambda r: r["group_pos"])
    return out


def assign_split(runs, test_units=0.25, test_runs=0.2):
    """deterministic splits, never across a tunnel.

    tunnel groups (traffic-like stages): 25% test per (tier, stage), stratified by
    (mode, esp shape) so each pair contributes its share; inside a stratum the test
    tunnels rotate over (family, nat-t) such that the two modes of a shape get
    opposite family and nat-t, and every (family, nat-t) combination is used equally.
    with the 32 set-A tunnels: exactly one test tunnel per shape x mode pair (8).
    single runs (handshake, edge): 20% test per (tier, stage, scenario), lowest hash.
    after p0, a stage with fewer test tunnels than strata spreads them: modes
    alternate and shapes rotate per stage, so both modes reach test."""
    split = {}
    us = units(runs)
    strata = {}
    for uid, rs in us.items():
        r = rs[0]
        if r["group"]:
            strata.setdefault(("g", r["tier"], r["stage"]), []).append(uid)
        else:
            strata.setdefault(("r", r["tier"], r["stage"], r["scenario"]), []).append(uid)
    # (family, nat-t) rotation: index i and i + 2 differ in both
    combos = [("v4", False), ("v4", True), ("v6", True), ("v6", False)]
    for k, uids in strata.items():
        if k[0] == "r":
            uids.sort(key=lambda u: h(u, 16))
            n = round(len(uids) * test_runs)
            for i, u in enumerate(uids):
                split[u] = "test" if i < n else "train"
            continue
        by = {}
        for u in uids:
            c = us[u][0]["config"]
            by.setdefault((c["mode"], c.get("esp_shape", c["esp_proposal"])), []).append(u)
        pairs = sorted(by)
        want = round(len(uids) * test_units)
        # largest remainder: how many test tunnels each (mode, shape) stratum gives
        quota = {p: len(by[p]) * want / len(uids) for p in pairs}
        take = {p: int(quota[p]) for p in pairs}
        rot = int(h(f"{k[1]}:{k[2]}", 4), 16) % 4
        shapes = sorted({p[1] for p in pairs})

        def spread(p):
            if k[1] in legacy:
                return p
            j = (shapes.index(p[1]) - rot) % len(shapes)
            return ((j + (p[0] == "transport")) % 2, j)
        for p in sorted(pairs, key=lambda p: (-(quota[p] - take[p]), spread(p)))[:want - sum(take.values())]:
            take[p] += 1
        for p in pairs:
            mode, shape = p
            start = (rot + shapes.index(shape) + (2 if mode == "transport" else 0)) % 4
            def order(u, start=start):
                c = us[u][0]["config"]
                ci = combos.index((c["outer_family"], bool(c["encap"])))
                return ((ci - start) % 4, h(u, 16))
            ranked = sorted(by[p], key=order)
            for j, u in enumerate(ranked):
                split[u] = "test" if j < take[p] else "train"
    for r in runs:
        r["split"] = split[r["group"] or r["run_id"]]


def design_sha():
    """fingerprint of the experiment design: every shard of a tier must share it"""
    return hashlib.sha256(b"".join((here / f).read_bytes() for f in ("matrix.yaml", "edge.yaml", "netem.yaml"))).hexdigest()[:16]


def cost(run):
    """estimated wall seconds for one run"""
    o = matrix["overhead_s"]
    t = run["duration_s"] + run.get("capture_delay_s", 0) + o["base"]
    if run["group_pos"] == 0:
        t += o["tunnel_up"]
    for a in run["apps"]:
        t += o.get(a, 0)
    return t


def plan_sha(runs):
    """fingerprint of a tier's plan (runs, configs, splits, groups): every slice of
    a tier must share it"""
    keys = ("run_id", "stage", "scenario", "config", "apps", "duration_s", "split", "group", "group_pos")
    rows = sorted(({k: r[k] for k in keys} for r in runs), key=lambda x: x["run_id"])
    return h(json.dumps(rows, sort_keys=True), 16)


def slice_units(runs, i, n):
    """--slice i/n: units dealt round-robin in hash order, stratum by stratum
    (tunnel groups by (stage, mode, esp shape), single runs by (stage, scenario)),
    with the dealer position carried across strata. every
    slice gets a balanced mix of apps, configs and scenarios, and totals differ
    by at most one unit per stage."""
    us = units(runs)
    strata = {}
    for uid, rs in us.items():
        r = rs[0]
        # tunnel groups hold every app, so balance them by config; single runs by scenario
        k = (r["stage"], r["config"]["mode"], r["config"].get("esp_shape", "")) if r["group"] else (r["stage"], r["scenario"])
        strata.setdefault(k, []).append(uid)
    keep, deal = set(), 0
    for k in sorted(strata):
        for u in sorted(strata[k], key=lambda u: h(u, 16)):
            if deal % n == i - 1:
                keep.add(u)
            deal += 1
    return [r for r in runs if (r["group"] or r["run_id"]) in keep]


def deal(runs, i, n):
    """--slice i/n after p0 (the legacy tiers keep slice_units). units (tunnel
    groups, single runs) are dealt stratum by stratum (stage, edge case), largest
    units first, each to the least-loaded slice in estimated seconds, so the slices
    finish together. among equally loaded slices a tunnel group goes where its
    config, wire shape and mode are least represented, so no config is tied to one
    machine. replay strata (external pcaps) are dealt round-robin last: whether
    their pcaps exist never moves another unit. inside the slice the units run in
    seeded random order (a group's runs together, in group order), so run type is
    not tied to time of capture; "order" is each run's position."""
    if not runs:
        return []
    us = units(runs)
    strata = {}
    for uid, rs in us.items():
        strata.setdefault((rs[0]["stage"], rs[0]["edge_case"] or ""), []).append(uid)
    ucost = {u: sum(cost(r) for r in rs) for u, rs in us.items()}
    replay = sorted(k for k in strata if us[strata[k][0]][0]["replayed"])
    main = sorted((k for k in strata if k not in replay), key=lambda k: (-max(ucost[u] for u in strata[k]), k))
    load, got = [0] * n, [[] for _ in range(n)]

    def akey(u):
        c = us[u][0]["config"]
        return (c["mode"], c.get("esp_shape", ""), c["outer_family"], bool(c["encap"]))

    def clash(u, s):
        if not us[u][0]["group"]:
            return (0, 0, 0)
        c, have = akey(u), [akey(v) for v in got[s] if us[v][0]["group"]]
        return (sum(x == c for x in have), sum(x[1] == c[1] for x in have), sum(x[0] == c[0] for x in have))

    for k in main:
        for u in sorted(strata[k], key=lambda u: h(u, 16)):
            s = min(range(n), key=lambda s: (load[s], clash(u, s), s))
            load[s] += ucost[u]
            got[s].append(u)
    for j, u in enumerate(u for k in replay for u in sorted(strata[k], key=lambda u: h(u, 16))):
        got[j % n].append(u)
    mine = sorted(got[i - 1])
    random.Random(f"{matrix['seeds'][runs[0]['tier']]}:order:{i}/{n}").shuffle(mine)
    out = []
    for u in mine:
        out += [{**r, "order": len(out) + j} for j, r in enumerate(us[u])]
    return out
