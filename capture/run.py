"""orchestrator: plan -> run -> validate -> record.

usage: python3 capture/run.py --tier p0 [--labs 3] [--slice 1/2] [--scenario voip e01 ...]
                              [--resume] [--fill-gaps] [--dry-run] [--limit N] [--yes]

resumable: runs whose latest manifest entry is ok are always skipped, so a
killed batch (idle timeout, ctrl-c) continues where it stopped. batches over
2 hours need --yes (ask the user first).

--labs n runs n labs side by side on this machine, one worker process each
(placement rules in capture/placement.py). --slice i/n takes a deterministic,
balanced share of the plan so teammates' codespaces can split it (merge the
manifests with tools/merge.py). after p0 a slice runs in its seeded order
(plan.deal), and timing-sensitive runs are captured alone on the machine.
"""
import argparse
import hashlib
import importlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

here = Path(__file__).resolve().parent
sys.path[:0] = [str(here), str(here.parent / "lab"), str(here.parent / "gen")]
import common
import observe
import placement
import plan
import topo
from lab import dx, sh

root = plan.root
raw = root / "dataset" / "raw"
manifest = root / "dataset" / "manifest.jsonl"
env = json.loads((root / "dataset" / "env.json").read_text()) if (root / "dataset" / "env.json").exists() else {}
backend = env.get("ipsec_backend", "kernel")
r_ = topo.c["router"]
esp_min = 100          # traffic runs below this many esp packets fail validation
snat_ip = "172.31.1.11"  # e12: gw_a's udp leaves through a source nat to this address
attempts = 3           # first try + 2 retries


logfile = None   # dataset/raw/_logs/<tier>-<stamp>.log: survives codespace restarts, unlike /tmp
lab_versions = {}  # package versions + image ids of this batch (topo.versions)
plan_id = ""       # plan.plan_sha of the batch's tier, recorded in every run
n_labs = int(os.environ.get("ANTAR_LABS", "1"))  # labs running side by side in this batch


def log(*a):
    line = " ".join([time.strftime("%H:%M:%S"), *map(str, a)])
    print(line, flush=True)
    if logfile:
        with open(logfile, "a") as f:
            f.write(line + "\n")


# ---------------------------------------------------------------- manifest

def history():
    last, tries = {}, Counter()
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                if "annotation" in m:
                    continue
                last[m["run_id"]] = m["status"]
                tries[m["run_id"]] += 1
    return last, tries


slim = ("notes", "sha256")


def record(meta):
    """one line per attempt; the full record stays in raw/<run_id>/meta.json"""
    m = {k: v for k, v in meta.items() if k not in slim}
    m["observed"] = {k: v for k, v in (meta.get("observed") or {}).items()
                     if k not in ("errors", "proposals", "esp_first_seq", "replay_counter", "spis", "ike_spis")}
    import fcntl
    with open(manifest, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(m, sort_keys=True, default=list) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)


# ---------------------------------------------------------------- captures

def cap_start(run, inner_on):
    """outer + ike on the router, inner on host_a (tunnel) or nflog on gw_a (transport)"""
    dx(r_, "pkill tcpdump; rm -rf /tmp/cap; mkdir -p /tmp/cap; true")
    dx(r_, "tcpdump -i any -s 128 --time-stamp-precision nano -w /tmp/cap/outer.pcap >/dev/null 2>&1", detach=True)
    # full packets for ike only: on 4500 keep what starts with the 4-byte non-esp
    # marker, so esp-in-udp data never lands in this capture
    bpf = ("udp port 500 or (ip and udp port 4500 and udp[8:4] = 0) or "
           "(ip6 and udp port 4500 and ip6[48:4] = 0)")
    dx(r_, f"tcpdump -i any -s 0 --time-stamp-precision nano -w /tmp/cap/ike_full.pcap '{bpf}' >/dev/null 2>&1", detach=True)
    if inner_on:
        n, cmd = inner_cmd(run)
        dx(n, "pkill tcpdump; rm -rf /tmp/cap; mkdir -p /tmp/cap; true")
        dx(n, cmd, detach=True)
    time.sleep(1)
    # fail fast: a capture that did not start must not look like "0 packets"
    _, out = dx(r_, "pgrep -c -x tcpdump", check=False)
    if out.strip() != "2":
        raise RuntimeError(f"router captures not running ({out.strip()} tcpdump)")
    if inner_on and dx(n, "pgrep -x tcpdump", check=False)[0] != 0:
        raise RuntimeError(f"inner capture on {n} did not start")
    return time.time()


def inner_cmd(run):
    # nflog cannot do nanosecond time stamps: transport-mode inner is microsecond
    if run["config"]["mode"] == "transport":
        return topo.c["gw_a"], "tcpdump -i nflog:7 -s 0 -w /tmp/cap/inner.pcap >/dev/null 2>&1"
    return topo.c["host_a"], "tcpdump -i eth0 -s 96 --time-stamp-precision nano -w /tmp/cap/inner.pcap not arp >/dev/null 2>&1"


def cap_stop(run, d):
    n, _ = inner_cmd(run)
    for x in (r_, n):
        dx(x, "pkill -INT tcpdump; sleep 1; pkill tcpdump; true", check=False)
    sh(f"docker cp {r_}:/tmp/cap/outer.pcap {d}/outer.pcap")
    sh(f"docker cp {r_}:/tmp/cap/ike_full.pcap {d}/ike_full.pcap")
    if dx(n, "test -f /tmp/cap/inner.pcap", check=False)[0] == 0:
        sh(f"docker cp {n}:/tmp/cap/inner.pcap {d}/inner.pcap")
    else:
        sh(f": > {d}/inner.pcap")
    # ike.pcap keeps ike only (esp-in-udp data would make it large)
    sh(f"tshark -r {d}/ike_full.pcap -Y isakmp -w {d}/ike.pcap -F pcap", check=False, timeout=600)
    if not (d / "ike.pcap").exists():
        shutil.copy(d / "ike_full.pcap", d / "ike.pcap")
    (d / "ike_full.pcap").unlink()


def xfrm_snap(d, tag):
    for s in "ab":
        _, out = dx(topo.c[f"gw_{s}"], "ip -s xfrm state; echo; ip xfrm policy", check=False)
        with open(d / f"xfrm_{s}.txt", "a") as f:
            f.write(f"== {tag} {time.time():.3f}\n{out}\n")


xfrm_every_s = 10


def xfrm_tick(d, last):
    """periodic key dumps during the capture (xfrm_<gw>_periodic.txt, apart from the
    start and end dumps that validation reads): an sa rekeyed away before the end dump
    keeps its keys for the labels"""
    if time.time() - last[0] < xfrm_every_s:
        return
    last[0] = time.time()
    for s in "ab":
        _, out = dx(topo.c[f"gw_{s}"], "ip -s xfrm state", check=False)
        with open(d / f"xfrm_{s}_periodic.txt", "a") as f:
            f.write(f"== periodic {time.time():.3f}\n{out}\n")


# ---------------------------------------------------------------- lab state

def reset(run):
    """a clean lab: no ipsec, no nflog, no nat, no extra initiators, plus reset_traffic"""
    topo.stop_ipsec()
    topo.nflog(False)
    topo.nat(False)
    reset_traffic(run)
    if run.get("edge_case") != "e18":
        topo.multi_down()


def reset_traffic(run):
    """between two runs on a kept tunnel: no netem, edge rules, captures, noise,
    generators or internet dns left over. the tunnel (charon, sas, policies) stays up"""
    topo.netem(None)
    topo.inet_dns(False)
    dx(r_, "nft delete table inet edge 2>/dev/null; pkill tcpdump; pkill tcpreplay; true", check=False)
    for ipt in ("iptables", "ip6tables"):
        dx(topo.c["gw_b"], f"while {ipt} -D OUTPUT -p udp -m multiport --sports 500,4500 -j DROP 2>/dev/null; do :; done", check=False)
    g = topo.c["gw_a"]
    dev = topo.iface(g, topo.gw["a"]["v4"])
    dx(g, f"while iptables -t nat -D POSTROUTING -o {dev} -s {topo.gw['a']['v4']} -p udp -j SNAT --to-source {snat_ip} 2>/dev/null; do :; done; "
          f"ip addr del {snat_ip}/24 dev {dev} 2>/dev/null; conntrack -F 2>/dev/null; true", check=False)
    dx(topo.c["noise_a"], "pkill -f [n]oise.py; true", check=False)
    for n in ("host_a", "cli_gw", "host_b", "svc_gw"):
        dx(topo.c[n], "pkill -f [p]ython3.-u./gen; pkill baresip; pkill -f [c]hrome; pkill tcpreplay; "
                      "iptables -S INPUT | grep -- '-j DROP' | sed 's/^-A/-D/' | xargs -r -L1 iptables; true", check=False)


def edge_rules(rules):
    txt = "\n".join(["add table inet edge", "add chain inet edge fwd_ { type filter hook forward priority -20; }"] +
                    [f"add rule inet edge fwd_ {r}" for r in rules])
    topo.put(r_, "/tmp/edge.nft", txt + "\n")
    dx(r_, "nft -f /tmp/edge.nft")


def pre_setup(run):
    """edge actions that must be in place before the tunnel is initiated"""
    st = run.get("setup", [])
    notes = {}
    if "drop_ike_from_responder" in st:
        # at gw_b's egress, not on the router: the router's tcpdump sees ingress
        # before any forward drop, and the wire must show a silent responder
        for ipt in ("iptables", "ip6tables"):
            dx(topo.c["gw_b"], f"{ipt} -I OUTPUT -p udp -m multiport --sports 500,4500 -j DROP")
    if "drop_ike_auth" in st:
        # exchange type is ike header byte 18 (+4 behind the non-esp marker on 4500)
        edge_rules(["udp dport 500 @th,208,8 35 drop", "udp sport 500 @th,208,8 35 drop",
                    "udp dport 4500 @th,240,8 35 drop", "udp sport 4500 @th,240,8 35 drop"])
    if "loss20_during_setup" in st:
        for dev in topo.rtr_ifaces():
            dx(r_, f"tc qdisc replace dev {dev} root netem loss 20%")
    if "extra_initiators" in st:
        notes["extra_ids"] = topo.multi_up()
    if "snat_initiator" in st:
        g = topo.c["gw_a"]
        dev = topo.iface(g, topo.gw["a"]["v4"])
        dx(g, f"ip addr add {snat_ip}/24 dev {dev}")
        dx(g, f"iptables -t nat -A POSTROUTING -o {dev} -s {topo.gw['a']['v4']} -p udp -j SNAT --to-source {snat_ip}")
        # nat is decided on a flow's first packet: drop stale ike flows of earlier runs
        dx(g, "conntrack -F 2>/dev/null; true")
        notes["snat"] = snat_ip
    return notes


def half_open_flood(run):
    fam = run["config"]["outer_family"]
    _, out = dx(topo.c["noise_a"], f"python3 /ikeinit.py {topo.gw['b'][fam]} 3")
    time.sleep(1)
    return out


def replay_esp(run, d):
    """e26: grab up to 40 esp packets gw_a -> gw_b on the router and inject them again
    toward gw_b. the router image has no tcpreplay: the host's runs in the router's
    network namespace (same interface, same frames)"""
    dev = topo.iface(r_, topo.rtr["b"]["v4"])
    src = topo.gw["a"][run["config"]["outer_family"]]
    host = "ip6" if ":" in src else "ip"
    # a fresh file each time: in the sticky /tmp (fs.protected_regular) tcpdump cannot
    # overwrite the one an earlier run left, and would replay a dead sa's packets
    dx(r_, f"rm -f /tmp/replay.pcap; timeout 10 tcpdump -i {dev} -c 40 -w /tmp/replay.pcap "
           f"'{host} src {src} and esp' >/dev/null 2>&1; true", timeout=30)
    f = raw / f".replay-{topo.lab_id}.pcap"
    sh(f"docker cp {r_}:/tmp/replay.pcap {f}")
    n = int(sh(f"tcpdump -nr {f} 2>/dev/null | wc -l", check=False)[1] or 0)
    pid = sh(f"docker inspect -f '{{{{.State.Pid}}}}' {r_}")[1].strip()
    rc, out = sh(f"sudo nsenter -t {pid} -n tcpreplay -q -i {dev} {f}", check=False)
    f.unlink()
    return {"replayed_packets": n, "rc": rc, "out": out[-200:]}


# ---------------------------------------------------------------- apps

def app_plan(run, rng, dur):
    """[(app, offset_s, length_s)] - mixtures are staggered so a run holds pure and mixed segments"""
    apps = [a for a in run["apps"]]
    if run["stage"] == "mixtures" and len(apps) > 1:
        rng.shuffle(apps)
        out = []
        for i, a in enumerate(apps):
            s = 0 if i == 0 else rng.uniform(0, 0.35 * dur)
            e = dur if i == 0 else rng.uniform(max(s + 20, 0.65 * dur), dur)
            out.append((a, round(s, 1), round(max(10, min(e, dur) - s), 1)))
        return out
    return [(a, 0, dur) for a in apps]


def module_for(app):
    return {"icmp_big": "icmp", "chat": "chat"}.get(app, common.module(app))


def run_app(app, seed, ctx, offset, length, out):
    time.sleep(offset)
    mod = importlib.import_module(module_for(app))
    try:
        if app == "icmp_big":
            ev = mod.start(length, seed, ctx, big=True)
        else:
            ev = mod.start(length, seed, ctx)
    except Exception as e:
        ev = [{"app": app, "event": "app", "start": time.time(), "stop": time.time(), "rc": 1, "err": str(e)[:400]}]
    for e in ev:
        e["app"] = app if e.get("app") in (None, module_for(app), common.module(app)) else e["app"]
    out.extend(ev)


def start_apps(run, ctx, dur, rng):
    evs, threads = [], []
    for i, (app, off, length) in enumerate(app_plan(run, rng, dur)):
        seed = (run["seed"] + 7919 * i) % 2**31
        t = threading.Thread(target=run_app, args=(app, seed, ctx, off, length, evs), daemon=True)
        t.start()
        threads.append(t)
    return evs, threads


# ---------------------------------------------------------------- one run

def tunnel_up():
    _, out = dx(topo.c["gw_a"], "swanctl --list-sas", check=False)
    return "ESTABLISHED" in out and "INSTALLED" in out


def log_sizes():
    return {s_: int((dx(topo.c[f"gw_{s_}"], "stat -c %s /var/log/charon.log", check=False)[1] or "0").strip() or 0)
            for s_ in "ab"}


def execute_reuse(run, d, labst):
    """a mid_stream run on its group's kept tunnel: the capture starts on the
    established tunnel, so it holds no ike setup and esp sequence numbers carry
    on from the earlier runs. if the lab lost the tunnel (another lab ran here,
    a resume, a crash) it is rebuilt first, outside the capture"""
    cfg, dur = run["config"], run["duration_s"]
    rng = random.Random(run["seed"])
    notes = {"timeline": []}

    def mark(what, **kw):
        notes["timeline"].append({"t": round(time.time(), 3), "what": what, **kw})

    rebuilt = labst.get("tunnel") != run["group"] or not tunnel_up()
    if rebuilt:
        reset(run)
        labst["confs"] = topo.deploy(cfg, {}, backend)
        if cfg.get("internet"):
            topo.nat(True)
        rc, out = topo.initiate(timeout=40, check=False)
        mark("tunnel_rebuilt", rc=rc)
        labst.update(tunnel=run["group"], tunnel_up=time.time())
        time.sleep(1)
    else:
        reset_traffic(run)
    if cfg.get("internet"):
        notes["dns"] = topo.inet_dns(True)
    for s_ in "ab":
        (d / f"swanctl_{s_}.conf").write_text(labst["confs"][s_])
    if run.get("netem") and run["netem"] != "lan":
        topo.netem(plan.netems[run["netem"]])
    topo.nflog(cfg["mode"] == "transport")
    ctx = topo.gen_ctx(cfg, d)
    ctx.update(split=run["split"], replay_label=run.get("replay_label"), replay_rank=run.get("replay_rank"))
    off = log_sizes()
    t0 = cap_start(run, True)
    mark("capture_start")
    xfrm_snap(d, "start")
    noise_on(run)
    app_len = max(5, dur - (time.time() - t0) - 2)
    evs, threads = start_apps(run, ctx, app_len, rng) if run["apps"] else ([], [])
    mark("apps_start", apps=run["apps"], length=round(app_len, 1))
    tick = [time.time()]
    while time.time() - t0 < dur:
        xfrm_tick(d, tick)
        time.sleep(0.5)
    for t in threads:
        t.join(timeout=60)
    xfrm_snap(d, "end")
    mark("capture_stop")
    noise_off()
    cap_stop(run, d)
    full = {}
    for s_ in "ab":
        _, lg = dx(topo.c[f"gw_{s_}"], "cat /var/log/charon.log", check=False)
        full[s_] = lg
        # the run keeps the log of its own window; the setup is in the group's first run
        (d / f"charon_{s_}.log").write_text(lg.encode()[off[s_]:].decode(errors="replace") + "\n")
    notes["tunnel"] = {"group": run["group"], "reused": not rebuilt, "rebuilt": rebuilt,
                       "age_s": round(t0 - labst["tunnel_up"], 1), "log_offset": off}
    notes["_full_logs"] = full
    sched = [{**e, "start": round(e["start"] - t0, 3), "stop": round(e["stop"] - t0, 3)}
             for e in sorted(evs, key=lambda e: e["start"])]
    (d / "schedule.json").write_text(json.dumps({"capture_start_epoch": t0, "entries": sched,
                                                 "timeline": [{**x, "t": round(x["t"] - t0, 3)} for x in notes["timeline"]]},
                                                indent=1, default=list))
    return t0, sched, notes


def execute(run, d, labst):
    if run["group"] and run["group_pos"] > 0:
        return execute_reuse(run, d, labst)
    cfg = run["config"]
    rng = random.Random(run["seed"])
    st = run.get("setup", [])
    dur = run["duration_s"]
    over = run.get("over") or {}
    notes = {"timeline": []}

    def mark(what, **kw):
        notes["timeline"].append({"t": round(time.time(), 3), "what": what, **kw})

    reset(run)
    if "extra_initiators" in st:
        over = json.loads(json.dumps(over))
        over.setdefault("b", {})["extra_conns"] = [topo.multi_conn(g, "r") for g in topo.multi]
    if "voip_child" in st:
        # e23: a second child sa for voip (udp: sip and rtp) next to the first one for the rest
        over = json.loads(json.dumps(over))
        f = cfg["inner_family"]
        for s_, p_ in (("a", "b"), ("b", "a")):
            over.setdefault(s_, {})["children"] = [{}, {"name": "voip", "local_ts": f"{topo.lan[s_][f]}[udp]",
                                                         "remote_ts": f"{topo.lan[p_][f]}[udp]"}]
    confs = topo.deploy(cfg, over, backend)
    for s in "ab":
        (d / f"swanctl_{s}.conf").write_text(confs[s])
    if cfg.get("internet"):
        topo.nat(True)
        notes["dns"] = topo.inet_dns(True)
    if run.get("netem") and run["netem"] != "lan":
        topo.netem(plan.netems[run["netem"]])
    notes.update(pre_setup(run))
    if cfg["mode"] == "transport":
        topo.nflog(True)
    ctx = topo.gen_ctx(cfg, d)
    ctx.update(split=run["split"], replay_label=run.get("replay_label"), replay_rank=run.get("replay_rank"))

    delay = run.get("capture_delay_s", 0)
    before = run.get("capture_start") == "before_tunnel"
    init = {}

    def initiate():
        rc, out = topo.initiate(timeout=min(60, dur), check=False)
        if "voip_child" in st:
            rc2, out2 = dx(topo.c["gw_a"], "swanctl --initiate --child voip --timeout 20", check=False, timeout=35)
            rc, out = rc or rc2, out + "\n" + out2
        init.update(rc=rc, out=out[-600:], t=time.time())
        mark("initiate_done", rc=rc)

    t0 = None
    if before:
        t0 = cap_start(run, True)
        mark("capture_start")
        xfrm_snap(d, "start")
    if "half_open_flood" in st:
        notes["flood"] = half_open_flood(run)
        mark("half_open_flood")
    th = threading.Thread(target=initiate, daemon=True)
    mark("initiate")
    th.start()
    th.join(timeout=25 if run.get("edge_case") else 40)
    if "extra_initiators" in st:
        notes["extra"] = topo.multi_start(max(10, dur - 15))
        mark("extra_initiators")
    if "loss20_during_setup" in st:
        th.join(timeout=40)
        topo.netem(None)
        mark("loss_removed")
    if not before:
        # mid-stream: traffic runs for `delay` seconds before the capture starts
        app_len = dur + delay - 2
        evs, threads = start_apps(run, ctx, app_len, rng) if run["apps"] else ([], [])
        noise_on(run)
        time.sleep(delay)
        t0 = cap_start(run, True)
        mark("capture_start")
        xfrm_snap(d, "start")
    else:
        app_len = max(5, dur - (time.time() - t0) - 2)
        if run.get("app_len_s"):
            app_len = min(app_len, run["app_len_s"])
        noise_on(run)
        evs, threads = start_apps(run, ctx, app_len, rng) if run["apps"] else ([], [])
    mark("apps_start", apps=run["apps"], length=round(app_len, 1))
    done = {}
    tick = [time.time()]
    while time.time() - t0 < dur:
        xfrm_tick(d, tick)
        el = time.time() - t0
        if "terminate_at_35" in st and el >= 35 and "term" not in done:
            done["term"] = dx(topo.c["gw_a"], "swanctl --terminate --ike lab --timeout 10", check=False)[0]
            mark("terminate", rc=done["term"])
        if "replay_esp_at_30" in st and el >= 30 and "replay" not in done:
            done["replay"] = replay_esp(run, d)
            mark("replay_esp")
        time.sleep(0.5)
    for t in threads:
        t.join(timeout=60)
    xfrm_snap(d, "end")
    mark("capture_stop")
    noise_off()
    cap_stop(run, d)
    for s in "ab":
        _, lg = dx(topo.c[f"gw_{s}"], "cat /var/log/charon.log", check=False)
        (d / f"charon_{s}.log").write_text(lg + "\n")
    if "extra_initiators" in st:
        for g in topo.multi:
            _, lg = dx(topo.c[g], "cat /var/log/charon.log; echo; ip -s xfrm state; swanctl --list-sas", check=False)
            (d / f"extra_{g}.txt").write_text(lg + "\n")
    _, sas = dx(topo.c["gw_b"], "swanctl --list-sas", check=False)
    notes["sas_b_end"] = sas[-3000:]
    notes["initiate"] = init
    notes["actions"] = done
    if run["group"]:
        labst.update(tunnel=run["group"], tunnel_up=init.get("t", t0), confs=confs)
        notes["tunnel"] = {"group": run["group"], "first": True}
    else:
        labst.update(tunnel=None)
    sched = []
    for e in sorted(evs, key=lambda e: e["start"]):
        sched.append({**e, "start": round(e["start"] - t0, 3), "stop": round(e["stop"] - t0, 3)})
    (d / "schedule.json").write_text(json.dumps({"capture_start_epoch": t0, "entries": sched,
                                                 "timeline": [{**x, "t": round(x["t"] - t0, 3)} for x in notes["timeline"]]},
                                                indent=1, default=list))
    return t0, sched, notes


def noise_on(run):
    if run.get("noise"):
        dx(topo.c["noise_a"], f"python3 /noise.py {run['seed']} both >/dev/null 2>&1", detach=True)


def noise_off():
    dx(topo.c["noise_a"], "pkill -f [n]oise.py; true", check=False)


# ---------------------------------------------------------------- observe + validate

def observed(run, d, t0, sched, full=None):
    cfg = run["config"]
    ca = observe.charon((d / "charon_a.log").read_text())
    cb = observe.charon((d / "charon_b.log").read_text())
    whole = observe.charon(full["a"]) if full else ca
    ik = observe.ike(d / "ike.pcap")
    null = "null" in cfg["esp_proposal"]
    es = observe.esp(d / "outer.pcap", null=null)
    xa = observe.xfrm_state((d / "xfrm_a.txt").read_text())
    xb = observe.xfrm_state((d / "xfrm_b.txt").read_text())
    inner_n = observe.count(d / "inner.pcap")
    o = {"established": whole["ike_established"] > 0 and whole["child_established"] > 0,
         "ike_established": ca["ike_established"], "child_established": ca["child_established"],
         "notifies": sorted(ik["notifies"] | ca["notifies"] | cb["notifies"]),
         "wire_notifies": sorted(ik["notifies"]),
         "exchanges": ik["exchanges"], "log_exchanges": ca["exchanges"],
         "v1_exchanges": dict(ik["v1_exchanges"]),
         "esp_packets": es["packets"], "ah_packets": es["ah_packets"], "ike_packets": ik["packets"],
         "init_requests": ik["init_requests"], "init_responses": ik["init_responses"],
         "auth_requests": ik["auth_requests"], "ike_retransmits": ik["retransmits"],
         "responder_spi_zero": ik["responder_spi_zero"], "ike_fragments": ik["fragments"],
         "ike_spis": sorted(ik["ispis"]), "cleartext_ids": sorted(ik["cleartext_ids"]),
         "child_rekeys": ca["child_rekeys"], "ike_rekeys": ca["ike_rekeys"],
         "pfs_in_rekey": ca["pfs_seen"], "proposals": ca["proposals"],
         "spis": sorted(es["spis"]), "esp_first_seq": es["first_seq"],
         "esp_udp4500": es["udp4500"], "ip_fragments": es["ip_fragments"],
         "esp_duplicates": es["duplicates"],
         "esp_plaintext": observe.null_plaintext(d / "outer.pcap") if null else 0,
         "outer_families": sorted(es["outer_family"]), "inner_packets": inner_n,
         "inner_families": sorted(observe.inner_family(d / "inner.pcap")) if inner_n else [],
         "keepalives": observe.keepalives(d / "outer.pcap") if cfg["encap"] else 0,
         "nonesp_marker": ik["nonesp_marker"], "deletes": ca["deletes"] + cb["deletes"],
         "nat_local": ca["nat_local"], "nat_remote": ca["nat_remote"],
         "xfrm_replay_window": sorted(xa["replay_window"] | xb["replay_window"]),
         "xfrm_esn": xa["esn"] or xb["esn"],
         "replay_counter": {k: v["replay"] for k, v in xb["sections"].items()},
         "last_esp_s": round(es["last_time"] - t0, 3) if es["last_time"] else None,
         "first_ike_s": round(ik["first"] - t0, 3) if ik["first"] else None,
         "errors": ca["errors"][:5] + cb["errors"][:5]}
    o["_esp_times"] = es["times"]
    o["ike_sas"] = len(ik["ispis"])
    o["ike_established_b"] = cb["ike_established"]
    if "extra_initiators" in run.get("setup", []):
        # tunnel-grouping ground truth: which spis belong to which initiator
        o["tunnels"] = {}
        for g in topo.multi:
            f = d / f"extra_{g}.txt"
            txt = f.read_text() if f.exists() else ""
            ch = observe.charon(txt)
            o["tunnels"][g] = {"established": ch["ike_established"] > 0 and ch["child_established"] > 0,
                               "addr": topo.multi[g]["ip"], "behind_nat": topo.multi[g]["encap"],
                               "esp_spis": sorted(observe.xfrm_state(txt)["spis"])}
    o["nat_t_src_ports"] = len(ik["src_ports"].get("172.31.1.40", set()))
    return o


def esp_windows(times, t0, sched, dur):
    """2 s windows aligned to capture start. an app's windows are the ones it is
    active in (its schedule interval overlaps the window); "esp" counts windows
    that hold any esp/ah, and esp_active the app windows that hold esp."""
    n = int(dur // 2)
    esp = {int((t - t0) // 2) for t in times if 0 <= t - t0 < 2 * n}
    per = defaultdict(set)
    for e in sched:
        if e.get("event") == "app":
            per[e["app"]] |= {w for w in range(n) if e["start"] < 2 * w + 2 and e["stop"] > 2 * w}
    return {"esp": len(esp), **{k: len(v) for k, v in per.items()},
            "esp_active": {k: len(v & esp) for k, v in per.items()}}


def check_expect(exp, o, run):
    """edge expectations -> list of failed checks"""
    bad = []

    def need(c, what):
        if not c:
            bad.append(what)
    for k, v in exp.items():
        if k == "established":
            need(o["established"] == v, f"established={o['established']}")
        elif k == "esp":
            need((o["esp_packets"] > 5) == v, f"esp_packets={o['esp_packets']}")
        elif k == "exchanges":
            need(all(x in o["exchanges"] for x in v), f"exchanges={o['exchanges']}")
        elif k == "no_exchanges":
            need(not any(x in o["exchanges"] for x in v), f"exchanges={o['exchanges']}")
        elif k == "notifies":
            need(all(x in o["notifies"] for x in v), f"notifies={o['notifies']}")
        elif k == "min_init_requests":
            need(o["init_requests"] >= v, f"init_requests={o['init_requests']}")
        elif k == "min_auth_requests":
            need(o["auth_requests"] >= v, f"auth_requests={o['auth_requests']}")
        elif k == "init_response":
            need((o["init_responses"] > 0) == v, f"init_responses={o['init_responses']}")
        elif k == "responder_spi_zero":
            need(o["responder_spi_zero"] is True and o["init_responses"] == 0, "responder answered")
        elif k == "no_ike":
            need(o["ike_packets"] == 0, f"ike_packets={o['ike_packets']}")
        elif k == "esp_first_seq_min":
            f = min(o["esp_first_seq"].values()) if o["esp_first_seq"] else 0
            need(f >= v, f"first_seq={f}")
        elif k == "spi_change":
            need(len(o["spis"]) > 2, f"spis={len(o['spis'])}")
        elif k == "ike_spi_change":
            need(o["ike_sas"] >= 2 and o["ike_rekeys"] >= 1, f"ike_spis={o['ike_sas']} rekeys={o['ike_rekeys']}")
        elif k == "delete":
            need(o["deletes"] > 0, "no delete")
        elif k == "esp_stops":
            term = [x for x in run.get("_timeline", []) if x["what"] == "terminate"]
            ts = term[0]["t"] if term else None
            need(ts is not None and o["last_esp_s"] is not None and o["last_esp_s"] < ts + 3,
                 f"last_esp={o['last_esp_s']} terminate={ts}")
        elif k == "udp4500_esp":
            need(o["esp_udp4500"] > 0, "no esp-in-udp")
        elif k == "non_esp_marker":
            need(o["nonesp_marker"], "no ike on 4500")
        elif k == "keepalives":
            need(o["keepalives"] > 0, "no nat-t keepalives")
        elif k == "nat_local":
            need(o["nat_local"] == v, f"nat_local={o['nat_local']}")
        elif k == "v1_exchanges":
            for x, n in v.items():
                need(o["v1_exchanges"].get(x, 0) >= n, f"v1 {x}={o['v1_exchanges'].get(x, 0)}")
        elif k == "cleartext_id":
            need(len(o["cleartext_ids"]) > 0, "no cleartext id payload on the wire")
        elif k == "init_transforms":
            p = " ".join(o["proposals"])
            need(all(x in p for x in v), f"proposals={o['proposals'][:2]}")
        elif k == "esp_plaintext":
            need(o["esp_plaintext"] > 0, "esp payload not readable")
        elif k == "ike_retransmits":
            need(o["ike_retransmits"] > 0, "no retransmits")
        elif k == "outcome_recorded":
            pass
        elif k == "min_ike_sas":
            # established on the responder, not merely attempted on the wire
            est = [g for g, t in (o.get("tunnels") or {}).items() if t["established"]]
            need(o["ike_established_b"] >= v and len(est) == len(o.get("tunnels") or {}) and o["ike_sas"] >= v,
                 f"established on gw_b={o['ike_established_b']} extra up={est} wire spis={o['ike_sas']}")
        elif k == "nat_t_ports":
            need(o["nat_t_src_ports"] >= v, f"nat_t_src_ports={o['nat_t_src_ports']}")
        elif k == "ah":
            need(o["ah_packets"] > 5, f"ah_packets={o['ah_packets']}")
        elif k == "xfrm_replay_window":
            need(o["xfrm_replay_window"] == [v], f"replay_window={o['xfrm_replay_window']}")
        elif k == "xfrm_esn":
            need(o["xfrm_esn"], "esn not set")
        elif k == "ike_fragments":
            need(o["ike_fragments"], "no ike fragments")
        elif k == "min_child_sas":
            need(o["child_established"] >= v, f"child_sas={o['child_established']}")
        elif k == "min_esp_spis":
            need(len(o["spis"]) >= v, f"spis={len(o['spis'])}")
        elif k == "families_differ":
            need(o["outer_families"] and o["inner_families"] and o["outer_families"] != o["inner_families"],
                 f"outer={o['outer_families']} inner={o['inner_families']}")
        elif k == "ip_fragments":
            need(o["ip_fragments"] > 0, "no ip fragments")
        elif k == "duplicate_seq":
            need(o["esp_duplicates"] > 0, "no duplicate seq")
        elif k == "replay_counter_rises":
            rc = list(o["replay_counter"].values())
            need(len(rc) >= 2 and rc[-1] > rc[0], f"replay_counter={o['replay_counter']}")
        else:
            bad.append(f"unknown check {k}")
    return bad


def expected(run):
    if run.get("edge_case"):
        return run["expect"]
    ex = ["IKE_SA_INIT", "IKE_AUTH"] if run.get("capture_start") == "before_tunnel" else []
    if run["stage"] == "handshake":
        ex.append("CREATE_CHILD_SA")
    return {"esp": True, "ike_exchanges": ex}


def app_ok(app, evs):
    """did the generator actually produce its traffic, not merely exit cleanly?"""
    ev = [e for e in evs if e.get("app") == app and e.get("event") != "app"]
    if app == "voip":
        return any(e.get("established") for e in ev if e["event"] == "call")
    if app in ("web",):
        return any(e.get("loaded") for e in ev if e["event"] == "page")
    if app == "web_light":
        return any(e.get("bytes", 0) > 0 for e in ev)
    if app == "video":
        return any(e.get("frags", 0) > 0 for e in ev if e["event"] == "play")
    if app == "email":
        return any(e["event"] in ("send", "fetch") and e.get("rc", 0) in (0, "cut at deadline") for e in ev)
    if app == "bulk":
        return any(e.get("rc") in (0, "cut at deadline") for e in ev)
    if app == "chat":
        return any(e["event"] == "message" for e in ev)
    if app in ("icmp", "icmp_big"):
        return any(" 0 received" not in e.get("summary", "") for e in ev)
    if app == "youtube":
        # blocked (datacenter address) is recorded, never worked around
        return any(e["event"] in ("play", "blocked") for e in ev)
    return True


def validate(run, o, sched, last=True):
    """-> (status, reasons). an app that reported a block (youtube) fails the attempt
    so the normal retries run; the last attempt keeps the run and records the block"""
    why = []
    apps = [e for e in sched if e.get("event") == "app"]
    for e in apps:
        if e.get("rc") not in (0, None):
            why.append(f"generator {e['app']} rc={e['rc']} {e.get('err', '')[-160:]}")
        elif not run.get("edge_case") and not run.get("replayed") and not app_ok(e["app"], sched):
            why.append(f"generator {e['app']} produced none of its traffic (see schedule.json)")
    if run.get("edge_case"):
        if o["inner_packets"] == 0 and run["expect"].get("esp") and run["apps"]:
            why.append("inner capture empty")
        bad = check_expect(run["expect"], o, run)
        if why:
            return "failed", why
        return ("mismatch", bad) if bad else ("ok", [])
    if not o["established"]:
        why.append("tunnel not established")
    ex = expected(run)["ike_exchanges"]
    miss = [x for x in ex if x not in o["exchanges"]]
    if miss:
        why.append(f"missing exchanges {miss}")
    if o["esp_packets"] < esp_min:
        why.append(f"esp_packets={o['esp_packets']} < {esp_min}")
    if o["inner_packets"] < 10:
        why.append(f"inner capture has {o['inner_packets']} packets")
    if run["stage"] == "handshake" and o["child_rekeys"] < 1:
        why.append("no child rekey observed")
    if run.get("replayed") and not any(e.get("event") == "replay" for e in sched):
        why.append("replay did not run")
    if o.get("blocked") and not last:
        why += [f"{a} blocked ({r}): retried, the last attempt records it" for a, r in o["blocked"].items()]
    return ("failed", why) if why else ("ok", [])


# ---------------------------------------------------------------- record

def finish(d):
    """compress captures (after the run, never during) and checksum everything"""
    for f in ("outer.pcap", "ike.pcap", "inner.pcap"):
        p = d / f
        if p.exists():
            sh(f"zstd -q -f --rm -T0 -10 {p}", timeout=1800)
    sums = {}
    for p in sorted(d.iterdir()):
        if p.is_file() and p.name != "meta.json":
            sums[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return sums


def one(run, attempt, labst, last=True):
    # capture into a work folder: an earlier ok folder is only replaced once this
    # attempt is complete and ok (a killed attempt must never destroy good data)
    final = raw / run["run_id"]
    d = raw / f".tmp-{run['run_id']}"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    t_start = time.time()
    status, why, o, notes, sched, t0 = "failed", [], {}, {}, [], None
    # machine load and concurrency, sampled for the whole run
    samples, stop = {"cpu": [], "conc": []}, threading.Event()

    def sampler():
        while not stop.is_set():
            samples["cpu"].append(placement.cpu_busy(1.0))
            samples["conc"].append(1 + len(placement.active_now(topo.lab_id)))
            stop.wait(4)
    smp = threading.Thread(target=sampler, daemon=True)
    smp.start()
    la0 = os.getloadavg()
    try:
        t0, sched, notes = execute(run, d, labst)
        run["_timeline"] = [{**x, "t": round(x["t"] - t0, 3)} for x in notes["timeline"]]
        o = observed(run, d, t0, sched, notes.pop("_full_logs", None))
        o["windows_2s"] = esp_windows(o.pop("_esp_times"), t0, sched, run["duration_s"])
        # apps that reported a block (youtube from a datacenter address): recorded, never worked around
        o["blocked"] = {e["app"]: e.get("reason", "") for e in sched if e.get("event") == "blocked"}
        status, why = validate(run, o, sched, last)
    except Exception as e:
        why = [f"exception: {str(e).strip()[-600:]}"]
        labst.update(tunnel=None)
    stop.set()
    smp.join(timeout=5)
    t_end = time.time()
    over = placement.overlaps(topo.lab_id, t_start, t_end)
    conc = max(samples["conc"] or [1])
    sums = finish(d)
    meta = {k: v for k, v in run.items() if not k.startswith("_") and k not in ("over", "expect", "setup")}
    rp = next((e for e in sched if e.get("event") == "replay"), None)
    if rp and rp.get("source"):
        # replayed public captures: what exactly was replayed (gen/replay.py)
        meta.update({"label": rp.get("label"), "source": rp["source"],
                     "replay": {k: rp.get(k) for k in ("doi", "scenario", "device", "split", "source_file",
                                                       "start_s", "end_s", "pcap", "packets", "sha256", "client_ip")}})
    meta.update({"expected": expected(run), "observed": o, "status": status, "reasons": why,
                 "attempt": attempt, "edge_setup": run.get("setup", []), "overrides": run.get("over") or {},
                 "capture_start_epoch": t0, "wall_s": round(time.time() - t_start, 1),
                 "ipsec_backend": backend,
                 "strongswan_version": lab_versions.get("strongswan") or env.get("strongswan_version", ""),
                 "lab": lab_versions,
                 "kernel": platform.release(), "netem_available": env.get("netem", True),
                 "noise": run.get("noise", False), "sha256": sums, "notes": {k: v for k, v in notes.items() if k != "timeline"},
                 "bytes": sum(p.stat().st_size for p in d.iterdir() if p.is_file()),
                 "ts_precision": {"outer": "ns", "ike": "ns",
                                  "inner": "us" if run["config"]["mode"] == "transport" else "ns"},
                 "plan": {"tier_seed": plan.matrix["seeds"].get(run["tier"]), "design_sha": plan.design_sha(),
                          "plan_sha": plan_id, "code": sh(f"git -C {root} rev-parse --short HEAD", check=False)[1].strip()},
                 "lab_id": topo.lab_id, "labs": n_labs,
                 # timing-sensitive and captured alone on the machine (no other run overlapped)
                 "timing_valid": bool(run.get("timed")) and conc == 1 and not over,
                 "concurrency": {"max": conc,
                                 "mean": round(sum(samples["conc"]) / max(1, len(samples["conc"])), 2),
                                 "overlapping": over},
                 "load": {"cpu_busy_mean": round(sum(samples["cpu"]) / max(1, len(samples["cpu"])), 1),
                          "cpu_busy_max": max(samples["cpu"] or [0]),
                          "loadavg_start": [round(x, 2) for x in la0],
                          "loadavg_end": [round(x, 2) for x in os.getloadavg()]},
                 "machine": placement.machine(),
                 "images": {k: v for k, v in lab_versions.items() if k.startswith(("image_", "digest_"))},
                 "inner_capture": "nflog on gw_a (policy match, both directions)" if run["config"]["mode"] == "transport"
                 else "host_a eth0"})
    (d / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True, default=list))
    if status == "ok":
        if final.exists():
            shutil.rmtree(final)
        d.rename(final)
        d = final
    record(meta)
    if status != "ok":
        keep = raw / "_attempts" / f"{run['run_id']}-a{attempt}"
        keep.parent.mkdir(exist_ok=True)
        if keep.exists():
            shutil.rmtree(keep)
        shutil.move(str(d), keep)
    return status, why


# ---------------------------------------------------------------- batch

def gaps(runs, last):
    """edge cases short of their ok reps (mismatches are kept but not counted)
    get new reps after the highest rep ever attempted"""
    extra = []
    tiers = {r["tier"] for r in runs if r.get("edge_case")}
    for tier in tiers:
        seed = plan.matrix["seeds"][tier]
        level = [st for st in plan.matrix["tiers"][tier] if st["stage"] == "edge"][0]
        for eid, e in plan.edges[level["level"]].items():
            if not any(r.get("edge_case") == eid for r in runs):
                continue
            att = {rid: st for rid, st in last.items() if rid.startswith(f"{tier}-{eid}-")}
            ok = sum(st == "ok" for st in att.values())
            pending = [r for r in runs if r.get("edge_case") == eid and r["run_id"] not in att]
            short = level["reps"] - ok - len(pending)
            top = max([int(rid.rsplit("-r", 1)[1]) for rid in att] + [level["reps"]])
            for i in range(max(0, short)):
                extra.append(plan.edge_run(tier, eid, e, top + 1 + i, seed))
    for r in extra:
        r["split"] = "train"
    by = defaultdict(list)
    for r in extra:
        by[r["edge_case"]].append(r)
    # keep every edge case represented in test: a replacement rep inherits test
    # when no ok test run exists for it yet
    for eid, rs in by.items():
        have = any(st == "ok" and m == "test" for rid, (st, m) in splits(last).items() if f"-{eid}-" in rid)
        if not have:
            rs[0]["split"] = "test"
    return extra


def splits(last):
    """run_id -> (status, split) from the manifest"""
    out = {}
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                if "annotation" not in m:
                    out[m["run_id"]] = (m["status"], m.get("split"))
    return out


def hms(s):
    return f"{int(s // 3600)}h{int(s % 3600 // 60):02d}m"


def sliced(runs, i, n):
    """slice i/n of a plan as a batch takes it: seeded order after p0, the
    round-robin dealer for the legacy tiers"""
    if runs and runs[0]["tier"] not in plan.legacy:
        return plan.deal(runs, i, n)
    return plan.slice_units(runs, i, n) if n > 1 else runs


def identity(tier):
    """what every slice of a tier must share: seed, design, plan and images"""
    lock = root / "lab" / "images.lock"
    imgs = " ".join(f"{a}={b.split(':')[-1][:12]}" for a, b in (l.split() for l in lock.read_text().splitlines())) \
        if lock.exists() else "no images.lock"
    return (f"tier {tier} seed {plan.matrix['seeds'][tier]} design {plan.design_sha()} "
            f"plan {plan.plan_sha(plan.build(tier))} images {imgs}")


def dry_run(runs, todo, labs, slices=1):
    """per-stage table for the selection, then per-shard estimates: wall clock
    simulated with `labs` parallel labs and the placement rules"""
    cores = os.cpu_count()
    by = defaultdict(list)
    for r in runs:
        by[r["stage"]].append(r)
    print(f"{'stage':<11}{'runs':>6}{'todo':>6}{'skip':>6}{'serial':>9}   scenarios")
    for st, rs in by.items():
        t = [r for r in rs if r["run_id"] in todo and not r.get("skip")]
        sk = sum(1 for r in rs if r.get("skip"))
        sc = Counter(r["scenario"] for r in rs)
        print(f"{st:<11}{len(rs):>6}{len(t):>6}{sk:>6}{hms(sum(plan.cost(r) for r in t)):>9}   "
              + ", ".join(f"{k}:{v}" for k, v in sc.items()))
    for k, v in {r["scenario"]: r["skip"] for r in runs if r.get("skip")}.items():
        print(f"  skip {k}: {v}")
    split = Counter(r["split"] for r in runs)
    nm = Counter(r.get("netem") for r in runs if r["stage"] != "edge")
    tr = [r for r in runs if r["group"]]
    mid = sum(r["capture_start"] == "mid_stream" for r in tr)
    print(f"\nsplit: {dict(split)}  netem (non-edge): {dict(nm)}  "
          f"mid_stream: {mid}/{len(tr)} traffic runs = {mid / max(1, len(tr)):.0%} (min 15%)")
    print(f"\n{labs} lab(s) per machine, {cores} cores; heavy (video/web/bulk) one at a time, "
          f"voip never next to heavy\n")
    setup = plan.matrix.get("shard_setup_s", 0) if slices > 1 else 0
    print(f"{'shard':<7}{'tunnels':>8}{'heavy':>6}{'light':>6}{'voip':>5}{'wall':>9}{'+setup':>8}"
          f"{'core-h':>8}{'storage':>9}   modes / shapes")
    todo_runs = [r for r in runs if r["run_id"] in todo and not r.get("skip")]
    rows = []
    for i in range(1, slices + 1):
        sl = [r for r in sliced(runs, i, slices) if r["run_id"] in todo and not r.get("skip")]
        wall, _ = placement.simulate(sl, labs, plan.cost)
        gb, n = storage(sl, {r["run_id"] for r in sl})
        grp = {r["group"]: r["config"] for r in sl if r["group"]}
        modes = {c["mode"] for c in grp.values()}
        shapes = {c.get("esp_shape") for c in grp.values() if c.get("esp_shape")}
        cls = Counter(r["cls"] for r in sl)
        rows.append({"i": i, "tunnels": len(grp), "cls": cls, "wall": wall, "tot": wall + setup, "gb": gb,
                     "modes": modes, "shapes": shapes})
    all_shapes = {r["config"].get("esp_shape") for r in todo_runs if r["group"] and r["config"].get("esp_shape")}
    all_modes = {r["config"]["mode"] for r in todo_runs if r["group"]}
    flags = []
    for x in rows:
        ch = x["tot"] * cores / 3600
        print(f"{f'{x[chr(105)]}/{slices}':<7}{x['tunnels']:>8}{x['cls']['heavy']:>6}{x['cls']['light']:>6}"
              f"{x['cls']['voip']:>5}{hms(x['wall']):>9}{hms(x['tot']):>8}{ch:>8.1f}{x['gb']:>8.2f}G   "
              f"{','.join(sorted(x['modes'])) or '-'} / {len(x['shapes'])} of {len(all_shapes)}")
        if all_modes - x["modes"]:
            flags.append(f"shard {x['i']}/{slices} lacks mode {', '.join(sorted(all_modes - x['modes']))}")
        if len(all_shapes - x["shapes"]) > 1:
            flags.append(f"shard {x['i']}/{slices} lacks {len(all_shapes - x['shapes'])} wire shapes")
    if slices > 1:
        lo, hi = min(x["tot"] for x in rows), max(x["tot"] for x in rows)
        if hi > 1.15 * lo:
            flags.append(f"longest shard is {hi / lo - 1:.0%} longer than the shortest (limit 15%)")
        print(f"{'all':<7}{sum(x['tunnels'] for x in rows):>8}{sum(x['cls']['heavy'] for x in rows):>6}"
              f"{sum(x['cls']['light'] for x in rows):>6}{sum(x['cls']['voip'] for x in rows):>5}"
              f"{hms(max(x['wall'] for x in rows)):>9}{hms(hi):>8}"
              f"{sum(x['tot'] for x in rows) * cores / 3600:>8.1f}{sum(x['gb'] for x in rows):>8.2f}G   "
              f"(wall = slowest shard; core-hours and storage summed; setup {hms(setup)} per shard, estimated)")
    for f in flags:
        print("FLAG:", f)
    if slices > 1 and not flags:
        print("balance: every shard within 15% of the others, with both modes and all wire shapes")
    tot = [0, 0, max(x["tot"] for x in rows), 0]
    print(f"\nplan: {identity(runs[0]['tier'])}")
    print("storage from the median measured size per scenario (manifest ok runs); "
          "free quotas: 120 core-hours/month, 15 GB-month")
    if tot[2] > 2 * 3600:
        print("a shard is over 2 hours: ask before starting (CLAUDE.md section 1), then pass --yes")
    return tot[2]


def storage(runs, todo):
    """projected bytes for todo runs, from the median measured size per scenario
    (falls back to the stage median, then the overall median)"""
    import statistics
    sizes = defaultdict(list)
    # measured runs: this manifest, plus archived calibration runs (dataset/raw/_dev)
    for mf in [manifest] + sorted(raw.glob("_dev/*/manifest.jsonl")):
        if not mf.exists():
            continue
        for line in mf.read_text().splitlines():
            if line.strip():
                m = json.loads(line)
                if m.get("status") == "ok" and m.get("bytes"):
                    sizes[("s", m["scenario"])].append(m["bytes"])
                    sizes[("t", m["stage"])].append(m["bytes"])
                    sizes["all"].append(m["bytes"])
    if not sizes:
        return 0, 0
    tot = 0
    for r in runs:
        if r["run_id"] in todo and not r.get("skip"):
            v = sizes.get(("s", r["scenario"]))
            if v:
                tot += statistics.median(v)
            elif len(r["apps"]) > 1 and all(sizes.get(("s", a)) for a in r["apps"]):
                # unmeasured mixture: its apps' medians added (they overlap in time, so an upper bound)
                tot += sum(statistics.median(sizes[("s", a)]) for a in r["apps"])
            else:
                tot += statistics.median(sizes.get(("t", r["stage"])) or sizes["all"])
    return tot / 1e9, len(sizes["all"])


def disk():
    _, out = sh(f"du -sb {raw}", check=False)
    b = int(out.split()[0]) if out else 0
    msg = f"dataset/raw is {b / 1e9:.2f} GB"
    if b > 10e9:
        msg += " - over 10 GB: export (tools/export.py) and prune exported tiers"
    return msg


def select(args):
    """the plan, sliced first (a shard's share never depends on other filters),
    then narrowed by --scenario / --rep / --ids"""
    runs = sliced(plan.build(args.tier), *parse_slice(args.slice))
    if args.scenario:
        runs = [r for r in runs if r["scenario"] in args.scenario or r["stage"] in args.scenario]
    if args.rep:
        runs = [r for r in runs if r["rep"] in args.rep]
    if args.ids is not None:
        runs = [r for r in runs if r["run_id"] in args.ids]
    return runs


def parse_slice(v):
    if not v:
        return 1, 1
    i, n = (int(x) for x in v.split("/"))
    if not 1 <= i <= n:
        raise SystemExit(f"--slice {v}: need 1 <= i <= n")
    return i, n


def live_workers():
    """pids of run.py worker processes on this machine (any batch)"""
    out = []
    for d in Path("/proc").iterdir():
        if d.name.isdigit() and int(d.name) != os.getpid():
            try:
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if "capture/run.py" in cmd and "--worker" in cmd:
                out.append(int(d.name))
    return out


def worker(k, batch_file):
    """one lab: bring it up, then claim and run until the batch is exhausted"""
    global logfile, lab_versions, plan_id
    b = json.loads(Path(batch_file).read_text())
    logfile = Path(b["log"]).with_name(Path(b["log"]).stem + f"-lab{k}.log")
    runs = b["runs"]
    ids = {r["run_id"] for r in runs}
    plan_id = plan.plan_sha(plan.build(runs[0]["tier"]))
    topo.up(build=False)
    lab_versions = topo.versions()
    log(f"lab {k} up:", json.dumps(lab_versions))
    _, tries = history()
    labst = {"tunnel": None}
    parent = os.getppid()
    while True:
        # an orphaned worker (its coordinator was killed) must stop: a new batch
        # would otherwise run on the same lab and both would ruin each other's runs
        if os.getppid() != parent:
            log(f"lab {k}: coordinator gone, stopping")
            break
        with placement.locked():
            done = set(placement.load_state().get("done", {}))
        if ids <= done:
            break
        if placement.cpu_busy(2.0) > placement.max_busy:
            time.sleep(3)
            continue
        run = placement.claim(runs, k, done)
        if run is None:
            time.sleep(3)
            continue
        t0, status = time.time(), "failed"
        for a in range(tries[run["run_id"]] + 1, tries[run["run_id"]] + attempts + 1):
            status, why = one(run, a, labst, last=a == tries[run["run_id"]] + attempts)
            log(f"lab {k} {run['run_id']} attempt {a}: {status}" + (f" - {'; '.join(why)[:300]}" if why else ""))
            if status == "ok":
                break
        placement.release(k, run, status, t0, time.time())
    reset({})
    log(f"lab {k} done")


def status(runs, last, tries):
    """completion of a selection: ok, exhausted (3 attempts, not ok), pending"""
    sys.path.insert(0, str(root / "tools"))
    import checkmeta
    by = defaultdict(Counter)
    pending, exhausted = [], []
    for r in runs:
        if r.get("skip"):
            by[r["stage"]]["skipped"] += 1
        elif last.get(r["run_id"]) == "ok":
            by[r["stage"]]["ok"] += 1
        elif tries[r["run_id"]] >= attempts:
            by[r["stage"]]["exhausted"] += 1
            exhausted.append(f"{r['run_id']} ({last.get(r['run_id'])})")
        else:
            by[r["stage"]]["pending"] += 1
            pending.append(r["run_id"])
    for st, c in by.items():
        print(f"{st:<11}" + "  ".join(f"{k} {v}" for k, v in sorted(c.items())))
    bad = [r["run_id"] for r in runs if last.get(r["run_id"]) == "ok" and checkmeta.check(raw / r["run_id"])]
    for x in exhausted[:20]:
        print("  exhausted:", x)
    for x in bad[:20]:
        print("  folder fails checkmeta:", x)
    done = not pending and not bad
    print(f"{'COMPLETE' if done else 'NOT COMPLETE'}: {len(pending)} pending, {len(exhausted)} exhausted "
          f"(rerun with --fill-gaps), {len(bad)} invalid folders")
    sys.exit(0 if done else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", required=True, choices=sorted(plan.matrix["tiers"]))
    ap.add_argument("--labs", type=int, default=1, help="labs side by side on this machine")
    ap.add_argument("--slice", help="i/n: this codespace's share of the plan")
    ap.add_argument("--scenario", nargs="*", help="scenario or stage names")
    ap.add_argument("--resume", action="store_true", help="skip runs already ok (always on)")
    ap.add_argument("--fill-gaps", action="store_true", help="also retry exhausted runs, add edge reps")
    ap.add_argument("--retry", action="store_true", help="retry runs that used up their attempts (no new reps)")
    ap.add_argument("--redo", action="store_true",
                    help="capture the selected runs again even if ok (new attempts; the latest ok counts)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--rep", type=int, nargs="*", help="only these reps")
    ap.add_argument("--ids", nargs="+", help="only these run ids")
    ap.add_argument("--list", action="store_true", help="print run ids")
    ap.add_argument("--status", action="store_true", help="is this selection (slice) complete? exit 1 if not")
    ap.add_argument("--yes", action="store_true", help="confirm a batch estimated over 2 hours")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--batch", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.worker is not None:
        return worker(args.worker, args.batch)
    si, sn = parse_slice(args.slice)
    runs = select(args)
    last, tries = history()
    if args.fill_gaps:
        runs += gaps(runs, last)
    todo = [r for r in runs if (args.redo or last.get(r["run_id"]) != "ok") and not r.get("skip")
            and (args.fill_gaps or args.retry or args.redo or tries[r["run_id"]] < attempts)]
    if args.list:
        for r in runs:
            print(r["run_id"], r["split"], r["cls"], r.get("netem"), r.get("capture_start"),
                  last.get(r["run_id"], "-"), r.get("skip") or "")
    if args.status:
        return status(runs, last, tries)
    if args.dry_run or args.list:
        # estimates for every shard of the chosen split: the whole plan dealt as the
        # batches deal it, then narrowed to the selection
        full = plan.build(args.tier)
        want = None
        if args.scenario or args.rep or args.ids is not None:
            want = {r["run_id"] for r in select(argparse.Namespace(**{**vars(args), "slice": None}))}
        extra = gaps(full, last) if args.fill_gaps else []
        ftodo = {r["run_id"] for r in full if last.get(r["run_id"]) != "ok" and not r.get("skip")
                 and (want is None or r["run_id"] in want)} | {r["run_id"] for r in extra}
        dry_run(full + extra, ftodo, args.labs, sn)
        return
    todo.sort(key=lambda r: r.get("order", 10 ** 9))
    if args.limit:
        todo = todo[:args.limit]
    global logfile
    (raw / "_logs").mkdir(parents=True, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    logfile = raw / "_logs" / f"{args.tier}-{stamp}.log"
    log("args:", " ".join(sys.argv[1:]))
    log("plan:", identity(args.tier))
    wall, _ = placement.simulate(todo, args.labs, plan.cost)
    log(f"{len(todo)} runs to do ({len(runs) - len(todo)} done or skipped), "
        f"estimate {hms(wall)} with {args.labs} lab(s)")
    if wall > 2 * 3600 and not args.yes:
        sys.exit("estimate over 2 hours: confirm with the user, then rerun with --yes")
    if not todo:
        return
    # docker hygiene first (a restart can leave a whole unused image store behind)
    log(sh(f"bash {root}/lab/cleanup.sh", check=False, timeout=1800)[1].splitlines()[-1:])
    free = shutil.disk_usage(root).free / 1e9
    if free < 5:
        sys.exit(f"only {free:.1f} GB free on /workspaces: run lab/cleanup.sh, export and prune old runs first")
    if not args.no_build:
        # the pinned registry images and media snapshot of lab/images.lock (the same
        # digests on every shard); a refused pull stops the batch, never a local build
        sh(f"bash {root}/lab/images.sh pull", timeout=3600)
        lock = dict(l.split() for l in (root / "lab" / "images.lock").read_text().splitlines())
        mark = root / "lab" / "media" / ".digest"
        if "media" in lock and (not mark.exists() or mark.read_text().strip() != lock["media"]):
            sh(f"bash {root}/lab/images.sh pull-media", timeout=3600)
    # one batch per machine: refuse while workers of another batch are alive
    others = live_workers()
    if others:
        sys.exit(f"workers of another batch are still running (pids {others}): stop them first")
    # keys once, before any worker starts (workers only copy them into their labs)
    topo.ensure_keys()
    # a fresh batch: its runs, and an empty placement state
    placement.sched_dir.mkdir(parents=True, exist_ok=True)
    bf = placement.sched_dir / f"batch-{stamp}.json"
    bf.write_text(json.dumps({"runs": todo, "log": str(logfile), "labs": args.labs}, default=list))
    with placement.locked():
        placement.save_state({"batch": bf.name, "active": {}, "held": {}, "done": {}, "history": []})
    procs = []

    def stop(sig, frame):
        # stopping the coordinator stops its workers
        for p in procs:
            p.terminate()
        sys.exit(f"stopped by signal {sig}")
    import signal
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for k in range(args.labs):
        e = {**os.environ, "ANTAR_LAB": str(k), "ANTAR_LABS": str(args.labs)}
        procs.append(subprocess.Popen([sys.executable, __file__, "--tier", args.tier, "--worker", str(k),
                                       "--batch", str(bf)], env=e))
        time.sleep(5)
    rc = [p.wait() for p in procs]
    with placement.locked():
        st = placement.load_state()
    n_ok = sum(v == "ok" for v in st.get("done", {}).values())
    log(f"batch done: {n_ok}/{len(todo)} ok, worker exit codes {rc}. {disk()}")


if __name__ == "__main__":
    main()
