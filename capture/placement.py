"""parallel labs on one machine: shared state, placement rules, load, simulation.

each lab is driven by its own worker process (ANTAR_LAB=k). workers share one
state file under a lock and each claims its next run with choose():

  - heavy runs (video, web, bulk): at most one at a time on the machine
  - voip never runs next to a heavy run
  - no run starts while the machine's cpu is above max_busy
  - a tunnel group stays on the lab that holds its tunnel; its first run
    (before_tunnel) goes first. a lab that has nothing runnable in its group may
    take other work and release the group (its tunnel is then rebuilt, uncaptured,
    by whichever lab continues it: the remaining runs are mid_stream anyway)
"""
import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sched_dir = root / "dataset" / "raw" / "_sched"
max_busy = 70.0


@contextmanager
def locked():
    sched_dir.mkdir(parents=True, exist_ok=True)
    with open(sched_dir / "lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def load_state():
    p = sched_dir / "state.json"
    return json.loads(p.read_text()) if p.exists() else {}


def save_state(s):
    p = sched_dir / "state.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(s))
    tmp.replace(p)


def cpu_times():
    v = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    idle = v[3] + v[4]
    return sum(v), idle


def cpu_busy(window=2.0):
    """machine cpu busy % over the next `window` seconds"""
    t1, i1 = cpu_times()
    time.sleep(window)
    t2, i2 = cpu_times()
    return round(100.0 * (1 - (i2 - i1) / max(1, t2 - t1)), 1)


def allowed(cls, active):
    """may a run of class cls start next to the active runs of the other labs?"""
    kinds = {a["cls"] for a in active}
    if cls == "heavy":
        return "heavy" not in kinds and "voip" not in kinds
    if cls == "voip":
        return "heavy" not in kinds
    return True


def unit_of(r):
    return r["group"] or r["run_id"]


def eligible(runs, held_unit, others_held, done, active_ids):
    """runs a lab may take now, ignoring the class rules: its held group's pending
    runs, plus the next run of every unit nobody holds"""
    pend = {}
    for r in runs:
        if r["run_id"] in done or r["run_id"] in active_ids:
            continue
        pend.setdefault(unit_of(r), []).append(r)
    out = []
    for u, rs in pend.items():
        if u in others_held:
            continue
        rs.sort(key=lambda r: r["group_pos"])
        first_pending = rs[0]["group_pos"] == 0
        # a group whose first run is still pending must start with it
        out += [(u == held_unit, r) for r in (rs[:1] if first_pending else rs)]
    return out


def pick(runs, lab, state, done):
    """next run for this lab, or None. keeps the critical lane (heavy + voip) busy,
    stays on the held tunnel when it can"""
    active = [a for k, a in state.get("active", {}).items() if k != str(lab)]
    active_ids = {a["run_id"] for a in state.get("active", {}).values()}
    held = state.get("held", {})
    mine = next((u for u, k in held.items() if k == lab), None)
    others = {u for u, k in held.items() if k != lab}
    cand = [(own, r) for own, r in eligible(runs, mine, others, done, active_ids) if allowed(r["cls"], active)]
    if not cand:
        return None
    rank = {"heavy": 0, "voip": 1, "light": 2}
    cand.sort(key=lambda x: (rank[x[1]["cls"]], not x[0], x[1]["group_pos"], x[1]["run_id"]))
    lane_free = allowed("heavy", active)
    # prefer lane work while the lane is free; otherwise stay on the held tunnel
    if not lane_free:
        cand.sort(key=lambda x: (not x[0], rank[x[1]["cls"]], x[1]["group_pos"], x[1]["run_id"]))
    return cand[0][1]


def claim(runs, lab, done, cost_fn=None):
    """under the lock: choose, mark active, update the held tunnel group"""
    with locked():
        s = load_state()
        r = pick(runs, lab, s, done)
        if r is None:
            return None
        s.setdefault("active", {})[str(lab)] = {"run_id": r["run_id"], "cls": r["cls"], "since": time.time()}
        held = s.setdefault("held", {})
        for u, k in list(held.items()):
            if k == lab:
                del held[u]
        if r["group"]:
            held[r["group"]] = lab
        save_state(s)
        return r


def release(lab, run, status, t0, t1):
    with locked():
        s = load_state()
        s.get("active", {}).pop(str(lab), None)
        s.setdefault("done", {})[run["run_id"]] = status
        s.setdefault("history", []).append({"lab": lab, "run_id": run["run_id"], "cls": run["cls"],
                                            "start": t0, "end": t1, "status": status})
        save_state(s)


def overlaps(lab, t0, t1):
    """runs of other labs that overlapped [t0, t1] (finished ones and still active ones)"""
    with locked():
        s = load_state()
    out = []
    for h in s.get("history", []):
        if h["lab"] != lab and h["start"] < t1 and h["end"] > t0:
            out.append({"lab": h["lab"], "run_id": h["run_id"], "cls": h["cls"]})
    for k, a in s.get("active", {}).items():
        if int(k) != lab and a["since"] < t1:
            out.append({"lab": int(k), "run_id": a["run_id"], "cls": a["cls"]})
    return out


def active_now(lab):
    with locked():
        s = load_state()
    return [{"lab": int(k), **a} for k, a in s.get("active", {}).items() if int(k) != lab]


def simulate(runs, labs, cost_fn, reuse_cost=5):
    """discrete-event estimate of wall seconds with the placement rules (no load
    limit). returns (wall_s, per-lab busy seconds)"""
    t, done, active, held = 0.0, set(), {}, {}
    free_at = {k: 0.0 for k in range(labs)}
    tunnel = {k: None for k in range(labs)}
    busy = {k: 0.0 for k in range(labs)}
    ids = {r["run_id"]: r for r in runs}
    while len(done) < len(runs):
        started = False
        for k in sorted(free_at, key=lambda k: free_at[k]):
            if free_at[k] > t or str(k) in active:
                continue
            state = {"active": {str(j): a for j, a in active.items()},
                     "held": {u: j for u, j in held.items()}}
            r = pick(runs, k, state, done)
            if r is None:
                continue
            d = cost_fn(r)
            if r["group"] and r["group_pos"] > 0 and tunnel[k] != r["group"]:
                d += reuse_cost
            for u, j in list(held.items()):
                if j == k:
                    del held[u]
            if r["group"]:
                held[r["group"]] = k
            tunnel[k] = r["group"]
            active[str(k)] = {"run_id": r["run_id"], "cls": r["cls"], "end": t + d}
            free_at[k] = t + d
            busy[k] += d
            started = True
        ends = [a["end"] for a in active.values()]
        if not ends:
            if not started:
                break
            continue
        t = min(ends)
        for k, a in list(active.items()):
            if a["end"] <= t:
                done.add(a["run_id"])
                del active[k]
    return max(free_at.values()), busy


def machine():
    mem = 0
    try:
        mem = int(next(l for l in open("/proc/meminfo") if l.startswith("MemTotal")).split()[1]) / 1e6
    except Exception:
        pass
    model = ""
    try:
        model = next(l for l in open("/proc/cpuinfo") if l.startswith("model name")).split(":", 1)[1].strip()
    except Exception:
        pass
    return {"cores": os.cpu_count(), "mem_gb": round(mem, 1), "cpu": model,
            "codespace": os.environ.get("CODESPACE_NAME", ""), "machine_class": os.environ.get("ANTAR_MACHINE", "")}
