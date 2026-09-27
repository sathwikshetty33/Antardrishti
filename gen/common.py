"""shared generator plumbing.

host side:      launch() runs `python3 /gen/<app>.py` inside the client container
                and collects the json schedule events it prints.
container side: args(), emit(), until() for the client loops.
"""
import argparse
import json
import sys
import time


# app class -> module, where the class name would shadow a stdlib package
modules = {"email": "mail"}


def module(app):
    return modules.get(app, app)


def launch(ctx, app, duration, seed, extra="", who="cli"):
    """blocking: run the in-container client for duration seconds, return schedule entries"""
    import subprocess
    t0 = time.time()
    cmd = (f"docker exec {ctx[who]} timeout -k 5 {int(duration) + 45} python3 -u /gen/{module(app)}.py "
           f"--duration {duration} --seed {seed} --ip {ctx['ip']} --fam {ctx['fam']} {extra}")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    events = []
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            events.append(json.loads(line))
    events.append({"app": app, "event": "app", "start": t0, "stop": time.time(),
                   "rc": p.returncode, "err": p.stderr.strip()[-400:] if p.returncode else ""})
    return events


def args(extra=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--ip", required=True, help="server address")
    ap.add_argument("--fam", default="v4")
    for a, kw in (extra or {}).items():
        ap.add_argument(a, **kw)
    a = ap.parse_args()
    a.deadline = time.time() + a.duration
    a.host = f"[{a.ip}]" if ":" in a.ip else a.ip
    return a


def emit(app, event, start, stop=None, **detail):
    print(json.dumps({"app": app, "event": event, "start": start,
                      "stop": stop if stop is not None else time.time(), **detail}), flush=True)


def left(a):
    return a.deadline - time.time()


def nap(a, s):
    """sleep s seconds, but never past the deadline"""
    time.sleep(max(0, min(s, left(a))))


def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)
