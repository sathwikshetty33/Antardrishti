"""model bundle (analyzer/CLAUDE.md section 9): models/v1.

  python -m analyzer.bundle build     copy boosters, calibrators, thresholds, schema, overhead
                                      table, error table and metadata into models/v1, with a
                                      sha-256 manifest
  load(path) -> dict                  the bundle, checked against its manifest
"""
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from analyzer import common as cm
from analyzer import features as fx
from analyzer import lgbm

work = cm.feat / "work"
libs = ["numpy", "pandas", "pyarrow", "lightgbm", "scikit-learn", "scipy", "matplotlib", "zstandard"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def environment():
    from importlib.metadata import version
    mem = next(l for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal"))
    cpu = next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines()
                if l.startswith("model name")), platform.processor())
    osr = dict(l.split("=", 1) for l in Path("/etc/os-release").read_text().splitlines() if "=" in l)
    return {"os": osr.get("PRETTY_NAME", "").strip('"'), "kernel": platform.release(), "cpu": cpu,
            "cores": __import__("os").cpu_count(), "mem_gb": round(int(mem.split()[1]) / 1024 ** 2, 1),
            "python": sys.version.split()[0], "libraries": {k: version(k) for k in libs},
            "machine": "owner's WSL2 Ubuntu machine (local, not a codespace)"}


def releases():
    out = {}
    for d in sorted((cm.data / "dl").iterdir()):
        for s in sorted(d.glob("*.sha256")):
            line = s.read_text().split()
            out.setdefault(d.name, {})[line[1].lstrip("*")] = line[0]
    return out


def build():
    dst = cm.models
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    names = [f"config_{n}" for n in ("suite", "mode", "pfs")] + [f"{k}_{a}" for k in ("presence", "share")
                                                                 for a in cm.apps]
    for n in names:
        shutil.copy(work / f"{n}.txt", dst / f"{n}.txt")
    cal = {}
    for n in ("suite", "mode", "pfs"):
        j = json.loads((work / f"config_{n}.json").read_text())
        cal[f"config_{n}"] = {"calibration": j["calibration"], "rounds": j["rounds"]}
    cfeats = json.loads((work / "config_suite.json").read_text())["features"]
    for a in cm.apps:
        j = json.loads((work / f"presence_{a}.json").read_text())
        cal[f"presence_{a}"] = {"calibration": j["calibration"], "threshold": j["threshold"], "rounds": j["rounds"],
                                "oof_f1": j["oof_f1"]}
        cal[f"share_{a}"] = {"rounds": j["rounds_share"]}
    (dst / "calibration.json").write_text(json.dumps(cal, indent=1))
    wfeats = json.loads((work / "window_features.json").read_text())
    schema = {"config": {"columns": cfeats, "dtype": "float64"}, "window": {"columns": wfeats, "dtype": "float32"},
              "apps": cm.apps, "suites": cm.suites, "window_s": fx.win_s, "evidence_sizes": fx.sizes}
    (dst / "schema.json").write_text(json.dumps(schema, indent=1))
    (dst / "overhead.json").write_text(json.dumps({"formula": "8 + iv + (block - 1) / 2 + 2 + icv + inner ip header "
                                                              "(tunnel mode: 20 v4, 40 v6); nat-t adds nothing (the esp "
                                                              "length excludes the udp header)",
                                                   "table": fx.overhead_table()}, indent=1))
    shutil.copy(work / "error_table.json", dst / "error_table.json")
    commit = subprocess.run(["git", "-C", str(cm.root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    meta = {"bundle": "v1", "commit": commit, "seed": cm.seed, "dataset_seeds": [26001, 26002, 26003, 26004, 26005],
            "data_releases": releases(), "environment": environment(),
            "results": json.loads((cm.feat / "results" / "headline.json").read_text())
            if (cm.feat / "results" / "headline.json").exists() else None}
    (dst / "metadata.json").write_text(json.dumps(meta, indent=1))
    files = sorted(p for p in dst.iterdir() if p.name != "SHA256SUMS")
    (dst / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n" for p in files))
    print(f"models/v1: {len(files)} files, commit {commit[:7]}")


def load(path=None):
    d = Path(path or cm.models)
    for line in (d / "SHA256SUMS").read_text().splitlines():
        h, name = line.split(None, 1)
        if sha(d / name.strip()) != h:
            raise ValueError(f"bundle file {name} does not match SHA256SUMS")
    schema = json.loads((d / "schema.json").read_text())
    cal = json.loads((d / "calibration.json").read_text())
    boosters = {p.stem: lgbm.booster(str(p)) for p in d.glob("*.txt")}
    for k, b in boosters.items():
        cols = schema["config" if k.startswith("config") else "window"]["columns"]
        if b.num_feature() != len(cols):
            raise ValueError(f"{k}: {b.num_feature()} features, schema has {len(cols)}")
    return {"dir": d, "schema": schema, "calibration": cal, "boosters": boosters,
            "errors": json.loads((d / "error_table.json").read_text()),
            "metadata": json.loads((d / "metadata.json").read_text())}


if __name__ == "__main__":
    if sys.argv[1:] == ["build"]:
        build()
    else:
        print(__doc__)
