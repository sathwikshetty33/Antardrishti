"""check run folders against the contract in CLAUDE.md section 4.

usage: python3 tools/checkmeta.py [run_id ...]   (default: every run in dataset/raw)
exits non-zero if any ok run is missing a field or a file, or a checksum is wrong.
"""
import hashlib
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
raw = root / "dataset" / "raw"

top = ["run_id", "tier", "scenario", "rep", "seed", "split", "config", "apps", "netem",
       "capture_start", "noise", "replayed", "internet", "edge_case", "expected", "observed",
       "ipsec_backend", "strongswan_version", "kernel", "status", "duration_s", "sha256"]
cfg = ["ike_version", "ike_proposal", "esp_proposal", "pfs", "dh", "mode", "outer_family",
       "inner_family", "encap", "auth", "aggressive", "esn", "replay_window", "ike_rekey_s",
       "child_rekey_s", "dpd_delay_s", "fragmentation"]
obs = ["established", "notifies", "esp_packets", "ike_packets", "child_rekeys", "spis"]
files = ["outer.pcap.zst", "ike.pcap.zst", "inner.pcap.zst", "charon_a.log", "charon_b.log",
         "xfrm_a.txt", "xfrm_b.txt", "swanctl_a.conf", "swanctl_b.conf", "schedule.json", "meta.json"]


def check(d):
    bad = []
    try:
        m = json.loads((d / "meta.json").read_text())
    except Exception as e:
        return [f"meta.json unreadable: {e}"]
    bad += [f"meta.{k} missing" for k in top if k not in m]
    bad += [f"config.{k} missing" for k in cfg if k not in m.get("config", {})]
    bad += [f"observed.{k} missing" for k in obs if k not in m.get("observed", {})]
    bad += [f"file {f} missing" for f in files if not (d / f).exists()]
    if m.get("run_id") != d.name:
        bad.append(f"run_id {m.get('run_id')} != folder {d.name}")
    if m.get("split") not in ("train", "test"):
        bad.append(f"split={m.get('split')}")
    for f, h in (m.get("sha256") or {}).items():
        p = d / f
        if not p.exists():
            bad.append(f"checksummed file {f} missing")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != h:
            bad.append(f"sha256 mismatch {f}")
    if m.get("status") != "ok":
        bad.append(f"status={m.get('status')} (only ok runs belong in raw/)")
    return bad


def main():
    ids = sys.argv[1:]
    dirs = [raw / i for i in ids] if ids else sorted(p for p in raw.iterdir() if p.is_dir() and not p.name.startswith("_"))
    n_bad = 0
    for d in dirs:
        bad = check(d)
        if bad:
            n_bad += 1
            print(f"FAIL {d.name}: " + "; ".join(bad))
    print(f"{len(dirs) - n_bad}/{len(dirs)} run folders valid")
    sys.exit(1 if n_bad else 0)


if __name__ == "__main__":
    main()
