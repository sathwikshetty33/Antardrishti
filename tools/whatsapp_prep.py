"""prepare public whatsapp captures for the p1 whatsapp replay runs.

sources (cc by 4.0), downloaded to dataset/external/whatsapp/src/ and extracted
to src/x/: itc-net-blend-60 (mendeley; the whatsapp messenger archive of scenarios
a to e) and itc-net-audio-5 (figshare; the whatsapp voice-call files).

per source pcap: a sustained udp media flow (>= 20 s at >= 20 packets/s; whatsapp
calls use udp 3478 relays or peer to peer) is a call. call intervals are labelled
voip. the rest of a blend-60 file, 5 s away from any call, is chat (messaging and
media); the rest of an audio-5 file (call setup and teardown) is excluded. each
labelled segment is cut into 80 s chunks (a 90 s run leaves about 85 s for the replay
after the tunnel setup, so a chunk replays whole); a chunk under 30 s or with fewer
than 150 packets is excluded (too short or sparse for a replay run). chunks keep the captured link type (ethernet) and go to
dataset/external/whatsapp/ with manifest.jsonl (source, scenario, label, offsets,
split, sha256). the split is by source (owner, 2026-09-28): every chunk of a source
file shares its split, blend-60 scenario b (one user, one phone, two isps) is test and
a, c, d, e train; audio-5 has no scenarios, so its files are kept together by capturing
device: the device 192.168.137.218 (20 of 100 files) is test.
usage: python3 tools/whatsapp_prep.py
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
out = root / "dataset" / "external" / "whatsapp"
src = out / "src" / "x"
sources = {"blend60": ("itc-net-blend-60", {"A": "10.17632/ssv23kfcgs.3", "B": "10.17632/3zggb53m4x.3",
                                            "C": "10.17632/gp8r347j38.3", "D": "10.17632/mcmf627yh5.3",
                                            "E": "10.17632/gdtnnfyr7s.3"}),
           "audio5": ("itc-net-audio-5", {"": "10.6084/m9.figshare.24721035.v2"})}
chunk_s, min_chunk_s, min_packets, guard_s = 80, 30, 150, 5
test_scenarios, test_devices = {"B"}, {"192.168.137.218"}


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def calls(pcap):
    """merged [start, end] intervals of sustained udp media flows"""
    iv = []
    for line in run(f"tshark -n -r '{pcap}' -q -z conv,udp").splitlines():
        if "<->" not in line:
            continue
        vals = [x for x in line.replace(",", "").split() if re.match(r"^[\d.]+$", x)]
        frames, rel, dur = int(vals[4]), float(vals[-2]), float(vals[-1])
        if dur >= 20 and frames / dur >= 20:
            iv.append([rel, rel + dur])
    merged = []
    for a, b in sorted(iv):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def device(pcap):
    """the capturing phone: its most frequent private (hotspot) address"""
    c = {}
    for a in run(f"tshark -n -r '{pcap}' -T fields -e ip.src -e ip.dst").split():
        if a.startswith("192.168."):
            c[a] = c.get(a, 0) + 1
    return max(c, key=c.get) if c else ""


def segments(pcap, kind):
    """[(label, start, end)] for one source file"""
    dur = float(re.search(r"Capture duration:\s+([\d.]+)", run(f"capinfos -M '{pcap}'")).group(1))
    cv = calls(pcap)
    seg = [("voip", a, b) for a, b in cv]
    if kind == "blend60":
        t = 0.0
        for a, b in cv + [[dur + guard_s, dur + guard_s]]:
            if a - guard_s > t:
                seg.append(("chat", t, a - guard_s))
            t = b + guard_s
    return sorted(seg, key=lambda s: s[1]), dur, cv


def main():
    for p in out.glob("wa-*.pcap"):
        p.unlink()
    rows, excluded = [], []
    for kind, (name, dois) in sources.items():
        for pcap in sorted(src.glob(f"{kind}*/**/*.pcap")):
            sc = pcap.parent.parent.name[-1] if kind == "blend60" else ""
            tag = re.search(r"_([A-E]_\d+)_Final|_(\d+)\.pcap$", pcap.name)
            ident = (tag.group(1) or tag.group(2).zfill(3)).replace("_", "")
            seg, dur, cv = segments(pcap, kind)
            dev = device(pcap)
            split = "test" if (sc in test_scenarios if kind == "blend60" else dev in test_devices) else "train"
            k = {"chat": 0, "voip": 0}
            for label, a, b in seg:
                t = a
                while b - t >= min_chunk_s:
                    e = min(t + chunk_s, b)
                    k[label] += 1
                    f = out / f"wa-{kind}-{ident}-{label}-{k[label]:02d}.pcap"
                    run(f"tshark -n -r '{pcap}' -Y 'frame.time_relative >= {t:.6f} && frame.time_relative < {e:.6f}' "
                        f"-F pcap -w '{f}'")
                    n = int(re.search(r"Number of packets:\s+(\d+)", run(f"capinfos -M '{f}'")).group(1))
                    row = {"file": f.name, "label": label, "source": name, "doi": dois[sc],
                           "scenario": sc or "audio5", "device": dev, "split": split, "source_file": pcap.name,
                           "start_s": round(t, 3), "end_s": round(e, 3), "packets": n}
                    if n < min_packets:
                        excluded.append({**row, "reason": f"{n} packets < {min_packets}"})
                        f.unlink()
                    else:
                        row["sha256"] = hashlib.sha256(f.read_bytes()).hexdigest()
                        rows.append(row)
                    t = e
                if 0 < b - t < min_chunk_s:
                    excluded.append({"source_file": pcap.name, "label": label, "start_s": round(t, 3),
                                     "end_s": round(b, 3), "reason": f"remainder under {min_chunk_s} s"})
    with open(out / "manifest.jsonl", "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with open(out / "excluded.jsonl", "w") as fh:
        for r in excluded:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    by = {}
    for r in rows:
        by.setdefault((r["source"], r["label"]), []).append(r)
    for k, v in sorted(by.items()):
        print(f"{k[0]:<17} {k[1]:<5} {len(v):>4} chunks, {sum(r['end_s'] - r['start_s'] for r in v) / 3600:.2f} h")
    print(f"excluded: {len(excluded)} pieces -> excluded.jsonl; manifest: {len(rows)} chunks -> manifest.jsonl")


if __name__ == "__main__":
    main()
