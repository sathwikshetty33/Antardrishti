#!/usr/bin/env python3
"""Antardrishti capture agent: feeds a live outer IPsec capture to a live session.

Standard library only (urllib, gzip, subprocess); no pip installs. Run as root (tcpdump
needs raw sockets). Two short-lived tcpdump processes per chunk: esp/ah at -s 128 (sizes and
timing are enough; the payload stays opaque anyway) and ike (udp 500, and udp 4500 with the
non-esp marker) at full size. Each finished pair is gzipped and posted with its sequence
number and the session's sensor key; the local files are deleted on success and the post is
retried with backoff on failure.

    sudo python3 antardrishti-agent.py --api https://your-deployment --session <id> --key <key>
"""
import argparse
import gzip
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

MIN_CHUNK_S, MAX_CHUNK_S = 2, 10
ESP_BPF, ESP_SNAPLEN = "esp or ah", 128
IKE_BPF, IKE_SNAPLEN = "udp port 500 or udp port 4500", 0


def clamp_chunk_seconds(v):
    return max(MIN_CHUNK_S, min(MAX_CHUNK_S, v))


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", help="the deployment's base url, e.g. https://antardrishti-zeta.vercel.app")
    ap.add_argument("--session", help="live session id (from POST /api/live)")
    ap.add_argument("--key", help="the session's sensor key")
    ap.add_argument("--iface", default=None, help="capture interface (default: the default-route interface)")
    ap.add_argument("--chunk-seconds", type=float, default=5.0,
                    help=f"seconds per chunk, clamped to {MIN_CHUNK_S}-{MAX_CHUNK_S} (default 5)")
    ap.add_argument("--list-ifaces", action="store_true", help="list interfaces and exit")
    return ap


def default_iface():
    """the interface of the default route, read from /proc/net/route (linux)"""
    try:
        with open("/proc/net/route") as f:
            next(f, None)
            for line in f:
                fields = line.split()
                if len(fields) > 1 and fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    return None


def list_ifaces():
    try:
        out = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True, check=True)
        print(out.stdout, end="")
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"could not list interfaces: {e}", file=sys.stderr)


def check_prereqs():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("this agent must run as root (tcpdump needs raw sockets): sudo python3 ...")
    if shutil.which("tcpdump") is None:
        sys.exit("tcpdump was not found on PATH; install it and try again")


def start_tcpdump(iface, bpf, snaplen, path):
    cmd = ["tcpdump", "-i", iface, "-s", str(snaplen), "-w", path, "-U", "-q", "-n", bpf]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_tcpdump(proc, timeout=5):
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------- the chunk upload

def build_multipart_body(boundary, seq, esp_gz, ike_gz):
    """a multipart/form-data body matching what POST /api/live/{id}/chunks expects: seq as a
    plain field, esp (and, when captured, ike) as gzipped pcap files"""
    b = boundary.encode()
    parts = [b"--" + b + b'\r\nContent-Disposition: form-data; name="seq"\r\n\r\n' + str(seq).encode() + b"\r\n"]

    def add_file(name, filename, data):
        parts.append(b"--" + b + f'\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                     .encode() + b"Content-Type: application/gzip\r\n\r\n" + data + b"\r\n")

    add_file("esp", "esp.pcap.gz", esp_gz)
    if ike_gz is not None:
        add_file("ike", "ike.pcap.gz", ike_gz)
    parts.append(b"--" + b + b"--\r\n")
    return b"".join(parts)


def post_chunk(api, sid, key, seq, esp_path, ike_path, timeout=20):
    boundary = uuid.uuid4().hex
    with open(esp_path, "rb") as f:
        esp_gz = gzip.compress(f.read())
    ike_gz = None
    if ike_path and os.path.getsize(ike_path) > 24:
        with open(ike_path, "rb") as f:
            ike_gz = gzip.compress(f.read())
    body = build_multipart_body(boundary, seq, esp_gz, ike_gz)
    req = urllib.request.Request(f"{api.rstrip('/')}/api/live/{sid}/chunks", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                                          "x-sensor-key": key})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def post_with_retry(api, sid, key, seq, esp_path, ike_path, tries=4):
    for attempt in range(tries):
        try:
            return post_chunk(api, sid, key, seq, esp_path, ike_path)
        except (urllib.error.URLError, OSError) as e:
            if attempt == tries - 1:
                print(f"seq {seq}: giving up after {tries} tries ({e})", file=sys.stderr)
                return None
            time.sleep(2 ** attempt)


def stop_session(api, sid, key):
    try:
        req = urllib.request.Request(f"{api.rstrip('/')}/api/live/{sid}/stop", method="POST",
                                     headers={"x-sensor-key": key})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------- the loop

def run(args):
    check_prereqs()
    iface = args.iface or default_iface()
    if not iface:
        sys.exit("could not determine the default interface; pass --iface (see --list-ifaces)")
    chunk_s = clamp_chunk_seconds(args.chunk_seconds)
    stopped = {"v": False}
    signal.signal(signal.SIGINT, lambda *_: stopped.__setitem__("v", True))
    signal.signal(signal.SIGTERM, lambda *_: stopped.__setitem__("v", True))
    seq = 0
    with tempfile.TemporaryDirectory(prefix="antar-agent-") as td:
        try:
            while not stopped["v"]:
                t0 = time.time()
                esp_path = os.path.join(td, f"esp-{seq}.pcap")
                ike_path = os.path.join(td, f"ike-{seq}.pcap")
                esp_p = start_tcpdump(iface, ESP_BPF, ESP_SNAPLEN, esp_path)
                ike_p = start_tcpdump(iface, IKE_BPF, IKE_SNAPLEN, ike_path)
                time.sleep(chunk_s)
                stop_tcpdump(esp_p)
                stop_tcpdump(ike_p)
                result = post_with_retry(args.api, args.session, args.key, seq, esp_path, ike_path)
                packets = result.get("packets_in_chunk", "?") if result else "?"
                tunnels = (result.get("analysis") or {}).get("tunnel_count", "?") if result else "?"
                print(f"seq {seq}: {packets} packets, {tunnels} tunnels, {'ok' if result else 'FAILED'} "
                      f"({time.time() - t0:.1f}s)")
                for p in (esp_path, ike_path):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                if result and result.get("status") == "completed":
                    print(f"session completed: {result.get('note') or 'reached a live-session cap'}")
                    break
                seq += 1
        finally:
            stop_session(args.api, args.session, args.key)
            print("stopped")


def main():
    args = build_parser().parse_args()
    if args.list_ifaces:
        list_ifaces()
        return
    if not (args.api and args.session and args.key):
        sys.exit("--api, --session and --key are required (see --help)")
    run(args)


if __name__ == "__main__":
    main()
