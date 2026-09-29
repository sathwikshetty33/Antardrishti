#!/usr/bin/env python3
"""Antardrishti capture agent: feeds a live outer IPsec capture to a live session.

Standard library only (urllib, gzip, subprocess, threading); no pip installs. Run as root
(tcpdump needs raw sockets). Two tcpdump processes capture continuously, rotated every
--chunk-seconds: ESP and AH (and ESP in UDP 4500) cut to their first 128 bytes, since sizes
and timing are all the analysis reads, and IKE (UDP 500, and UDP 4500 with the non-ESP
marker) in full. A second thread gzips each finished pair and posts it with its sequence
number and the session's sensor key, retrying with backoff; captures that finish while a post
is still in flight go together in the next chunk. Files are deleted once sent.

    sudo python3 antardrishti-agent.py --api https://your-deployment --session <id> --key <key>
"""
import argparse
import gzip
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

MIN_CHUNK_S, MAX_CHUNK_S = 2, 10
MAX_MERGE = 6  # finished captures sent as one chunk at most
# udp 4500 carries both ike (a 4-byte zero "non-esp marker" first) and esp in udp (nat-t)
NATT_IKE = "(ip and udp port 4500 and udp[8:4] = 0) or (ip6 and udp port 4500 and ip6[48:4] = 0)"
ESP_BPF, ESP_SNAPLEN = f"esp or ah or (udp port 4500 and not ({NATT_IKE}))", 128
IKE_BPF, IKE_SNAPLEN = f"udp port 500 or {NATT_IKE}", 0


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


def merge(paths, out):
    """concatenate pcaps of one interface and snaplen (one header, then every record) -> packets"""
    first = True
    n = 0
    with open(out, "wb") as f:
        for p in paths:
            try:
                with open(p, "rb") as g:
                    data = g.read()
            except OSError:
                continue
            if len(data) < 24:
                continue
            f.write(data if first else data[24:])
            first = False
            n += len(data) - 24
    return n


def post_chunk(api, sid, key, seq, esp_path, ike_path, timeout=120):
    boundary = uuid.uuid4().hex
    with open(esp_path, "rb") as f:
        esp_gz = gzip.compress(f.read())
    ike_gz = None
    if ike_path and os.path.exists(ike_path) and os.path.getsize(ike_path) > 24:
        with open(ike_path, "rb") as f:
            ike_gz = gzip.compress(f.read())
    body = build_multipart_body(boundary, seq, esp_gz, ike_gz)
    req = urllib.request.Request(f"{api.rstrip('/')}/api/live/{sid}/chunks", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                                          "x-sensor-key": key})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def detail(e):
    try:
        return json.loads(e.read()).get("detail") or e.reason
    except Exception:
        return e.reason


def post_with_retry(args, seq, esp_path, ike_path, stop, tries=4):
    """-> (reply, None) or (None, (http status or None, message)); 4xx other than 429 is final"""
    err = (None, "not sent")
    for attempt in range(tries):
        try:
            return post_chunk(args.api, args.session, args.key, seq, esp_path, ike_path), None
        except urllib.error.HTTPError as e:
            err = (e.code, detail(e))
            if 400 <= e.code < 500 and e.code != 429:
                return None, err
        except (urllib.error.URLError, OSError) as e:
            err = (None, str(getattr(e, "reason", e)))
        if stop.wait(1 if err[0] == 429 else 2 ** attempt):
            break
    return None, err


def session_seq(args):
    req = urllib.request.Request(f"{args.api.rstrip('/')}/api/live/{args.session}")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())["last_seq"] + 1


def stop_session(args):
    try:
        req = urllib.request.Request(f"{args.api.rstrip('/')}/api/live/{args.session}/stop", method="POST",
                                     headers={"x-sensor-key": args.key})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def post_loop(args, ready, stop, td):
    """send the finished captures in order, one status line per chunk"""
    seq = 0
    try:
        seq = session_seq(args)  # a restarted agent continues the session's sequence
    except Exception:
        pass
    while not stop.is_set():
        try:
            pairs = [ready.get(timeout=0.5)]
        except queue.Empty:
            continue
        while len(pairs) < MAX_MERGE:
            try:
                pairs.append(ready.get_nowait())
            except queue.Empty:
                break
        t0 = time.time()
        esp_path = os.path.join(td, f"send-{seq}-esp.pcap")
        ike_path = os.path.join(td, f"send-{seq}-ike.pcap")
        merge([p[0] for p in pairs], esp_path)
        merge([p[1] for p in pairs], ike_path)
        reply, err = post_with_retry(args, seq, esp_path, ike_path, stop)
        if err and err[0] == 409:
            try:
                seq = session_seq(args)
                reply, err = post_with_retry(args, seq, esp_path, ike_path, stop)
            except Exception:
                pass
        for p in [esp_path, ike_path] + [x for pair in pairs for x in pair]:
            try:
                os.remove(p)
            except OSError:
                pass
        took = f"{time.time() - t0:.1f}s" + (f", {len(pairs)} captures in one chunk" if len(pairs) > 1 else "")
        if reply:
            print(f"seq {seq}: {reply.get('packets_in_chunk', '?')} packets, "
                  f"{(reply.get('analysis') or {}).get('tunnel_count', '?')} tunnels, {reply.get('status')} ({took})",
                  flush=True)
            seq += 1
            if reply.get("status") == "completed":
                print(f"session completed: {reply.get('note') or 'it reached a live-session cap'}", flush=True)
                stop.set()
            continue
        code, msg = err
        print(f"seq {seq}: not sent ({f'HTTP {code}: ' if code else ''}{msg})", flush=True)
        if code == 403:
            print("the sensor key does not match this session: check --session and --key", flush=True)
            stop.set()
        elif code in (404, 410):
            print("this session cannot take chunks any more: create a new session", flush=True)
            stop.set()
        elif code == 413:
            print("the chunk was too large and was dropped: try a lower --chunk-seconds", flush=True)


# ---------------------------------------------------------------- the loop

def run(args):
    check_prereqs()
    iface = args.iface or default_iface()
    if not iface:
        sys.exit("could not determine the default interface; pass --iface (see --list-ifaces)")
    chunk_s = clamp_chunk_seconds(args.chunk_seconds)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    ready = queue.Queue()
    print(f"capturing on {iface} in {chunk_s:g} s chunks; Ctrl+C stops", flush=True)
    with tempfile.TemporaryDirectory(prefix="antar-agent-") as td:
        poster = threading.Thread(target=post_loop, args=(args, ready, stop, td), daemon=True)
        poster.start()
        k = 0
        try:
            while not stop.is_set():
                esp_path = os.path.join(td, f"esp-{k}.pcap")
                ike_path = os.path.join(td, f"ike-{k}.pcap")
                procs = [start_tcpdump(iface, ESP_BPF, ESP_SNAPLEN, esp_path),
                         start_tcpdump(iface, IKE_BPF, IKE_SNAPLEN, ike_path)]
                stop.wait(chunk_s)
                for p in procs:
                    stop_tcpdump(p)
                if procs[0].returncode not in (0, -signal.SIGTERM) and not os.path.exists(esp_path):
                    print(f"tcpdump could not capture on {iface} (see --list-ifaces)", flush=True)
                    stop.set()
                    break
                ready.put((esp_path, ike_path))
                k += 1
        finally:
            stop.set()
            poster.join(timeout=10)
            stop_session(args)
            print("stopped", flush=True)


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
