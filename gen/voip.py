"""voip: baresip calling asterisk (ext 100, echo) over sip/rtp.

codec alternates by seed parity: g.711 u-law with 20 ms ptime, or opus.
calls have random lengths with short gaps; the audio source is tts speech.
"""
import os
import random
import subprocess
import time

from common import args, emit, launch, left, nap


def start(duration, seed, ctx):
    return launch(ctx, "voip", duration, seed)


conf = """poll_method epoll
sip_listen {listen}
net_interface {dev}
audio_player aufile,/tmp/bs/rx.wav
audio_source aufile,{wav}
audio_alert aufile,/tmp/bs/alert.wav
audio_level no
module_path /usr/lib/baresip/modules
module g711.so
module opus.so
module aufile.so
module_app account.so
module_app menu.so
opus_bitrate 32000
opus_stereo no
opus_sprop_stereo no
rtp_ports 30000-40000
"""


def main():
    a = args()
    rng = random.Random(a.seed)
    codec = "opus" if a.seed % 2 else "pcmu"
    os.makedirs("/tmp/bs", exist_ok=True)
    wav = "/opt/voice/voice48k.wav" if codec == "opus" else "/opt/voice/voice8k.wav"
    # bind to the address the kernel routes from: a wildcard lets baresip pick
    # e.g. a link-local source, which no ipsec policy covers
    src = subprocess.run(f"ip route get {a.ip}", shell=True, capture_output=True, text=True).stdout.split()
    dev = src[src.index("dev") + 1]
    src = src[src.index("src") + 1]
    listen = f"[{src}]:5070" if a.fam == "v6" else f"{src}:5070"
    open("/tmp/bs/config", "w").write(conf.format(listen=listen, wav=wav, dev=dev))
    codecs = "opus/48000/2" if codec == "opus" else "PCMU/8000/1"
    open("/tmp/bs/accounts", "w").write(
        f"<sip:lab@{a.host};transport=udp>;auth_pass=voip-throwaway;"
        f"audio_codecs={codecs};ptime=20;regint=0\n")
    open("/tmp/bs/contacts", "w").write("")
    while left(a) > 8:
        n = int(min(rng.uniform(15, 70), left(a) - 2))
        t = time.time()
        fam = "-6" if a.fam == "v6" else "-4"
        p = subprocess.run(["baresip", fam, "-f", "/tmp/bs", "-e", f"/dial sip:100@{a.host}", "-t", str(n)],
                           capture_output=True, text=True, timeout=n + 20)
        log = p.stdout + p.stderr
        ok = "Call established" in log or "established" in log
        emit("voip", "call", t, codec=codec, ptime=20, length_s=n, established=ok)
        if not ok:
            print(log[-600:], file=__import__("sys").stderr)
        nap(a, rng.uniform(1, 5))


if __name__ == "__main__":
    main()
