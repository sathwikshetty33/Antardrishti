"""video: chrome + hls.js playing big buck bunny / sintel from nginx.

5-rung abr ladder (240p-1080p), so the player adapts to netem conditions.
occasionally the viewer seeks. level switches are recorded in the schedule.
"""
import random
import time

from common import args, emit, launch, left, nap


def start(duration, seed, ctx):
    return launch(ctx, "video", duration, seed)


def main():
    from browser import new_context, open_browser, sync_playwright
    a = args()
    rng = random.Random(a.seed)
    name = rng.choice(["bbb", "sintel"])
    t0 = rng.randint(0, 150)
    with sync_playwright() as pw:
        b = open_browser(pw, a.ip)
        page = new_context(b).new_page()
        t = time.time()
        page.goto(f"https://{a.host}/player.html?v={name}&t={t0}", timeout=30000)
        seek = rng.uniform(20, a.duration - 10) if rng.random() < 0.25 and a.duration > 40 else None
        while left(a) > 0.5:
            if seek and a.duration - left(a) >= seek:
                to = rng.randint(0, 280)
                page.evaluate(f"document.getElementById('v').currentTime = {to}")
                emit("video", "seek", time.time(), to=to)
                seek = None
            nap(a, 1)
        st = page.evaluate("window.stats")
        pos = page.evaluate("document.getElementById('v').currentTime")
        b.close()
    emit("video", "play", t, video=name, start_pos=t0, end_pos=round(pos, 1),
         frags=st["frags"], bytes=st["bytes"], levels=st["levels"],
         switches=[[round(t + x, 3), lv] for x, lv in st["switches"]][:200], errors=st["errors"][:20])


if __name__ == "__main__":
    main()
