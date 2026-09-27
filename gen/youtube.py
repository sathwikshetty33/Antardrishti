"""youtube (realism tier, internet): chrome plays an openly licensed film on youtube.

youtube often blocks datacenter addresses (a consent or bot-check page, or a
player that never starts). that is recorded as blocked and the generator stops:
never worked around (no sign-in, no cookies, no clicking through, no other site).
"""
import random
import time

from common import args, emit, launch, left, nap

# blender foundation films (cc-by) on the blender foundation's channel
films = {"aqz-KE-bpKQ": "big buck bunny", "eRsGyueVLvQ": "sintel"}
pos_js = "(() => { const v = document.querySelector('video'); return v ? v.currentTime : -1; })()"


def start(duration, seed, ctx):
    return launch(ctx, "youtube", duration, seed)


def ev(page, js, default):
    """evaluate in the page; a navigation in progress (consent redirect) is not an error"""
    try:
        return page.evaluate(js)
    except Exception:
        return default


def blocked(page):
    """why the film is not playing, or None while it plays"""
    if "consent." in page.url:
        return "consent page"
    txt = ev(page, "document.body ? document.body.innerText.slice(0, 3000) : ''", "")
    if "not a bot" in txt or "Sign in to confirm" in txt:
        return "bot check"
    if ev(page, pos_js, -1) < 0:
        return "no video element"
    return None


def main():
    from browser import new_context, open_browser, sync_playwright
    a = args()
    rng = random.Random(a.seed)
    vid = rng.choice(sorted(films))
    with sync_playwright() as pw:
        b = open_browser(pw, a.ip, internet=True)
        page = new_context(b).new_page()
        t = time.time()
        try:
            page.goto(f"https://www.youtube.com/watch?v={vid}", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            emit("youtube", "blocked", t, video=vid, reason=f"page did not load: {str(e).splitlines()[0][:200]}")
            b.close()
            return
        pos, why = -1, None
        for i in range(20):
            nap(a, 1)
            why = blocked(page)
            pos = ev(page, pos_js, -1)
            if why in ("consent page", "bot check") or pos > 1:
                break
            if i == 8 and pos >= 0:
                # a paused player: press play, as a viewer would
                ev(page, "document.querySelector('video').play()", None)
        if why or pos <= 1:
            emit("youtube", "blocked", t, video=vid, reason=why or f"player did not start (position {pos})",
                 url=page.url[:200])
            b.close()
            return
        start_pos = pos
        while left(a) > 1:
            nap(a, 2)
        end_pos = ev(page, pos_js, -1)
        b.close()
    emit("youtube", "play", t, video=vid, film=films[vid], start_pos=round(start_pos, 1), end_pos=round(end_pos, 1))


if __name__ == "__main__":
    main()
