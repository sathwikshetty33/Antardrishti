"""web: chrome visiting mirrored pages with random think times (2-15 s).

sometimes the user opens a fresh context (cold cache), sometimes scrolls.
"""
import random
import sys
import time
import urllib.request
import ssl

from common import args, emit, launch, left, nap


def start(duration, seed, ctx):
    return launch(ctx, "web", duration, seed)


def pages(a):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    txt = urllib.request.urlopen(f"https://{a.host}/sites/index.txt", context=c, timeout=10).read().decode()
    return [l.strip() for l in txt.splitlines() if l.strip()]


def main():
    from browser import new_context, open_browser, sync_playwright
    a = args()
    rng = random.Random(a.seed)
    lst = pages(a)
    with sync_playwright() as pw:
        b = open_browser(pw, a.ip)
        ctx = new_context(b)
        page = ctx.new_page()
        while left(a) > 2:
            if rng.random() < 0.15:
                ctx.close()
                ctx = new_context(b)
                page = ctx.new_page()
            path = rng.choice(lst)
            t = time.time()
            try:
                page.goto(f"https://{a.host}{path}", wait_until="load", timeout=max(1000, int(left(a) * 1000)))
                ok = True
            except Exception as e:
                ok = False
                print(str(e)[:300], file=sys.stderr)
            emit("web", "page", t, path=path, loaded=ok)
            think = rng.uniform(2, 15)
            if ok and rng.random() < 0.5:
                for _ in range(rng.randint(1, 5)):
                    try:
                        page.mouse.wheel(0, rng.randint(300, 1500))
                    except Exception:
                        break
                    nap(a, rng.uniform(0.3, 1.5))
            nap(a, think)
        b.close()


if __name__ == "__main__":
    main()
