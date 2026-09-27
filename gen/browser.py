"""in-container playwright helpers shared by video and web."""
from playwright.sync_api import sync_playwright

flags = ["--autoplay-policy=no-user-gesture-required", "--ignore-certificate-errors",
         "--no-sandbox", "--disable-dev-shm-usage", "--disable-background-networking",
         "--disable-component-update", "--no-first-run",
         # the lab has no internet: external names in mirrored pages fail at once
         # instead of hanging the load event (and no dns noise leaks into the class)
         "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {server}", "--disable-features=Translate,OptimizationHints,MediaRouter"]


def open_browser(pw, server, internet=False):
    args = [f.format(server=server) for f in flags
            if not (internet and f.startswith("--host-resolver-rules"))]
    return pw.chromium.launch(channel="chrome", headless=True, args=args)


def new_context(b):
    return b.new_context(ignore_https_errors=True, viewport={"width": 1366, "height": 800})


__all__ = ["sync_playwright", "open_browser", "new_context"]
