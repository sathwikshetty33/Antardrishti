"""take the ui screenshots in app/docs/screenshots (dev only; needs the api on :8000, vite on
:5173 and the 3 demo analyses): python app/docs/screenshots.py"""
import json
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

base = "http://localhost:5173"
out = Path(__file__).resolve().parent / "screenshots"


def get(path):
    return json.loads(urllib.request.urlopen(base + path).read())


def post(path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"content-type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())


def main():
    out.mkdir(parents=True, exist_ok=True)
    runs = {a["name"]: a["id"] for a in get("/api/analyses") if a["status"] == "done"}
    mix = next(v for k, v in runs.items() if k.startswith("Three-app"))
    agg = next(v for k, v in runs.items() if k.startswith("IKEv1"))
    errors = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        for theme in ("dark", "light"):
            ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
            ctx.add_init_script(f"localStorage.setItem('antar-theme', '{theme}')")
            pg = ctx.new_page()
            pg.on("pageerror", lambda e: errors.append(str(e)))
            pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            shots = [("overview", "/"), ("analysis", f"/analyses/{agg}"), ("tunnel", f"/analyses/{mix}/tunnels/0"),
                     ("threats", f"/analyses/{agg}/threats"), ("upload", "/upload")]
            if theme == "dark":
                shots += [("reports", "/reports"), ("analyses", "/analyses")]
            for name, path in shots:
                pg.goto(base + path)
                pg.wait_for_timeout(1800)
                if name == "threats":
                    cells = pg.locator("button[aria-label^='likelihood']:not([disabled])")
                    if cells.count():
                        cells.first.click()
                        pg.locator("tbody tr").first.click()
                        pg.wait_for_timeout(500)
                pg.screenshot(path=str(out / f"{name}-{theme}.png"), full_page=True)
            ctx.close()
        ctx = b.new_context(viewport={"width": 1440, "height": 900})
        pg = ctx.new_page()
        pg.goto(base + "/replay")
        pg.wait_for_timeout(800)
        pg.get_by_role("button", name="Start replay").click()
        pg.wait_for_timeout(16000)
        pg.screenshot(path=str(out / "replay-dark.png"), full_page=True)
        for kind in ("executive", "technical"):
            pg.goto(f"{base}/reports/{agg}/{kind}")
            pg.wait_for_timeout(2000)
            pg.screenshot(path=str(out / f"report-{kind}.png"), full_page=True)
            pg.pdf(path=str(out / f"report-{kind}.pdf"), format="A4", print_background=True)
        ctx.close()
        ctx = b.new_context(viewport={"width": 1920, "height": 1080})
        pg = ctx.new_page()
        pg.goto(f"{base}/analyses/{mix}/tunnels/0")
        pg.wait_for_timeout(1800)
        pg.screenshot(path=str(out / "tunnel-1920.png"), full_page=False)
        ctx.close()
        ctx = b.new_context(viewport={"width": 390, "height": 844})
        pg = ctx.new_page()
        pg.goto(base + "/")
        pg.wait_for_timeout(1500)
        pg.screenshot(path=str(out / "overview-mobile.png"), full_page=False)
        ctx.close()
        b.close()
    print("console errors:", errors or "none")


if __name__ == "__main__":
    main()
