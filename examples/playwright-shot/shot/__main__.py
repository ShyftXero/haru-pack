import os, pathlib, sys
from playwright.sync_api import sync_playwright

def main():
    out = pathlib.Path(os.getcwd()) / "shot.png"   # run-in-place: lands next to the exe
    url = sys.argv[1] if len(sys.argv) > 1 else None
    html = ("<body style='font-family:system-ui;margin:3rem'>"
            "<h1 style='color:#b5179e'>haru-pack + Playwright</h1>"
            "<p>Rendered by a <b>bundled Firefox</b>, fully offline.</p></body>")
    with sync_playwright() as p:
        b = p.firefox.launch(headless=True)
        pg = b.new_page()
        if url: pg.goto(url)
        else:   pg.set_content(html)
        pg.screenshot(path=str(out), full_page=True)
        b.close()
    print(f"[shot] wrote {out}")

if __name__ == "__main__":
    main()
