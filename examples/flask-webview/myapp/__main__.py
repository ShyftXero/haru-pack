import os, socket, threading, sys
from . import create_app

def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def main():
    port = int(os.environ.get("FLASKUI_PORT", _free_port()))
    app = create_app()
    url = f"http://127.0.0.1:{port}"
    # server thread
    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True)
    t.start()

    headless = os.environ.get("FLASKUI_HEADLESS") == "1" or not (os.environ.get("DISPLAY") or sys.platform == "win32" or sys.platform == "darwin")
    if headless:
        print(f"[flaskui] serving headless at {url} (set FLASKUI_HEADLESS=0 with a display for a window)", flush=True)
        # in headless/test mode, print URL and wait briefly so callers can curl it
        secs = float(os.environ.get("FLASKUI_HEADLESS_SECONDS", "0"))
        if secs > 0:
            import time; time.sleep(secs)
        return 0
    # desktop window (Windows: Edge WebView2; macOS: WKWebView; Linux: needs GTK/QT webkit)
    try:
        import webview
        webview.create_window("My App", url)
        webview.start()   # blocks until window closed
        return 0
    except Exception as e:
        print(f"[flaskui] webview unavailable ({e}); open {url} in a browser", flush=True)
        try:
            import webbrowser; webbrowser.open(url)
        except Exception:
            pass
        input("press Enter to quit...")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
