"""A browser Rosco can drive — but only ever a step Ross approved.

Playwright owns one real Chromium in a SINGLE dedicated thread (its sync API is
not thread-safe and the console is threaded); each request marshals a command to
that thread and waits for the result. There are no "free" moves here: navigating,
clicking and typing are all proposed in chat and run only from the confirmed
path, the same gate as an email draft. It never types a password or a card
number, and never answers a CAPTCHA - those stay Ross's to do by hand.

Playwright is an optional, heavy dependency (it bundles a browser), so it is
imported lazily: this module loads without it and every call returns a clear
'not set up' note until:  pip install playwright  &&  playwright install chromium
"""
from __future__ import annotations

import threading
from queue import Queue

_driver = None
_guard = threading.Lock()

INSTALL_HINT = ("browser control needs Playwright — run once:  "
                "pip install playwright   then   playwright install chromium")


def available() -> tuple[bool, str]:
    try:
        import playwright  # noqa: F401
        return True, ""
    except Exception:
        return False, INSTALL_HINT


def driver() -> "_Driver":
    global _driver
    with _guard:
        if _driver is None:
            _driver = _Driver()
        return _driver


class _Driver:
    """Owns the browser on its own thread; call() is safe from any thread."""

    def __init__(self) -> None:
        self._cmds: Queue = Queue()
        self._ready = threading.Event()
        self._start_err = ""
        self._page = None
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self._start_err = str(e)
            self._ready.set()
            return
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)   # visible, so Ross watches
                self._page = browser.new_page()
                self._ready.set()
                while True:
                    fn, args, res = self._cmds.get()
                    if fn == "__stop__":
                        break
                    try:
                        res["value"] = self._do(fn, args)
                    except Exception as e:
                        res["error"] = str(e)[:300]
                    res["ev"].set()
        except Exception as e:
            self._start_err = str(e)
            self._ready.set()

    def _do(self, fn, args) -> dict:
        pg = self._page
        if fn == "navigate":
            pg.goto(args["url"], wait_until="domcontentloaded", timeout=25000)
            return {"url": pg.url, "title": pg.title(),
                    "text": pg.inner_text("body")[:args.get("max", 5000)]}
        if fn == "read":
            return {"url": pg.url, "title": pg.title(),
                    "text": pg.inner_text("body")[:args.get("max", 5000)]}
        if fn == "click":
            pg.get_by_text(args["target"], exact=False).first.click(timeout=8000)
            pg.wait_for_load_state("domcontentloaded", timeout=8000)
            return {"clicked": args["target"], "url": pg.url, "title": pg.title()}
        if fn == "type":
            loc = (pg.get_by_label(args["target"]) if args.get("by") == "label"
                   else pg.get_by_placeholder(args["target"]))
            loc.first.fill(str(args.get("text", "")), timeout=8000)
            return {"typed_into": args["target"], "url": pg.url}
        if fn == "current":
            return {"url": pg.url, "title": pg.title()}
        return {"error": f"unknown browser command {fn!r}"}

    def call(self, fn: str, args: dict | None = None, timeout: int = 35) -> dict:
        ok, why = available()
        if not ok:
            return {"error": why}
        if not self._ready.wait(25):
            return {"error": "the browser did not start in time"}
        if self._start_err:
            return {"error": "browser failed to start: " + self._start_err[:200]}
        ev = threading.Event()
        res = {"ev": ev}
        self._cmds.put((fn, args or {}, res))
        if not ev.wait(timeout):
            return {"error": "browser action timed out"}
        return res.get("value") or {"error": res.get("error", "browser error")}
