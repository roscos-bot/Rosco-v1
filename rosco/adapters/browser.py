"""A browser Rosco can drive — but only ever a step Ross approved.

Playwright owns one real Chromium in a SINGLE dedicated thread (its sync API is
not thread-safe and the console is threaded); each request marshals a command to
that thread and waits for the result. There are no "free" moves here: navigating,
clicking and typing are all proposed in chat and run only from the confirmed
path, the same gate as an email draft. It never types a password or a card
number, and never answers a CAPTCHA - those stay Ross's to do by hand.

DIAGNOSIS EYES (added 2026-08-19). Driving a console to reproduce a bug is only
half of it — Rosco has to SEE what went wrong. So the page carries two rolling
buffers, filled by listeners set once at start: every console message / page
error, and every failed or >=400 network response. `screenshot` returns the
pixels; `observe` returns the whole picture at once — url, title, body text, the
recent console errors, the recent network failures, and a screenshot — which is
the single call Cortex grounds a diagnosis on. All of these are READS; they
change nothing on the page.

Playwright is an optional, heavy dependency (it bundles a browser), so it is
imported lazily: this module loads without it and every call returns a clear
'not set up' note until:  pip install playwright  &&  playwright install chromium
"""
from __future__ import annotations

import base64
import threading
from collections import deque
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
        # Rolling diagnosis buffers, appended from Playwright-thread listeners.
        # deque append is atomic, and only the Playwright thread writes them, so
        # no lock is needed; a reader snapshots with list(...).
        self._console: deque = deque(maxlen=300)
        self._netfail: deque = deque(maxlen=150)
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
                self._wire_capture(self._page)
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

    def _wire_capture(self, pg) -> None:
        """Listen for the two things that reveal an 'unexpected outcome': what the
        page logged (console + uncaught errors) and which requests failed."""
        def on_console(m):
            try:
                self._console.append({"type": m.type, "text": (m.text or "")[:600]})
            except Exception:
                pass
        def on_pageerror(e):
            self._console.append({"type": "pageerror", "text": str(e)[:600]})
        def on_response(r):
            try:
                if r.status >= 400:
                    self._netfail.append({"kind": "http", "status": r.status,
                                          "method": r.request.method, "url": r.url[:300]})
            except Exception:
                pass
        def on_requestfailed(r):
            try:
                self._netfail.append({"kind": "failed", "method": r.method,
                                      "url": r.url[:300],
                                      "error": (r.failure or "")[:200]})
            except Exception:
                pass
        pg.on("console", on_console)
        pg.on("pageerror", on_pageerror)
        pg.on("response", on_response)
        pg.on("requestfailed", on_requestfailed)

    def _snapshot(self, pg, *, shot: bool, max_text: int) -> dict:
        out = {"url": pg.url, "title": pg.title()}
        if max_text:
            out["text"] = pg.inner_text("body")[:max_text]
        if shot:
            out["png_b64"] = base64.b64encode(pg.screenshot()).decode()
        return out

    def _do(self, fn, args) -> dict:
        pg = self._page
        if fn == "navigate":
            pg.goto(args["url"], wait_until="domcontentloaded", timeout=25000)
            return self._snapshot(pg, shot=False, max_text=args.get("max", 5000))
        if fn == "read":
            return self._snapshot(pg, shot=False, max_text=args.get("max", 5000))
        if fn == "click":
            pg.get_by_text(args["target"], exact=False).first.click(timeout=8000)
            pg.wait_for_load_state("domcontentloaded", timeout=8000)
            return {"clicked": args["target"], "url": pg.url, "title": pg.title()}
        if fn == "type":
            if args.get("secret"):
                return {"error": "refused — never types passwords, cards or 2FA codes"}
            loc = (pg.get_by_label(args["target"]) if args.get("by") == "label"
                   else pg.get_by_placeholder(args["target"])).first
            try:                       # backstop: never fill a password / one-time-code field
                el = loc.element_handle(timeout=8000)
                typ = (el.get_attribute("type") or "").lower()
                ac = (el.get_attribute("autocomplete") or "").lower()
                if typ == "password" or "password" in ac or "one-time-code" in ac:
                    return {"error": "refused — that's a password/OTP field; Ross types those by hand"}
            except Exception:
                pass                   # can't introspect it → fall through and fill normally
            loc.fill(str(args.get("text", "")), timeout=8000)
            return {"typed_into": args["target"], "url": pg.url}
        if fn == "current":
            return {"url": pg.url, "title": pg.title()}
        # --- diagnosis eyes (all reads) ---
        if fn == "screenshot":
            return self._snapshot(pg, shot=True, max_text=args.get("max", 0))
        if fn == "console":
            return {"console": list(self._console)[-int(args.get("n", 50)):]}
        if fn == "network":
            return {"failures": list(self._netfail)[-int(args.get("n", 40)):]}
        if fn == "observe":
            snap = self._snapshot(pg, shot=True, max_text=args.get("max", 4000))
            snap["console"] = list(self._console)[-int(args.get("n", 30)):]
            snap["failures"] = list(self._netfail)[-int(args.get("n", 20)):]
            return snap
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
