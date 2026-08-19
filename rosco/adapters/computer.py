"""Rosco's hands on the whole machine — mouse, keyboard, and eyes on the screen.

Where adapters/browser.py drives one Chromium tab, this drives the actual desktop:
it screenshots the screen and moves/clicks/types/scrolls anywhere. It exists so
Rosco can reproduce an "unexpected outcome" in ANY console — the web ones and the
native shells around them — and show Ross exactly what broke.

The guarantees are the same as the browser's, on purpose:

  VISIBLE     every action happens on the real screen Ross is watching; there is
              no hidden or off-screen surface.

  STOPPABLE — TWO INDEPENDENT PANIC PATHS, one per hand:
     * MOUSE: pyautogui FAILSAFE is on — shove the mouse into any screen corner
       and the next action raises instead of running.
     * KEYBOARD: a double-tap of Esc (two presses within 0.6s) trips the SAME
       stop flag every call() checks, so a sweep halts between steps. The watcher
       is deliberately minimal: it inspects each key ONLY to see whether it is
       Esc and to time the taps, and keeps NOTHING — it is a panic button, not a
       keylogger. It's armed by the caller around a control session (arm_panic /
       disarm_panic) and off the rest of the time.

  NEVER SECRETS  `type` refuses when the caller marks the text secret; passwords,
              card numbers and 2FA codes stay Ross's to enter by hand, and CAPTCHAs
              stay his to solve.

Both pyautogui and the Esc watcher (pynput) are optional deps, imported lazily:
this module loads without them and each call returns a clear 'not set up' note
until:  pip install pyautogui pillow pynput
"""
from __future__ import annotations

import base64
import io
import threading
import time

_guard = threading.Lock()          # one OS action at a time
_stop = threading.Event()          # either panic path sets this

INSTALL_HINT = ("computer control needs pyautogui — run once:  "
                "pip install pyautogui pillow")
PANIC_HINT = ("the Esc kill-switch needs pynput — run once:  pip install pynput  "
              "(the mouse-corner failsafe works without it)")


def available() -> tuple[bool, str]:
    try:
        import pyautogui  # noqa: F401
        return True, ""
    except Exception:
        return False, INSTALL_HINT


# ---- the shared stop flag (both panic paths + the caller use it) -------------

def request_stop() -> None:
    """Halt any in-flight sweep; the next call() refuses until clear_stop()."""
    _stop.set()


def clear_stop() -> None:
    _stop.clear()


def stopped() -> bool:
    return _stop.is_set()


# ---- keyboard panic: double-tap Esc -> request_stop -------------------------

_listener = None
_last_esc = [0.0]


def arm_panic() -> tuple[bool, str]:
    """Start watching for a double-Esc. Idempotent; returns (armed, note)."""
    global _listener
    if _listener is not None:
        return True, ""
    try:
        from pynput import keyboard
    except Exception:
        return False, PANIC_HINT

    def on_press(key):
        # Look at nothing but whether this is Esc, and how fast it repeated.
        if key == keyboard.Key.esc:
            now = time.monotonic()
            if now - _last_esc[0] < 0.6:
                request_stop()
            _last_esc[0] = now

    _listener = keyboard.Listener(on_press=on_press)
    _listener.daemon = True
    _listener.start()
    return True, ""


def disarm_panic() -> None:
    global _listener
    if _listener is not None:
        try:
            _listener.stop()
        except Exception:
            pass
        _listener = None


# ---- the desktop itself ------------------------------------------------------

def _pg():
    import pyautogui
    pyautogui.FAILSAFE = True       # mouse to a screen corner aborts the next action
    pyautogui.PAUSE = 0.1
    return pyautogui


def _screenshot_b64(max_w: int = 1280) -> tuple[str, list]:
    pg = _pg()
    img = pg.screenshot()           # PIL Image of the primary screen
    if img.width > max_w:
        h = int(img.height * max_w / img.width)
        img = img.resize((max_w, h))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode(), [img.width, img.height]


def _do(fn: str, args: dict) -> dict:
    pg = _pg()
    if fn == "screenshot":
        b64, size = _screenshot_b64(int(args.get("max_w", 1280)))
        return {"png_b64": b64, "shot_size": size, "screen": list(pg.size())}
    if fn == "move":
        pg.moveTo(int(args["x"]), int(args["y"]), duration=0.2)
        return {"moved": [args["x"], args["y"]]}
    if fn == "click":
        pg.click(int(args["x"]), int(args["y"]))
        return {"clicked": [args["x"], args["y"]]}
    if fn == "double_click":
        pg.doubleClick(int(args["x"]), int(args["y"]))
        return {"double_clicked": [args["x"], args["y"]]}
    if fn == "right_click":
        pg.rightClick(int(args["x"]), int(args["y"]))
        return {"right_clicked": [args["x"], args["y"]]}
    if fn == "scroll":
        pg.scroll(int(args.get("amount", -400)))
        return {"scrolled": int(args.get("amount", -400))}
    if fn == "type":
        if args.get("secret"):
            return {"error": "refused — never types passwords, cards or 2FA codes"}
        pg.typewrite(str(args.get("text", "")), interval=0.02)
        return {"typed": len(str(args.get("text", "")))}
    if fn == "key":
        keys = args.get("keys") or args.get("key") or ""
        if isinstance(keys, str) and "+" in keys:
            pg.hotkey(*[k.strip() for k in keys.split("+")])
        elif isinstance(keys, str):
            pg.press(keys)
        else:
            pg.press(list(keys))
        return {"pressed": keys}
    if fn == "launch":
        import os
        target = str(args.get("target", "")).strip()
        if not target:
            return {"error": "launch needs a target (a file, url, or app path)"}
        os.startfile(target)        # opens by file association; a broad, gated verb
        return {"launched": target}
    return {"error": f"unknown computer command {fn!r}"}


def call(fn: str, args: dict | None = None) -> dict:
    """Run one desktop action. Refuses if not set up or if a panic stop is set."""
    ok, why = available()
    if not ok:
        return {"error": why}
    if _stop.is_set():
        return {"error": "stopped — computer control is halted (clear the stop to resume)"}
    with _guard:
        try:
            return _do(fn, args or {})
        except Exception as e:
            return {"error": str(e)[:300]}
