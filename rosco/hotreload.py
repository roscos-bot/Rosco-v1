"""Hot-reload: swap a long-running service's code for the edited version WITHOUT
restarting, so a held passphrase (serve) or an unlocked session survives.

Watches the rosco/*.py sources and, on a change that still compiles, reloads the
modules so the next call runs the new code. A plain importlib.reload is only half
the job — existing OBJECTS keep their old class — so a caller that holds long-lived
instances re-bases or rebuilds them after reload_modules() (see TelegramBot._reload,
which rebuilds its doorway/console from the fresh modules).

This is what lets `rosco serve` pick up an edit without the passphrase-gated
restart that a fresh process would need.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def _sources() -> list[Path]:
    return sorted(_ROOT.rglob("*.py"))


def stamp() -> dict:
    """{path: mtime} of every rosco source — the change-detection snapshot."""
    out = {}
    for p in _sources():
        try:
            out[p] = p.stat().st_mtime
        except OSError:
            pass
    return out


def changed(base: dict):
    """(changed_filenames, new_stamp) since `base`. Callers keep the new stamp."""
    cur = stamp()
    names = {p.name for p in cur if base.get(p) != cur.get(p)}
    names |= {p.name for p in base if p not in cur}
    return names, cur


def compiles_ok():
    """(ok, why) — every source parses, so a half-typed save doesn't reload a
    broken tree. Returns the first offender's name + reason when not ok."""
    import py_compile
    for p in _sources():
        try:
            py_compile.compile(str(p), doraise=True)
        except py_compile.PyCompileError as e:
            return False, f"{p.name}: {str(e.msg)[:80]}"
        except Exception:
            pass
    return True, ""


def reload_modules() -> None:
    """Reload every already-imported rosco.* module (twice, so cross-module
    `from x import y` bindings settle onto the new code). __main__ is skipped so
    the running entrypoint's frame is left alone."""
    mods = [n for n in list(sys.modules)
            if n.startswith("rosco.") and n != "rosco.__main__"
            and sys.modules.get(n) is not None]
    for _ in range(2):
        for n in mods:
            try:
                importlib.reload(sys.modules[n])
            except Exception:
                pass
