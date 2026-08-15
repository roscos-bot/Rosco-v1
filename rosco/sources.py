"""A local cache of ingested source files, so a gist in the vault is backed by
the real thing WITHOUT needing the internet again.

Ingesting keeps only a distilled shorthand in the vault (see ingest.py); the full
file is kept HERE, keyed by the same source pointer the lesson carries
(gh:repo/path, drive:name). When an agent needs more than the gist it reads the
local copy first - network only if the file was never cached. That is what makes
'go re-read the source for detail' work on a plane, and it keeps a durable copy
even if the upstream file later moves or is deleted.

Plain files under ~/.rosco/sources/. No index, no db - the filename IS the key, so
a re-ingest overwrites cleanly and there is nothing to keep in sync.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path


def _safe(source: str) -> str:
    """A filesystem-safe, still-readable name, with a short hash tail so two
    different sources can never collide on the same file."""
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", source)[:80].strip("_") or "src"
    tail = hashlib.sha256(source.encode("utf-8")).hexdigest()[:8]
    return f"{base}.{tail}.txt"


def _dir(home) -> Path:
    d = Path(home) / "sources"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(home, source: str, content: str) -> str:
    """Keep a local copy of one source. Returns its path, or '' if it couldn't
    be written (a cache miss is never fatal - the live fetch still works)."""
    if not source or content is None:
        return ""
    try:
        p = _dir(home) / _safe(source)
        p.write_text(content, encoding="utf-8")
        return str(p)
    except OSError:
        return ""


def load(home, source: str) -> str | None:
    """The locally cached text for a source, or None if it was never cached."""
    if not source:
        return None
    try:
        p = _dir(home) / _safe(source)
        return p.read_text(encoding="utf-8") if p.exists() else None
    except OSError:
        return None


def have(home, source: str) -> bool:
    return bool(source) and (_dir(home) / _safe(source)).exists()
