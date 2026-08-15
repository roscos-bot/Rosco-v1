"""Higgsfield Cloud image generation — the one image-MAKING capability wired into
Rosco (the vision role only READS images; this creates them).

Async lifecycle: POST a prompt to a model endpoint, get a request id, then poll
GET /requests/{id}/status until the result URL appears. The auth scheme is
unsettled between Higgsfield's own sources ('Key ID:SECRET' vs 'Bearer <key>'),
so every call tries both and uses whichever authenticates - the same tactic the
key probe uses. Nothing here runs on its own: the chat gates an image the way it
gates a calendar write, because each generation spends.

Guardrail lives with the caller, not here: never point this at SteelHaven content
(the 'no AI-generated media' rule). This module just does what it's asked.
"""
from __future__ import annotations

import re
import time

from .. import safehttp

BASE = "https://platform.higgsfield.ai"
_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _code(err) -> str:
    m = re.search(r"HTTP (\d+)", str(err))
    return m.group(1) if m else ""


def _auth_call(key: str, url: str, *, method: str = "GET", payload=None, timeout: int = 30):
    """One call, trying 'Key <k>' then 'Bearer <k>'. Retries only on 401/403 (the
    other scheme might be right); any other error is real and raised."""
    k = (key or "").strip()
    last = None
    for scheme in ("Key " + k, "Bearer " + k):
        try:
            return safehttp.call(url, method=method, headers={"Authorization": scheme},
                                 payload=payload, timeout=timeout)
        except Exception as e:
            if _code(e) in ("401", "403"):
                last = e
                continue
            raise
    raise last or RuntimeError("higgsfield auth failed")


def _image_urls(obj) -> list[str]:
    """Every URL anywhere in a nested response, image-looking ones first — so we
    don't depend on Higgsfield's exact result field name."""
    out: list[str] = []

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            out.extend(_URL.findall(o))

    walk(obj)
    imgs = [u for u in out if re.search(r"\.(png|jpe?g|webp|gif)(\?|$)", u, re.I)]
    # de-dupe, keep order
    seen, ordered = set(), []
    for u in (imgs or out):
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def generate(key: str, prompt: str, *, num_images: int = 1,
             aspect_ratio: str = "1:1", polls: int = 30, every: float = 3.0) -> list[str]:
    """Make an image from a text prompt. Submits to soul/standard, polls the
    request to completion, returns the result image URL(s). Raises with a plain
    reason on failure or timeout."""
    prompt = (prompt or "").strip()
    if not prompt:
        raise ValueError("an image needs a prompt")
    sub = _auth_call(key, BASE + "/higgsfield-ai/soul/standard", method="POST",
                     payload={"prompt": prompt, "num_images": num_images,
                              "aspect_ratio": aspect_ratio}, timeout=30)
    rid = (sub.get("id") or sub.get("request_id")
           or (sub.get("data") or {}).get("id") if isinstance(sub, dict) else None)
    if not rid:                                  # some responses come back already done
        urls = _image_urls(sub)
        if urls:
            return urls
        raise RuntimeError("higgsfield accepted the prompt but returned no request id")
    for _ in range(polls):
        st = _auth_call(key, f"{BASE}/requests/{rid}/status", timeout=15)
        state = str((st.get("status") or st.get("state") or "")).lower() if isinstance(st, dict) else ""
        if state in ("failed", "error", "canceled", "cancelled", "rejected"):
            raise RuntimeError("higgsfield generation " + state)
        urls = _image_urls(st)
        if urls and state in ("", "completed", "succeeded", "success", "done", "finished", "ready"):
            return urls
        if urls:                                 # url present even without a clean state word
            return urls
        time.sleep(every)
    raise RuntimeError("higgsfield is still working — try again in a moment")
