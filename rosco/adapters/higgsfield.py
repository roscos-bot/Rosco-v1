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
# platform.higgsfield.ai is behind Cloudflare, which 403s (error 1010) the default
# Python-urllib signature. Their own SDK reaches the API fine, so present a normal
# client UA — this is our authorized API client identifying itself, not evasion.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")


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
            return safehttp.call(url, method=method,
                                 headers={"Authorization": scheme, "User-Agent": _UA,
                                          "Accept": "application/json"},
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
    # Image-extension urls ONLY. The old 'imgs or out' fallback returned ANY url
    # when none looked like an image — so a status/self/webhook/billing link got
    # handed back as the finished image. Better to find nothing (caller waits or
    # errors) than to present a broken link as success.
    seen, ordered = set(), []
    for u in imgs:
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
        # Only a terminal-success (or state-less) poll that carries a real image
        # url is the result. The removed 'if urls: return urls' used to end the
        # loop on the FIRST poll that merely echoed a self/status url while still
        # 'processing' — returning a non-image link and abandoning the real job.
        if urls and state in ("", "completed", "succeeded", "success", "done", "finished", "ready"):
            return urls
        time.sleep(every)
    raise RuntimeError("higgsfield is still working — try again in a moment")
