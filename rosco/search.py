"""Web search — Rosco's window on the open web, so an answer can be grounded in
current facts instead of a guess.

Pluggable and OPEN-SOURCE FIRST. The first usable backend wins, in this order:

  SEARXNG    a self-hosted (or public) metasearch engine — open source, NO key,
             and PRIVATE: it aggregates real engines from YOUR box and the query
             never goes to a commercial provider. This is to search what ollama is
             to models here: the local, keyless, on-your-own-terms option. Point
             it at your instance with `rosco secret set system searxng_url`
             (default http://localhost:8888; SearXNG must have the JSON format
             enabled — `search: {formats: [html, json]}` in its settings.yml).
  TAVILY / BRAVE   commercial APIs, used only if their key is stored — better rate
             limits and snippet quality when you want them.
  DUCKDUCKGO a keyless, best-effort fallback (the HTML endpoint) so search is
             never dead on arrival before SearXNG is up. Fragile and rate-limited;
             a stopgap, not the plan.

Every result is normalized to {title, url, snippet}. It all goes over safehttp
(https, no-redirect, size cap) — a localhost SearXNG is allowed because no
credential rides on that request. No backend reachable -> [] and the caller
answers from what it already has: the same "no key is never a worse answer" rule
the model layer holds.
"""
from __future__ import annotations

import html
import re
import urllib.parse

from . import safehttp

# Config/secret names in the vault (all under the 'system' business).
SEARXNG_URL = "searxng_url"
TAVILY_KEY = "tavily_api_key"
BRAVE_KEY = "brave_api_key"

# A normal browser UA: a bare urllib signature is refused by DDG and by some
# SearXNG instances behind a proxy. This is our client identifying itself.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")


def _cfg(vault, name: str) -> str:
    """A stored config/secret value, or '' — read defensively (no key, no crash)."""
    try:
        return (vault.get_secret("system", name) or "").strip()
    except Exception:
        return ""


def configured(vault) -> str:
    """Which backend web_search would use right now, for status/UI. Returns the
    keyless 'duckduckgo' when nothing is set."""
    if _cfg(vault, SEARXNG_URL):
        return "searxng"
    if _cfg(vault, TAVILY_KEY):
        return "tavily"
    if _cfg(vault, BRAVE_KEY):
        return "brave"
    return "duckduckgo"


def web_search(vault, query: str, *, n: int = 5, timeout: int = 12) -> list:
    """Top web results for a query as [{title, url, snippet}], best-effort.

    Picks the first configured backend (SearXNG url, then a commercial key) and
    falls back to keyless DuckDuckGo. Returns [] rather than raising when nothing
    is reachable, so the caller degrades to answering without the web."""
    query = (query or "").strip()
    if not query:
        return []
    base = _cfg(vault, SEARXNG_URL)
    if base:
        try:
            r = _searxng(base, query, n, timeout)
            if r:
                return r
        except Exception:
            pass
    tav = _cfg(vault, TAVILY_KEY)
    if tav:
        try:
            r = _tavily(tav, query, n, timeout)
            if r:
                return r
        except Exception:
            pass
    brave = _cfg(vault, BRAVE_KEY)
    if brave:
        try:
            r = _brave(brave, query, n, timeout)
            if r:
                return r
        except Exception:
            pass
    try:
        return _duckduckgo(query, n, timeout)     # keyless best-effort
    except Exception:
        return []


def _clip(s: str, n: int = 300) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()[:n]


def _searxng(base: str, query: str, n: int, timeout: int) -> list:
    url = base.rstrip("/") + "/search?" + urllib.parse.urlencode(
        {"q": query, "format": "json", "safesearch": "1"})
    d = safehttp.call(url, method="GET", timeout=timeout, headers={"User-Agent": _UA})
    out = []
    for r in (d.get("results") or [])[:n]:
        if isinstance(r, dict) and r.get("url"):
            out.append({"title": _clip(r.get("title", ""), 160),
                        "url": r["url"], "snippet": _clip(r.get("content", ""))})
    return out


def _tavily(key: str, query: str, n: int, timeout: int) -> list:
    d = safehttp.call("https://api.tavily.com/search", method="POST", timeout=timeout,
                      payload={"api_key": key, "query": query,
                               "max_results": n, "search_depth": "basic"})
    out = []
    for r in (d.get("results") or [])[:n]:
        if isinstance(r, dict) and r.get("url"):
            out.append({"title": _clip(r.get("title", ""), 160),
                        "url": r["url"], "snippet": _clip(r.get("content", ""))})
    return out


def _brave(key: str, query: str, n: int, timeout: int) -> list:
    url = "https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode(
        {"q": query, "count": n})
    d = safehttp.call(url, method="GET", timeout=timeout,
                      headers={"X-Subscription-Token": key, "User-Agent": _UA,
                               "Accept": "application/json"})
    out = []
    for r in ((d.get("web") or {}).get("results") or [])[:n]:
        if isinstance(r, dict) and r.get("url"):
            out.append({"title": _clip(r.get("title", ""), 160),
                        "url": r["url"], "snippet": _clip(r.get("description", ""))})
    return out


# DDG's HTML result: an anchor with class result__a (its href wraps the real
# target in a /l/?uddg= redirect), then a result__snippet anchor.
_DDG = re.compile(
    r'result__a[^>]*href="(?P<url>[^"]+)"[^>]*>(?P<title>.*?)</a>.*?'
    r'result__snippet[^>]*>(?P<snip>.*?)</a>', re.S | re.I)


def _duckduckgo(query: str, n: int, timeout: int) -> list:
    url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
    body = safehttp.call(url, method="GET", timeout=timeout, raw=True,
                         headers={"User-Agent": _UA})
    out = []
    for m in _DDG.finditer(body):
        u = html.unescape(m.group("url"))
        hit = re.search(r"[?&]uddg=([^&]+)", u)     # unwrap the redirect
        if hit:
            u = urllib.parse.unquote(hit.group(1))
        if u.startswith("//"):
            u = "https:" + u
        title = html.unescape(_clip(re.sub(r"<[^>]+>", "", m.group("title")), 160))
        snip = html.unescape(_clip(re.sub(r"<[^>]+>", "", m.group("snip"))))
        if u:
            out.append({"title": title, "url": u, "snippet": snip})
        if len(out) >= n:
            break
    return out
