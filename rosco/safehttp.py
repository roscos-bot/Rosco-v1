"""One hardened way to call an outside service. Credentials depend on it.

Consolidated from the tool-invoke path after an audit found urllib re-sends the
Authorization header across a redirect - handing a vault credential to whatever
host a compromised endpoint names, and following it into internal targets
(SSRF). Every outbound call that carries a secret goes through here so that
lesson lives in exactly one place rather than being re-learned per integration.

The guarantees, when a bearer credential is passed:

  HTTPS ONLY. A credential never goes over plaintext.
  NO REDIRECTS. The bearer reaches only the exact host named; a 3xx is refused,
    so a malicious response cannot walk the credential off to another host.
  NO INTERNAL TARGETS. A host that resolves to loopback, private, link-local,
    reserved or multicast space is refused before we connect.
  A SIZE CAP. A reply larger than the cap is refused rather than read into
    memory without bound.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from urllib.error import HTTPError

MAX_RESPONSE = 8 * 1024 * 1024      # 8 MB


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code,
                        f"refusing a redirect to {newurl!r}; a credential stays "
                        f"with the host it was sent to", headers, fp)


def is_internal(host: str) -> bool:
    """Does this host resolve to somewhere a credential must never go?"""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return True
    return False


def call(url: str, *, method: str = "POST", payload: dict | None = None,
         bearer: str | None = None, headers: dict | None = None,
         timeout: int = 60, max_bytes: int = MAX_RESPONSE,
         allow_internal: bool = False) -> dict:
    """Make one request and return the parsed JSON reply ({} for an empty body).

    A bearer credential forces https, forbids an internal target, and forbids
    following any redirect. Without a bearer the same no-redirect and size-cap
    protections still apply - they are cheap and there is no reason to relax them.
    """
    parsed = urllib.parse.urlparse(url)
    if bearer is not None:
        if parsed.scheme != "https":
            raise ValueError(f"refusing to send a credential over {parsed.scheme!r}; https only")
        if not allow_internal and is_internal(parsed.hostname or ""):
            raise PermissionError(
                f"{parsed.hostname!r} resolves to an internal address; "
                f"refusing to send a credential there")

    h = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        h["Content-Type"] = "application/json"
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    if headers:
        h.update(headers)

    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_bytes + 1)
    except HTTPError as e:
        # Surface WHY, and as a ValueError callers already handle. A provider's
        # 4xx body says what was wrong ("model not found", "invalid api key"),
        # and an opaque HTTPError buried that. A refused redirect (raised by
        # _NoRedirect) carries its reason here too.
        detail = ""
        try:
            detail = e.read(2000).decode("utf-8", "replace").strip()
        except Exception:
            pass
        raise ValueError(f"HTTP {e.code} from {parsed.hostname}: "
                         f"{detail[:400] or e.reason}") from None
    if len(body) > max_bytes:
        raise ValueError(f"reply larger than {max_bytes} bytes; refused")
    if not body.strip():
        return {}
    return json.loads(body.decode())
