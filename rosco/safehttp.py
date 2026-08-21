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
from urllib.error import HTTPError, URLError

MAX_RESPONSE = 8 * 1024 * 1024      # 8 MB


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code,
                        f"refusing a redirect to {newurl!r}; a credential stays "
                        f"with the host it was sent to", headers, fp)


# The invisibles a paste drags in: ASCII whitespace, every C0 control (NUL..US -
# this is where U+0016/SYN, a stray Ctrl-V, lives), DEL, the C1 controls, and the
# zero-width/BOM family. Stripped only from the ENDS of a credential, where they
# are unambiguously paste noise - no API key begins or ends with a control char.
_EDGE_JUNK = ("".join(chr(c) for c in range(0x00, 0x21)) + "\x7f"
              + "".join(chr(c) for c in range(0x80, 0xA0))
              + "​‌‍⁠﻿")


def clean_credential(value: str, *, label: str = "value") -> str:
    """A credential fit to use, or a clear refusal.

    A pasted key arrives with junk at the edges (a trailing newline, a leading
    Ctrl-V/SYN, a zero-width space from a copy) or - more insidiously - a control
    character in the MIDDLE. Sent as an HTTP header, urllib latin-1s any of it
    into the request and the provider's edge (Cloudflare) rejects it with an
    opaque, EMPTY-bodied 400 that reads like a bad model id or a mystery.

    Edge junk is stripped (it is never part of the token); an interior forbidden
    character is refused by name, because a control char between real characters
    means the stored value is genuinely corrupt - two things concatenated, a
    smart-quote in a passphrase - not an edge artifact to quietly paper over.

    Used both when SENDING (below) and when STORING (vault.put_secret), so a
    corrupt paste is caught at the door and never persists to fail cryptically
    on some later request.
    """
    v = (value or "").strip(_EDGE_JUNK)
    if not v:
        raise ValueError(
            f"the {label} is empty once stray/invisible characters are removed; "
            f"re-enter it")
    for i, ch in enumerate(v):
        o = ord(ch)
        if o < 0x20 or o > 0x7E:
            raise ValueError(
                f"the {label} carries a character HTTP forbids (U+{o:04X} at "
                f"position {i}) in the middle; the value is corrupt - re-enter "
                f"it cleanly")
    return v


def _header_value(name: str, value: str) -> str:
    """Clean a header value on its way onto the wire. See clean_credential."""
    return clean_credential(value, label=f"{name} header")


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
         form: dict | None = None, bearer: str | None = None,
         headers: dict | None = None, timeout: int = 60,
         max_bytes: int = MAX_RESPONSE, allow_internal: bool = False,
         raw: bool = False, binary: bool = False,
         body: bytes | None = None, content_type: str = ""):
    """Make one request and return the parsed JSON reply ({} for an empty body),
    or - with raw=True - the response body decoded as text. raw is for endpoints
    that return a document, not JSON (a Google Doc exported to text/plain, a CSV
    sheet); every other guard (https-on-credential, no redirect, size cap) is
    unchanged.

    A bearer credential (or a `form` body, which for OAuth carries the client
    secret) forces https, forbids an internal target, and forbids following any
    redirect. Without either the same no-redirect and size-cap protections still
    apply - they are cheap and there is no reason to relax them.

    `body` sends RAW BYTES with `content_type` instead of a JSON or form body -
    what a file upload needs (Drive's resumable PUT). It is exclusive with
    payload/form: a request has one body, and silently letting a second one win
    is how a caller ends up uploading the wrong thing. Every guard above still
    applies - an upload carries a bearer, so it is https-only, redirect-refusing
    and internal-target-refusing exactly like any other credentialed call.
    """
    parsed = urllib.parse.urlparse(url)
    if bearer is not None or form is not None:
        # A form body carries the OAuth client_secret; hold it to the same bar as
        # a bearer - https only, never an internal host, never a redirect.
        if parsed.scheme != "https":
            raise ValueError(f"refusing to send a credential over {parsed.scheme!r}; https only")
        if not allow_internal and is_internal(parsed.hostname or ""):
            raise PermissionError(
                f"{parsed.hostname!r} resolves to an internal address; "
                f"refusing to send a credential there")

    if body is not None and (payload is not None or form is not None):
        raise ValueError("pass body= OR payload=/form=, never both; a request has one body")

    h = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = body
        if content_type:
            h["Content-Type"] = content_type
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif payload is not None:
        data = json.dumps(payload).encode()
        h["Content-Type"] = "application/json"
    if bearer:
        # Validate, don't just strip: a trailing newline, an interior control
        # char, or a non-ASCII paste artifact all corrupt the credential header
        # and earn an opaque 400. _header_value refuses any of them by name.
        h["Authorization"] = f"Bearer {_header_value('Authorization', bearer)}"
    if headers:
        # Any caller-set header may carry a credential too (x-api-key,
        # x-goog-api-key) - hold them to the same clean-value bar.
        for k, val in headers.items():
            h[k] = _header_value(k, val) if isinstance(val, str) else val

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
        # A 401's body reflects the submitted credential back - every OpenAI-shaped
        # provider echoes a masked key ("Incorrect API key provided: sk-...XXXX").
        # That body is surfaced all the way to the browser, so on 401 keep only
        # status+host and drop it. A 403 is "forbidden / API not enabled /
        # insufficient scope" - no credential echo, and the body ("enable the
        # Drive API in project X") is the useful part - so 403 and every other
        # code keep their body.
        if e.code == 401:
            detail = "authentication rejected"
        raise ValueError(f"HTTP {e.code} from {parsed.hostname}: "
                         f"{detail[:400] or e.reason}") from None
    except (TimeoutError, URLError) as e:
        # A transport failure - connect/read timeout, connection refused, DNS.
        # urllib raises a raw URLError on the connect phase (a read timeout comes
        # up as socket.timeout == TimeoutError), and letting either escape raw
        # broke the docstring's promise that callers only handle ValueError, and
        # crashed `rosco run` on a transient blip. Normalize to a consistent
        # contract: timeouts as TimeoutError (see() retries these), every other
        # transport failure as ValueError. HTTPError is handled above (it, too,
        # subclasses URLError), so only genuine transport errors reach here.
        reason = getattr(e, "reason", e)
        if isinstance(e, TimeoutError) or isinstance(reason, (TimeoutError, socket.timeout)):
            raise TimeoutError(f"timed out reaching {parsed.hostname}") from None
        raise ValueError(f"could not reach {parsed.hostname}: {reason}") from None
    if len(body) > max_bytes:
        raise ValueError(f"reply larger than {max_bytes} bytes; refused")
    if binary:
        return body                          # raw bytes (a PDF download, say), past every guard
    if raw:
        return body.decode("utf-8", "replace")
    if not body.strip():
        return {}
    return json.loads(body.decode())
