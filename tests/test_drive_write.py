"""Drive WRITES - the safety properties of putting a deliverable somewhere.

Drive was read-only until deliverables needed it. Writing has two failure modes
reading never had, and both are covered here:

  Writing the WRONG company's Drive is visible to other people and cannot be
  quietly undone, so a write resolves its token through the same fail-closed
  guard the read side uses (access_for_guarded - proven in test_google_guard).

  A PUBLIC share is a one-click, irreversible leak. drive_share cannot mint an
  'anyone with the link' permission at all - these tests prove there is no
  argument, and no role, that produces one.

Also covers the resumable upload's second hop: Google hands back a session URL
in a Location header and we PUT the bearer to it, so that URL is held to the
same https + no-internal bar as any other credentialed target. A Location
header is remote input.

Pure/stubbed - safehttp is monkeypatched, so no real HTTP.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco import safehttp  # noqa: E402
from rosco.adapters import google as g  # noqa: E402


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def raises(name, fn, exc=Exception):
    try:
        fn()
    except exc:
        return not check(name, "refused", "refused")
    except Exception as e:
        return not check(name, f"wrong error {type(e).__name__}", "refused")
    return not check(name, "allowed", "refused")


class Spy:
    """Stands in for safehttp.call and records every request."""

    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply if reply is not None else {"id": "F1", "name": "n"}

    def __call__(self, url, **kw):
        self.calls.append({"url": url, **kw})
        return self.reply

    @property
    def last(self):
        return self.calls[-1]


class FakeResp:
    def __init__(self, loc):
        self._loc = loc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getheader(self, _n):
        return self._loc


def opener_returning(loc):
    class O:
        def open(self, req, timeout=None):
            return FakeResp(loc)

    return lambda *a, **k: O()


def main() -> int:
    fails = 0
    real_call = safehttp.call

    print("SHARING IS TO A PERSON, NEVER TO THE PUBLIC")
    spy = Spy()
    safehttp.call = spy
    try:
        g.drive_share("tok", "F1", "brent@example.com")
        fails += not check("a named share sends type=user", spy.last["payload"]["type"], "user")
        fails += not check("and the address it was given",
                           spy.last["payload"]["emailAddress"], "brent@example.com")
        fails += not check("default role is reader (least privilege)",
                           spy.last["payload"]["role"], "reader")
        fails += not check("and it does not email them unless asked",
                           "sendNotificationEmail=false" in spy.last["url"], True)
        # The whole point: no argument produces an 'anyone' permission.
        fails += raises("a share with no address is refused",
                        lambda: g.drive_share("tok", "F1", ""), ValueError)
        fails += raises("'anyone' as an address is refused (not an email)",
                        lambda: g.drive_share("tok", "F1", "anyone"), ValueError)
        fails += raises("handing over ownership is refused",
                        lambda: g.drive_share("tok", "F1", "b@x.com", "owner"), ValueError)
        fails += raises("an invented role is refused",
                        lambda: g.drive_share("tok", "F1", "b@x.com", "anyoneWithLink"),
                        ValueError)
        before = len(spy.calls)
        for bad in ("", "anyone", "public"):
            try:
                g.drive_share("tok", "F1", bad)
            except ValueError:
                pass
        fails += not check("and no refused share reached the wire at all",
                           len(spy.calls), before)

        print("\nA FOLDER IS A FOLDER, IN THE PLACE IT WAS ASKED FOR")
        g.drive_create_folder("tok", "SteelHaven Plans", "PARENT")
        fails += not check("mimeType marks it a folder",
                           spy.last["payload"]["mimeType"], g.FOLDER_MIME)
        fails += not check("and it is created inside the parent",
                           spy.last["payload"]["parents"], ["PARENT"])
        g.drive_create_folder("tok", "Loose")
        fails += not check("no parent means no parents key (Drive root)",
                           "parents" in spy.last["payload"], False)
        fails += raises("a nameless folder is refused",
                        lambda: g.drive_create_folder("tok", "  "), ValueError)

        print("\nMOVE RE-PARENTS, AND ONLY REMOVES WHAT IT WAS TOLD TO")
        g.drive_move("tok", "F1", "NEW", "OLD")
        fails += not check("adds the new parent", "addParents=NEW" in spy.last["url"], True)
        fails += not check("removes the old one", "removeParents=OLD" in spy.last["url"], True)
        g.drive_move("tok", "F1", "NEW")
        fails += not check("with no old parent it removes nothing",
                           "removeParents" in spy.last["url"], False)
        fails += raises("a move with no destination is refused",
                        lambda: g.drive_move("tok", "F1", ""), ValueError)

        print("\nUPLOAD: METADATA OPENS A SESSION, BYTES GO TO IT")
        sessions = []

        def fake_session(token, meta, *, timeout=120):
            sessions.append(meta)
            return "https://upload.googleapis.com/session/ABC"

        real_session = g._upload_session
        g._upload_session = fake_session
        try:
            g.drive_upload("tok", "hull.step", b"SOLID", "model/step", "PARENT")
            fails += not check("the bytes PUT to the session URL Google named",
                               spy.last["url"], "https://upload.googleapis.com/session/ABC")
            fails += not check("as a PUT", spy.last["method"], "PUT")
            fails += not check("the body is the raw bytes", spy.last["body"], b"SOLID")
            fails += not check("with the declared content type",
                               spy.last["content_type"], "model/step")
            fails += not check("and the metadata carried the parent",
                               sessions[-1]["parents"], ["PARENT"])
            fails += not check("and the name", sessions[-1]["name"], "hull.step")
            fails += raises("a nameless upload is refused",
                            lambda: g.drive_upload("tok", "", b"x", "text/plain"), ValueError)
            fails += raises("text instead of bytes is refused",
                            lambda: g.drive_upload("tok", "a.txt", "not bytes", "text/plain"),
                            ValueError)
        finally:
            g._upload_session = real_session
    finally:
        safehttp.call = real_call

    print("\nTHE SESSION URL IS REMOTE INPUT, HELD TO THE SAME BAR")
    import urllib.request
    real_opener = urllib.request.build_opener
    for loc, why in (("http://upload.googleapis.com/s/1", "a plaintext session URL is refused"),
                     ("https://127.0.0.1/s/1", "a loopback session URL is refused"),
                     ("", "a missing session URL is refused")):
        urllib.request.build_opener = opener_returning(loc)
        try:
            fails += raises(why, lambda: g._upload_session("tok", {"name": "x"}),
                            (ValueError, PermissionError))
        finally:
            urllib.request.build_opener = real_opener

    urllib.request.build_opener = opener_returning("https://upload.googleapis.com/s/OK")
    try:
        fails += not check("a good https session URL is returned",
                           g._upload_session("tok", {"name": "x"}),
                           "https://upload.googleapis.com/s/OK")
    finally:
        urllib.request.build_opener = real_opener

    print("\nSAFEHTTP'S RAW BODY KEEPS EVERY GUARD")
    fails += raises("body= plus payload= is refused (one body per request)",
                    lambda: safehttp.call("https://x.test/", body=b"a", payload={"b": 1}),
                    ValueError)
    fails += raises("body= plus form= is refused",
                    lambda: safehttp.call("https://x.test/", body=b"a", form={"b": "1"}),
                    ValueError)
    fails += raises("an upload over plaintext is refused (bearer, http)",
                    lambda: safehttp.call("http://x.test/", bearer="t", body=b"a",
                                          content_type="application/octet-stream"),
                    ValueError)
    fails += raises("an upload to an internal host is refused (bearer, loopback)",
                    lambda: safehttp.call("https://localhost/up", bearer="t", body=b"a",
                                          content_type="application/octet-stream"),
                    PermissionError)

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
