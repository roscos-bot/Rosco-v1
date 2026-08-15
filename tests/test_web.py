"""The web console's safety properties, over a real socket.

Separate from test_core because it needs a live server and HTTP. The properties
here are the ones the localhost web surface adds: it starts locked, refuses a
foreign Host, refuses writes without the CSRF token, and drives the real
answer-the-queue loop end to end - the same loop the CLI proves, through the wire.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco.arrive import Arrival, Doorway, Proposal  # noqa: E402
from rosco.console import Console  # noqa: E402
from rosco.grants import GET  # noqa: E402
from rosco.web import ConsoleServer  # noqa: E402

PW = "a long enough passphrase"


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def req(port, method, path, body=None, headers=None, host="127.0.0.1"):
    c = HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": f"{host}:{port}"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read().decode()
    cookie = r.getheader("Set-Cookie")
    c.close()
    try:
        j = json.loads(raw)
    except ValueError:
        j = {"_raw": raw[:80]}
    return r.status, j, cookie


def main() -> int:
    fails = 0
    home = Path(tempfile.mkdtemp()) / "rosco"
    con = Console(home)
    con.init(PW)
    con.enrol(PW, "brent", "telegram", "8481123")
    # a real pending ask to answer through the web
    Doorway(con.open(), _F()).handle(Arrival("telegram", "8481123", "send me the bound book"))

    srv = ConsoleServer(con, 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        print("\nLOCKED BY DEFAULT")
        st, j, _ = req(port, "GET", "/api/overview")
        fails += not check("overview reports locked before unlock", j.get("unlocked"), False)
        st, j, _ = req(port, "GET", "/api/queue")
        fails += not check("the queue is refused while locked", st, 401)

        print("\nHOST ALLOW-LIST")
        st, j, _ = req(port, "GET", "/api/overview", host="evil.example.com")
        fails += not check("a foreign Host is refused (anti DNS-rebind)", st, 421)

        print("\nUNLOCK")
        st, j, cookie = req(port, "POST", "/api/unlock", {"passphrase": "wrong"})
        fails += not check("a wrong passphrase does not unlock", st, 401)
        st, j, cookie = req(port, "POST", "/api/unlock", {"passphrase": PW})
        fails += not check("the right passphrase unlocks", st, 200)
        fails += not check("and returns a CSRF token", bool(j.get("csrf")), True)
        token = j.get("csrf")
        sess = cookie.split(";")[0]        # rosco_session=...

        print("\nREADS, ONCE UNLOCKED")
        st, q, _ = req(port, "GET", "/api/queue", headers={"Cookie": sess})
        fails += not check("the queue reads with the session", st, 200)
        fails += not check("and shows the pending ask", len(q) >= 1, True)
        st, m, _ = req(port, "GET", "/api/mesh", headers={"Cookie": sess})
        fails += not check("the mesh is the real roster", len(m.get("nodes", [])) > 30, True)
        fails += not check("Rosco is in it", any(n["label"] == "Rosco" for n in m["nodes"]), True)

        print("\nWRITES NEED THE CSRF TOKEN")
        aid = q[0]["id"]
        st, j, _ = req(port, "POST", "/api/answer", {"id": aid, "verdict": "allow-once"},
                       headers={"Cookie": sess})
        fails += not check("a write without the CSRF header is refused", st, 403)
        st, j, _ = req(port, "POST", "/api/answer", {"id": aid, "verdict": "allow-once"},
                       headers={"Cookie": sess, "X-Rosco-CSRF": "wrong"})
        fails += not check("a wrong CSRF token is refused", st, 403)
        st, j, _ = req(port, "POST", "/api/answer", {"id": aid, "verdict": "allow-once"},
                       headers={"Cookie": sess, "X-Rosco-CSRF": token})
        fails += not check("the right token answers the ask", st, 200)

        print("\nWRITES NEED A SESSION AT ALL")
        st, j, _ = req(port, "POST", "/api/answer", {"id": aid, "verdict": "allow-always"},
                       headers={"X-Rosco-CSRF": token})
        fails += not check("no cookie means no write", st, 401)

        print("\nSETTINGS PAGE")
        # Config is authority - every setting is a signed write, gated like answering.
        st, j, _ = req(port, "GET", "/api/cfg/state", headers={"Cookie": sess})
        fails += not check("settings state reads with the session", st, 200)
        fails += not check("and lists the roles", "chat" in (j.get("roles") or []), True)
        fails += not check("but is refused while locked",
                           req(port, "GET", "/api/cfg/state")[0], 401)
        # A write needs the CSRF token.
        st, j, _ = req(port, "POST", "/api/cfg/budget", {"scope": "*", "usd": "150"},
                       headers={"Cookie": sess})
        fails += not check("a setting write without CSRF is refused", st, 403)
        st, j, _ = req(port, "POST", "/api/cfg/budget", {"scope": "*", "usd": "150"},
                       headers={"Cookie": sess, "X-Rosco-CSRF": token})
        fails += not check("a setting write with the token applies", st, 200)
        st, j, _ = req(port, "GET", "/api/cfg/state", headers={"Cookie": sess})
        fails += not check("and the change shows in the state",
                           any(b["cap"] == 150 for b in (j.get("budgets") or [])), True)
        # A secret can be set, but its value is never read back.
        st, j, _ = req(port, "POST", "/api/cfg/secret",
                       {"name": "openrouter_api_key", "value": "sk-or-secret"},
                       headers={"Cookie": sess, "X-Rosco-CSRF": token})
        fails += not check("a secret stores via settings", st, 200)
        st, j, _ = req(port, "GET", "/api/cfg/state", headers={"Cookie": sess})
        blob = json.dumps(j)
        fails += not check("the key name is listed",
                           "system:openrouter_api_key" in (j.get("secretsHeld") or []), True)
        fails += not check("but the value is never in the state", "sk-or-secret" in blob, False)
        # A bad setting comes back as an error, not a crash.
        st, j, _ = req(port, "POST", "/api/cfg/nope", {},
                       headers={"Cookie": sess, "X-Rosco-CSRF": token})
        fails += not check("an unknown setting is a clean error", st, 400)

        print("\nCHAT WITH ROSCO")
        # Chat is a gated write (it spends on a model call), so it needs the
        # session and the CSRF token like any other action.
        st, j, _ = req(port, "POST", "/api/chat", {"message": "hi"},
                       headers={"Cookie": sess})
        fails += not check("chat without the CSRF token is refused", st, 403)
        st, j, _ = req(port, "POST", "/api/chat", {"message": "hi"})
        fails += not check("chat with no session is refused", st, 401)
        # With the token it runs; no model key is set in this test, so Rosco
        # replies that no chat model is set - proving the path works and degrades.
        st, j, _ = req(port, "POST", "/api/chat", {"message": "what's waiting?"},
                       headers={"Cookie": sess, "X-Rosco-CSRF": token})
        fails += not check("chat with the token reaches Rosco", st, 200)
        # A fake key is set by the settings test above, so the call is attempted
        # and fails cleanly - never a crash. Either way the reply mentions the
        # chat model rather than throwing.
        fails += not check("and a model failure degrades to a message, not a crash",
                           "chat model" in (j.get("reply") or ""), True)

        print("\nLIVE ACTIVITY FEED")
        st, act, _ = req(port, "GET", "/api/activity", headers={"Cookie": sess})
        fails += not check("activity reads with the session", st, 200)
        # the pending bound-book ask (rum) should map to its captain, CaptainMorgan
        fails += not check("a real event is pinned to the right captain node",
                           any(e["node"] == "CaptainMorgan" for e in act), True)
        fails += not check("and it is refused while locked",
                           req(port, "GET", "/api/activity")[0], 401)

        print("\nTHE LOOP CLOSED")
        st, q2, _ = req(port, "GET", "/api/queue", headers={"Cookie": sess})
        fails += not check("the answered ask left the queue", len(q2), len(q) - 1)

        print("\nNO INLINE SCRIPT, EXTERNAL APP.JS")
        c = HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse(); page = r.read().decode(); csp = r.getheader("Content-Security-Policy"); c.close()
        fails += not check("script-src forbids inline", "'unsafe-inline'" not in (csp or "").split("script-src")[-1], True)
        fails += not check("the page carries no inline <script> body",
                           "<script>" not in page.replace('<script src="/app.js">', ""), True)

        print("\nTOOL CREDENTIAL DOES NOT FOLLOW A REDIRECT")
        fails += tool_redirect_check()
    finally:
        srv.shutdown()

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


def tool_redirect_check():
    """A compromised tool endpoint 302s to a capture host; the bearer must NOT go."""
    from rosco.tools import Tools
    from rosco.vault import Vault, derive_key
    from rosco.keys import Signer, Trust

    captured = {"auth": None}

    class Grab(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            # first host redirects; the (would-be) second host records the header
            if self.path == "/tool":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/steal")
                self.end_headers()
            else:
                captured["auth"] = self.headers.get("Authorization")
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.end_headers(); self.wfile.write(b'{"ok":true}')

    from http.server import HTTPServer
    import threading as _t
    hs = HTTPServer(("127.0.0.1", 0), Grab)
    _t.Thread(target=hs.serve_forever, daemon=True).start()
    p = hs.server_address[1]

    home = Path(tempfile.mkdtemp()) / "r"
    key = Signer.generate()
    log = __import__("rosco.store", fromlist=["Log"]).Log(home / "r.db", "console",
              ross=key, trust=Trust(ross=key.public))
    v = Vault(log, key=derive_key("pw", b"s"))
    v.put_secret("system", "k", "sk-vault-SUPERSECRET")
    tt = Tools(log)
    # register with http allowed only because no https loopback in test; the
    # https rule is checked in test_core. Here we prove the redirect is refused.
    tt.register("t", f"http://127.0.0.1:{p}/tool", auth_secret="")  # no cred: prove redirect refused
    tt.register("tc", f"http://127.0.0.1:{p}/tool")                 # will 302
    bad = 0
    try:
        tt.invoke("tc", {}, vault=v, business="")
        # if it did not raise, it followed the redirect - a failure
        bad += not check("invoke refuses to follow a redirect", "followed", "refused")
    except Exception:
        bad += not check("invoke refuses to follow a redirect", "refused", "refused")
    bad += not check("no credential reached the redirect target", captured["auth"], None)
    hs.shutdown()
    return bad

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


class _F:
    def classify(self, text):
        return Proposal("rum", "bound-book", GET, 0.95, "named")


if __name__ == "__main__":
    raise SystemExit(main())
