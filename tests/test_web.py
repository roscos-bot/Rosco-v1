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

        print("\nTHE LOOP CLOSED")
        st, q2, _ = req(port, "GET", "/api/queue", headers={"Cookie": sess})
        fails += not check("the answered ask left the queue", len(q2), len(q) - 1)
    finally:
        srv.shutdown()

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


class _F:
    def classify(self, text):
        return Proposal("rum", "bound-book", GET, 0.95, "named")


if __name__ == "__main__":
    raise SystemExit(main())
