"""The console with a face - a localhost web app over the real modules.

Same authority model as the CLI, same rule: only this machine, and only after
Ross unlocks. The design was approved as a mockup; this is it wired to live data.

WHY A LOCAL WEB SERVER IS TREATED AS HOSTILE TERRAIN. A browser on Ross's
machine can be pointed at 127.0.0.1 by any web page he happens to have open, and
DNS-rebinding can make a remote site's JavaScript talk to a local server. So a
localhost bind is necessary and not sufficient. Three more guards:

  BIND 127.0.0.1 ONLY. Never 0.0.0.0 - the network must not reach it at all.
  This is the same "only localhost changes anything" rule as the whole system.

  HOST ALLOW-LIST. Every request's Host header must be localhost or 127.0.0.1
  on our port. A rebinding attack arrives with the attacker's hostname in Host;
  it is refused before any handler runs.

  UNLOCK, THEN A TOKEN ON EVERY WRITE. Reading and writing both require an
  unlock (the passphrase, entered once), which mints a session held only in this
  process's memory. Writes additionally carry that token in a header no
  cross-site page can set, so a page that tricks the browser into POSTing still
  cannot act - it cannot read the cookie and cannot forge the header.

The passphrase lives in memory for the session, exactly as `rosco serve` holds
it - the price of a console that stays open. It is never written to disk and
never sent back to the browser; the browser holds an opaque token, nothing more.
"""
from __future__ import annotations

import json
import secrets as pysecrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .asks import ANSWERS, Asks
from .grants import ANY, DO, GET, SCOPE_ALL, SCOPES, Grants
from .identity import People
from .keys import ROSS
from .meter import ALL, Meter
from .models import Models
from .nodes import Nodes
from .roster import BUSINESSES, roster
from .tools import Tools
from .vault import Vault

APP = (Path(__file__).parent / "web_app.html")
APP_JS = (Path(__file__).parent / "web_app.js")

# script-src is 'self' with NO 'unsafe-inline': the page's script is served as a
# separate file, so an injected inline handler (an <img onerror=...> smuggled
# through log data) cannot execute even if an escaping sink is ever missed. This
# is the layer that makes the XSS class un-exploitable rather than just patched.
CSP_PAGE = ("default-src 'self'; style-src 'unsafe-inline'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
CSP_API = "default-src 'none'"


class Session:
    """One unlocked session. The passphrase and a token, in memory only."""
    def __init__(self, passphrase: str) -> None:
        self.passphrase = passphrase
        self.token = pysecrets.token_urlsafe(24)
        self.opened = time.time()


class ConsoleServer(ThreadingHTTPServer):
    def __init__(self, console, port: int) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.console = console
        self.session: Session | None = None      # single user, single session
        self.port = port

    # ---- the live data, assembled from the real modules ----

    def _log(self, s: Session | None):
        # A read uses the passphrase if we have it (some views want the vault);
        # the queue and grants do not need it, so an unlocked session is enough.
        return self.console.open(s.passphrase if s else None)

    def overview(self, s):
        # While locked, disclose nothing and do no work. /api/overview is the one
        # endpoint served before the session gate, so a locked reply must not
        # leak the spend total or the queue depth, nor run verify() unauthenticated.
        if s is None:
            return {"node": "console", "unlocked": False}
        log = self.console.open()
        asks = Asks(log)
        meter = Meter(log)
        spent = meter.reading(ALL)
        problems = log.verify()
        return {
            "node": "console",
            "unlocked": s is not None,
            "waiting": len(asks.pending()),
            "spend": round(spent.spent, 2),
            "spendCalls": spent.calls,
            "chains": "sound" if not problems else f"{len(problems)} problem(s)",
        }

    def queue(self, s):
        log = self.console.open()
        out = []
        for a in Asks(log).pending():
            out.append({"id": a.id, "person": a.person, "business": a.business,
                        "capability": a.capability, "verb": a.verb,
                        "detail": a.detail, "times": a.times, "nagged": a.nagged,
                        "seen": a.seen})
        return out

    def mesh(self, s):
        """Agents, people and sites as one graph - the real roster, live."""
        log = self.console.open()
        nodes, edges, seen = [], [], set()

        def node(nid, label, typ, **extra):
            if nid in seen:
                return
            seen.add(nid)
            nodes.append({"id": nid, "label": label, "type": typ, **extra})

        for a in roster():
            node(a.name, a.name, "agent", rank=a.rank, business=a.business,
                 reports=a.reports_to)
            if a.reports_to and a.reports_to != "ross":
                edges.append({"a": a.name, "b": a.reports_to, "kind": "command"})
        # people, linked to the businesses they can reach (from live grants)
        grants = Grants(log).live()
        access = {}
        for g in grants:
            if g.allow:
                access.setdefault(g.person, set()).add(g.business)
        for person, bizset in access.items():
            if person == ROSS:
                continue
            node("p:" + person, person.title(), "person",
                 business=", ".join(sorted(bizset)))
            for b in bizset:
                cap = next((c.captain for c in BUSINESSES if c.slug == b), None)
                if cap:
                    edges.append({"a": "p:" + person, "b": cap, "kind": "access"})
        # sites
        for n in Nodes(log).all():
            node("s:" + n.name, n.name, "site", business=n.site)
            edges.append({"a": "s:" + n.name, "b": "Rosco", "kind": "host"})
        # external tools, linked to the businesses that may reach them
        for t in Tools(log).all():
            node("t:" + t.name, t.name, "tool", business=", ".join(t.businesses),
                 caution=t.caution)
            for c in BUSINESSES:
                if t.reachable_by(c.slug) or "*" in t.businesses:
                    edges.append({"a": "t:" + t.name, "b": c.captain, "kind": "tool"})
        return {"nodes": nodes, "edges": edges}

    # ---- live activity: what the agents are actually doing ----

    _ACTIVITY = {
        "agent.produced": ("drafted", "agent"),
        "agent.answered": ("answered", "agent"),
        "ask.raised": ("a request landed", "captain"),
        "github.proposed": ("opened a PR", "captain"),
    }

    def activity(self, s, limit: int = 40):
        """Recent real events, each pinned to a node in the mesh.

        The frontend fires a light down the fibre into that node and flares it -
        so the graph reacts to what the system is genuinely doing, not to a timer.
        Read-only, session-gated, and it maps only events that name an agent or a
        business; nothing here discloses a message body.
        """
        from .roster import business as biz_of
        out = []
        for ev in self.console.open().replay():
            spec = self._ACTIVITY.get(ev["kind"])
            if not spec:
                continue
            label, kind = spec
            b = ev["body"]
            if kind == "agent":
                node = b.get("agent")
            else:                                   # a business -> its captain
                biz = biz_of(b.get("business", ""))
                node = biz.captain if biz else None
            if node:
                out.append({"id": ev["id"], "node": node, "what": label, "at": ev["ts"]})
        return out[-limit:]

    def grants_view(self, s):
        return [{"id": g.id, "person": g.person, "business": g.business,
                 "capability": g.capability, "verb": g.verb, "allow": g.allow,
                 "scope": g.scope, "reason": g.reason}
                for g in Grants(self.console.open()).live()]

    def people_view(self, s):
        p = People(self.console.open())
        names = sorted({h.person for h in p.handles()})
        return [{"person": n, "handles": [{"channel": h.channel, "raw": h.raw}
                                          for h in p.handles(person=n)]} for n in names]

    def spend_view(self, s):
        m = Meter(self.console.open())
        return {"report": m.report(), "budgets": [{"scope": b.scope, "cap": b.monthly_usd}
                                                  for b in m.budgets().values()]}

    # ---- the one write the dashboard needs first ----

    def answer(self, s, body):
        aid = body.get("id", ""); verdict = body.get("verdict", "")
        note = body.get("note", "")
        if verdict not in ANSWERS:
            raise ValueError("bad verdict")
        return self.console.answer(s.passphrase, aid, verdict, note)

    def chat(self, s, body):
        """Ross talking to Rosco at the console. Rosco answers across everything.

        A read: Rosco composes an answer grounded in the whole vault. It does not
        act - the same 'agents build, people ship' line holds here. Uses the CHAT
        model (quality over cost) since this is the seat Ross sits in.
        """
        from .agent import Agent
        from .llm import NoModel, complete
        from .meter import Meter
        msg = (body.get("message") or "").strip()[:2000]
        if not msg:
            return "..."
        log = self.console.open(s.passphrase)
        models = Models(log, Vault(log, key=self.console._vault_key(s.passphrase)))
        meter = Meter(log)

        def think(system, user):
            return complete(models, "chat", system, user, meter=meter)
        try:
            return Agent("Rosco", log, think=think, meter=meter).answer(
                msg, for_person="ross")
        except NoModel as e:
            return f"(no chat model set - {e})"
        except Exception as e:
            # A provider error, a bad model id, a timeout - it comes back as a
            # message in the chat, never as a crashed request.
            return f"(couldn't reach the chat model: {e})"

    # ---- settings: the CLI's config commands, as forms ----
    #
    # Every one is an authority write - a grant, a secret, a model choice - so it
    # runs through the exact signed console methods the CLI uses, gated by the
    # session and the CSRF token like any other action. The browser can configure
    # the system only because Ross unlocked it; a locked console can change nothing.

    def cfg_state(self, s):
        """What the settings forms show as current. No secret VALUES, only names."""
        from . import capabilities as caps
        from .github import GitHub
        from .meter import ALL, Meter
        from .models import ROLES
        from .roster import BUSINESSES
        from .tools import Tools
        log = self.console.open(s.passphrase)
        models = Models(log, Vault(log, key=self.console._vault_key(s.passphrase)))
        ch = models.choices(node="console")
        return {
            "roles": list(ROLES),
            "providers": ["openrouter", "anthropic", "openai", "google", "xai", "ollama"],
            "models": {r: {"model": c.model, "provider": c.provider, "why": c.why}
                       for r, c in ch.items()},
            "secretsHeld": Vault(log).secret_names(),
            "missingKeys": models.missing(node="console"),
            "budgets": [{"scope": b.scope, "cap": b.monthly_usd}
                        for b in Meter(log).budgets().values()],
            "businesses": [b.slug for b in BUSINESSES],
            "capabilities": sorted({c.name for c in caps.CATALOGUE}),
            "tools": [{"name": t.name, "businesses": list(t.businesses)}
                      for t in Tools(log).all()],
            "repos": [{"business": r.business, "slug": r.slug} for r in GitHub(log).all()],
            "people": sorted({h.person for h in People(log).handles()}),
        }

    def models_available(self, s, provider):
        """What a provider actually offers - for the model dropdown.

        Fetches the provider's own model list (over safehttp: no redirects, so
        the key can't be walked off). Uses the stored key where the provider
        needs one; returns an empty list with a note when there is none or the
        provider has no simple listing, and the form falls back to typing.
        """
        from .models import secret_name
        log = self.console.open(s.passphrase)
        key = ""
        try:
            key = Vault(log, key=self.console._vault_key(s.passphrase)).get_secret(
                "system", secret_name(provider)) or ""
        except Exception:
            pass
        try:
            return {"models": _list_models(provider, key)}
        except Exception as e:
            return {"models": [], "error": str(e)}

    def cfg(self, s, action, body):
        """Apply one setting. Returns the console's own confirmation string."""
        pw = s.passphrase
        c = self.console
        if action == "model":
            return c.model_set(pw, body["role"], body["model"], body["provider"],
                               node=body.get("node", ""))
        if action == "secret":
            v = body.get("value", "")
            if not v:
                raise ValueError("a key value is required")
            return c.secret_set(pw, body.get("business", "system"), body["name"], v)
        if action == "budget":
            return c.budget_set(pw, body.get("scope", "*"), body["usd"])
        if action == "ingest":
            text = (body.get("text") or "").strip()
            if text:
                from . import knowledge
                n = knowledge.ingest_text(Vault(c.open(pw)), body["business"], text,
                                          source="dashboard")
                return f"ingested {n} lessons into {body['business']}"
            return c.ingest(pw, body["business"])
        if action == "enrol":
            return c.enrol(pw, body["person"], body["channel"], body["address"])
        if action == "grant":
            from .grants import SCOPE_ALL
            return c.give(pw, body["person"], body["business"], body["capability"],
                          verb=body.get("verb", "get"),
                          scope=body.get("scope", SCOPE_ALL),
                          reason=body.get("reason", ""))
        if action == "tool":
            biz = body.get("businesses") or ["*"]
            return c.tool_add(pw, body["name"], body["endpoint"],
                              businesses=tuple(biz), secret=body.get("secret", ""),
                              caution=body.get("caution", ""))
        if action == "github":
            return c.github_link(pw, body["business"], body["repo"],
                                 branch=body.get("branch", "main"),
                                 secret=body.get("secret", "github_token"))
        raise ValueError(f"no such setting {action!r}")


def _list_models(provider, key):
    """The model ids a provider currently serves. Over safehttp, no redirects."""
    from . import safehttp
    if provider == "openrouter":
        d = safehttp.call("https://openrouter.ai/api/v1/models", method="GET",
                          bearer=key or None)
        return sorted({m.get("id", "") for m in (d.get("data") or []) if m.get("id")})
    if provider == "anthropic":
        if not key:
            raise RuntimeError("no anthropic key stored")
        d = safehttp.call("https://api.anthropic.com/v1/models", method="GET",
                          headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
        return sorted({m.get("id", "") for m in (d.get("data") or []) if m.get("id")})
    if provider == "openai":
        if not key:
            raise RuntimeError("no openai key stored")
        d = safehttp.call("https://api.openai.com/v1/models", method="GET", bearer=key)
        return sorted({m.get("id", "") for m in (d.get("data") or []) if m.get("id")})
    if provider == "ollama":
        d = safehttp.call("http://localhost:11434/api/tags", method="GET")
        return sorted({m.get("name", "") for m in (d.get("models") or []) if m.get("name")})
    return []          # google / xai: no simple public list - the form lets you type


LOCAL_HOSTS = None  # set per-server from its port


class Handler(BaseHTTPRequestHandler):
    server_version = "rosco/1"

    def log_message(self, *a):        # quiet; this is a personal tool
        pass

    # ---- guards ----

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _session(self):
        cookie = self.headers.get("Cookie") or ""
        tok = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("rosco_session="):
                tok = part[len("rosco_session="):]
        s = self.server.session
        if s and tok and pysecrets.compare_digest(tok, s.token):
            return s
        return None

    def _send(self, code, obj, cookie=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP_API)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    # ---- routing ----

    def do_GET(self):
        if not self._host_ok():
            return self._send(421, {"error": "bad host"})
        if self.path == "/" or self.path.startswith("/index"):
            try:
                html = APP.read_bytes()
            except OSError:
                html = b"<h1>web_app.html missing</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Content-Security-Policy", CSP_PAGE)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return self.wfile.write(html)
        if self.path == "/app.js":
            try:
                js = APP_JS.read_bytes()
            except OSError:
                js = b"/* web_app.js missing */"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(js)))
            self.send_header("Content-Security-Policy", CSP_PAGE)
            # Never cache the app - this is a single-user local tool under active
            # development, and a stale app.js is exactly the confusion that had
            # the dashboard calling routes the running server did not yet have.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return self.wfile.write(js)

        srv = self.server
        if self.path == "/api/overview":
            return self._send(200, srv.overview(self._session()))

        s = self._session()
        if s is None:
            return self._send(401, {"error": "locked"})
        if self.path.split("?")[0] == "/api/cfg/models":
            from urllib.parse import parse_qs, urlparse
            provider = (parse_qs(urlparse(self.path).query).get("provider") or [""])[0]
            return self._send(200, srv.models_available(s, provider))
        views = {"/api/queue": srv.queue, "/api/mesh": srv.mesh,
                 "/api/activity": srv.activity, "/api/cfg/state": srv.cfg_state,
                 "/api/grants": srv.grants_view, "/api/people": srv.people_view,
                 "/api/spend": srv.spend_view}
        fn = views.get(self.path.split("?")[0])
        if fn:
            return self._send(200, fn(s))
        return self._send(404, {"error": "no such view"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(421, {"error": "bad host"})
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})

        if self.path == "/api/unlock":
            pw = body.get("passphrase", "")
            try:
                self.server.console._ross(pw)         # unseal; raises if wrong
            except Exception:
                return self._send(401, {"error": "wrong passphrase"})
            self.server.session = Session(pw)
            cookie = ("rosco_session=" + self.server.session.token +
                      "; HttpOnly; SameSite=Strict; Path=/")
            return self._send(200, {"ok": True, "csrf": self.server.session.token}, cookie)

        # every other POST is a write: unlock + CSRF header, both required.
        s = self._session()
        if s is None:
            return self._send(401, {"error": "locked"})
        csrf = self.headers.get("X-Rosco-CSRF") or ""
        if not pysecrets.compare_digest(csrf, s.token):
            return self._send(403, {"error": "missing or bad CSRF token"})

        try:
            if self.path == "/api/answer":
                return self._send(200, {"ok": True, "result": self.server.answer(s, body)})
            if self.path == "/api/chat":
                return self._send(200, {"reply": self.server.chat(s, body)})
            if self.path.startswith("/api/cfg/"):
                msg = self.server.cfg(s, self.path[len("/api/cfg/"):], body)
                return self._send(200, {"ok": True, "msg": msg})
            if self.path == "/api/lock":
                self.server.session = None
                return self._send(200, {"ok": True})
        except (ValueError, KeyError, SystemExit) as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            # No handler may crash the request thread and print a traceback to
            # the console. Anything unexpected comes back as a 500 with a note.
            return self._send(500, {"error": f"server error: {e}"})
        return self._send(404, {"error": "no such action"})


def _stamp():
    """mtimes of the package's own source - what the watcher compares."""
    out = {}
    for p in Path(__file__).parent.rglob("*.py"):
        try:
            out[p] = p.stat().st_mtime
        except OSError:
            pass
    return out


def _supervise(port: int) -> None:
    """Run the server as a child and restart it when rosco/*.py changes.

    A supervisor rather than os.execv, because execv is flaky on Windows: this
    spawns `rosco web --no-reload` as a child, watches the source, and on any
    change terminates and respawns it. Stdlib only - no watchdog dependency, in
    keeping with the rest of the codebase.

    The served page is read from disk each request, so a browser reload already
    picks up HTML/JS edits; this is for the Python ROUTES, where a stale process
    calling endpoints it does not yet have was the confusion this removes.

    One honest cost: a restart drops the in-memory session, so the browser
    unlocks again. The passphrase lives only in memory by design - a reload
    cannot carry it across without writing it down, the one thing it must not do.
    """
    import subprocess
    child_cmd = [sys.executable, "-m", "rosco", *sys.argv[1:], "--no-reload"]
    print(f"console on http://127.0.0.1:{port}  (localhost only)")
    print("watching for code changes — it restarts itself. Ctrl-C to stop.")
    proc, base = None, _stamp()
    try:
        proc = subprocess.Popen(child_cmd)
        while True:
            time.sleep(1.0)
            if proc.poll() is not None:
                print(f"server exited ({proc.returncode}).")
                return
            cur = _stamp()
            changed = {p.name for p in cur if base.get(p) != cur.get(p)}
            changed |= {p.name for p in base if p not in cur}
            if changed:
                print(f"  code changed ({', '.join(sorted(changed)[:4])}) — "
                      f"restarting; unlock again in the browser.")
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                proc = subprocess.Popen(child_cmd)
                base = cur
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()


def serve_web(console, port: int = 8787, *, reload: bool = True) -> None:
    if reload:
        return _supervise(port)
    srv = ConsoleServer(console, port)
    print(f"console on http://127.0.0.1:{port}  (localhost only)")
    print("open it, unlock with your passphrase. Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
