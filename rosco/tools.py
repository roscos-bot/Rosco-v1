"""External tools - what agents can reach beyond themselves.

Ross wants to expand what the agents have to work with: Higgsfield for media,
an MCP server, some vendor API. Each of those is, in this system's terms, a
CAPABILITY WITH A CREDENTIAL - which means the machinery to govern it already
exists and does not need reinventing.

    Registering a tool is authority (only Ross, signed), like everything that
    decides what the system can do. It declares a name, where the tool lives,
    which businesses may reach it, and which vault secret holds its key.

    Using a tool is a grant. A registered tool exposes the capability
    'tool:<name>', and grants.decide() gates who may invoke it exactly as it
    gates the bound book or a spray log. An agent is not handed a tool because
    it exists; it is handed one because Ross granted it.

    The credential never leaves the vault in the clear. invoke() reads it at the
    moment of the call and passes it to the endpoint; it is never logged, never
    returned, never put in an event body.

A CAUTION TRAVELS WITH THE TOOL. Some tools fight a business's own rules. A
media generator is the obvious one: SteelHaven's brand voice forbids
AI-obvious media outright ("it reads as fake and kills trust"), so a tool like
Higgsfield granted to the SteelHaven bench is a standing contradiction. The tool
carries a `caution` string, shown when it is registered and when it is granted,
so the conflict is named rather than discovered later in something that shipped.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import safehttp
from .keys import ROSS
from .models import SYSTEM
from .store import Log

HTTP = "http"        # a plain JSON-over-HTTPS endpoint
MCP = "mcp"          # a Model Context Protocol server
KINDS = (HTTP, MCP)


@dataclass
class Tool:
    name: str
    kind: str
    endpoint: str
    businesses: tuple[str, ...]        # which businesses may reach it; ("*",) = any
    auth_secret: str                   # vault secret name (in SYSTEM scope), or ""
    note: str = ""
    caution: str = ""
    registered: str = ""

    @property
    def capability(self) -> str:
        return f"tool:{self.name}"

    def reachable_by(self, business: str) -> bool:
        return "*" in self.businesses or business in self.businesses


class Tools:
    """The registry of external tools, projected from the log."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing ---------------------------------------------------------

    def register(self, name: str, endpoint: str, *, kind: str = HTTP,
                 businesses: tuple = ("*",), auth_secret: str = "",
                 note: str = "", caution: str = "", by: str = ROSS) -> dict:
        """Add a tool. Only Ross, and it is signed.

        Registering a tool widens what the system can do, which is the same
        class of decision as a grant - so it carries Ross's signature and a
        node without his key cannot introduce one.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross registers a tool; {by!r} tried {name!r}")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}")
        if not (name or "").strip() or not (endpoint or "").strip():
            raise ValueError("a tool needs a name and an endpoint")
        # HTTP tools carry a bearer credential, so the endpoint must be https -
        # a plaintext endpoint would put the vault secret on the wire in the
        # clear, and there is no reason to register one.
        if kind == HTTP and auth_secret and not endpoint.strip().lower().startswith("https://"):
            raise ValueError("a tool with a credential must have an https endpoint")
        return self.log.append(
            "tool.registered",
            {"name": name.strip().lower(), "kind": kind, "endpoint": endpoint.strip(),
             "businesses": list(businesses), "auth_secret": auth_secret,
             "note": note, "caution": caution},
            subject=name.strip().lower(), actor=ROSS,
        )

    def retire(self, name: str, *, by: str = ROSS) -> dict:
        """Stop offering a tool. Its past use stays on record."""
        if by != ROSS:
            raise PermissionError(f"only Ross retires a tool; {by!r} tried")
        return self.log.append("tool.retired", {"name": name.strip().lower()},
                               subject=name.strip().lower(), actor=ROSS)

    # ---- reading ---------------------------------------------------------

    def all(self) -> list[Tool]:
        live: dict[str, Tool] = {}
        retired: set[str] = set()
        for ev in self.log.replay(kind="tool.registered"):
            b = ev["body"]
            live[b["name"]] = Tool(
                name=b["name"], kind=b.get("kind", HTTP), endpoint=b["endpoint"],
                businesses=tuple(b.get("businesses") or ("*",)),
                auth_secret=b.get("auth_secret", ""), note=b.get("note", ""),
                caution=b.get("caution", ""), registered=ev["ts"])
        for ev in self.log.replay(kind="tool.retired"):
            retired.add(ev["body"]["name"])
        return [t for n, t in live.items() if n not in retired]

    def find(self, name: str) -> Tool | None:
        n = (name or "").strip().lower()
        for t in self.all():
            if t.name == n:
                return t
        return None

    def capabilities(self) -> list[str]:
        """The capability each live tool exposes, for the vocabulary.

        The doorway unions these with the static catalogue so the classifier may
        route to a tool and grants.decide() may gate it - a registered tool is a
        real thing to ask for, an unregistered name is not.
        """
        return [t.capability for t in self.all()]

    # ---- invoking --------------------------------------------------------

    def invoke(self, name: str, payload: dict, *, vault, business: str = "") -> dict:
        """Call a tool. The credential is read here and never travels further.

        Generic HTTP for now: POST JSON with a bearer credential and return the
        parsed response. Tools whose API differs (and most do) get a small
        per-tool adapter that maps request and response shapes - this is the
        seam that stays constant beneath them. MCP tools are not wired yet.
        """
        t = self.find(name)
        if t is None:
            raise ValueError(f"no such tool {name!r}")
        # Fail CLOSED on the offered-to check. The gate used to be skipped when
        # `business` was falsy, so a caller that passed nothing reached a tool it
        # was never offered. A business-scoped tool now refuses an unnamed caller.
        if "*" not in t.businesses and not t.reachable_by(business or ""):
            raise PermissionError(
                f"{name!r} is not offered to {business or '(no business given)'}")
        if t.kind != HTTP:
            raise NotImplementedError(f"{t.kind} tools are not wired yet")

        key = None
        if t.auth_secret:
            key = vault.get_secret(SYSTEM, t.auth_secret)
            if not key:
                raise RuntimeError(
                    f"{name!r} needs the vault secret system:{t.auth_secret}, "
                    f"which is not set. `rosco secret set system {t.auth_secret}`")
        # safehttp enforces https, no-redirect, no-internal-target and the size
        # cap when a credential is present - the hardening that lives in one place.
        return safehttp.call(t.endpoint, method="POST", payload=payload, bearer=key)
