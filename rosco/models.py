"""Which model answers, and how that gets changed without editing code.

Ross's requirement: the choice is saved locally and swappable, agents are
constantly trying new models, and when one appears that needs a key he does not
have, the system asks for it rather than going quiet.

So models are addressed by ROLE, not by name. Nothing in the system says
"claude-opus-5"; it says `pick(WORKHORSE)`. Swapping what does the heavy lifting
is then one event, applied everywhere at once, and no agent has a model name
baked into it that somebody has to go and find later.

    CHAT       the thing Ross talks to at the console. Quality over cost.
    WORKHORSE  the daily grind - triage, drafting, classification. Volume.
    CHEAP      bulk and background. Summarising a mailbox, scoring a trial.
    VISION     images. Jobsite photos, plan markups, a screenshot of a form.
    LOCAL      runs on the machine. What a sealed or cut-off node falls back to.

TWO DOORS, ON PURPOSE. OpenRouter is the default because one key reaches nearly
every model, which is what makes "try the new ones" actually possible - a model
released on Tuesday is available on Tuesday, with no account to open. The
workhorse role points at a direct provider key instead, because that is where
the volume goes and direct is materially cheaper and has better limits.

The cost of the middleman is real and worth saying plainly: traffic through
OpenRouter is seen by OpenRouter. That is acceptable for trials and for general
work, and it is why anything touching the bound book, financials, or the vault
should be pinned to a direct provider - see sensitive_roles().

WHAT HAPPENS WHEN THERE IS NO KEY. It asks Ross, through the same queue as
everything else. It does not fall back to a weaker model silently, because a
system that quietly degrades is one where nobody notices it has been answering
with the cheap model for three weeks.
"""
from __future__ import annotations

from dataclasses import dataclass

from .grants import ROSS
from .store import Log

CHAT = "chat"
WORKHORSE = "workhorse"
CHEAP = "cheap"
VISION = "vision"
LOCAL = "local"
ROLES = (CHAT, WORKHORSE, CHEAP, VISION, LOCAL)

OPENROUTER = "openrouter"
ANTHROPIC = "anthropic"
OPENAI = "openai"
# The Gemini model API (AI Studio key, generativelanguage.googleapis.com) - a
# DIFFERENT credential from the Google Workspace OAuth used by the Gmail/Drive/
# Calendar connectors. Named 'gemini' so the model key (gemini_api_key) never
# gets confused with the Workspace creds (google_client_id/secret/refresh_token).
GEMINI = "gemini"
XAI = "xai"
OLLAMA = "ollama"          # on-machine; needs no key and no internet

# Where a provider's credential lives in the vault. 'system' rather than a
# business, because a model key is infrastructure - it is not RUM's or
# SteelHaven's, and scoping it to one would mean the others could not think.
SYSTEM = "system"


def secret_name(provider: str) -> str:
    return f"{provider}_api_key"


@dataclass(frozen=True)
class Choice:
    role: str
    model: str             # 'anthropic/claude-opus-5', 'openai/gpt-5', ...
    provider: str
    node: str = ""         # "" means everywhere; a name pins it to one machine
    why: str = ""
    chosen: str = ""

    @property
    def needs_key(self) -> bool:
        return self.provider != OLLAMA


@dataclass
class Trial:
    model: str
    role: str
    verdict: str           # 'better' | 'same' | 'worse' | 'failed'
    note: str
    at: str
    by: str


# Sensible starting points. Deliberately not authoritative - they are what the
# system uses until Ross changes one, and changing one is an event, not an edit.
DEFAULTS = {
    CHAT:      ("anthropic/claude-opus-5", OPENROUTER),
    WORKHORSE: ("claude-sonnet-5", ANTHROPIC),
    CHEAP:     ("anthropic/claude-haiku-4.5", OPENROUTER),
    VISION:    ("anthropic/claude-opus-5", OPENROUTER),
    LOCAL:     ("llama3.1:8b", OLLAMA),
}


class Models:
    """The model registry: what is chosen, what has been tried, what is missing."""

    def __init__(self, log: Log, vault=None) -> None:
        self.log = log
        self.vault = vault

    # ---- writing ---------------------------------------------------------

    def choose(self, role: str, model: str, provider: str, *, node: str = "",
               why: str = "", by: str = ROSS) -> dict:
        """Point a role at a model.

        Only Ross. A model choice decides what reads his mail and drafts in his
        name, and it moves money through the provider he is billed by - both are
        his to decide. It is also the one setting an agent would most plausibly
        want to change about itself, which is exactly why it cannot.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross picks models; {by!r} tried to set {role}")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        if not (model or "").strip():
            raise ValueError("a choice needs a model id")
        return self.log.append(
            "model.chosen",
            {"role": role, "model": model.strip(), "provider": provider,
             "node": node, "why": why},
            subject=f"{role}@{node or '*'}", actor=ROSS,
        )

    def pin_agent(self, agent: str, model: str, provider: str, *,
                  why: str = "", by: str = ROSS) -> dict:
        """Pin ONE agent (a graph node) to its own model, whatever its role.

        The rest of the system stays role-addressed - swap the workhorse once,
        it changes everywhere. This is the deliberate exception: when Ross wants
        HavenMind on Opus but a bulk classifier on Haiku, he says so per agent,
        and that agent's think() uses it. Still only Ross - a model choice reads
        his mail and spends his money, the same reason choose() is his alone.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross pins models; {by!r} tried to pin {agent}")
        agent = (agent or "").strip()
        if not agent:
            raise ValueError("which agent?")
        if not (model or "").strip():
            raise ValueError("a pin needs a model id")
        return self.log.append(
            "model.pinned",
            {"agent": agent, "model": model.strip(), "provider": provider, "why": why},
            subject=agent, actor=ROSS,
        )

    def unpin_agent(self, agent: str, *, by: str = ROSS) -> dict:
        """Clear an agent's pin - it falls back to whatever its role resolves to."""
        if by != ROSS:
            raise PermissionError(f"only Ross unpins models; {by!r} tried {agent}")
        agent = (agent or "").strip()
        if not agent:
            raise ValueError("which agent?")
        return self.log.append(
            "model.unpinned", {"agent": agent}, subject=agent, actor=ROSS)

    def trial(self, model: str, role: str, verdict: str, *, note: str = "",
              by: str = "rosco") -> dict:
        """Record how a model did.

        Agents write these - trialling is their job, not Ross's. What they
        cannot do is act on the result; a good trial is an argument for a
        change, and choose() is still his.
        """
        if verdict not in ("better", "same", "worse", "failed"):
            raise ValueError("verdict must be better | same | worse | failed")
        return self.log.append(
            "model.trialled",
            {"model": model, "role": role, "verdict": verdict, "note": note[:600]},
            subject=model, actor=by,
        )

    def spotted(self, model: str, provider: str, *, note: str = "",
                by: str = "rosco") -> dict:
        """A model worth trying that we cannot reach yet.

        This is the "ask and I'll get you a key" path. It is written as a fact
        so it accumulates - if four agents independently want the same provider
        that is a stronger case than one asking twice.
        """
        return self.log.append(
            "model.spotted",
            {"model": model, "provider": provider, "note": note[:400]},
            subject=provider, actor=by,
        )

    # ---- reading ---------------------------------------------------------

    def choices(self, *, node: str = "") -> dict[str, Choice]:
        """Current pick per role, most specific first.

        A choice pinned to this node beats a global one, so the cloud VM can run
        something cheap without changing what the house uses.
        """
        latest: dict[tuple, Choice] = {}
        for ev in self.log.replay(kind="model.chosen"):
            b = ev["body"]
            key = (b["role"], b.get("node", ""))
            latest[key] = Choice(
                role=b["role"], model=b["model"], provider=b["provider"],
                node=b.get("node", ""), why=b.get("why", ""), chosen=ev["ts"],
            )
        out: dict[str, Choice] = {}
        for role in ROLES:
            model, provider = DEFAULTS[role]
            out[role] = Choice(role, model, provider, why="default")
            if (role, "") in latest:
                out[role] = latest[(role, "")]
            if node and (role, node) in latest:
                out[role] = latest[(role, node)]
        return out

    def pick(self, role: str, *, node: str = "") -> Choice:
        """What should answer this. The call every agent makes."""
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        return self.choices(node=node or self.log.node)[role]

    def pins(self) -> dict[str, Choice]:
        """agent name -> its pinned Choice. Latest wins; an unpin clears it.

        Both kinds are read and merged in time order, so a pin then an unpin
        leaves the agent unpinned - the same latest-event-wins the rest of the
        registry uses.
        """
        events = []
        for ev in self.log.replay(kind="model.pinned"):
            events.append((ev["ts"], "pin", ev["body"]))
        for ev in self.log.replay(kind="model.unpinned"):
            events.append((ev["ts"], "unpin", ev["body"]))
        events.sort(key=lambda e: e[0])
        latest: dict[str, Choice] = {}
        for ts, op, b in events:
            agent = (b.get("agent") or "").strip()
            if not agent:
                continue
            if op == "unpin":
                latest.pop(agent, None)
            else:
                latest[agent] = Choice(
                    role="pinned", model=b.get("model", ""),
                    provider=b.get("provider", ""), why=b.get("why", ""), chosen=ts)
        return latest

    def pin_for(self, agent: str) -> Choice | None:
        """This agent's pinned model, or None to fall back to its role."""
        return self.pins().get((agent or "").strip())

    def key_for(self, choice: Choice) -> str | None:
        """The credential, or None if we do not hold one.

        None is a real answer, not an error. The caller's job is to ask Ross for
        a key - see missing() - rather than quietly reaching for a model that
        does work.
        """
        if not choice.needs_key:
            return ""
        if self.vault is None:
            return None
        # Stripped: a key pasted with a trailing newline would otherwise ride
        # into the request header malformed and be rejected by the provider.
        v = self.vault.get_secret(SYSTEM, secret_name(choice.provider))
        return v.strip() if v else v

    def missing(self, *, node: str = "") -> list[str]:
        """Providers a current choice needs and the vault does not hold.

        Checked with the vault's key when there is one; without a key this
        cannot tell held-from-absent and says so by returning nothing rather
        than crying wolf on a sealed node.
        """
        if self.vault is None:
            return []
        held = set(self.vault.secret_names(SYSTEM))
        out = []
        for c in self.choices(node=node).values():
            if not c.needs_key:
                continue
            if f"{SYSTEM}:{secret_name(c.provider)}" not in held:
                out.append(c.provider)
        return sorted(set(out))

    def wanted(self) -> list[dict]:
        """Models agents asked for and could not reach, most-requested first."""
        tally: dict[tuple, dict] = {}
        for ev in self.log.replay(kind="model.spotted"):
            b = ev["body"]
            if not (b.get("provider") and b.get("model")):
                continue
            k = (b["provider"], b["model"])
            row = tally.setdefault(k, {"provider": b["provider"], "model": b["model"],
                                       "asks": 0, "notes": []})
            row["asks"] += 1
            if b.get("note"):
                row["notes"].append(b["note"])
        return sorted(tally.values(), key=lambda r: -r["asks"])

    def leaderboard(self, role: str = "") -> list[dict]:
        """How trialled models have actually done."""
        tally: dict[str, dict] = {}
        for ev in self.log.replay(kind="model.trialled"):
            b = ev["body"]
            if role and b["role"] != role:
                continue
            # b["verdict"] used to index the row directly, so an unexpected
            # value from a compromised node was a KeyError that killed the whole
            # leaderboard on every node.
            verdict = str(b.get("verdict", "")).strip().lower()
            if not b.get("model") or verdict not in ("better", "same", "worse", "failed"):
                continue
            row = tally.setdefault(b["model"], {
                "model": b["model"], "better": 0, "same": 0, "worse": 0, "failed": 0})
            row[verdict] += 1
        rows = list(tally.values())
        rows.sort(key=lambda r: (-(r["better"] - r["worse"] - 2 * r["failed"]), r["model"]))
        return rows

    @staticmethod
    def sensitive_roles() -> tuple[str, ...]:
        """Work that should not travel through a middleman.

        The bound book is an ATF record, the financials are not public, and
        vault content is the keys to everything. Those go to a direct provider
        or nowhere - not because OpenRouter is untrustworthy, but because
        "who saw this" has a shorter answer when there is one fewer party.
        """
        return (WORKHORSE,)

    def report(self, *, node: str = "") -> str:
        """What Ross reads when he wants to know what is thinking for him."""
        lines = []
        for role, c in self.choices(node=node or self.log.node).items():
            where = f" @{c.node}" if c.node else ""
            tag = "" if c.why != "default" else "  (default, never set)"
            lines.append(f"  {role:10} {c.model:34} via {c.provider}{where}{tag}")
        gaps = self.missing(node=node)
        if gaps:
            lines.append("")
            for g in gaps:
                lines.append(f"  !! no key for {g} - a chosen role cannot run")
        want = self.wanted()
        if want:
            lines.append("")
            for w in want[:5]:
                lines.append(f"  ?  {w['model']} ({w['provider']}) - asked for {w['asks']}x")
        return "\n".join(lines)
