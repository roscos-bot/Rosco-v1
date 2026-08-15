"""Who may do what - and what happens when nobody has said.

The whole system reduces to one call: somebody arrived on some channel, wants
something from some business, and this decides which of four things happens.

    SELF      they do it themselves, inside their grant. Nobody is interrupted.
    ANSWER    Rosco answers for Ross, because he would have said the same.
    ASK       nobody knows, so it waits for Ross - and only Ross.
    DECLINE   explicitly refused.

Two rules are structural rather than configurable, because they are the ones
that make the rest safe:

ONLY ROSS GRANTS. give() refuses any other author. Not John for SteelHaven, not
Lucas for RUM, not a person widening their own scope. The power to say yes is
not delegable, so there is no path by which the system talks itself into more
access than it was given.

UNKNOWN IS NEVER YES. An untaught request returns ASK, never a guess from a
similar case. Silence from Ross is not consent: the request waits, indefinitely,
with no timeout that quietly becomes an approval. This is the rule that costs
the most in practice and is worth every bit of it.

Everything else is learned. Grants accumulate one answer at a time and are
permanent until revoked, so the system starts nearly ignorant and gets quieter
every week.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .store import Log

# The four outcomes.
SELF = "self"
ANSWER = "answer"
ASK = "ask"
DECLINE = "decline"

# The two verbs. Reading and doing are different powers and are granted apart:
# Brent may GET the spray schedule without being able to DO anything to it.
GET = "get"
DO = "do"

# Channel trust. Ross's rule: the spoofable ones carry a higher approval rate.
#
# A Telegram id was paired by him and cannot be forged. Google Chat is
# authenticated by Google. An email From: header is a suggestion, and caller ID
# is worse - both are trivially faked for a few pence, which matters the moment
# the thing on the other end can move stock or take a payment.
STRONG = ("telegram", "chat", "console")
WEAK = ("email", "phone")

ROSS = "ross"


@dataclass(frozen=True)
class Request:
    person: str            # 'brent'
    business: str          # 'sugar-creek'
    capability: str        # 'spray-log', 'bom', 'qbo.classify'
    verb: str = GET        # GET | DO
    channel: str = "telegram"
    detail: str = ""       # free text, carried into the ask so Ross sees it


@dataclass(frozen=True)
class Decision:
    outcome: Literal["self", "answer", "ask", "decline"]
    why: str
    grant_id: str = ""

    @property
    def needs_ross(self) -> bool:
        return self.outcome == ASK


@dataclass
class Grant:
    id: str
    person: str
    business: str
    capability: str
    verb: str
    allow: bool
    outcome: str           # for allows: SELF or ANSWER
    reason: str
    given: str
    revoked: bool = False


class Grants:
    """The permission ledger, projected from the log."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing ---------------------------------------------------------

    def give(self, person: str, business: str, capability: str, *,
             verb: str = GET, outcome: str = SELF, reason: str = "",
             by: str = ROSS) -> dict:
        """Grant. Only Ross may call this, and the check is not a formality.

        `outcome` says what an allowed request becomes: SELF means they act
        themselves, ANSWER means Rosco replies on Ross's behalf. The difference
        matters - "Brent may see the BOM" and "Brent may change the BOM" are
        both allows, and only one of them should ever be SELF.
        """
        if by != ROSS:
            raise PermissionError(
                f"only Ross grants; {by!r} tried to give {person}:{business}:{capability}")
        if verb not in (GET, DO):
            raise ValueError(f"verb must be {GET!r} or {DO!r}")
        if outcome not in (SELF, ANSWER):
            raise ValueError(f"an allow resolves to {SELF!r} or {ANSWER!r}")
        return self.log.append(
            "grant.given",
            {"person": person, "business": business, "capability": capability,
             "verb": verb, "allow": True, "outcome": outcome, "reason": reason},
            subject=self._key(person, business, capability, verb), actor=ROSS,
        )

    def deny(self, person: str, business: str, capability: str, *,
             verb: str = GET, reason: str = "", by: str = ROSS) -> dict:
        """Refuse explicitly. Different from never having been asked.

        An explicit deny is remembered so the same request stops reaching Ross,
        and so the person gets a straight answer rather than an indefinite wait.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross denies; {by!r} tried to")
        return self.log.append(
            "grant.denied",
            {"person": person, "business": business, "capability": capability,
             "verb": verb, "allow": False, "reason": reason},
            subject=self._key(person, business, capability, verb), actor=ROSS,
        )

    def revoke(self, grant_id: str, *, reason: str = "", by: str = ROSS) -> dict:
        """Withdraw. Grants are permanent until this is called."""
        if by != ROSS:
            raise PermissionError(f"only Ross revokes; {by!r} tried to")
        return self.log.append(
            "grant.revoked", {"grant": grant_id, "reason": reason},
            subject=grant_id, actor=ROSS,
        )

    # ---- the decision ----------------------------------------------------

    def decide(self, req: Request) -> Decision:
        """The one call the whole system turns on."""
        if req.person == ROSS:
            return Decision(SELF, "Ross")

        if req.verb not in (GET, DO):
            return Decision(DECLINE, f"unknown verb {req.verb!r}")

        g = self._match(req)

        if g is None:
            # Never taught. This is the common case early on, and the rule is
            # absolute: ask, do not infer from a neighbouring capability.
            return Decision(ASK, "no grant on record")

        if not g.allow:
            return Decision(DECLINE, g.reason or "explicitly denied", g.id)

        # Allowed - but a weak channel cannot carry a DO. Anyone can send mail
        # claiming to be Lucas; nobody should be able to move stock that way.
        if req.channel in WEAK and g.verb == DO:
            return Decision(
                ASK,
                f"allowed, but {req.channel} is spoofable and this is an action",
                g.id,
            )

        # A weak channel asking to GET something is downgraded from acting on
        # their own to Rosco answering, so the reply is composed rather than
        # handing over a tool.
        if req.channel in WEAK and g.outcome == SELF:
            return Decision(ANSWER, f"allowed; {req.channel} is read-only in effect", g.id)

        return Decision(g.outcome, g.reason or "granted", g.id)

    # ---- reading ---------------------------------------------------------

    def live(self, *, person: str = "", business: str = "") -> list[Grant]:
        """Every grant currently in force."""
        out: dict[str, Grant] = {}
        revoked: set[str] = set()
        for ev in self.log.replay(kind="grant.*"):
            b = ev["body"]
            if ev["kind"] == "grant.revoked":
                revoked.add(b["grant"])
                continue
            out[ev["id"]] = Grant(
                id=ev["id"], person=b["person"], business=b["business"],
                capability=b["capability"], verb=b.get("verb", GET),
                allow=b.get("allow", False), outcome=b.get("outcome", SELF),
                reason=b.get("reason", ""), given=ev["ts"],
            )
        rows = [g for gid, g in out.items() if gid not in revoked]
        if person:
            rows = [g for g in rows if g.person == person]
        if business:
            rows = [g for g in rows if g.business == business]
        rows.sort(key=lambda g: (g.business, g.person, g.capability))
        return rows

    def _match(self, req: Request) -> Grant | None:
        """Newest live grant for exactly this person/business/capability/verb.

        Deliberately exact. A wildcard would be convenient and is precisely how
        a system ends up granting more than anyone remembers agreeing to; if
        Ross wants Brent to have everything in Sugar Creek, that is a capability
        called '*' he grants on purpose, not one inferred here.
        """
        best: Grant | None = None
        for g in self.live(person=req.person, business=req.business):
            if g.verb != req.verb:
                continue
            if g.capability not in (req.capability, "*"):
                continue
            if best is None or g.given >= best.given:
                # An exact capability always beats a wildcard, whatever the date.
                if best is not None and best.capability == req.capability and g.capability == "*":
                    continue
                best = g
        return best

    @staticmethod
    def _key(person: str, business: str, capability: str, verb: str) -> str:
        return f"{person}@{business}:{capability}:{verb}"
