"""Who may do what - and what happens when nobody has said.

The whole system reduces to one call: somebody arrived on some channel, wants
something from some business, and this decides which of four things happens.

    SELF      they do it themselves, inside their grant. Nobody is interrupted.
    ANSWER    Rosco answers for Ross, because he would have said the same.
    ASK       nobody knows, so it waits for Ross - and only Ross.
    DECLINE   explicitly refused.

Two rules are structural rather than configurable, because they are the ones
that make the rest safe:

ONLY ROSS GRANTS. give() refuses any other author, and - since a Python check is
worth nothing across three machines - the event itself carries his signature and
is discarded on replay without it. See keys.py. The power to say yes is not
delegable, so there is no path by which the system talks itself into more access
than it was given.

UNKNOWN IS NEVER YES. An untaught request returns ASK, never a guess from a
similar case. Silence from Ross is not consent: the request waits, indefinitely,
with no timeout that quietly becomes an approval. This is the rule that costs
the most in practice and is worth every bit of it.

The rule is also why an *unidentified* sender returns ASK rather than matching
anything. An audit found that an empty person - which is exactly what identity
resolution returns for a stranger - fell through the listing filter and matched
every grant in the business, turning "unknown is never yes" into "unknown is
everyone". Both ends are now guarded: decide() refuses a request that cannot
name who is asking, and live() distinguishes "no filter" from "the empty name".

Everything else is learned. Grants accumulate one answer at a time and are
permanent until revoked, so the system starts nearly ignorant and gets quieter
every week.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .keys import ROSS
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
#
# This is an ALLOW-LIST, and that is the whole point. The first version tested
# `channel in WEAK`, which meant every string that was not literally "email" or
# "phone" - a typo, a new adapter, a value an attacker chose - was handled as
# unforgeable. A channel nobody has classified is not trusted; it asks.
STRONG = ("telegram", "chat", "console")
WEAK = ("email", "phone")
KNOWN = STRONG + WEAK


def _norm(s: str) -> str:
    """One spelling for names.

    identity.py lowercases the people it resolves. If this module did not, a
    grant written 'Brent' and a request carrying 'brent' would silently fail to
    meet - and worse, a deny written in the wrong case would be inert while the
    allow it was meant to overturn stayed in force.
    """
    return (s or "").strip().lower()


@dataclass(frozen=True)
class Request:
    person: str            # 'brent'
    business: str          # 'sugar-creek'
    capability: str        # 'spray-log', 'bom', 'qbo.classify'
    verb: str = GET        # GET | DO
    channel: str = ""      # deliberately no default - see decide()
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
    order: int = 0          # position in the log's total order - see _match()
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
        if not _norm(person) or not _norm(business) or not _norm(capability):
            raise ValueError("a grant needs a person, a business and a capability")
        return self.log.append(
            "grant.given",
            {"person": _norm(person), "business": _norm(business),
             "capability": _norm(capability), "verb": verb, "allow": True,
             "outcome": outcome, "reason": reason},
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
            {"person": _norm(person), "business": _norm(business),
             "capability": _norm(capability), "verb": verb, "allow": False,
             "reason": reason},
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
        person, business = _norm(req.person), _norm(req.business)
        capability = _norm(req.capability)

        # An unidentified sender matches nothing. This is the first check on
        # purpose: identity.resolve() returns an empty person for a stranger,
        # an ambiguous address and a lapsed enrolment alike, and every one of
        # those must reach Ross rather than the grant table.
        if not person:
            return Decision(ASK, "cannot tell who is asking")
        if not business:
            return Decision(ASK, "cannot tell which business this is about")
        if not capability:
            return Decision(ASK, "cannot tell what is being asked for")

        # A channel nobody has classified is not assumed safe.
        if req.channel not in KNOWN:
            return Decision(
                ASK,
                f"arrived on {req.channel or 'no channel'}, which has no trust tier; "
                f"classify it in grants.STRONG or grants.WEAK")

        if req.verb not in (GET, DO):
            return Decision(DECLINE, f"unknown verb {req.verb!r}")

        if person == ROSS:
            # Ross is ungated - but only where the channel proves it is him.
            #
            # His address is the most valuable one in the system to forge: a
            # From: header saying ross@steelhaven.homes costs nothing to fake,
            # and an ungated bypass reached that way hands over everything at
            # once. So the bypass requires a channel that cannot be spoofed,
            # and Ross arriving by mail or phone is treated as a claim like
            # anybody else's - it lands in the queue and he confirms it at the
            # console. That is the same "only localhost changes anything" rule
            # the rest of the system runs on, applied to its owner.
            if req.channel in STRONG:
                return Decision(SELF, "Ross, on a channel that proves it")
            return Decision(
                ASK,
                f"claims to be Ross over {req.channel}, which is spoofable; "
                f"confirm at the console")

        g = self._match(person, business, capability, req.verb)

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

    def live(self, *, person: str | None = None,
             business: str | None = None) -> list[Grant]:
        """Every grant currently in force.

        `None` means no filter; the empty string means the empty name and
        matches nothing. The first version conflated them with a falsy test,
        and an unidentified sender consequently matched every grant in the
        business. Keeping the distinction in the type is what stops that
        recurring.
        """
        out: dict[str, Grant] = {}
        revoked: set[str] = set()
        for n, ev in enumerate(self.log.replay(kind="grant.*")):
            b = ev["body"]
            if ev["kind"] == "grant.revoked":
                revoked.add(b["grant"])
                continue
            # Exact kinds only. replay()'s filter is SQL LIKE - suffix-matching
            # and case-insensitive - so "grant.*" also returns 'grant.suggested'
            # and 'GRANT.GIVEN'. Treating everything that was not a revoke as a
            # live allow is precisely how an unsigned event became a permission.
            if ev["kind"] not in ("grant.given", "grant.denied"):
                continue
            out[ev["id"]] = Grant(
                id=ev["id"], person=_norm(b["person"]), business=_norm(b["business"]),
                capability=_norm(b["capability"]), verb=b.get("verb", GET),
                allow=b.get("allow", False), outcome=b.get("outcome", SELF),
                reason=b.get("reason", ""), given=ev["ts"], order=n,
            )
        rows = [g for gid, g in out.items() if gid not in revoked]
        if person is not None:
            rows = [g for g in rows if g.person == _norm(person)]
        if business is not None:
            rows = [g for g in rows if g.business == _norm(business)]
        rows.sort(key=lambda g: (g.business, g.person, g.capability))
        return rows

    def _match(self, person: str, business: str, capability: str,
               verb: str) -> Grant | None:
        """The grant that governs this request: most specific, then newest.

        Specificity outranks recency, and that ordering is the whole content of
        this function. If Ross grants 'brent:*:get' and then denies
        'brent:bom:get', the exact deny governs the BOM however much later the
        wildcard was written - the first version compared dates first and a
        later wildcard allow silently overrode an earlier explicit deny.

        Within one specificity tier the newest wins, because that is Ross
        changing his mind, which he is entitled to do. Overturning a deny
        therefore means granting the same exact capability again, not casting a
        wider net around it.

        WITH ONE OVERRIDE: the newest statement wins outright if it is a deny.
        Specificity-only had a mirror hole. Ross grants 'brent:bound-book' and
        later, wanting him off everything, denies 'brent:*'. Under specificity
        alone the exact allow still governs - so the blanket cut-off leaves
        precisely the capability that matters still granted, silently. A deny
        written last is unambiguous and beats everything older whatever its
        shape; an allow written last still has to be specific enough to win.

        "Newest" means position in the log's total order, NOT the timestamp.
        Timestamps have one-second resolution, so a deny and the allow that
        overturns it can share one - and the first version then tie-broke on a
        random uuid, which meant the same pair of grants could decide either way
        on two machines. `order` comes from replay(), which is sorted
        (ts, node, seq) and is therefore identical on every node.
        """
        cands = [g for g in self.live(person=person, business=business)
                 if g.verb == verb and g.capability in (capability, "*")]
        if not cands:
            return None
        newest = max(cands, key=lambda g: g.order)
        if not newest.allow:
            return newest
        cands.sort(key=lambda g: (0 if g.capability == "*" else 1, g.order))
        return cands[-1]

    @staticmethod
    def _key(person: str, business: str, capability: str, verb: str) -> str:
        return f"{_norm(person)}@{_norm(business)}:{_norm(capability)}:{verb}"
