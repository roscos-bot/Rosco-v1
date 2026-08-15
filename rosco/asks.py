"""Things waiting on Ross.

His hard rule: *if you don't know what to allow or disallow you ask me, and only
me.* This is where those land. Everything about the module follows from taking
that literally.

NOTHING EXPIRES. There is no timeout, no auto-approve after a day, no "assume
yes for read-only". An unanswered ask waits forever. That is the whole point -
a timeout is a way of saying yes without deciding, and a system that does that
has quietly replaced Ross's judgement with a clock.

THE QUEUE IS IN THE LOG. Not a file that a crash loses and not memory that a
reboot clears. A node that dies mid-week comes back holding every question it
had, because the questions are events like everything else.

ANSWERING TEACHES. Ross can answer once, or answer for good. Answering for good
writes the grant, so the same question never reaches him twice. That is the
learning loop he described - the system starts nearly ignorant and gets quieter
every week, and it gets quieter because he answered, not because it guessed.

ASKING TWICE DOES NOT QUEUE TWICE. Brent asking three times is one question with
a count on it. Otherwise the honest behaviour of a person who did not get a
reply - asking again - becomes a way to bury the queue.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .grants import ASK, DO, GET, ROSS, STRONG, Decision, Grants, Request, _norm
from .store import Log

# The shortest id prefix answer() will accept. Long enough that two open asks
# colliding is not something an attacker can arrange cheaply, and get() refuses
# an ambiguous prefix outright anyway.
MIN_PREFIX = 8

# What Ross can say. The 'always' forms write a grant; the 'once' forms do not.
ALLOW_ONCE = "allow-once"
ALLOW_ALWAYS = "allow-always"
DENY_ONCE = "deny-once"
DENY_ALWAYS = "deny-always"
ANSWERS = (ALLOW_ONCE, ALLOW_ALWAYS, DENY_ONCE, DENY_ALWAYS)


@dataclass
class Ask:
    id: str
    person: str
    business: str
    capability: str
    verb: str
    channel: str
    detail: str                 # what they actually said, in their words
    why: str                    # why the system could not answer it
    raised: str
    times: int = 1              # asked again, on a channel that proves who they are
    nagged: int = 0             # asked again from somewhere spoofable - not evidence
    last: str = ""              # most recent time they arrived
    answer: str = ""
    answered: str = ""
    note: str = ""              # Ross's reason, if he gave one
    spent: bool = False         # a one-off permission that has been used
    order: int = 0              # position in the log's total order
    seen: list = field(default_factory=list)   # every channel it arrived on
    also: list = field(default_factory=list)   # how repeats worded it

    @property
    def open(self) -> bool:
        return not self.answer

    @property
    def allowed(self) -> bool:
        """Still good for something.

        A spent ALLOW_ONCE is not. Without that check 'just this time' reads as
        permission forever, which is the one thing ALLOW_ONCE exists to prevent.
        """
        if self.answer == ALLOW_ONCE:
            return not self.spent
        return self.answer == ALLOW_ALWAYS

    def line(self) -> str:
        """One row, for the console list and the Telegram digest."""
        age = f"x{self.times}" if self.times > 1 else "  "
        if self.nagged:
            age += f"(+{self.nagged}?)"     # unverifiable repeats, marked as such
        return (f"{self.id[:8]}  {self.person:9} {self.business:13} "
                f"{self.verb.upper():4} {self.capability:18} {age:9}  {self.detail[:40]}")


class Asks:
    """The queue. Only Ross empties it."""

    def __init__(self, log: Log, grants: Grants | None = None) -> None:
        self.log = log
        self.grants = grants or Grants(log)

    # ---- writing ---------------------------------------------------------

    def raise_(self, req: Request, decision: Decision) -> dict:
        """Put a request in front of Ross.

        Collapses onto an open ask for the same person/business/capability/verb
        rather than adding a second row - the count and the newest wording are
        what change. A person who asks again is still asking one thing.
        """
        if decision.outcome != ASK:
            raise ValueError(
                f"only an ASK belongs in the queue; this decided {decision.outcome!r}")

        person = _norm(req.person)
        if not person:
            # An unidentified sender has no business in this queue. Every
            # stranger would otherwise collapse onto one shared ask - identity
            # returns the same empty person for all of them - and answering it
            # would grant to nobody, or to everybody, depending on how the
            # answer was later read. Strangers are recorded by
            # People.saw_stranger() and enrolled by Ross, deliberately.
            raise ValueError(
                "cannot queue an ask with no identified person; record the "
                "arrival with People.saw_stranger() instead")

        existing = self._open_for(person, req)
        if existing:
            return self.log.append(
                "ask.repeated",
                # The original wording is kept. Letting a repeat overwrite it
                # means somebody who can forge an email can rewrite what Ross
                # reads before he answers - the question he sees would not be
                # the question that was asked.
                {"ask": existing.id, "channel": req.channel, "also": req.detail[:300]},
                subject=existing.id, actor=person,
            )
        # verb is normalised too. It was the one field the last pass missed, and
        # it was enough on its own: 'do', 'DO' and ' do' produced three separate
        # pending asks for one question, which is precisely the flooding this
        # dedupe exists to prevent.
        verb = _norm(req.verb)
        return self.log.append(
            "ask.raised",
            {"person": person, "business": _norm(req.business),
             "capability": _norm(req.capability), "verb": verb,
             "channel": req.channel, "detail": req.detail[:600], "why": decision.why},
            subject=f"{person}@{_norm(req.business)}:{_norm(req.capability)}:{verb}",
            actor=person,
        )

    def answer(self, ask_id: str, answer: str, *, note: str = "",
               by: str = ROSS) -> dict:
        """Ross decides. Only Ross.

        `allow-always` and `deny-always` write a grant as well as closing the
        question, which is how the queue shrinks over time. The grant is written
        with Ross as author because Ross is who answered - there is no path here
        that lets anything else manufacture one.
        """
        if by != ROSS:
            raise PermissionError(
                f"only Ross answers the queue; {by!r} tried to answer {ask_id[:8]}")
        if answer not in ANSWERS:
            raise ValueError(f"answer must be one of {', '.join(ANSWERS)}")

        a = self.get(ask_id)
        if a is None:
            raise KeyError(f"no such ask {ask_id}")
        if not a.open:
            raise ValueError(f"{a.id[:8]} was already answered {a.answer!r}")

        # The grant is written FIRST. If it fails, the ask stays open and Ross
        # sees it again; the other order closes the question and silently leaves
        # the permission unwritten, which reads as "handled" and is not.
        if answer == ALLOW_ALWAYS:
            self.grants.give(a.person, a.business, a.capability, verb=a.verb,
                             reason=note or f"answered on {a.raised[:10]}")
        elif answer == DENY_ALWAYS:
            self.grants.deny(a.person, a.business, a.capability, verb=a.verb,
                             reason=note or f"answered on {a.raised[:10]}")

        # a.id, NOT ask_id. all() keys its rows on the full event id, so logging
        # the prefix Ross actually typed - the 8 characters digest() itself
        # prints - meant the lookup missed, the ask never closed, and answering
        # it again wrote the grant a second time. Every time.
        return self.log.append(
            "ask.answered",
            {"ask": a.id, "answer": answer, "note": note, "typed": ask_id},
            subject=a.id, actor=ROSS,
        )

    def spend(self, ask_id: str, *, by: str = "rosco") -> dict:
        """Mark a one-off permission used.

        ALLOW_ONCE means once. Without this the ask simply reads 'allowed'
        forever and nothing distinguishes a permission that has been used from
        one still standing - so 'just this time' quietly becomes standing
        permission, which is the thing ALLOW_ONCE exists to avoid.
        """
        a = self.get(ask_id)
        if a is None:
            raise KeyError(f"no such ask {ask_id}")
        return self.log.append("ask.spent", {"ask": a.id}, subject=a.id, actor=by)

    # ---- reading ---------------------------------------------------------

    def all(self) -> list[Ask]:
        rows: dict[str, Ask] = {}
        for n, ev in enumerate(self.log.replay(kind="ask.*")):
            b = ev["body"]
            # Belt and braces. keys.malformed() now refuses a short body at both
            # write paths, so nothing should reach here missing a field - but a
            # projection that CRASHES on a bad row takes the whole queue down on
            # every node, permanently, and the queue is what implements "ask me
            # and only me". It skips instead.
            if not isinstance(b, dict):
                continue
            if ev["kind"] == "ask.raised":
                if not (b.get("person") and b.get("business") and b.get("capability")):
                    continue
                rows[ev["id"]] = Ask(
                    id=ev["id"], person=b["person"], business=b["business"],
                    capability=b["capability"], verb=b.get("verb") or GET,
                    channel=b.get("channel", ""), detail=b.get("detail", ""),
                    why=b.get("why", ""), raised=ev["ts"], last=ev["ts"], order=n,
                    seen=[b.get("channel", "")],
                )
            elif ev["kind"] == "ask.repeated":
                a = rows.get(b.get("ask") or "")
                if a:
                    # "They have asked three times" is a real signal Ross acts
                    # on, so it must not be forgeable. A repeat arriving on a
                    # spoofable channel counts separately: anyone who can put an
                    # enrolled person's address in a From: header could otherwise
                    # manufacture urgency on their behalf.
                    if b.get("channel") in STRONG:
                        a.times += 1
                    else:
                        a.nagged += 1
                    a.last = ev["ts"]
                    # Appended, never overwriting a.detail - see raise_().
                    if b.get("also"):
                        a.also.append(b["also"])
                    if b.get("channel") and b["channel"] not in a.seen:
                        a.seen.append(b["channel"])
            elif ev["kind"] == "ask.answered":
                a = rows.get(b.get("ask") or "")
                if a:
                    a.answer = b.get("answer", "")
                    a.answered = ev["ts"]
                    a.note = b.get("note", "")
            elif ev["kind"] == "ask.spent":
                a = rows.get(b.get("ask") or "")
                if a:
                    a.spent = True
        out = list(rows.values())
        # Oldest first: the queue is a debt, and the oldest question is the one
        # somebody has been waiting on longest. Sorted on the log's own total
        # order rather than the body's timestamp, which a node that raised the
        # ask chose for itself and could back-date to jump the queue.
        out.sort(key=lambda a: a.order)
        return out

    def pending(self) -> list[Ask]:
        return [a for a in self.all() if a.open]

    def get(self, ask_id: str) -> Ask | None:
        """Resolve an id, or an unambiguous prefix of one.

        The first version returned the first row whose id started with the
        given string, in list order. Two problems, and the second is an attack:
        a one-character prefix matched something, and `ask.raised` is not an
        authority kind - so a compromised node could plant an ask with a
        back-dated timestamp and an id sharing its first characters with a real
        one, and Ross answering the real question would grant the planted one.
        An ambiguous prefix now refuses rather than picks.
        """
        want = (ask_id or "").strip()
        if not want:
            return None
        if len(want) < MIN_PREFIX:
            raise ValueError(
                f"{want!r} is too short to name an ask; give at least "
                f"{MIN_PREFIX} characters")
        # Exact and prefix matches are resolved in ONE namespace, deliberately.
        #
        # Trying exact-first was itself the hole. Event ids are chosen by
        # whoever writes the event, so a compromised node could plant an ask
        # whose entire id was the 8-character prefix the digest prints for a
        # real one. Ross read the digest, typed what it showed him, and the
        # exact-match branch handed him the planted ask - minting a Ross-signed
        # grant for whatever the attacker had put in it. store.absorb() now
        # requires ids to be uuids, which closes it at the source; resolving in
        # one namespace means an ambiguity refuses rather than silently
        # preferring one, whichever way such a row arrived.
        hits = [a for a in self.all() if a.id == want or a.id.startswith(want)]
        if len(hits) > 1:
            raise ValueError(
                f"{want!r} matches {len(hits)} asks ({', '.join(h.id for h in hits)}); "
                f"give the full id")
        return hits[0] if hits else None

    def _open_for(self, person: str, req: Request) -> Ask | None:
        for a in self.pending():
            if (a.person == person and a.business == _norm(req.business)
                    and a.capability == _norm(req.capability)
                    and a.verb == _norm(req.verb)):
                return a
        return None

    def open_id(self, req: Request) -> str:
        """The canonical open ask for this request, or ''.

        An adapter needs this after raise_(): a repeat returns its own event id,
        not the ask's, so anything that later looks the ask up by that id -
        notifying Ross, say - would find nothing. This returns the ask itself.
        """
        a = self._open_for(_norm(req.person), req)
        return a.id if a else ""

    def digest(self, limit: int = 12) -> str:
        """The queue, as Ross reads it at the console or on his phone."""
        rows = self.pending()
        if not rows:
            return "Nothing waiting."
        head = f"{len(rows)} waiting on you:\n"
        body = "\n".join("  " + a.line() for a in rows[:limit])
        more = f"\n  ...and {len(rows) - limit} more" if len(rows) > limit else ""
        return head + body + more

    def waiting_on(self, person: str) -> list[Ask]:
        """What one person is still waiting for. For answering them honestly."""
        return [a for a in self.pending() if a.person == person]
