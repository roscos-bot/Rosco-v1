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

from .grants import ASK, DO, GET, ROSS, Decision, Grants, Request
from .store import Log

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
    times: int = 1              # how often they have asked
    last: str = ""              # most recent time they asked
    answer: str = ""
    answered: str = ""
    note: str = ""              # Ross's reason, if he gave one
    seen: list = field(default_factory=list)   # every channel it arrived on

    @property
    def open(self) -> bool:
        return not self.answer

    @property
    def allowed(self) -> bool:
        return self.answer in (ALLOW_ONCE, ALLOW_ALWAYS)

    def line(self) -> str:
        """One row, for the console list and the Telegram digest."""
        age = f"x{self.times}" if self.times > 1 else "  "
        return (f"{self.id[:8]}  {self.person:9} {self.business:13} "
                f"{self.verb.upper():4} {self.capability:18} {age}  {self.detail[:44]}")


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

        existing = self._open_for(req)
        if existing:
            return self.log.append(
                "ask.repeated",
                {"ask": existing.id, "channel": req.channel, "detail": req.detail[:600]},
                subject=existing.id, actor=req.person,
            )
        return self.log.append(
            "ask.raised",
            {"person": req.person, "business": req.business,
             "capability": req.capability, "verb": req.verb,
             "channel": req.channel, "detail": req.detail[:600], "why": decision.why},
            subject=f"{req.person}@{req.business}:{req.capability}:{req.verb}",
            actor=req.person,
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
            raise ValueError(f"{ask_id[:8]} was already answered {a.answer!r}")

        ev = self.log.append(
            "ask.answered",
            {"ask": ask_id, "answer": answer, "note": note},
            subject=ask_id, actor=ROSS,
        )
        if answer == ALLOW_ALWAYS:
            self.grants.give(a.person, a.business, a.capability, verb=a.verb,
                             reason=note or f"answered on {a.raised[:10]}")
        elif answer == DENY_ALWAYS:
            self.grants.deny(a.person, a.business, a.capability, verb=a.verb,
                             reason=note or f"answered on {a.raised[:10]}")
        return ev

    # ---- reading ---------------------------------------------------------

    def all(self) -> list[Ask]:
        rows: dict[str, Ask] = {}
        for ev in self.log.replay(kind="ask.*"):
            b = ev["body"]
            if ev["kind"] == "ask.raised":
                rows[ev["id"]] = Ask(
                    id=ev["id"], person=b["person"], business=b["business"],
                    capability=b["capability"], verb=b.get("verb", GET),
                    channel=b.get("channel", ""), detail=b.get("detail", ""),
                    why=b.get("why", ""), raised=ev["ts"], last=ev["ts"],
                    seen=[b.get("channel", "")],
                )
            elif ev["kind"] == "ask.repeated":
                a = rows.get(b["ask"])
                if a:
                    a.times += 1
                    a.last = ev["ts"]
                    if b.get("detail"):
                        a.detail = b["detail"]
                    if b.get("channel") and b["channel"] not in a.seen:
                        a.seen.append(b["channel"])
            elif ev["kind"] == "ask.answered":
                a = rows.get(b["ask"])
                if a:
                    a.answer = b["answer"]
                    a.answered = ev["ts"]
                    a.note = b.get("note", "")
        out = list(rows.values())
        # Oldest first: the queue is a debt, and the oldest question is the one
        # somebody has been waiting on longest.
        out.sort(key=lambda a: a.raised)
        return out

    def pending(self) -> list[Ask]:
        return [a for a in self.all() if a.open]

    def get(self, ask_id: str) -> Ask | None:
        for a in self.all():
            if a.id == ask_id or a.id.startswith(ask_id):
                return a
        return None

    def _open_for(self, req: Request) -> Ask | None:
        for a in self.pending():
            if (a.person == req.person and a.business == req.business
                    and a.capability == req.capability and a.verb == req.verb):
                return a
        return None

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
