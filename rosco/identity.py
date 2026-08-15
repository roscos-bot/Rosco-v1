"""Who is this, and how sure are we?

Every grant in the system is attached to a person. This module is what turns
"a message arrived on Telegram from 8481123" into "this is Brent" - and it is
therefore the single point where the whole permission model can be defeated. If
this returns the wrong person, every rule in grants.py is enforced perfectly
against the wrong human.

So it answers with a confidence, not a name:

    CERTAIN   paired by Ross on a channel that cannot be forged. This is Brent.
    CLAIMED   the address matches somebody we know, but the channel is
              spoofable. This is somebody SAYING they are Brent.
    UNKNOWN   nobody, or ambiguously several, or an enrolment that has expired.

CLAIMED is the important one and it is why this is not a dictionary lookup. An
email From: header is a suggestion. Caller ID is worse. Matching the address to
a known person is genuinely useful - it tells us which conversation this belongs
to - but it is evidence, not proof, and the system must never spend it as proof.

Three rules that look like paranoia and are not:

NOBODY IS RESOLVED BY DISPLAY NAME. Google Chat and Telegram both let a user
set their own name to anything. Resolution keys on the immutable id and nothing
else; a display name reading "Ross Fusz" means nothing at all.

AMBIGUITY IS UNKNOWN, NEVER A PICK. If one address resolves to two people the
answer is nobody. Silently choosing the first match is how Grace ends up
holding Brent's grants.

ROSS IS NOT SPECIAL HERE. He gets no shortcut - see the note on the bypass in
grants.py. An address is not an identity, and his address is the most valuable
one to forge in the entire system.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .grants import ROSS, STRONG, WEAK
from .store import Log


def _utc(value: str) -> str:
    """Normalise a time to the one spelling the rest of the system uses.

    Expiry used to be compared as a raw string, which works only while every
    value happens to share a format. It does not: '2026-12-01' sorts against
    '2026-08-14T00:00:00Z' by luck, and an offset like '+02:00' compares as
    though it were UTC, leaving a lapsed handle live for two extra hours.
    Parsing on the way in means the comparison is between like and like, and a
    value nobody can parse is rejected at enrolment rather than silently
    treated as 'never expires'.
    """
    v = (value or "").strip()
    if not v:
        return ""
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"cannot read {value!r} as a time: {e}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Something no real time can be later than. An enrolment whose expiry cannot be
# read is treated as already lapsed rather than as never lapsing.
LAPSED = "0000-00-00T00:00:00Z"


def _utc_or_lapsed(value: str) -> str:
    """Read-path expiry. Never raises.

    enrol() rejects an unreadable expiry outright, which is right on the write
    path. Doing the same on the READ path was a mistake: handles() calls this on
    every enrolment row, so one bad value - from a Ross-signed body assembled by
    a script, or a future importer - made resolve() raise for a completely
    unrelated person on a completely unrelated channel. One malformed row took
    identity down for everyone.

    Fails closed. An expiry nobody can parse retires the handle instead of
    granting it eternal life, and the caller sees a lapsed enrolment rather than
    an exception.
    """
    try:
        return _utc(value)
    except ValueError:
        return LAPSED


def _within_ago(seconds: int) -> str:
    """RFC3339 timestamp `seconds` in the past, for cheap recency checks."""
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds))

CERTAIN = "certain"
CLAIMED = "claimed"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Identity:
    person: str            # "" when UNKNOWN - there is no such thing as a partial name
    confidence: str
    why: str
    handle: str = ""       # the enrolment event that matched

    @property
    def known(self) -> bool:
        return bool(self.person)

    @property
    def proven(self) -> bool:
        """Only CERTAIN counts. Read this before doing anything irreversible."""
        return self.confidence == CERTAIN


@dataclass
class Handle:
    id: str
    person: str
    channel: str
    address: str           # already normalised
    raw: str               # exactly as Ross typed it, for showing back to him
    note: str
    enrolled: str
    until: str = ""        # RFC3339; "" means no expiry
    order: int = 0         # position in the log's total order - see resolve()
    retired: bool = False


def normalise(channel: str, address: str) -> str:
    """One address, one spelling.

    Per channel, because the channels genuinely differ:

    EMAIL is case-insensitive in practice at every provider anyone here uses,
    so it lowercases. Plus-tags are deliberately NOT stripped - stripping is
    safe reasoning for Gmail and wrong for providers that treat the tag as part
    of the mailbox, and an address that fails to match merely asks Ross rather
    than admitting a stranger.

    PHONE keeps digits only and drops a leading NANP 1, so +1 (314) 555-0123
    and 3145550123 are the same line. Everybody in this system is US-dialled;
    if that ever stops being true this needs revisiting rather than extending.

    TELEGRAM and CHAT ids are opaque strings from someone else's system. They
    are compared exactly, with no case folding, because we do not get to decide
    what they mean.
    """
    a = (address or "").strip()
    if channel == "email":
        return a.lower()
    if channel == "phone":
        digits = re.sub(r"\D", "", a)
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        return digits
    if channel in ("telegram", "chat"):
        return a
    return a.lower()


class People:
    """The enrolment book. Ross puts people in it; nothing else does."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing ---------------------------------------------------------

    def enrol(self, person: str, channel: str, address: str, *,
              note: str = "", until: str = "", by: str = ROSS) -> dict:
        """Attach a channel address to a person.

        Only Ross, for the same reason only Ross grants: enrolment IS a grant.
        Handing someone a handle on a person is handing them that person's
        permissions, one step removed, and a system that lets an agent enrol
        somebody has no permission model at all.

        `until` exists because phone numbers get recycled and staff leave. An
        enrolment with no expiry is a claim that this address will identify this
        person forever, which is true of a Telegram id and is not true of a
        mobile number.
        """
        if by != ROSS:
            raise PermissionError(
                f"only Ross enrols; {by!r} tried to attach {channel}:{address} to {person}")
        if channel not in STRONG + WEAK:
            raise ValueError(f"unknown channel {channel!r}")
        if not (person or "").strip() or not (address or "").strip():
            raise ValueError("a handle needs both a person and an address")
        return self.log.append(
            "identity.enrolled",
            {"person": person.strip().lower(), "channel": channel,
             "address": normalise(channel, address), "raw": address.strip(),
             "note": note, "until": _utc(until)},
            subject=f"{channel}:{normalise(channel, address)}", actor=ROSS,
        )

    def retire(self, handle_id: str, *, reason: str = "", by: str = ROSS) -> dict:
        """Stop an address resolving. The record of it having existed stays."""
        if by != ROSS:
            raise PermissionError(f"only Ross retires a handle; {by!r} tried to")
        return self.log.append(
            "identity.retired", {"handle": handle_id, "reason": reason},
            subject=handle_id, actor=ROSS,
        )

    # ---- reading ---------------------------------------------------------

    def handles(self, *, person: str = "", include_retired: bool = False) -> list[Handle]:
        rows: dict[str, Handle] = {}
        retired: set[str] = set()
        # Two EXACT-kind replays, not a broad "identity.*". resolve() calls this
        # on every inbound message, and "identity.*" also matches the
        # identity.stranger flood - so a stream of messages from unpaired
        # accounts made every later resolve() fetch and parse every stranger
        # row ever recorded. These two queries never touch strangers.
        for n, ev in enumerate(self.log.replay(kind="identity.enrolled")):
            b = ev["body"]
            rows[ev["id"]] = Handle(
                id=ev["id"], person=b["person"], channel=b["channel"],
                address=b["address"], raw=b.get("raw", b["address"]),
                note=b.get("note", ""), enrolled=ev["ts"], order=n,
                # Re-parsed on READ as well as on write. Normalising only in
                # enrol() left the raw string comparison live for any
                # identity.enrolled event assembled another way - a Ross-signed
                # body from a script, a future importer - and that is exactly
                # the comparison that let an offset time expire two hours late.
                until=_utc_or_lapsed(b.get("until", "")),
            )
        for ev in self.log.replay(kind="identity.retired"):
            retired.add(ev["body"]["handle"])
        out = []
        for hid, h in rows.items():
            h.retired = hid in retired
            if h.retired and not include_retired:
                continue
            if person and h.person != person.strip().lower():
                continue
            out.append(h)
        out.sort(key=lambda h: (h.person, h.channel, h.address))
        return out

    def resolve(self, channel: str, address: str, *, at: str = "") -> Identity:
        """The call the whole permission model rests on."""
        from .store import now

        addr = normalise(channel, address)
        if not addr:
            return Identity("", UNKNOWN, "no address on the message")

        when = _utc(at) if at else now()
        matches = [h for h in self.handles()
                   if h.channel == channel and h.address == addr]

        # Only the newest enrolment per person counts. Re-enrolling an address
        # is how Ross adds an expiry or a note to one, and the first version
        # kept both rows live - so the older, unexpiring handle went on
        # resolving and the new expiry did nothing at all.
        #
        # "Newest" is position in the log's total order, not the timestamp. The
        # first attempt at this fix sorted on (enrolled, id) - one-second
        # timestamps and then a random uuid - so re-enrolling within the same
        # second picked a winner at random, and the audit caught it still open.
        newest: dict[str, Handle] = {}
        for h in sorted(matches, key=lambda h: h.order):
            newest[h.person] = h
        matches = list(newest.values())

        # Expiry is checked before anything else. A recycled mobile number
        # belongs to a stranger the moment the enrolment lapses, and a stranger
        # holding an expired handle is the most dangerous shape this takes.
        live = [h for h in matches if not h.until or h.until > when]
        expired = [h for h in matches if h not in live]

        if not live:
            if expired:
                return Identity("", UNKNOWN,
                                f"{channel} {addr} was {expired[0].person}'s until "
                                f"{expired[0].until}; that enrolment has lapsed")
            return Identity("", UNKNOWN, f"no enrolment for {channel} {addr}")

        people = {h.person for h in live}
        if len(people) > 1:
            # Never pick. Two people behind one address is a mistake in the
            # book, and guessing which resolves it in favour of whoever was
            # enrolled first rather than whoever is actually typing.
            return Identity("", UNKNOWN,
                            f"{channel} {addr} is enrolled to {len(people)} people "
                            f"({', '.join(sorted(people))}); refusing to choose")

        h = live[0]
        if channel in STRONG:
            return Identity(h.person, CERTAIN,
                            f"paired on {channel}, which cannot be forged", h.id)
        if channel in WEAK:
            return Identity(h.person, CLAIMED,
                            f"{channel} matches {h.person}, but {channel} is spoofable",
                            h.id)
        # An allow-list here too, matching grants.py. enrol() gates the write
        # side today, so this is currently unreachable - but an enrolment on an
        # unclassified channel arriving another way (a Ross-signed body built by
        # a script, a future adapter) would otherwise have a real person's name
        # attached to it on the strength of nothing.
        return Identity("", UNKNOWN,
                        f"{channel!r} has no trust tier; classify it in "
                        f"grants.STRONG or grants.WEAK before believing it")

    def whois(self, person: str) -> str:
        """Every way a person can reach the system. For Ross to read."""
        hs = self.handles(person=person)
        if not hs:
            return f"{person} has no handles - nothing they send will be recognised."
        lines = [f"{person}:"]
        for h in hs:
            tier = "strong" if h.channel in STRONG else "SPOOFABLE"
            gone = f" until {h.until}" if h.until else ""
            lines.append(f"  {h.channel:9} {h.raw:34} [{tier}]{gone}"
                         + (f"  {h.note}" if h.note else ""))
        return "\n".join(lines)

    def strangers(self, limit: int = 20) -> list[dict]:
        """Unresolved arrivals, newest last.

        Worth surfacing to Ross rather than dropping: an unknown handle is
        usually a person he means to enrol, and occasionally it is somebody
        probing. Both are things he wants to see.
        """
        rows = [ev for ev in self.log.replay(kind="identity.stranger")]
        return rows[-limit:]

    STRANGER_WINDOW = 3600      # seconds; one record per address per hour

    def saw_stranger(self, channel: str, address: str, detail: str = "") -> dict | None:
        """Record an arrival we could not place - at most once per address, hourly.

        Without the window, an unpaired account sending a stream of messages
        wrote one permanent event each: unbounded disk, and a growing pile the
        stranger list has to page through. The dedupe is keyed on the subject,
        which is indexed, so the check is cheap and touches only this address's
        own rows - not the whole stranger pile. Returns None when it collapses a
        repeat, so the caller can tell nothing new was written.
        """
        subject = f"{channel}:{normalise(channel, address)}"
        recent = [ev for ev in self.log.replay(kind="identity.stranger", subject=subject)]
        if recent:
            last = recent[-1]["ts"]
            if last > _within_ago(self.STRANGER_WINDOW):
                return None
        return self.log.append(
            "identity.stranger",
            {"channel": channel, "address": normalise(channel, address),
             "raw": address, "detail": detail[:400]},
            subject=subject,
        )
