"""The log. Everything Rosco knows is derived from it.

One table, append-only, per node. Facts go in; nothing is ever updated or
deleted. Every view of the world - who someone is, what they may do, what is in
RUM's book - is a projection replayed from these rows.

Three reasons it is built this way, all of them Ross's requirements rather than
taste:

RUM's bound book is a legal record. An ATF inspector asks what the shop held on
a date, and the honest answer has to be reconstructable rather than asserted.
An append-only log answers that by construction; a table you can UPDATE cannot,
however careful everyone is.

Every site keeps working while cut off. A node writes its own events to its own
SQLite file with no coordinator to reach, and reconciles when the link returns.
Appends from different nodes merge without conflict because nothing is ever
overwritten - the hard part of syncing mutable rows simply does not arise.

A grant has to explain itself. "Why can Brent see this?" is answerable when the
grant is an event with an author, a timestamp and a reason attached, and is not
answerable when it is a row someone edited in 2024.

WHAT THE HASH DOES AND DOES NOT DO. It chains each node's events so a missing or
altered row is detectable on replay. It is unkeyed, so it proves *integrity* and
says nothing about *authorship* - anybody able to write the table could rewrite
a chain and recompute every hash forward. That is why every event also carries
an Ed25519 signature from the node that wrote it, and why events that decide who
may do what carry a second signature from Ross. See keys.py; the distinction was
found by an audit of the first version, which claimed the hash alone was enough.
It was not.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator

from .keys import Signer, Trust, known, malformed, needs_ross

SCHEMA_VERSION = 3

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    -- NOT NULL is explicit: SQLite's legacy exemption lets a non-INTEGER
    -- PRIMARY KEY hold NULL, and absorb() dedupes on `WHERE id=?`, which never
    -- matches NULL. A peer could otherwise hand us the same row twice.
    id          TEXT PRIMARY KEY NOT NULL,  -- uuid4, generated at the writing node
    seq         INTEGER NOT NULL,       -- per-node monotonic
    node        TEXT NOT NULL,          -- which site wrote it
    ts          TEXT NOT NULL,          -- RFC3339 UTC, when the node believed it happened
    kind        TEXT NOT NULL,          -- 'identity.enrolled', 'grant.given', ...
    subject     TEXT,                   -- the thing it is about, for cheap lookup
    actor       TEXT,                   -- who caused it; 'ross' for anything he approved
    body        TEXT NOT NULL,          -- json payload
    prev        TEXT,                   -- previous event hash on this node
    hash        TEXT NOT NULL,          -- sha256 over the canonical form
    nsig        TEXT NOT NULL,          -- originating node's signature over the same
    rsig        TEXT,                   -- Ross's signature; required for authority kinds
    UNIQUE(node, seq)                   -- one event per position. A second is a fork.
);
CREATE INDEX IF NOT EXISTS ix_events_kind    ON events(kind);
CREATE INDEX IF NOT EXISTS ix_events_subject ON events(subject);
CREATE INDEX IF NOT EXISTS ix_events_node    ON events(node, seq);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now() -> str:
    """RFC3339 UTC to the second. Deliberately not the local clock.

    Nodes are in different buildings and one of them may be a cloud VM in
    another region; comparing local times across them is how you get an event
    that appears to precede the thing that caused it.
    """
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def canonical(obj: Any) -> str:
    """Stable JSON. Two nodes must hash the same fact identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


_SIGNED_FIELDS = ("id", "seq", "node", "ts", "kind", "subject", "actor", "body", "prev")


def signable(ev: dict) -> bytes:
    """The exact bytes both signatures and the hash cover.

    Includes seq and prev, so a signature is bound to a position on a specific
    chain. Ross signing a grant on the console's chain does not yield a
    signature somebody can lift onto a different node's chain at a different
    point - the message would differ and the signature would not verify.
    """
    body = ev["body"]
    return canonical({
        "id": ev["id"], "seq": ev["seq"], "node": ev["node"], "ts": ev["ts"],
        "kind": ev["kind"], "subject": ev.get("subject", "") or "",
        "actor": ev.get("actor", "") or "",
        "body": json.loads(body) if isinstance(body, str) else body,
        "prev": ev.get("prev", "") or "",
    }).encode()


class Unauthorised(ValueError):
    """An event that could not prove it was allowed to say what it says."""


class Log:
    """An append-only, signed event log - one file per node."""

    def __init__(self, path: str | Path, node: str, *,
                 signer: Signer | None = None, ross: Signer | None = None,
                 trust: Trust | None = None) -> None:
        self.path = Path(path)
        self.node = node
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # A node mints its own key beside its database on first run, and its
        # public half goes into the trust file so it can verify its own rows.
        self.signer = signer or Signer.load_or_create(self.path.with_suffix(".node.key"))
        self.ross = ross
        self.trust = trust if trust is not None else Trust.load(
            self.path.parent / "trust.json")
        if not self.trust.knows(node):
            self.trust.add_node(node, self.signer.public)
        # A console holding Ross's signing key obviously trusts his public half.
        # Without this the console wrote a perfectly good signed grant, replay()
        # discarded it for want of a public key nobody had installed, and the
        # grant evaporated with no error at all - indistinguishable from never
        # having granted it, which is the exact trap this was meant to avoid.
        if self.ross is not None and self.trust.bootstrapping:
            self.trust.ross = self.ross.public

        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        # WAL so a reader (the employee site, say) never blocks the writer, and
        # a power cut at the shop cannot half-write a bound-book entry.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(_DDL)
        self._check_schema()

    def _check_schema(self) -> None:
        row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        if row is None:
            self.db.execute("INSERT INTO meta(key, value) VALUES('schema', ?)",
                            (str(SCHEMA_VERSION),))
            return
        held = int(row["value"])
        if held != SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} is schema v{held}, this code is v{SCHEMA_VERSION}. "
                f"v1 logs are unsigned and cannot be upgraded in place - their "
                f"authority events were never authenticated, so importing them "
                f"would launder exactly the claims signing exists to check.")

    # ---- writing ---------------------------------------------------------

    def append(self, kind: str, body: dict, *, subject: str = "",
               actor: str = "", ts: str = "") -> dict:
        """Add one fact. Returns the stored event.

        Signs with this node's key always, and with Ross's key when the event
        claims authority. Without his key present, an authority event is refused
        rather than written unsigned - a node that cannot prove Ross said
        something must not record that he did.
        """
        if not known(kind):
            raise Unauthorised(
                f"{kind!r} is not a declared event kind. Add it to keys.KINDS with "
                f"the proof it must carry. Undeclared kinds are how an unsigned "
                f"event gets projected as a signed one.")
        problem = malformed(kind, body)
        if problem:
            raise Unauthorised(f"{kind!r} body is unusable: {problem}")

        prev_row = self.db.execute(
            "SELECT hash, seq FROM events WHERE node=? ORDER BY seq DESC LIMIT 1",
            (self.node,),
        ).fetchone()
        prev = prev_row["hash"] if prev_row else ""
        seq = (prev_row["seq"] + 1) if prev_row else 1

        ev = {
            "id": str(uuid.uuid4()), "seq": seq, "node": self.node,
            "ts": ts or now(), "kind": kind, "subject": subject,
            "actor": actor, "body": body, "prev": prev,
        }
        msg = signable(ev)
        ev["hash"] = hashlib.sha256(msg).hexdigest()
        ev["nsig"] = self.signer.sign(msg)
        ev["rsig"] = ""

        if needs_ross(kind, body):
            if self.ross is None:
                raise Unauthorised(
                    f"{kind} needs Ross's signature and his key is not on this node. "
                    f"Authority is exercised at the console, not by a running agent.")
            if self.trust.bootstrapping:
                raise Unauthorised(
                    f"{kind} would be signed but this node holds no public key for "
                    f"Ross, so nothing here - including this node - could ever verify "
                    f"it. Install trust.json before granting; a write that silently "
                    f"evaporates is worse than one that fails.")
            ev["rsig"] = self.ross.sign(msg)

        self.db.execute(
            "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash,nsig,rsig)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev["id"], ev["seq"], ev["node"], ev["ts"], ev["kind"], ev["subject"],
             ev["actor"], canonical(ev["body"]), ev["prev"], ev["hash"],
             ev["nsig"], ev["rsig"]),
        )
        return ev

    # ---- reading ---------------------------------------------------------

    def replay(self, *, kind: str = "", subject: str = "",
               unchecked: bool = False) -> Iterator[dict]:
        """Every matching event, oldest first, with unauthorised ones dropped.

        Ordered by (ts, node, seq) rather than insertion: after a sync the local
        table holds another site's events interleaved, and insertion order would
        make the same log replay differently on different nodes.

        Two filters run here, and it is worth being exact about their reach.

        UNDECLARED KINDS ARE DROPPED. `kind` is matched with SQL LIKE, which is
        suffix-matching and case-insensitive, so a caller asking for "grant.*"
        gets 'grant.suggested' and 'GRANT.GIVEN' too. That mismatch - wildcard
        projection against an exact authority set - was a critical hole. Every
        row is now checked against the declared vocabulary before it is served.

        AUTHORITY EVENTS ARE SIGNATURE-CHECKED, and only those. It guards
        against a row that reached the table some way other than absorb() -
        including a hand-edited SQLite file - but only for events that claim
        authority. The node signature on ordinary events is NOT re-checked here:
        Ed25519 verification is tens of microseconds, which is nothing on the
        rare authority row and minutes on a replay of a large log. Ordinary rows
        are guarded by absorb() on the way in and by verify() on a schedule.
        A hand-edited lesson will be served until verify() next runs.
        """
        sql = "SELECT * FROM events"
        where, args = [], []
        if kind:
            where.append("kind LIKE ?")
            args.append(kind.replace("*", "%"))
        if subject:
            where.append("subject = ?")
            args.append(subject)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts, node, seq"
        for r in self.db.execute(sql, args):
            # A row whose body will not parse is skipped, never raised on. It
            # cannot satisfy any rule below, and raising here takes down every
            # projection on the node - grants, identity, nodes, the queue, all
            # of it - permanently, on the strength of one bad row. rejected()
            # surfaces them.
            try:
                parsed = json.loads(r["body"])
            except (ValueError, TypeError):
                continue
            ev = {**dict(r), "body": parsed}
            if unchecked:
                yield ev
                continue
            if not known(ev["kind"]):
                continue
            if needs_ross(ev["kind"], ev["body"]) and \
                    not self.trust.ross_signed(ev["rsig"] or "", signable(ev)):
                continue
            yield ev

    def rejected(self) -> list[dict]:
        """Authority events present in the table that do not verify.

        replay() drops these silently so a projection cannot be poisoned. This
        surfaces them, because a row like that is either corruption or somebody
        trying something, and both are things Ross wants to see.
        """
        out = []
        for r in self.db.execute("SELECT * FROM events ORDER BY ts, node, seq"):
            try:
                parsed = json.loads(r["body"])
            except (ValueError, TypeError):
                out.append({**dict(r), "body": None, "problem": "body is not JSON"})
                continue
            ev = {**dict(r), "body": parsed}
            if not known(ev["kind"]):
                out.append({**ev, "problem": "undeclared kind"})
            elif needs_ross(ev["kind"], ev["body"]) and \
                    not self.trust.ross_signed(ev["rsig"] or "", signable(ev)):
                out.append({**ev, "problem": "no signature from Ross"})
        return out

    def verify(self) -> list[str]:
        """Re-walk every chain: contiguity, hashes, and both signatures.

        This is what gets run before anyone relies on the bound book, and after
        every sync.
        """
        problems: list[str] = []
        if self.trust.bootstrapping:
            # Fail-closed but silent is still a trap. With no public key for
            # Ross, ross_signed() returns False for everything, so every
            # authority event is dropped and the system is merely useless rather
            # than unsafe - but it looks identical to a node that has simply
            # never been granted anything. Say so.
            problems.append(
                "no public key for Ross in trust.json - every authority event on "
                "this node is being discarded, so grants, enrolments and answers "
                "will all read as absent")
        nodes = [r["node"] for r in self.db.execute("SELECT DISTINCT node FROM events")]
        for node in nodes:
            prev = ""
            rows = self.db.execute(
                "SELECT * FROM events WHERE node=? ORDER BY seq", (node,)
            ).fetchall()
            for i, r in enumerate(rows, start=1):
                try:
                    ev = {**dict(r), "body": json.loads(r["body"])}
                except (ValueError, TypeError):
                    problems.append(f"{node}: seq {r['seq']} has a body that is not JSON")
                    prev = r["hash"]
                    continue
                if r["seq"] != i:
                    problems.append(f"{node}: gap at seq {i} (found {r['seq']})")
                if r["prev"] != prev:
                    problems.append(f"{node}: chain break at seq {r['seq']}")
                msg = signable(ev)
                if hashlib.sha256(msg).hexdigest() != r["hash"]:
                    problems.append(f"{node}: hash mismatch at seq {r['seq']}")
                if not self.trust.node_signed(node, r["nsig"] or "", msg):
                    problems.append(
                        f"{node}: seq {r['seq']} is not signed by {node} "
                        f"({'unknown node' if not self.trust.knows(node) else 'bad signature'})")
                if not known(ev["kind"]):
                    problems.append(
                        f"{node}: seq {r['seq']} is an undeclared kind ({ev['kind']!r})")
                elif needs_ross(ev["kind"], ev["body"]) and \
                        not self.trust.ross_signed(r["rsig"] or "", msg):
                    problems.append(
                        f"{node}: seq {r['seq']} claims authority ({ev['kind']}) "
                        f"without Ross's signature")
                prev = r["hash"]
        return problems

    # ---- syncing ---------------------------------------------------------

    def since(self, node: str, seq: int) -> list[dict]:
        """This node's events after `seq`. The whole of the sync protocol."""
        return [{**dict(r), "body": json.loads(r["body"])} for r in self.db.execute(
            "SELECT * FROM events WHERE node=? AND seq>? ORDER BY seq", (node, seq)
        )]

    def high_water(self) -> dict[str, int]:
        """Highest CONTIGUOUS seq per node - what a peer is asked for.

        Contiguous rather than MAX(seq) on purpose. A hostile peer that hands us
        one event at seq 9,000,000 would otherwise raise our mark past every
        real event, and we would never ask for the genuine 41..8,999,999 again -
        censoring a whole chain with a single row. Counting from 1 until the
        first gap means a stray high row can only be ignored.
        """
        marks: dict[str, int] = {}
        for node in [r["node"] for r in self.db.execute("SELECT DISTINCT node FROM events")]:
            n = 0
            for r in self.db.execute(
                    "SELECT seq FROM events WHERE node=? ORDER BY seq", (node,)):
                if r["seq"] != n + 1:
                    break
                n = r["seq"]
            marks[node] = n
        return marks

    def absorb(self, events: Iterable[dict]) -> int:
        """Take events from a peer. Returns how many were new.

        Idempotent by primary key, so re-syncing the same range is harmless -
        which matters because a shop on a flaky link will do exactly that.

        Everything below is refused rather than stored, because each one lets a
        peer corrupt history rather than merely add to it:

        EVENTS CLAIMING TO BE OURS. Nothing may write our chain but us. Without
        this a peer can hand us a row stamped with our own node name at a seq
        beyond our high-water, and the next append() chains onto the forgery.

        EVENTS NOT SIGNED BY THE NODE THEY CLAIM. This is what makes a relay
        safe: the cloud VM can pass the shop's events along, and cannot alter
        one, because it cannot produce the shop's signature over the change.

        AUTHORITY WITHOUT ROSS'S SIGNATURE. A compromised node may write
        whatever it likes on its own chain. What it may not do is have anybody
        believe it granted something.

        A BROKEN PREV LINK. The incoming row must chain onto the row we already
        hold at seq-1, so a peer cannot splice an alternative history in.

        A SEQ ALREADY TAKEN. Two different events at one position is a fork -
        refuse, and let a human work out which branch is real.
        """
        n = 0
        for ev in events:
            if ev.get("node") == self.node:
                raise Unauthorised(
                    f"refusing an event claiming to be from this node ({self.node}); "
                    f"nothing writes our chain but us")
            # Event ids are chosen by whoever wrote the event, so they are
            # attacker-controlled. Two separate criticals came out of that: a
            # planted ask whose whole id WAS a real ask's printed 8-character
            # prefix hijacked Ross's answer and minted an arbitrary grant, and
            # an id squatted from another chain made absorb() skip a real
            # grant.revoked as a "duplicate", censoring it forever.
            #
            # Requiring the shape append() already produces costs nothing
            # legitimate and removes both.
            try:
                uuid.UUID(str(ev.get("id", "")))
            except (ValueError, AttributeError, TypeError):
                raise Unauthorised(
                    f"event id {ev.get('id')!r} is not a uuid; ids are chosen by "
                    f"the writer and an arbitrary one can squat a real event") from None

            held = self.db.execute(
                "SELECT node, seq, hash FROM events WHERE id=?", (ev["id"],)).fetchone()
            if held is not None:
                # A genuine re-sync repeats the SAME row. Anything else is one
                # chain claiming another's id, and skipping it silently is what
                # let a revocation be suppressed.
                if (held["node"], held["seq"], held["hash"]) == (
                        ev.get("node"), ev.get("seq"), ev.get("hash")):
                    continue
                raise Unauthorised(
                    f"id {ev['id']} is already held at {held['node']} seq {held['seq']}; "
                    f"refusing an id squat from {ev.get('node')!r} seq {ev.get('seq')}")

            body = ev["body"]
            parsed = json.loads(body) if isinstance(body, str) else body
            msg = signable(ev)

            if not known(ev["kind"]):
                raise Unauthorised(
                    f"{ev['kind']!r} from {ev.get('node')!r} is not a declared kind; "
                    f"an undeclared kind is how an unsigned event gets projected "
                    f"as a signed one")
            problem = malformed(ev["kind"], parsed)
            if problem:
                raise Unauthorised(
                    f"{ev['kind']} from {ev.get('node')!r} is unusable: {problem}. "
                    f"A body whose shape nobody checked is how one unsigned row "
                    f"permanently kills a projection on every node.")
            if hashlib.sha256(msg).hexdigest() != ev["hash"]:
                raise Unauthorised(
                    f"event {ev['id']} from {ev.get('node')!r} does not match its own hash")
            if not self.trust.knows(ev["node"]):
                raise Unauthorised(
                    f"no public key for node {ev['node']!r}; it is not in trust.json")
            if not self.trust.node_signed(ev["node"], ev.get("nsig", ""), msg):
                raise Unauthorised(
                    f"event {ev['id']} is not signed by {ev['node']!r}")
            if needs_ross(ev["kind"], parsed) and \
                    not self.trust.ross_signed(ev.get("rsig", ""), msg):
                raise Unauthorised(
                    f"{ev['kind']} from {ev['node']!r} claims authority without "
                    f"Ross's signature")

            clash = self.db.execute(
                "SELECT id FROM events WHERE node=? AND seq=?", (ev["node"], ev["seq"])
            ).fetchone()
            if clash:
                raise Unauthorised(
                    f"{ev['node']} seq {ev['seq']} is already held by a different event "
                    f"({clash['id']}); the peer's chain has forked")

            # The row must chain onto what we already hold. A MISSING predecessor
            # is refused, not waved through - the first version skipped the check
            # in that case, so a peer could hand us a signed row at seq 900 with
            # a made-up prev and we would take it, leaving a permanent gap that
            # only verify() ever complained about. since() always returns a
            # contiguous run from our own mark, so a legitimate sync never lands
            # here out of order.
            if ev["seq"] == 1:
                expect = ""
            else:
                prior = self.db.execute(
                    "SELECT hash FROM events WHERE node=? AND seq=?",
                    (ev["node"], ev["seq"] - 1)).fetchone()
                if prior is None:
                    raise Unauthorised(
                        f"{ev['node']} seq {ev['seq']} arrived before seq "
                        f"{ev['seq'] - 1}; refusing to leave a hole in the chain")
                expect = prior["hash"]
            if (ev.get("prev", "") or "") != expect:
                raise Unauthorised(
                    f"{ev['node']} seq {ev['seq']} does not chain onto the row we hold")

            self.db.execute(
                "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash,nsig,rsig)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev["id"], ev["seq"], ev["node"], ev["ts"], ev["kind"],
                 ev.get("subject", ""), ev.get("actor", ""),
                 body if isinstance(body, str) else canonical(body),
                 ev.get("prev", ""), ev["hash"], ev.get("nsig", ""), ev.get("rsig", "")),
            )
            n += 1
        return n

    def close(self) -> None:
        self.db.close()
