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

from .keys import AUTHORITY, Signer, Trust

SCHEMA_VERSION = 2

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,       -- uuid4, generated at the writing node
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


def needs_ross(kind: str, body: dict) -> bool:
    """Does this event require Ross's signature to be believed?

    The authority kinds always do - they decide who may do what. On top of
    those, a lesson claiming basis 'told' does too, because 'told' means Ross
    said it, and an unsigned claim that Ross said something is exactly how an
    agent would come to argue with him using his own words. Lessons that are
    merely observed or inferred need no signature; there are hundreds of them
    and they grant nothing.
    """
    if kind in AUTHORITY:
        return True
    if kind in ("vault.learned", "vault.corrected") and body.get("basis") == "told":
        return True
    return False


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

        Authority events are signature-checked here as well as on the way in.
        That is not redundant - absorb() guards the network, and this guards
        anything that reached the table another way, including somebody editing
        the SQLite file by hand. The check runs only on events that claim
        authority, which are rare; the bulk of the log is not re-verified on
        every read.
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
            ev = {**dict(r), "body": json.loads(r["body"])}
            if not unchecked and needs_ross(ev["kind"], ev["body"]):
                if not self.trust.ross_signed(ev["rsig"] or "", signable(ev)):
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
            ev = {**dict(r), "body": json.loads(r["body"])}
            if needs_ross(ev["kind"], ev["body"]) and \
                    not self.trust.ross_signed(ev["rsig"] or "", signable(ev)):
                out.append(ev)
        return out

    def verify(self) -> list[str]:
        """Re-walk every chain: contiguity, hashes, and both signatures.

        This is what gets run before anyone relies on the bound book, and after
        every sync.
        """
        problems: list[str] = []
        nodes = [r["node"] for r in self.db.execute("SELECT DISTINCT node FROM events")]
        for node in nodes:
            prev = ""
            rows = self.db.execute(
                "SELECT * FROM events WHERE node=? ORDER BY seq", (node,)
            ).fetchall()
            for i, r in enumerate(rows, start=1):
                ev = {**dict(r), "body": json.loads(r["body"])}
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
                if needs_ross(ev["kind"], ev["body"]) and \
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
            cur = self.db.execute("SELECT 1 FROM events WHERE id=?", (ev["id"],))
            if cur.fetchone():
                continue

            body = ev["body"]
            parsed = json.loads(body) if isinstance(body, str) else body
            msg = signable(ev)

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

            prior = self.db.execute(
                "SELECT hash FROM events WHERE node=? AND seq=?",
                (ev["node"], ev["seq"] - 1)).fetchone()
            expect = prior["hash"] if prior else ("" if ev["seq"] == 1 else None)
            if expect is not None and (ev.get("prev", "") or "") != expect:
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
