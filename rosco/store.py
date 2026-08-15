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

The schema is deliberately dull: an id, who and where it came from, what kind of
fact it is, its payload, and a hash chain. The interesting part is entirely in
what gets appended.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,       -- uuid4, generated at the writing node
    seq         INTEGER,                -- per-node monotonic; NULL until assigned
    node        TEXT NOT NULL,          -- which site wrote it
    ts          TEXT NOT NULL,          -- RFC3339 UTC, when the node believed it happened
    kind        TEXT NOT NULL,          -- 'person.added', 'grant.given', ...
    subject     TEXT,                   -- the thing it is about, for cheap lookup
    actor       TEXT,                   -- who caused it; 'ross' for anything he approved
    body        TEXT NOT NULL,          -- json payload
    prev        TEXT,                   -- previous event hash on this node
    hash        TEXT NOT NULL           -- sha256 over the canonical form below
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


class Log:
    """An append-only event log, one file per node."""

    def __init__(self, path: str | Path, node: str) -> None:
        self.path = Path(path)
        self.node = node
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        # WAL so a reader (the employee site, say) never blocks the writer, and
        # a power cut at the shop cannot half-write a bound-book entry.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(_DDL)
        self.db.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema', ?)",
            (str(SCHEMA_VERSION),),
        )

    # ---- writing ---------------------------------------------------------

    def append(self, kind: str, body: dict, *, subject: str = "",
               actor: str = "", ts: str = "") -> dict:
        """Add one fact. Returns the stored event.

        The hash chains to this node's previous event, so a tampered or missing
        row is detectable by replay. It chains per NODE rather than globally:
        a global chain would need every node to agree on an order, which is
        exactly the coordination we refuse to require.
        """
        prev_row = self.db.execute(
            "SELECT hash, seq FROM events WHERE node=? ORDER BY seq DESC LIMIT 1",
            (self.node,),
        ).fetchone()
        prev = prev_row["hash"] if prev_row else ""
        seq = (prev_row["seq"] + 1) if prev_row else 1

        ev = {
            "id": str(uuid.uuid4()),
            "seq": seq,
            "node": self.node,
            "ts": ts or now(),
            "kind": kind,
            "subject": subject,
            "actor": actor,
            "body": body,
            "prev": prev,
        }
        ev["hash"] = hashlib.sha256(canonical(
            {k: ev[k] for k in ("id", "node", "ts", "kind", "subject", "actor", "body", "prev")}
        ).encode()).hexdigest()

        self.db.execute(
            "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ev["id"], ev["seq"], ev["node"], ev["ts"], ev["kind"], ev["subject"],
             ev["actor"], canonical(ev["body"]), ev["prev"], ev["hash"]),
        )
        return ev

    # ---- reading ---------------------------------------------------------

    def replay(self, *, kind: str = "", subject: str = "") -> Iterator[dict]:
        """Every matching event, oldest first.

        Ordered by (ts, node, seq) rather than insertion: after a sync the local
        table holds another site's events interleaved, and insertion order would
        make the same log replay differently on different nodes.
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
            yield {**dict(r), "body": json.loads(r["body"])}

    def verify(self) -> list[str]:
        """Re-walk every node's chain. Returns a list of problems, empty if sound.

        This is what gets run before anyone relies on the bound book, and after
        every sync. A break means either corruption or that somebody edited the
        database by hand, and the difference does not matter much.
        """
        problems: list[str] = []
        nodes = [r["node"] for r in self.db.execute("SELECT DISTINCT node FROM events")]
        for node in nodes:
            prev = ""
            rows = self.db.execute(
                "SELECT * FROM events WHERE node=? ORDER BY seq", (node,)
            ).fetchall()
            for i, r in enumerate(rows, start=1):
                if r["seq"] != i:
                    problems.append(f"{node}: gap at seq {i} (found {r['seq']})")
                if r["prev"] != prev:
                    problems.append(f"{node}: chain break at seq {r['seq']}")
                want = hashlib.sha256(canonical({
                    "id": r["id"], "node": r["node"], "ts": r["ts"], "kind": r["kind"],
                    "subject": r["subject"], "actor": r["actor"],
                    "body": json.loads(r["body"]), "prev": r["prev"],
                }).encode()).hexdigest()
                if want != r["hash"]:
                    problems.append(f"{node}: hash mismatch at seq {r['seq']}")
                prev = r["hash"]
        return problems

    # ---- syncing ---------------------------------------------------------

    def since(self, node: str, seq: int) -> list[dict]:
        """This node's events after `seq`. The whole of the sync protocol."""
        return [{**dict(r), "body": json.loads(r["body"])} for r in self.db.execute(
            "SELECT * FROM events WHERE node=? AND seq>? ORDER BY seq", (node, seq)
        )]

    def high_water(self) -> dict[str, int]:
        """Highest seq seen per node - what a peer is asked for."""
        return {r["node"]: r["m"] for r in self.db.execute(
            "SELECT node, MAX(seq) AS m FROM events GROUP BY node"
        )}

    def absorb(self, events: Iterable[dict]) -> int:
        """Take events from a peer. Returns how many were new.

        Idempotent by primary key, so re-syncing the same range is harmless -
        which matters because a shop on a flaky link will do exactly that.
        Foreign events are never re-hashed: their hash is the peer's claim about
        its own chain, and verify() checks it independently.
        """
        n = 0
        for ev in events:
            cur = self.db.execute("SELECT 1 FROM events WHERE id=?", (ev["id"],))
            if cur.fetchone():
                continue
            body = ev["body"]
            self.db.execute(
                "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ev["id"], ev["seq"], ev["node"], ev["ts"], ev["kind"], ev.get("subject", ""),
                 ev.get("actor", ""),
                 body if isinstance(body, str) else canonical(body),
                 ev.get("prev", ""), ev["hash"]),
            )
            n += 1
        return n

    def close(self) -> None:
        self.db.close()
