"""The Vault - one permissioned store, two kinds of content.

Every agent learns, and what it learns goes here. So do the credentials. They
are the same store on purpose: both are things an agent holds, both are scoped
to one business, and both need the same question answered before anything is
handed over - may THIS reader have THIS?

    SECRET    encrypted at rest, never rendered, machine-only.
              RUM's QBO refresh token. SteelHaven's Workspace credentials.

    LEARNING  readable, and projected out to markdown so Ross can sit down and
              read what an agent has concluded about his own business.
              "Dix wants 60 days notice on the Outer Road lease."
              "Sanjay's valuations run high until the loan file lands."

Learning is written as events, like everything else, which buys three things:

It is correctable. An agent that learns something wrong is fixed by appending a
correction, not by editing the past. What it believed, when, and who told it
otherwise all survive - which matters the first time an agent tells Lucas
something confidently wrong and nobody can work out where it got it.

It is attributable. Every lesson carries how it was learned: Ross said so, it
was observed happening, or it was inferred. Those are not the same weight, and
an agent that cannot tell them apart will eventually present its own guess back
to Ross as his own instruction.

It is siloed by construction. A lesson belongs to a business. Remington's FFL
knowledge is RUM's; asking HavenMind about it returns nothing, because the
scope is part of the record rather than a filter applied afterwards.

Only Rosco reads across businesses, and only to enrich - see grants.py, where
the check runs against the person who will READ the answer rather than the
agent that produced it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .store import Log, now

# How a lesson came to be believed, weakest last. An agent must never present
# INFERRED as though Ross had said it.
TOLD = "told"            # Ross said so directly
OBSERVED = "observed"    # it watched this happen, repeatedly
INFERRED = "inferred"    # it worked this out, and could be wrong
WEIGHT = {TOLD: 3, OBSERVED: 2, INFERRED: 1}


@dataclass
class Lesson:
    """One thing an agent believes, and why."""
    id: str
    agent: str                 # 'Remington', 'HavenMind', ...
    business: str              # 'rum', 'steelhaven', ...
    text: str
    basis: str = INFERRED
    source: str = ""           # a message id, a file, 'ross'
    learned: str = ""
    superseded_by: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def live(self) -> bool:
        return not self.superseded_by


class Vault:
    """Learning and secrets for every agent, over one log."""

    def __init__(self, log: Log, *, key: bytes | None = None) -> None:
        self.log = log
        self._key = key

    # ---- learning --------------------------------------------------------

    def learn(self, agent: str, business: str, text: str, *,
              basis: str = INFERRED, source: str = "", tags: tuple = ()) -> dict:
        """Record something an agent now believes.

        Deliberately not deduplicated on the way in. An agent learning the same
        thing twice from two sources is evidence the thing is true, and
        collapsing that on write throws the evidence away. recall() folds them.
        """
        if basis not in WEIGHT:
            raise ValueError(f"basis must be one of {sorted(WEIGHT)}, got {basis!r}")
        return self.log.append(
            "vault.learned",
            {"agent": agent, "business": business, "text": text.strip(),
             "basis": basis, "source": source, "tags": list(tags)},
            subject=f"{business}:{agent}", actor=source or agent,
        )

    def correct(self, lesson_id: str, text: str, *, by: str = "ross",
                basis: str = TOLD) -> dict:
        """Supersede a lesson. The old one stays readable, marked dead.

        Corrections default to TOLD by Ross, because in practice a correction
        is nearly always him saying "no, that is wrong" - and a correction that
        inherited the weak basis of the thing it replaced would be argued with
        by the very agent it was meant to fix.
        """
        return self.log.append(
            "vault.corrected",
            {"replaces": lesson_id, "text": text.strip(), "basis": basis},
            subject=lesson_id, actor=by,
        )

    def forget(self, lesson_id: str, *, by: str = "ross", why: str = "") -> dict:
        """Retire a lesson with nothing in its place."""
        return self.log.append(
            "vault.forgot", {"lesson": lesson_id, "why": why},
            subject=lesson_id, actor=by,
        )

    def recall(self, *, business: str = "", agent: str = "",
               contains: str = "", include_dead: bool = False) -> list[Lesson]:
        """What is believed now, strongest basis first.

        The business filter is the silo. Omitting it is how Rosco reads across
        everything, and nothing else should be calling it that way.
        """
        lessons: dict[str, Lesson] = {}
        replaced: dict[str, str] = {}
        dropped: set[str] = set()

        for ev in self.log.replay(kind="vault.*"):
            b = ev["body"]
            if ev["kind"] == "vault.learned":
                lessons[ev["id"]] = Lesson(
                    id=ev["id"], agent=b["agent"], business=b["business"],
                    text=b["text"], basis=b.get("basis", INFERRED),
                    source=b.get("source", ""), learned=ev["ts"],
                    tags=tuple(b.get("tags", ())),
                )
            elif ev["kind"] == "vault.corrected":
                old = b["replaces"]
                replaced[old] = ev["id"]
                if old in lessons:
                    src = lessons[old]
                    lessons[ev["id"]] = Lesson(
                        id=ev["id"], agent=src.agent, business=src.business,
                        text=b["text"], basis=b.get("basis", TOLD),
                        source=ev["actor"], learned=ev["ts"], tags=src.tags,
                    )
            elif ev["kind"] == "vault.forgot":
                dropped.add(b["lesson"])

        out = []
        for lid, les in lessons.items():
            les.superseded_by = replaced.get(lid, "")
            dead = bool(les.superseded_by) or lid in dropped
            if dead and not include_dead:
                continue
            if business and les.business != business:
                continue
            if agent and les.agent != agent:
                continue
            if contains and contains.lower() not in les.text.lower():
                continue
            out.append(les)
        out.sort(key=lambda l: (-WEIGHT.get(l.basis, 0), l.learned))
        return out

    def to_markdown(self, business: str, agent: str = "") -> str:
        """The readable projection - what an agent has worked out, on a page.

        This is the point of storing learning as text rather than as vectors:
        Ross can read it, disagree with a line, and have that disagreement
        become a correction. A memory he cannot inspect is one he cannot govern.
        """
        rows = self.recall(business=business, agent=agent)
        head = f"# What {agent or 'the ' + business + ' bench'} has learned\n"
        if not rows:
            return head + "\n_Nothing yet._\n"
        parts = [head]
        for basis in (TOLD, OBSERVED, INFERRED):
            group = [r for r in rows if r.basis == basis]
            if not group:
                continue
            label = {TOLD: "Ross said so", OBSERVED: "Observed happening",
                     INFERRED: "Worked out - may be wrong"}[basis]
            parts.append(f"\n## {label}\n")
            for r in group:
                who = f" _{r.agent}_" if not agent else ""
                parts.append(f"- {r.text}{who}  \n  <sub>{r.learned} &middot; {r.source or 'unattributed'}</sub>")
        return "\n".join(parts) + "\n"

    # ---- secrets ---------------------------------------------------------
    #
    # Encryption is deliberately small and dependency-free: a key derived per
    # secret from the vault key, AES-free XOR-with-keystream would be a toy, so
    # this uses the stdlib's HMAC as a CTR-mode keystream. It is honest crypto
    # for data at rest on a machine Ross controls, and it is replaceable - the
    # envelope records its own scheme so a future one can be introduced without
    # rewriting stored values.

    def _stream(self, nonce: bytes, n: int) -> bytes:
        if not self._key:
            raise RuntimeError("vault opened without a key; cannot touch secrets")
        out, ctr = b"", 0
        while len(out) < n:
            out += hmac.new(self._key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
            ctr += 1
        return out[:n]

    def put_secret(self, business: str, name: str, value: str, *,
                   by: str = "ross") -> dict:
        """Store a credential. Only Ross puts secrets in, by construction."""
        self._require_key()
        nonce = os.urandom(16)
        raw = value.encode()
        blob = bytes(a ^ b for a, b in zip(raw, self._stream(nonce, len(raw))))
        tag = hmac.new(self._key, nonce + blob, hashlib.sha256).hexdigest()
        return self.log.append(
            "vault.secret",
            {"business": business, "name": name, "scheme": "hmac-sha256-ctr/1",
             "nonce": base64.b64encode(nonce).decode(),
             "blob": base64.b64encode(blob).decode(), "tag": tag},
            subject=f"{business}:{name}", actor=by,
        )

    def _require_key(self) -> None:
        if not self._key:
            raise RuntimeError("vault opened without a key; cannot touch secrets")

    def get_secret(self, business: str, name: str) -> str | None:
        """Latest value for a named secret, or None.

        Rotation is just another append: the newest wins, and the old envelope
        stays in the log as a record that a rotation happened - without the old
        plaintext, which nothing can recover.
        """
        self._require_key()
        latest = None
        for ev in self.log.replay(kind="vault.secret", subject=f"{business}:{name}"):
            latest = ev
        if not latest:
            return None
        b = latest["body"]
        nonce = base64.b64decode(b["nonce"])
        blob = base64.b64decode(b["blob"])
        want = hmac.new(self._key, nonce + blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, b["tag"]):
            raise ValueError(f"{business}:{name} failed its integrity check")
        return bytes(a ^ b2 for a, b2 in zip(blob, self._stream(nonce, len(blob)))).decode()

    def secret_names(self, business: str = "") -> list[str]:
        """What is held, without touching any value.

        Deliberately available without the key: a health check should be able to
        report that RUM has no QBO token yet without being able to read the ones
        that do exist.
        """
        seen = []
        for ev in self.log.replay(kind="vault.secret"):
            b = ev["body"]
            if business and b["business"] != business:
                continue
            label = f"{b['business']}:{b['name']}"
            if label not in seen:
                seen.append(label)
        return seen


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Vault key from a passphrase. 600k rounds, per OWASP's 2023 floor."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000, dklen=32)
