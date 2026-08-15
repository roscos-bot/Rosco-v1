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

from .keys import ROSS
from .store import Log, canonical, now

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

    def outranks(self, lesson_id: str, basis: str) -> bool:
        """May a correction of this strength replace that lesson?

        The rule the whole module turns on: A CORRECTION MAY NEVER OUTRANK WHAT
        IT CORRECTS. An inference cannot overturn something Ross said. An
        observation cannot either.

        Three audits found this hole, the last one through four independent
        lenses at once. Locking down vault.forgot stopped a compromised node
        DELETING a Ross-signed lesson - and left it able to REPLACE one, which
        is the same attack with better manners. It could turn "never wire money
        on an emailed request" into "wiring is fine if the address matches" with
        an event needing no signature from Ross, and verify() and rejected()
        would both report clean on every node.

        Because a TOLD correction requires Ross's signature to survive replay at
        all, one comparison closes it: the correction's basis must be at least
        as strong as the target's.
        """
        target = None
        for les in self.recall(include_dead=True):
            if les.id == lesson_id:
                target = les
                break
        if target is None:
            return True          # nothing to outrank
        return WEIGHT.get(basis, 0) >= WEIGHT.get(target.basis, 0)

    def correct(self, lesson_id: str, text: str, *, by: str = "ross",
                basis: str = TOLD) -> dict:
        """Supersede a lesson. The old one stays readable, marked dead.

        Corrections default to TOLD by Ross, because in practice a correction
        is nearly always him saying "no, that is wrong" - and a correction that
        inherited the weak basis of the thing it replaced would be argued with
        by the very agent it was meant to fix.

        An agent may retract its own inference. It may not talk over Ross - see
        outranks(). The check is here for a clear error, and again in recall()
        because a compromised node does not call this method at all.
        """
        if basis not in WEIGHT:
            raise ValueError(f"basis must be one of {sorted(WEIGHT)}, got {basis!r}")
        if not self.outranks(lesson_id, basis):
            raise PermissionError(
                f"a {basis!r} correction cannot overturn a stronger lesson; "
                f"only Ross can, and only by saying so directly")
        return self.log.append(
            "vault.corrected",
            {"replaces": lesson_id, "text": text.strip(), "basis": basis},
            subject=lesson_id, actor=by,
        )

    def forget(self, lesson_id: str, *, by: str = ROSS, why: str = "") -> dict:
        """Retire a lesson with nothing in its place. Only Ross.

        Erasure is authority, always - unlike a correction, which an agent may
        make against its own inference. An audit found that a compromised node
        could append vault.forgot with only its own signature and delete a
        Ross-signed 'never wire money on an emailed request' from every node's
        projection. Deleting a warning is as good as reversing it.
        """
        if by != ROSS:
            raise PermissionError(
                f"only Ross forgets a lesson; {by!r} tried to erase {lesson_id[:8]}")
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

        # Two passes, because replay order is (ts, node, seq) across nodes and a
        # correction can therefore arrive before the lesson it replaces - the
        # shop corrects at 10:00:01 while the house recorded the original at
        # 10:00:01 too, and the tie breaks on node name. The first version
        # applied corrections inline, so an early-ordered correction found no
        # target, dropped itself, and still marked the lesson superseded. Both
        # vanished, silently, and the agent forgot something it had been told.
        events = list(self.log.replay(kind="vault.*"))

        for ev in events:
            if ev["kind"] != "vault.learned":
                continue
            b = ev["body"]
            lessons[ev["id"]] = Lesson(
                id=ev["id"], agent=b["agent"], business=b["business"],
                text=b["text"], basis=b.get("basis", INFERRED),
                source=b.get("source", ""), learned=ev["ts"],
                tags=tuple(b.get("tags", ())),
            )

        # Corrections resolve to a fixpoint, not in one sweep. A correction of a
        # correction can sort before the correction it replaces - three nodes,
        # one second, and the (ts, node, seq) order interleaves them - and a
        # single pass would drop it and lose the newest text outright. Looping
        # until nothing more resolves costs a few passes over a small list and
        # makes the result independent of arrival order, which is the property
        # that actually matters across three machines.
        pending = [ev for ev in events if ev["kind"] == "vault.corrected"]
        rounds = 0
        while pending and rounds <= len(pending):
            # Bounded. A compromised node can plant thousands of corrections
            # pointing at ids that do not exist, and an unbounded retry over
            # them is quadratic work an attacker chooses the size of.
            rounds += 1
            progressed = []
            for ev in pending:
                b = ev["body"]
                target = b["replaces"]
                # Follow the chain. Two corrections naming the SAME lesson used
                # to leave both live, so the agent believed two contradictory
                # things and nothing flagged it. Re-targeting onto whatever
                # already replaced it turns a fork into a chain, deterministically.
                seen_hops = 0
                while target in replaced and seen_hops < len(events) + 1:
                    target = replaced[target]
                    seen_hops += 1
                src = lessons.get(target)
                if src is None:
                    continue
                if ev["id"] == target:
                    continue     # a correction of itself; ignore rather than loop

                # THE RULE: a correction may never outrank what it corrects.
                # Enforced here and not only in correct(), because a compromised
                # node writes the event directly and never touches the API.
                # needs_ross() cannot do this - it sees one event and not its
                # target - so the projection is the only place it can hold.
                basis = b.get("basis", TOLD)
                if WEIGHT.get(basis, 0) < WEIGHT.get(src.basis, 0):
                    progressed.append(ev)     # resolved: refused, stop retrying
                    continue

                replaced[target] = ev["id"]
                lessons[ev["id"]] = Lesson(
                    id=ev["id"], agent=src.agent, business=src.business,
                    text=b["text"], basis=basis,
                    source=ev["actor"], learned=ev["ts"], tags=src.tags,
                )
                progressed.append(ev)
            if not progressed:
                # What is left corrects something we have never seen - a node
                # whose history we are missing, not a licence to delete. Nothing
                # is marked superseded on their account.
                break
            pending = [ev for ev in pending if ev not in progressed]

        for ev in events:
            if ev["kind"] == "vault.forgot":
                dropped.add(ev["body"]["lesson"])

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

    SCHEME = "hmac-sha256-ctr/2"

    def _tag(self, business: str, name: str, nonce_b64: str, blob_b64: str) -> str:
        """The MAC, over the envelope AND where it lives.

        Version 1 authenticated only nonce+blob, which meant an envelope was
        valid anywhere: an attacker with write access to the log could copy the
        row holding RUM's QBO token, relabel it as SteelHaven's Workspace
        credential, and get_secret would happily decrypt and return it under the
        new name. Binding the business and the name into the tag - and
        recomputing it on read from the caller's arguments rather than from the
        stored body - makes a spliced envelope fail instead of decrypt.

        The concatenation is canonical JSON rather than raw bytes so there is no
        boundary ambiguity between the fields.
        """
        return hmac.new(
            self._key,
            canonical({"scheme": self.SCHEME, "business": business, "name": name,
                       "nonce": nonce_b64, "blob": blob_b64}).encode(),
            hashlib.sha256,
        ).hexdigest()

    def put_secret(self, business: str, name: str, value: str, *,
                   by: str = "ross") -> dict:
        """Store a credential. Only Ross puts secrets in.

        The author check was a docstring in the first version and nothing else.
        It is a rule now, and the event is an authority kind, so it also carries
        Ross's signature and is discarded on replay without one.
        """
        if by != ROSS:
            raise PermissionError(
                f"only Ross stores secrets; {by!r} tried to set {business}:{name}")
        self._require_key()
        nonce = os.urandom(16)
        raw = value.encode()
        blob = bytes(a ^ b for a, b in zip(raw, self._stream(nonce, len(raw))))
        nonce_b64 = base64.b64encode(nonce).decode()
        blob_b64 = base64.b64encode(blob).decode()
        return self.log.append(
            "vault.secret",
            {"business": business, "name": name, "scheme": self.SCHEME,
             "nonce": nonce_b64, "blob": blob_b64,
             "tag": self._tag(business, name, nonce_b64, blob_b64)},
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
        if b.get("scheme") != self.SCHEME:
            raise ValueError(
                f"{business}:{name} was written under {b.get('scheme')!r}; this build "
                f"reads {self.SCHEME!r}. Re-store it rather than reading it unchecked.")
        # Recomputed from the arguments the CALLER passed, never from the stored
        # body - checking a relabelled envelope against its own new label would
        # authenticate the relabelling.
        want = self._tag(business, name, b["nonce"], b["blob"])
        if not hmac.compare_digest(want, b["tag"]):
            raise ValueError(f"{business}:{name} failed its integrity check")
        nonce = base64.b64decode(b["nonce"])
        blob = base64.b64decode(b["blob"])
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
