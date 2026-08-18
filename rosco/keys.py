"""Signing keys, and the root of trust.

An audit of the first cut found the hole this module exists to close. The rule
"only Ross grants" was enforced in Python: give() checked its caller and raised.
That check is real inside one process and worth nothing across three machines,
because Log.append() is unauthenticated - anything able to write an event could
write one stamped actor="ross", and every other node replayed it as fact. One
compromised site could mint itself a CERTAIN handle on Ross's name and a grant
to go with it.

The hash chain did not help. It is unkeyed, so it proves an ordering has not
been *accidentally* damaged and proves nothing at all about who wrote it: a
relay could rewrite a chain it was passing on and recompute every hash forward,
and verify() would call the result clean. The first version of nodes.py claimed
otherwise. It was wrong, and the claim is corrected there.

So authority is signed now, at two layers:

NODE SIGNATURE, on every event. Written with the originating node's key, over
the same canonical form the hash covers. A relay can pass a chain on; it cannot
alter one, because it cannot re-sign what it changed.

ROSS SIGNATURE, on authority events only - grants, enrolments, node
registrations, model choices, answers to the queue, secrets. These are the
events that decide who may do what, and they now carry a signature from a key
that lives on Ross's console and nowhere else. A compromised node can still
write whatever it likes on its own chain. What it cannot do is have anybody
believe it.

THE ROOT OF TRUST IS A FILE ROSS CARRIES. Public keys cannot be distributed by
the log they authenticate - that is circular. So trust.json is placed on each
node out of band, holding Ross's public key and each node's. It is small, it is
manual, and being manual is the point: adding a node is a thing a human does
deliberately, on every machine, rather than something the network can decide.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption,
                                                          PrivateFormat, PublicFormat)

ROSS = "ross"

# What an event must prove to be believed.
NODE = "node"      # the writing node's signature is enough
AUTHORED = "ross"  # Ross's signature too - this decides who may do what
BASIS = "basis"    # Ross's, unless the body carries an explicitly weak basis

# EVERY kind that may exist, declared. Nothing else is accepted, written, or
# replayed - and that closure is the point, not tidiness.
#
# A second audit found the reason. Authority was an exact-match set while the
# projections read by wildcard: Grants.live() consumed replay(kind="grant.*"),
# which becomes SQL `LIKE 'grant.%'` - suffix-matching AND case-insensitive.
# So a kind the authority set had never heard of walked straight through.
# A compromised node could append 'grant.suggested' (or 'GRANT.GIVEN', or
# 'grant.given2', or 'grant.given ') with its own signature and no signature
# from Ross, and every node projected it as a live grant while verify() and
# rejected() both reported clean. It handed a stranger unlimited DO on RUM's
# bound book.
#
# Widening the authority set would not have fixed it - the next undeclared kind
# would do the same thing. Declaring the whole vocabulary does, because an
# undeclared kind now has nowhere to land.
KINDS: dict[str, str] = {
    "grant.given": AUTHORED,
    "grant.denied": AUTHORED,
    "grant.revoked": AUTHORED,

    "identity.enrolled": AUTHORED,
    "identity.retired": AUTHORED,
    "identity.stranger": NODE,        # "somebody we could not place turned up"

    "node.registered": AUTHORED,
    "node.retired": AUTHORED,
    "node.seen": NODE,

    "model.chosen": AUTHORED,
    "model.pinned": AUTHORED,         # one agent gets its own model, whatever its role
    "model.unpinned": AUTHORED,       # ...cleared, back to the role default
    "model.trialled": NODE,           # agents may judge a model
    "model.spotted": NODE,            # ...and ask for one

    "ask.raised": NODE,               # anybody may ask
    "ask.repeated": NODE,
    "ask.answered": AUTHORED,         # only Ross may answer
    "ask.spent": NODE,                # a one-off permission has been used up

    "vault.secret": AUTHORED,
    "vault.learned": BASIS,           # 'Ross told me' needs Ross
    "vault.corrected": BASIS,         # an agent may retract its own inference
    "vault.forgot": AUTHORED,         # erasure is authority, always

    "budget.set": AUTHORED,           # a spend cap is Ross's policy
    "model.billed": NODE,             # what a call cost - agents record it
    "spend.alerted": NODE,            # a soft threshold was crossed, warned once

    # Pairing Ross's own Telegram. The challenge is AUTHORED - it must carry his
    # signature - because an audit found the old plaintext pair.json turned a
    # mere file-write into a Ross-signed enrolment: anyone who could drop a file
    # picked the code, and the running service honoured it. A signed challenge
    # in the log cannot be forged by a file-writer who lacks the key.
    "pair.challenge": AUTHORED,
    "pair.consumed": AUTHORED,         # a challenge was spent, signed on success
    "pair.attempt": NODE,             # a wrong code was tried - for the lockout

    # External tools - Higgsfield, an MCP server, a vendor API. Registering one
    # widens what the system can do, so it is authority, like a grant.
    "tool.registered": AUTHORED,
    "tool.retired": AUTHORED,

    # GitHub - linking a business to a repo is authority; a proposal (branch,
    # commit, PR) an agent makes is a plain node fact, recorded for the log.
    "github.linked": AUTHORED,
    "github.unlinked": AUTHORED,
    "github.proposed": NODE,

    # An agent did a piece of work and proposed it. A plain node fact - the
    # agent watched itself do this; it is not Ross's word and grants nothing.
    "agent.produced": NODE,
    "agent.answered": NODE,           # an agent answered an allowed read

    # Ingestion review: a candidate item Rosco proposes a home for (NODE - a
    # proposal grants nothing), and Ross's one-by-one routing decision. The
    # actual knowledge write on 'ingest' is a separate SIGNED vault.learned;
    # these two only drive the review queue and the routing-accuracy signal, so
    # a forged one plants no knowledge - it grants nothing and stores nothing.
    "ingest.proposed": NODE,
    "ingest.decided": NODE,

    # Inbox triage in Next: Ross acted on an email (archive/reply/trash/...). A
    # plain node fact — it grants nothing — and it is the domain->action signal
    # the importance ranker learns from; a batch sweep records one per domain.
    "inbox.acted": NODE,

    # A to-do Rosco captured from an email Ross closed out. NODE — a task grants
    # nothing; it is a reminder, read defensively like every node body.
    "task.created": NODE,
    "task.done": NODE,

    # A shipment tracking number Rosco captured from the inbox, and its close-out.
    # NODE — it grants nothing; it's a note Ross can verify against the carrier.
    "tracking.recorded": NODE,
    "tracking.closed": NODE,

    # A Gmail 'watch window': Ross said 'about to check email' (open, stashes the
    # history cursor) / 'done' (closed). NODE — it only bookmarks and observes
    # Ross's own mailbox; what he did in the window is folded into inbox.acted.
    "email.watch": NODE,

    # A SteelHaven Meet transcript Rosco auto-ingested. NODE — it grants nothing;
    # it is the dedup marker (one per transcript file id) AND the ledger entry for
    # a no-review auto-learn, so Ross can see exactly what got pulled in. The
    # knowledge itself is a separate OBSERVED vault.learned (Rosco watched the
    # meeting, so 'observed' — never 'told', which would need Ross's signature).
    "meeting.ingested": NODE,
}

# Bases that an agent may claim on its own signature. Anything else - missing,
# miscased, unrecognised, or 'told' - needs Ross.
WEAK_BASIS = frozenset({"observed", "inferred"})

# Kept as a name because other modules read it, but derived rather than written
# twice - two lists of the same thing drift.
AUTHORITY = frozenset(k for k, v in KINDS.items() if v == AUTHORED)


# What each kind's body must contain. Declared for the same reason the kinds are.
#
# A fourth audit found that declaring the vocabulary was not enough. Anything a
# compromised node can write with only its own signature - every NODE kind, and
# a BASIS kind with a weak basis - is attacker-controlled input, and the
# projections read it by subscript. ONE `ask.repeated` with an empty body, from
# any registered node, permanently killed the ask queue on every node: pending(),
# digest(), get() and raise_() all raised KeyError, so Ross could neither see the
# questions waiting on him nor receive new ones. verify() reported clean and
# rejected() reported nothing, the rows survived restart, and they re-arrived on
# the next sync. That is the queue that implements his cardinal rule.
#
# store.replay() already refuses to raise on a body that will not PARSE, for
# exactly this reason. The guard stopped at JSON validity; shape is the next door.
REQUIRED: dict[str, tuple[str, ...]] = {
    "grant.given": ("person", "business", "capability"),
    "grant.denied": ("person", "business", "capability"),
    "grant.revoked": ("grant",),

    "identity.enrolled": ("person", "channel", "address"),
    "identity.retired": ("handle",),
    "identity.stranger": ("channel", "address"),

    "node.registered": ("name", "site", "role"),
    "node.retired": ("node",),
    "node.seen": ("name",),

    "model.chosen": ("role", "model", "provider"),
    "model.pinned": ("agent", "model", "provider"),
    "model.unpinned": ("agent",),
    "model.trialled": ("model", "role", "verdict"),
    "model.spotted": ("model", "provider"),

    "ask.raised": ("person", "business", "capability", "verb"),
    "ask.repeated": ("ask",),
    "ask.answered": ("ask", "answer"),
    "ask.spent": ("ask",),

    "vault.secret": ("business", "name", "nonce", "blob", "tag"),
    "vault.learned": ("agent", "business", "text"),
    "vault.corrected": ("replaces", "text"),
    "vault.forgot": ("lesson",),

    "budget.set": ("scope", "monthly_usd"),
    "model.billed": ("provider", "model", "prompt_tokens", "completion_tokens"),
    "spend.alerted": ("scope", "period", "threshold"),

    "pair.challenge": ("hash", "expires"),
    "pair.consumed": ("challenge",),
    "pair.attempt": ("challenge",),

    "tool.registered": ("name", "kind", "endpoint"),
    "tool.retired": ("name",),

    "github.linked": ("business", "owner", "name"),
    "github.unlinked": ("business",),
    "github.proposed": ("business", "agent", "branch"),

    "agent.produced": ("agent", "business"),
    "agent.answered": ("agent", "business"),

    "ingest.proposed": ("cand", "text"),
    "ingest.decided": ("cand", "action"),
    "inbox.acted": ("domain", "action"),
    "task.created": ("id", "text"),
    "task.done": ("id",),
    "tracking.recorded": ("number",),
    "tracking.closed": ("number",),
    "email.watch": ("state",),
    "meeting.ingested": ("file", "name"),
}

# Fields whose value must come from a closed set. An unexpected one used as a
# dict key - models.leaderboard did `row[b["verdict"]]` - is the same crash.
ENUMS: dict[tuple[str, str], tuple[str, ...]] = {
    ("model.trialled", "verdict"): ("better", "same", "worse", "failed"),
    ("ask.answered", "answer"): ("allow-once", "allow-always", "deny-once", "deny-always"),
    ("vault.learned", "basis"): ("told", "observed", "inferred"),
    ("vault.corrected", "basis"): ("told", "observed", "inferred"),
    ("node.registered", "role"): ("site", "rendezvous"),
    ("grant.given", "scope"): ("all", "subject"),
    # A raised ask's verb is get or do, nothing else. This is the first line
    # against a compromised node planting an ask whose "verb" is a script
    # payload the dashboard would render - a malformed verb is now dropped at
    # absorb() and replay(), before it can reach any screen. The dashboard also
    # escapes it and forbids inline script, so it is three layers deep.
    ("ask.raised", "verb"): ("get", "do"),
    # A routing decision is 'ingest'/'skip'; the inbox tidy verbs also land here
    # via Ingest.acted (they clear a card without learning). A malformed action
    # from a compromised node is dropped at absorb().
    ("ingest.decided", "action"): ("ingest", "skip", "archive", "star", "keep",
                                   "done", "markread", "trash", "spam", "reply"),
    # 'read' and 'file' join the tidy verbs — both from a Gmail watch. 'read' is a
    # message opened/marked (UNREAD removed) and kept; 'file' is one read THEN
    # cleared from the inbox (or an already-read message filed away). Both are mild
    # positive engagement; only 'archive' — inbox cleared while still UNREAD — is a
    # dismissal. 'read' is also distinct from a dashboard 'markread'.
    ("inbox.acted", "action"): ("archive", "star", "keep", "done", "markread",
                                "trash", "spam", "reply", "read", "file"),
    ("email.watch", "state"): ("open", "closed"),
}


def known(kind: str) -> bool:
    """Is this a kind the system has declared? Undeclared is never accepted."""
    return kind in KINDS


def malformed(kind: str, body) -> str | None:
    """Why this body is unusable, or None if it is fine.

    Checked on the way in at append() AND absorb(), so a malformed event never
    lands in any log. The projections are defensive as well - belt and braces,
    because a row could reach the table by other means - but the real guarantee
    is that nothing gets to write one.
    """
    if not isinstance(body, dict):
        return f"body is {type(body).__name__}, not an object"
    for field in REQUIRED.get(kind, ()):
        value = body.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return f"missing {field!r}"
        if not isinstance(value, (str, int, float, bool, list, dict)):
            return f"{field!r} is not a JSON scalar"
    for (k, field), allowed in ENUMS.items():
        if k != kind:
            continue
        value = body.get(field)
        if value is None and field == "basis":
            continue           # absent basis is handled by needs_ross, fail-closed
        if value is not None and str(value).strip().lower() not in allowed:
            return f"{field}={value!r} is not one of {', '.join(allowed)}"
    return None


def needs_ross(kind: str, body) -> bool:
    """Does this event require Ross's signature to be believed?

    Fails closed everywhere. An undeclared kind needs it (though it should have
    been refused before reaching here), and so does an event whose body is not
    even an object - a peer can put a list or a string there, and something that
    cannot be inspected cannot be trusted. The first version called .get() on it
    and raised AttributeError deep inside sync, which sync_from did not catch.
    """
    rule = KINDS.get(kind)
    if rule is None:
        return True
    if rule == NODE:
        return False
    if rule == AUTHORED:
        return True
    # BASIS: only an explicitly weak, recognised basis escapes.
    if not isinstance(body, dict):
        return True
    return str(body.get("basis", "")).strip().lower() not in WEAK_BASIS


class Signer:
    """One Ed25519 identity - a node's, or Ross's."""

    def __init__(self, raw: bytes) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(raw)

    @classmethod
    def generate(cls) -> "Signer":
        k = Ed25519PrivateKey.generate()
        return cls(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    @classmethod
    def load(cls, path: str | Path) -> "Signer":
        return cls(Path(path).read_bytes())

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Signer":
        """A node mints its own key the first time it runs.

        The node key is not a secret Ross needs to handle - it identifies the
        machine, and a machine that loses it is a machine that needs
        re-registering, which is the correct amount of friction.
        """
        p = Path(path)
        if p.exists():
            return cls.load(p)
        s = cls.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(s.raw)
        try:
            os.chmod(p, 0o600)   # no-op on some Windows filesystems; harmless
        except OSError:
            pass
        return s

    @property
    def raw(self) -> bytes:
        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def public(self) -> str:
        return self._key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()


def verify(public_hex: str, signature_hex: str, message: bytes) -> bool:
    """Did the holder of this public key sign this exact message?"""
    if not public_hex or not signature_hex:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


class Trust:
    """The public keys this machine believes. Placed by Ross, out of band."""

    def __init__(self, ross: str = "", nodes: dict[str, str] | None = None) -> None:
        self.ross = ross
        self.nodes = dict(nodes or {})

    @classmethod
    def load(cls, path: str | Path) -> "Trust":
        p = Path(path)
        if not p.exists():
            return cls()
        d = json.loads(p.read_text(encoding="utf-8"))
        return cls(ross=d.get("ross", ""), nodes=d.get("nodes", {}))

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(
            {"ross": self.ross, "nodes": self.nodes}, indent=2), encoding="utf-8")

    @property
    def bootstrapping(self) -> bool:
        """True before Ross has installed his public key.

        Callers must treat this as "nothing is trustworthy yet" rather than as
        "everything is allowed". It exists so a fresh machine can say what is
        wrong instead of failing obscurely.
        """
        return not self.ross

    def add_node(self, name: str, public_hex: str) -> None:
        self.nodes[name] = public_hex

    def node_signed(self, node: str, signature: str, message: bytes) -> bool:
        return verify(self.nodes.get(node, ""), signature, message)

    def ross_signed(self, signature: str, message: bytes) -> bool:
        return verify(self.ross, signature, message)

    def knows(self, node: str) -> bool:
        return node in self.nodes

    def report(self) -> str:
        lines = [f"  ross    {self.ross[:16] + '...' if self.ross else 'NOT INSTALLED'}"]
        for n, k in sorted(self.nodes.items()):
            lines.append(f"  {n:8} {k[:16]}...")
        if self.bootstrapping:
            lines.append("\n  !! no key for Ross - authority events cannot be verified")
        return "\n".join(lines)
