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
}

# Bases that an agent may claim on its own signature. Anything else - missing,
# miscased, unrecognised, or 'told' - needs Ross.
WEAK_BASIS = frozenset({"observed", "inferred"})

# Kept as a name because other modules read it, but derived rather than written
# twice - two lists of the same thing drift.
AUTHORITY = frozenset(k for k, v in KINDS.items() if v == AUTHORED)


def known(kind: str) -> bool:
    """Is this a kind the system has declared? Undeclared is never accepted."""
    return kind in KINDS


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
