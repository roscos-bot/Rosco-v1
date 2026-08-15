"""The sites, and how they catch each other up.

Three machines, each with a full copy of the log and a UniFi network under it:
the RUM shop on W. Outer Road, the house at Spring Valley, and probably a cloud
VM. Ross's requirement is plain - each site keeps working with the internet
down, and reconciles when the link returns.

That is why the log is append-only and why chains are per node. Two sites that
both wrote while cut off have not conflicted; they have each added facts, and
merging is a matter of taking rows the other has not seen. No coordinator, no
election, nothing to be down.

WHAT SYNC ACTUALLY IS. Ask a peer for its high-water marks, work out what we
are missing on every chain it knows about, take those rows. That is the whole
protocol. It is idempotent, so a shop on a flaky link can run it in a loop.

WHY IT COPIES OTHER NODES' CHAINS TOO. The house and the shop may never see
each other directly - one is behind a residential connection and the other is
on a business line, and the only mutually reachable machine is the cloud VM. So
sync pulls every chain the peer holds, not just the peer's own. The shop's
events reach the house by way of the cloud, and the hash chain still proves
they are the shop's, because the cloud cannot alter them without breaking a
hash it does not have the ability to recompute convincingly - it would have to
forge the whole chain forward from the edit, and verify() walks the whole chain.

WHAT IT DOES NOT DO. It does not sync selectively. Filtering by kind - keeping
RUM's bound book off the house machine, say - would leave gaps in a chain whose
whole security property is contiguity, and verify() would be unable to tell a
deliberate omission from a deleted row. Access is grants.py's job; the log's
job is to be complete and provable. If selective replication is ever genuinely
needed, it needs a separate chain per silo, not a filter on this one.
"""
from __future__ import annotations

from dataclasses import dataclass

from .grants import ROSS
from .store import Log

SITE = "site"              # a real place with gear and people in it
RENDEZVOUS = "rendezvous"  # internet-reachable; how the sites find each other


@dataclass
class Node:
    id: str
    name: str              # matches Log.node - this is the chain's identity
    site: str              # 'RUM shop, W. Outer Rd'
    role: str
    reach: str             # host:port on the VPN, or a public name for the rendezvous
    note: str
    enrolled: str
    retired: bool = False


@dataclass
class SyncReport:
    peer: str
    taken: int
    chains: dict[str, int]     # node name -> rows taken from that chain
    refused: list[str]         # what was rejected, and why

    @property
    def clean(self) -> bool:
        return not self.refused

    def __str__(self) -> str:
        if not self.taken and not self.refused:
            return f"{self.peer}: already up to date"
        parts = [f"{self.peer}: took {self.taken}"]
        if self.chains:
            parts.append("(" + ", ".join(f"{k} +{v}" for k, v in sorted(self.chains.items())) + ")")
        if self.refused:
            parts.append(f"REFUSED {len(self.refused)}: " + "; ".join(self.refused[:3]))
        return " ".join(parts)


class Nodes:
    """The site registry, projected from the log like everything else."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing ---------------------------------------------------------

    def register(self, name: str, site: str, *, role: str = SITE, reach: str = "",
                 note: str = "", by: str = ROSS) -> dict:
        """Add a machine.

        Only Ross, and this is not bureaucracy: registering a node is declaring
        that a machine's events are worth absorbing. Anything that can enrol a
        node can introduce a chain of its own invention and have this system
        replay it as fact.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross registers a node; {by!r} tried to add {name!r}")
        if role not in (SITE, RENDEZVOUS):
            raise ValueError(f"role must be {SITE!r} or {RENDEZVOUS!r}")
        if not (name or "").strip():
            raise ValueError("a node needs a name, and it must match its Log.node")
        return self.log.append(
            "node.registered",
            {"name": name.strip(), "site": site, "role": role,
             "reach": reach, "note": note},
            subject=name.strip(), actor=ROSS,
        )

    def retire(self, node_id: str, *, reason: str = "", by: str = ROSS) -> dict:
        """Stop trusting a machine.

        Its past events stay - they are history, and history does not stop
        being true because a machine was decommissioned. What stops is
        absorbing anything new from it.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross retires a node; {by!r} tried to")
        return self.log.append(
            "node.retired", {"node": node_id, "reason": reason},
            subject=node_id, actor=ROSS,
        )

    def seen(self, name: str, *, high_water: dict | None = None) -> dict:
        """Note that a peer answered. Cheap liveness, written as a fact."""
        return self.log.append(
            "node.seen", {"name": name, "high_water": high_water or {}},
            subject=name,
        )

    # ---- reading ---------------------------------------------------------

    def all(self, *, include_retired: bool = False) -> list[Node]:
        rows: dict[str, Node] = {}
        retired: set[str] = set()
        for ev in self.log.replay(kind="node.*"):
            b = ev["body"]
            if ev["kind"] == "node.retired":
                retired.add(b["node"])
            elif ev["kind"] == "node.registered":
                rows[ev["id"]] = Node(
                    id=ev["id"], name=b["name"], site=b["site"], role=b["role"],
                    reach=b.get("reach", ""), note=b.get("note", ""), enrolled=ev["ts"],
                )
        out = []
        for nid, n in rows.items():
            n.retired = nid in retired
            if n.retired and not include_retired:
                continue
            out.append(n)
        out.sort(key=lambda n: (n.role != RENDEZVOUS, n.name))
        return out

    def named(self, name: str) -> Node | None:
        for n in self.all():
            if n.name == name:
                return n
        return None

    def trusted(self) -> set[str]:
        """Chain names we will absorb. Everything else is somebody's invention."""
        return {n.name for n in self.all()}

    def behind(self, peer_high_water: dict[str, int]) -> dict[str, int]:
        """How many rows we are missing on each chain, per the peer's marks."""
        mine = self.log.high_water()
        gaps = {}
        for node, their in peer_high_water.items():
            ours = mine.get(node, 0)
            if their > ours:
                gaps[node] = their - ours
        return gaps

    # ---- the protocol ----------------------------------------------------

    def sync_from(self, peer: Log, *, peer_name: str = "",
                  trust_unknown: bool = False) -> SyncReport:
        """Pull everything this peer has that we do not.

        Walks every chain the peer holds, so a relayed chain arrives even when
        its own node is unreachable. Each chain is absorbed in seq order, which
        keeps contiguity intact - the property verify() depends on.

        A chain from a node Ross has not registered is refused by default. That
        is the check that stops a compromised peer inventing 'node: audit' and
        having us replay its grants as though a fourth site existed.
        """
        name = peer_name or peer.node
        known = self.trusted()
        report = SyncReport(peer=name, taken=0, chains={}, refused=[])
        mine = self.log.high_water()

        for chain, their_max in sorted(peer.high_water().items()):
            if chain == self.log.node:
                # Our own chain, coming back at us. Never absorbed - store.py
                # refuses it outright - and not an error either: a peer holding
                # our events is the sync working.
                continue
            if chain not in known and not trust_unknown:
                report.refused.append(f"{chain} is not a registered node")
                continue
            ours = mine.get(chain, 0)
            if their_max <= ours:
                continue
            rows = peer.since(chain, ours)
            try:
                took = self.log.absorb(rows)
            except ValueError as e:
                # One bad chain must not stop the others. A forked or forged
                # chain is exactly the thing worth reporting rather than
                # swallowing, and the honest handling is to leave it alone and
                # tell Ross.
                report.refused.append(f"{chain}: {e}")
                continue
            if took:
                report.chains[chain] = took
                report.taken += took

        self.seen(name, high_water=peer.high_water())
        return report

    def health(self) -> str:
        """What Ross reads when he wants to know whether the sites are talking."""
        marks = self.log.high_water()
        lines = []
        for n in self.all():
            tag = "RENDEZVOUS" if n.role == RENDEZVOUS else "site"
            here = " (this machine)" if n.name == self.log.node else ""
            lines.append(f"  {n.name:10} {marks.get(n.name, 0):>7} events  "
                         f"{tag:11} {n.site}{here}")
        strays = sorted(set(marks) - self.trusted())
        if strays:
            lines.append("")
            for s in strays:
                lines.append(f"  !! {s}: {marks[s]} events from an UNREGISTERED node")
        return "\n".join(lines) or "  no nodes registered"
