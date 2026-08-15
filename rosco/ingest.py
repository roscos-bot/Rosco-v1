"""Ingestion, one item at a time — so Ross always knows what is being learned.

The old path (knowledge.ingest_text) split a doc into chunks and wrote every one
straight into a business as a TOLD lesson. Fast, but blind: it once stored a bare
Google Sheets URL as a "fact" about the personal business, because nobody looked.

This is the reviewed path. A doc is broken into candidate items; Rosco PROPOSES a
home for each (which business, how sure, why); Ross walks them one by one and
either accepts the proposal or sends it elsewhere - or skips it entirely. Only on
'ingest' is anything actually learned, and that write is the same SIGNED
vault.learned as before: nothing enters a business's memory without Ross's key.

WHY THE PROPOSAL IS NOT THE DECISION. A proposal is a NODE fact - Rosco's guess,
attacker-shaped in principle, granting nothing. The decision is Ross's, and the
knowledge write it triggers needs his signature. So the worst a bad proposal can
do is waste one glance; it can never plant a lesson.

LEARNING TO PLACE ITSELF. Every decision records whether Ross accepted the
proposed business unchanged. readiness() folds that into an accuracy the console
watches: once Rosco has been right often enough, recently enough, it has earned
the right to offer to auto-place the rest - "until it knows best where to put
what." Until then, every item waits for a human glance.
"""
from __future__ import annotations

import secrets as _secrets

from . import knowledge
from .vault import TOLD, Vault


def chunk(text: str) -> list[str]:
    """The candidate items in a pasted doc - reuse the one splitter."""
    return knowledge._chunks(text or "")


class Ingest:
    """The review queue over the append-only log. No state of its own."""

    def __init__(self, log, vault: Vault | None = None) -> None:
        self.log = log
        self.vault = vault

    # ---- writing ---------------------------------------------------------

    def add(self, items: list[dict], *, source: str = "paste",
            by: str = "rosco") -> int:
        """Queue routed candidates. Each item: {text, business, confidence, why}.
        A NODE write - a proposal, not a lesson. Blank items are dropped."""
        n = 0
        for it in items:
            text = (it.get("text") or "").strip()
            if not text:
                continue
            cand = _secrets.token_hex(4)
            biz = (it.get("business") or "").strip()
            try:
                conf = max(0.0, min(1.0, float(it.get("confidence", 0) or 0)))
            except (TypeError, ValueError):
                conf = 0.0
            self.log.append(
                "ingest.proposed",
                {"cand": cand, "text": text[:20000], "source": source,
                 "business": biz, "confidence": conf,
                 "why": (it.get("why") or "")[:200],
                 "summary": (it.get("summary") or "")[:240]},
                subject=source or "paste", actor=by)
            n += 1
        return n

    # ---- reading ---------------------------------------------------------

    def _decided_ids(self) -> set:
        out = set()
        for ev in self.log.replay(kind="ingest.decided"):
            c = ev["body"].get("cand")
            if c:
                out.add(c)
        return out

    def _proposals(self) -> dict:
        """cand -> its proposal body. Read defensively - a NODE body is untrusted."""
        out = {}
        for ev in self.log.replay(kind="ingest.proposed"):
            b = ev["body"]
            c = b.get("cand")
            if c:
                out[c] = b
        return out

    def pending(self) -> list[dict]:
        """Candidates still waiting on a glance, oldest first."""
        decided = self._decided_ids()
        out = []
        for ev in self.log.replay(kind="ingest.proposed"):
            b = ev["body"]
            c = b.get("cand")
            if not c or c in decided:
                continue
            out.append({"cand": c, "text": b.get("text", ""),
                        "source": b.get("source", ""),
                        "business": b.get("business", ""),
                        "confidence": b.get("confidence", 0),
                        "why": b.get("why", ""),
                        "summary": b.get("summary", "")})
        return out

    # ---- deciding --------------------------------------------------------

    def decide(self, cand: str, business: str, action: str, *,
               by: str = "ross") -> dict:
        """Ross's call on one item. 'ingest' learns the text into `business` (a
        SIGNED vault.learned via the captain); 'skip' just clears it. Either way
        a NODE ingest.decided records whether the proposal was accepted unchanged
        - the signal readiness() reads."""
        if action not in ("ingest", "skip"):
            raise ValueError("action must be ingest or skip")
        prop = self._proposals().get(cand)
        if prop is None:
            raise ValueError(f"unknown candidate {cand!r}")
        if cand in self._decided_ids():
            raise ValueError("that item was already decided")
        business = (business or "").strip()
        accepted = bool(action == "ingest" and business
                        and business == prop.get("business"))
        if action == "ingest":
            captain = knowledge._captain(business)
            if captain is None:
                raise ValueError(f"unknown business {business!r}")
            if self.vault is None:
                raise RuntimeError("no vault - cannot learn (open with the key)")
            self.vault.learn(captain, business, prop.get("text", ""),
                             basis=TOLD, source=prop.get("source", "ingest"))
        self.log.append(
            "ingest.decided",
            {"cand": cand, "action": action, "business": business,
             "proposed": prop.get("business", ""), "accepted": accepted},
            subject=business or prop.get("source", "ingest"), actor=by)
        return {"ok": True, "accepted": accepted}

    def clear_pending(self, *, by: str = "ross") -> int:
        """Skip every still-pending candidate at once - a queue reset.

        Each gets a NODE ingest.decided(action='skip'), so nothing is learned and
        the proposals stay on the append-only log as history; they just leave the
        pending view. This is the way to wipe a batch that was split badly (e.g.
        headings orphaned from their bodies) and re-ingest the doc cleanly.
        """
        n = 0
        for item in self.pending():
            self.log.append(
                "ingest.decided",
                {"cand": item["cand"], "action": "skip", "business": "",
                 "proposed": item.get("business", ""), "accepted": False},
                subject=item.get("source", "ingest"), actor=by)
            n += 1
        return n

    # ---- how good is Rosco getting at this? ------------------------------

    def readiness(self) -> dict:
        """Routing accuracy, and whether Rosco has earned an auto-place offer.

        Only 'ingest' decisions where a proposal actually existed count - a skip
        or a manual placement with no proposal is not a hit or a miss. Confident
        means a solid recent streak on a decent sample; deliberately not a single
        lucky guess."""
        total = 0
        accepted = 0
        recent = []
        for ev in self.log.replay(kind="ingest.decided"):
            b = ev["body"]
            if b.get("action") != "ingest" or not b.get("proposed"):
                continue
            total += 1
            hit = bool(b.get("accepted"))
            accepted += 1 if hit else 0
            recent.append(hit)
        recent = recent[-10:]
        rate = accepted / total if total else 0.0
        recent_rate = sum(recent) / len(recent) if recent else 0.0
        confident = total >= 8 and recent_rate >= 0.8
        return {"decided": total, "accepted": accepted,
                "rate": round(rate, 2), "recentRate": round(recent_rate, 2),
                "confident": confident, "pending": len(self.pending())}
