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


# The autonomy ladder. Rosco earns a rung by getting placements right in a row;
# a single wrong one snaps the streak (see readiness) and can drop it back. The
# names are what Ross reads; the gates are computed purely from the review
# history already tracked - no new telemetry. Entry needs a real sample first
# (a few decided) so one lucky guess never vaults it up the ladder. The top rung
# only ever automates the SAFE, REVERSIBLE, INTERNAL act (placing a lesson);
# nothing outbound, destructive or spending is ever automated at any rung.
STAGES = ("learning", "crawling", "walking", "running", "auto")
# stage -> (min streak, min DISTINCT businesses placed correctly, must be 'confident').
# The distinct-business gate is the anti-gaming rule: a 40-long streak of a bulk
# repo dumped into ONE bucket proves volume, not judgement. Earning the upper
# rungs takes correctly sorting items across SEVERAL real businesses - the actual
# skill the autonomy would exercise. Discernment, not a monotone pile.
_STAGE_GATE = {
    "learning": (0, 0, False), "crawling": (2, 1, False), "walking": (5, 2, False),
    "running": (10, 3, True), "auto": (20, 4, True)}
_MIN_SAMPLE = 3                     # decisions before anything above 'learning'


def _stage_for(streak: int, decided: int, distinct: int,
               confident: bool) -> tuple[str, str]:
    """(stage, one-line 'what earns the next rung'). The highest rung whose gate
    - streak AND business-variety AND (for the top two) recent accuracy - is met."""
    reached = "learning"
    for name in STAGES:
        min_s, min_d, need_c = _STAGE_GATE[name]
        if name != "learning" and decided < _MIN_SAMPLE:
            break
        if streak >= min_s and distinct >= min_d and (confident if need_c else True):
            reached = name
        else:
            break
    i = STAGES.index(reached)
    if i == len(STAGES) - 1:
        return reached, "top rung - Rosco may pre-place routine items; you still see every one"
    nxt = STAGES[i + 1]
    if decided < _MIN_SAMPLE:
        return reached, f"place {_MIN_SAMPLE - decided} more to get going"
    min_s, min_d, need_c = _STAGE_GATE[nxt]
    needs = []
    if streak < min_s:
        needs.append(f"{min_s - streak} more right in a row")
    if distinct < min_d:
        needs.append(f"correct placements in {min_d - distinct} more business(es)")
    if need_c and not confident:
        needs.append("a solid recent rate")
    if not needs:
        return reached, f"one more clean batch to reach {nxt}"
    return reached, " + ".join(needs) + f" to reach {nxt}"


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
            ref = it.get("ref")
            self.log.append(
                "ingest.proposed",
                {"cand": cand, "text": text[:8000], "source": source,
                 "business": biz, "confidence": conf,
                 "why": (it.get("why") or "")[:200],
                 "summary": (it.get("summary") or "")[:1200],   # the shorthand — what gets learned
                 "kind": (it.get("kind") or "").strip()[:20],   # email|doc|code|… drives the card's verbs
                 "ref": ref if isinstance(ref, dict) else {}},   # the handle to act on (gmail id+account, …)
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
                        "summary": b.get("summary", ""),
                        "kind": b.get("kind", ""),
                        "ref": b.get("ref") if isinstance(b.get("ref"), dict) else {}})
        return out

    def ref_of(self, cand: str) -> dict:
        """The stored kind + actionable handle for a candidate — what the email
        (and later calendar/chat) verbs need to touch the real object."""
        p = self._proposals().get(cand) or {}
        return {"kind": p.get("kind", ""), "source": p.get("source", ""),
                "ref": p.get("ref") if isinstance(p.get("ref"), dict) else {}}

    def acted(self, cand: str, action: str, *, by: str = "ross") -> dict:
        """Record a NON-learning decision on an item (an email tidy verb like
        archive/trash, a reference-keep) so the card clears and the act is on the
        log. Deliberately NOT a placement: proposed='' means readiness ignores it,
        so processing your inbox never moves the routing ladder."""
        prop = self._proposals().get(cand)
        if prop is None:
            raise ValueError(f"unknown candidate {cand!r}")
        if cand in self._decided_ids():
            raise ValueError("that item was already decided")
        return self.log.append(
            "ingest.decided",
            {"cand": cand, "action": action, "business": "",
             "proposed": "", "accepted": False},
            subject=prop.get("source", "ingest"), actor=by)

    def text_of(self, cand: str) -> str:
        """The raw text queued for a candidate - so a shorthand can be distilled
        from it at decide time when the card didn't carry one."""
        return (self._proposals().get(cand) or {}).get("text", "")

    # ---- deciding --------------------------------------------------------

    def decide(self, cand: str, business: str, action: str, *,
               by: str = "ross", learn_text: str | None = None,
               proposed: str | None = None) -> dict:
        """Ross's call on one item. 'ingest' LEARNS a distilled shorthand into
        `business` (a SIGNED vault.learned via the captain), NOT the raw doc -
        ingesting means understanding it and keeping a compact form, not dumping
        the source into the vault. The shorthand is `learn_text` (what the card
        showed as 'reads as'), falling back to the stored summary, and only to the
        raw text if there is no shorthand at all. 'skip' just clears it. Either
        way a NODE ingest.decided records whether the proposal was accepted
        unchanged - the signal readiness() reads.

        `proposed` is what Rosco ACTUALLY suggested for this item at decision
        time. The batch-review preview re-routes each item and shows a fresh
        suggestion, so scoring the acceptance against the stale queue-time
        proposal (blank for triage/drive-bulk, hard-'system' for github-bulk)
        wrongly excluded every bulk placement from the trust ladder. When the
        caller passes the previewed suggestion, `accepted`/readiness compare
        against what Ross was actually shown; a manual one-at-a-time decide passes
        nothing and falls back to the stored proposal, as before."""
        if action not in ("ingest", "skip"):
            raise ValueError("action must be ingest or skip")
        prop = self._proposals().get(cand)
        if prop is None:
            raise ValueError(f"unknown candidate {cand!r}")
        if cand in self._decided_ids():
            raise ValueError("that item was already decided")
        business = (business or "").strip()
        suggested = prop.get("business", "") if proposed is None else (proposed or "")
        accepted = bool(action == "ingest" and business
                        and business == suggested)
        if action == "ingest":
            captain = knowledge._captain(business)
            if captain is None:
                raise ValueError(f"unknown business {business!r}")
            if self.vault is None:
                raise RuntimeError("no vault - cannot learn (open with the key)")
            lesson = ((learn_text or "").strip()
                      or prop.get("summary", "").strip()
                      or prop.get("text", "")[:400])   # last resort: a snippet, never the whole raw source
            self.vault.learn(captain, business, lesson,
                             basis=TOLD, source=prop.get("source", "ingest"))
        self.log.append(
            "ingest.decided",
            {"cand": cand, "action": action, "business": business,
             "proposed": suggested, "accepted": accepted},
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
        hits = []
        placed = []                     # businesses of ACCEPTED placements, in order
        for ev in self.log.replay(kind="ingest.decided"):
            b = ev["body"]
            if b.get("action") != "ingest" or not b.get("proposed"):
                continue
            ok = bool(b.get("accepted"))
            hits.append(ok)
            if ok:
                placed.append(b.get("business", ""))
        total = len(hits)
        accepted = sum(hits)
        # Discernment: how many DISTINCT businesses the recent accepted placements
        # spanned. This is what the upper rungs gate on, so a bulk pile into one
        # bucket can't buy autonomy over the real, varied sorting task.
        distinct = len(set(b for b in placed[-20:] if b))
        recent = hits[-10:]
        rate = accepted / total if total else 0.0
        recent_rate = sum(recent) / len(recent) if recent else 0.0
        # The trust streak: consecutive right placements at the tail. It sets how
        # many Rosco may place in one reviewed batch — start at 1, widen as it
        # keeps getting them right, snap back the moment it's wrong (a miss zeroes
        # the streak). Earn the bigger batches; never granted blind.
        streak = 0
        for h in reversed(hits):
            if not h:
                break
            streak += 1
        next_batch = (1 if streak < 1 else 2 if streak < 2 else 5 if streak < 5
                      else 10 if streak < 10 else 20 if streak < 20 else 40)
        confident = total >= 8 and recent_rate >= 0.8
        stage, to_next = _stage_for(streak, total, distinct, confident)
        return {"decided": total, "accepted": accepted,
                "rate": round(rate, 2), "recentRate": round(recent_rate, 2),
                "confident": confident, "streak": streak, "nextBatch": next_batch,
                "pending": len(self.pending()), "distinct": distinct,
                "stage": stage, "stageIndex": STAGES.index(stage),
                "stages": list(STAGES), "toNext": to_next}
