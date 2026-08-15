"""An agent that does a business's work - and can be watched doing it.

The roster says who the agents are; this is what one of them IS when it runs.
Built general, so any roster entry becomes an agent, and demonstrated first as
HavenMind for SteelHaven.

THE LOOP, and every step is observable:

    GROUND   read what this agent has learned about its business from the vault,
             so it works from what it knows, not from nothing.
    THINK    call the chosen model with the agent's identity, its business, its
             lessons and the task. The model is injected - real via llm.complete,
             or a stub when you want to watch the loop with no key.
    CHECK    run the business's hard guardrails over the draft. For SteelHaven
             these are the ones that cannot be talked out of - never invent a
             statistic, never say radon-free, never mention FORTIFIED, always
             pair a steel claim with continuous insulation. A hit is surfaced,
             not silently shipped.
    LEARN    record what it just did to the vault (basis: observed), so the next
             run is grounded in this one. The agent gets better because it
             remembers, and Ross can read what it concluded.
    PROPOSE  the work is a draft for Ross, never a published thing. An agent
             builds; a person ships. Same rule as GitHub, same rule as the whole
             system.

Nothing here publishes, posts, sends, or spends beyond the model call itself.
The output is a proposal recorded on the log and put where Ross will see it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import roster
from .vault import OBSERVED, TOLD, Vault


@dataclass
class Result:
    agent: str
    business: str
    task: str
    draft: str
    warnings: list = field(default_factory=list)
    grounded_on: int = 0
    proposed: bool = False


# SteelHaven's hard guardrails, the ones the brand-voice work locked. These are
# the deterministic catch behind the model - the model is TOLD them in its
# grounding, and this refuses to let the two catastrophic ones through even if it
# forgets. Other businesses get their own set as they are taught.
_STEELHAVEN_FORBIDDEN = [
    (r"\bfortified\b", "mentions FORTIFIED - off-limits in all copy right now"),
    (r"radon[\s-]*free", "implies radon-free - never claim that"),
]
_STEELHAVEN_STEEL = re.compile(r"\bsteel\b", re.I)
_STEELHAVEN_INSULATION = re.compile(r"insulat", re.I)


class Agent:
    """One agent, able to do a piece of its business's work.

    `think(system, user) -> str` is the model. Inject the real one
    (llm.complete bound to the chosen model) in production, or a stub to watch
    the loop offline - the same shape the doorway uses for its classifier.
    """

    def __init__(self, name: str, log, *, think, meter=None) -> None:
        ent = roster.find(name)
        if ent is None:
            raise ValueError(f"no agent named {name!r} in the roster")
        self.name = ent.name
        self.rank = ent.rank
        self.business = ent.business
        self.log = log
        self.vault = Vault(log)
        self.think = think
        self.meter = meter

    # ---- grounding -------------------------------------------------------

    def knows(self):
        """What this agent has learned about its business. Its grounding."""
        return self.vault.recall(business=self.business, agent=self.name)

    def _system(self, lessons) -> str:
        told = [l for l in lessons if l.basis == TOLD]
        rest = [l for l in lessons if l.basis != TOLD]
        lines = [
            f"You are {self.name}, the agent for {self.business}. Rank: {self.rank}.",
            "You do this business's work and nothing else. You draft and propose;",
            "you never publish, send, or ship - a person does that.",
            "",
            "What you have been TOLD (treat as firm):",
        ]
        lines += [f"  - {l.text}" for l in told] or ["  - (nothing yet)"]
        if rest:
            lines.append("")
            lines.append("What you have observed or worked out:")
            lines += [f"  - {l.text}" for l in rest]
        return "\n".join(lines)

    # ---- guardrails ------------------------------------------------------

    def _check(self, draft: str) -> list[str]:
        warns = []
        if self.business == "steelhaven":
            low = draft.lower()
            for pat, why in _STEELHAVEN_FORBIDDEN:
                if re.search(pat, low):
                    warns.append(why)
            if _STEELHAVEN_STEEL.search(draft) and not _STEELHAVEN_INSULATION.search(draft):
                warns.append("a steel claim with no mention of continuous insulation - "
                             "steel conducts, so always pair the two")
        return warns

    # ---- the loop --------------------------------------------------------

    def work(self, task: str, *, narrate=lambda s: None) -> Result:
        narrate(f"{self.name} · {self.business} — taking the task")
        lessons = self.knows()
        narrate(f"  grounding on {len(lessons)} lesson(s) from the vault")

        narrate("  thinking with the model…")
        draft = (self.think(self._system(lessons), task) or "").strip()
        narrate(f"  drafted {len(draft)} characters")

        warnings = self._check(draft)
        if warnings:
            for w in warnings:
                narrate(f"  !! guardrail: {w}")
        else:
            narrate("  guardrails: clean")

        # Learn from having done it. Observed, not told - the agent watched
        # itself do this; it is not Ross's word.
        self.vault.learn(self.name, self.business,
                         f"Handled: {task[:80]}"
                         + (f" ({len(warnings)} guardrail flag(s))" if warnings else ""),
                         basis=OBSERVED, source=self.name)
        narrate("  recorded what it did to the vault")

        # Propose, never ship. The draft is a fact on the log for Ross to act on.
        self.log.append("agent.produced",
                        {"agent": self.name, "business": self.business,
                         "task": task[:200], "warnings": warnings,
                         "chars": len(draft)},
                        subject=self.business, actor=self.name)
        narrate("  proposed to Ross — not published")

        return Result(agent=self.name, business=self.business, task=task,
                      draft=draft, warnings=warnings, grounded_on=len(lessons),
                      proposed=True)


# The real brand facts, as SteelHaven lessons - the ingest that grounds
# HavenMind. Told by Ross (they are firm), so seeding them needs his key.
STEELHAVEN_FACTS = [
    "PermaHaven is the hero: a patent-pending, factory-panelized, 100% cold-formed-steel building SYSTEM - not a construction method. Assemblies arrive factory-built; no field framing.",
    "The core angle is cold-formed steel vs. wood: steel avoids rot, termites, mold, warping, fire and storm failure. Tagline: Steel-Strong, Smart-Secure.",
    "Real proof points, safe to cite: measured ~2.9 ACH50 blower-door, 0.3 pCi/L radon at The Duo (EPA action level is 4.0), R6 continuous exterior insulation, noncombustible CFS framing, documented QA.",
    "The Second Price(TM): purchase price vs. lifetime cost of ownership - first-time buyers' #1 fear is hidden post-purchase cost. Strongest differentiated lane.",
    "Audience: first-time buyers in the St. Louis metro and Midwest, people overlooked by the housing market. Voice: warm, plain-spoken, on the buyer's side - the honest ally, not a salesman.",
    "Never invent statistics. Never imply a home is radon-free. Do NOT mention FORTIFIED at all right now. Always pair a steel claim with continuous exterior insulation (steel conducts ~300-400x wood).",
    "Never use AI-generated media - it reads as fake and kills trust. Real jobsite photos and B-roll only.",
]


def seed_steelhaven(vault: Vault) -> int:
    """Teach HavenMind SteelHaven. Told by Ross - needs his key on the log."""
    for fact in STEELHAVEN_FACTS:
        vault.learn("HavenMind", "steelhaven", fact, basis=TOLD, source="ross")
    return len(STEELHAVEN_FACTS)
