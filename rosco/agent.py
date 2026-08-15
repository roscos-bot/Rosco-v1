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
import unicodedata
from dataclasses import dataclass, field

from . import knowledge, roster
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


def _squeeze(text: str) -> str:
    """Unicode-normalised, letters/digits only - the form 'forbid' rules match on.

    So "FORT­IFIED", "f o r t i f i e d", "radon-free", "radon​free" and the like
    cannot walk past a naive word-boundary regex. An audit showed the first
    version was evadable exactly that way.
    """
    norm = unicodedata.normalize("NFKD", text or "").lower()
    return re.sub(r"[^a-z0-9]+", "", norm)


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
        """What this agent has learned about its business. Its grounding.

        Rosco (business '*') is the one agent that reads across everything - the
        chief-of-staff enrichment role from the design - so it grounds on the
        whole vault rather than a single business's slice. Every other agent sees
        only its own business, which is the silo.
        """
        if self.business == "*":
            return self.vault.recall()
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
        """The business's hard guardrails, from knowledge.py - data, not code.

        Every business's rules run the same way, so a new one is an entry in
        knowledge.KNOWLEDGE, never a branch here.
        """
        warns = []
        squeezed = _squeeze(draft)
        for rule in knowledge.guardrails(self.business):
            if rule[0] == "forbid" and rule[1] in squeezed:
                warns.append(rule[2])
            elif rule[0] == "pair" and re.search(rule[1], draft, re.I) \
                    and not re.search(rule[2], draft, re.I):
                warns.append(rule[3])
        return warns

    # ---- answering a read ------------------------------------------------

    def answer(self, question: str, *, for_person: str = "", context: str = "",
               history: str = "", confirm_intent: bool = False,
               narrate=lambda s: None) -> str:
        """Compose a direct answer to a read request. Grounds, thinks, replies.

        This is the read half of fulfilment - the doorway calls it when an
        allowed GET arrives. It never acts: it answers from what the agent knows
        and what the model composes, and records that it answered. `context` is
        live data a connector fetched for this turn (recent Drive files, inbox,
        calendar) - real and current, so the agent answers FROM it rather than
        saying it cannot look things up. `history` is the recent conversation for
        continuity; `confirm_intent` turns on the read-back-and-learn behaviour
        the console chat uses.
        """
        narrate(f"{self.name} answering for {self.business}")
        lessons = self.knows()
        system = (self._system(lessons) +
                  "\n\nAnswer the person directly and briefly. If you would need "
                  "to look something up that you do not have, say so plainly.")
        if history:
            system += ("\n\nRECENT CONVERSATION so far (oldest first) - the person's "
                       "newest message is what you are answering now:\n" + history)
        if context:
            system += ("\n\nLIVE DATA fetched for this question just now - it is "
                       "real and current, answer FROM it and cite specifics:\n"
                       + context)
        if confirm_intent:
            system += (
                "\n\nHOW YOU TALK — this is your voice with Ross:\n"
                "- Plain and direct: short sentences, real words, no corporate filler "
                "and no hedging for its own sake.\n"
                "- Lead with the answer or the point, THEN the why — never bury it "
                "under preamble or a wind-up.\n"
                "- Confident but honest: if you don't know, say so; if you were wrong, "
                "say so plainly and fix it.\n"
                "- Be a step ahead: name the obvious next move, flag a problem you "
                "notice, and when there's a clear best option recommend it rather than "
                "laying out every choice.\n"
                "- Structure only when it earns its keep (a short list, one bolded key "
                "line); don't over-format a plain answer.\n"
                "- Warm and on his side, never chatty for its own sake.\n"
                "- Don't over-assume — he has told you that you can be a little too "
                "assumptive. When you're inferring what he wants, name the assumption "
                "and check it in a line instead of barreling ahead; but when a choice "
                "is small and has an obvious default, just make it and say what you did.\n"
                "\nAfter answering, also do these:\n"
                "1) In ONE short, natural line, say what you take the person to be "
                "trying to accomplish and invite a correction - e.g. \"Sounds like "
                "you're trying to <goal> - tell me if I've got that wrong.\" Keep it "
                "human and vary the wording; never a rote template.\n"
                "2) If this message CORRECTS a goal you read wrong earlier in the "
                "conversation, acknowledge it in a clause, then on their own separate "
                "lines write one or more 'LEARN: <one durable, reusable sentence to "
                "remember next time>'. Only for a genuine, reusable correction about "
                "how this person works or what their words mean - never a one-off "
                "detail, and nothing at all if nothing was corrected.\n"
                "3) If they ask you to DO a writeable thing - draft/send an email, "
                "add a calendar event, post to a Google Chat space - NEVER claim you "
                "did it. Compose it in the reply, then on its OWN line emit exactly "
                "one JSON action the system will carry out:\n"
                "ACTION: {\"type\":\"gmail_draft\",\"to\":\"\",\"subject\":\"\",\"body\":\"\",\"reply_to_email\":<the list number they named, or omit>}\n"
                "ACTION: {\"type\":\"calendar_create\",\"summary\":\"\",\"start\":\"<local datetime like 2026-08-19T15:00:00, no offset>\",\"end\":\"<same>\",\"location\":\"\"}\n"
                "ACTION: {\"type\":\"chat_post\",\"space\":\"<space display name>\",\"text\":\"\"}\n"
                "A gmail_draft becomes a DRAFT in their Gmail (you never send); "
                "calendar_create and chat_post the system asks them to confirm first. "
                "Use the current date/time from LIVE DATA to resolve 'Tuesday 3pm'. "
                "Only emit an ACTION when they actually asked you to do it.")
        text = (self.think(system, question) or "").strip()
        # The read path runs the same hard guardrails as a draft. An answer is
        # lower-stakes than published copy, but a FORTIFIED or radon-free claim
        # said to a person is still a claim, so it is flagged in-line rather than
        # slipping out unmarked.
        for w in self._check(text):
            text += f"\n\n[flag: {w}]"
        self.log.append("agent.answered",
                        {"agent": self.name, "business": self.business,
                         "person": for_person, "chars": len(text)},
                        subject=self.business, actor=self.name)
        return text

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
        #
        # It records that it did work and how it went - NOT the raw task text.
        # The task is attacker-controlled (it is the inbound message), and a
        # lesson is read back into the model prompt on the next run; echoing
        # untrusted text into an agent's own grounding is a slow prompt-injection
        # that persists. The count of guardrail flags is the useful signal; the
        # words are not worth the risk.
        self.vault.learn(self.name, self.business,
                         f"Handled a {self.business} task"
                         + (f" - {len(warnings)} guardrail flag(s)" if warnings else
                            " - clean"),
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
