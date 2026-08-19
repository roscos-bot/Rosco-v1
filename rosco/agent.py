"""An agent that does a business's work - and can be watched doing it.

The roster says who the agents are; this is what one of them IS when it runs.
Built general, so any roster entry becomes an agent, and demonstrated first as
Bessemer for SteelHaven.

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


def _strip_toolcalls(text: str) -> str:
    """Remove any native tool-call markup a model leaked into its reply.

    grok (xai) emits <xai:function_call name="web_search">…</xai:function_call> as
    TEXT when it wants a tool this system doesn't wire — Rosco drives side effects
    through the ACTION protocol, not native tool-calls, so that markup is garbage
    in the reply. Strip whole blocks, then any stray tags left by a truncated one.
    """
    t = re.sub(r"<[\w:]*function_call\b.*?</[\w:]*function_call>", "", text or "",
               flags=re.S | re.I)
    t = re.sub(r"</?[\w:]*(?:function_call|tool_call|parameter|invoke|antml)\b[^>]*>",
               "", t, flags=re.I)
    return re.sub(r"\n{3,}", "\n\n", t).strip()


# When an agent grounds, inject only the lessons relevant to the task at hand, up
# to this many characters — not the whole vault. Rosco (business '*') reads across
# everything, so once its own code is ingested the vault is large; dumping all of
# it into every prompt would blow the context window and the bill. A small vault
# fits under the cap and is untouched; the cap only bites once there's a lot.
GROUNDING_CAP = 12000


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
        """What this agent can ground on: its business's shared knowledge.

        The silo is the BUSINESS, not the individual - see vault.py. A lesson
        belongs to 'rum', and every RUM agent stands on the same corpus: the
        captain AND the bench specialists it leans on. So grounding filters by
        business only. Who LEARNED each lesson is kept on the lesson (for
        attribution and the readable per-agent page), but it is never a wall
        between a captain and its own bench - a wall there would leave a
        delegated specialist blind, grounding on nothing, because the starter
        facts are all seeded under the captain's name.

        Rosco (business '*') is the one agent that reads across everything - the
        chief-of-staff enrichment role from the design - so it grounds on the
        whole vault rather than a single business's slice.
        """
        if self.business == "*":
            return self.vault.recall()
        return self.vault.recall(business=self.business)

    def _relevant(self, lessons, query, cap: int = GROUNDING_CAP):
        """The lessons most worth grounding on for THIS query, up to a char budget.

        Ranking is delegated to the vault (FTS5 BM25 x trust basis, with a lexical
        fallback) - an indexed, length-normalised ranked query rather than an
        O(lessons x terms) substring scan (see Vault.rank for what that does and
        doesn't buy - it's better lexical ranking, not semantic search). With no
        useful query terms it degrades to trust-order (told first), so even a vague
        ask grounds on the firmest facts rather than nothing. A vault that fits under
        the cap is returned whole - this only prunes once there's a lot (e.g.
        ingested code).
        """
        if not lessons or sum(len(l.text) for l in lessons) <= cap:
            return lessons
        out, used = [], 0
        for l in self.vault.rank(lessons, query):
            out.append(l)
            used += len(l.text)
            if used >= cap:
                break
        return out

    def _system(self, lessons) -> str:
        told = [l for l in lessons if l.basis == TOLD]
        rest = [l for l in lessons if l.basis != TOLD]

        def fmt(l):
            # Every lesson is a GIST. If it names where it came from, cite that so
            # this agent - or another it's helping - can pull the full source for
            # detail instead of trusting the shorthand alone. This is the hook that
            # makes compact knowledge sharable between agents without bloat.
            src = (l.source or "").strip()
            cite = (f"   [from {src} — fetch it for the full detail]"
                    if src.split(":")[0] in ("drive", "gh", "github", "url") else "")
            return f"  - {l.text}{cite}"

        lines = [
            f"You are {self.name}, the agent for {self.business}. Rank: {self.rank}.",
            "You do this business's work and nothing else. You draft and propose;",
            "you never publish, send, or ship - a person does that.",
            "",
            "What you know is kept as GISTS. A lesson that cites a source (drive:/gh:)",
            "is shorthand — go re-read that source when you need more than the gist.",
            "",
            "What you have been TOLD (treat as firm):",
        ]
        lines += [fmt(l) for l in told] or ["  - (nothing yet)"]
        if rest:
            lines.append("")
            lines.append("What you have observed or worked out:")
            lines += [fmt(l) for l in rest]
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
        lessons = self._relevant(self.knows(), question)
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
                "\n\nWHAT YOU ARE: You are Rosco, running INSIDE the Rosco console — a "
                "private dashboard on Ross's own machine. The neural-net graph, the "
                "'waiting on you' queue, and this chat are all you. When Ross says "
                "'this dashboard', 'the console', 'rosco', or 'rosco_v1', he means THIS "
                "system — your own code, in the repo roscos-bot/Rosco-v1. You are not a "
                "generic chatbot; you have no separate 'instructions' or Google Sheet to "
                "consult. When he asks, you read his Google (Gmail, Drive, Calendar, "
                "Sheets, Contacts, Chat) and his GitHub repos live, and you can draft an "
                "email or propose a calendar event or a pull request — but you never "
                "send, post, or merge on your own; that stays his call.\n"
                "\nYOUR OWN CODE: the whole system is Python plus a single-page, plain-"
                "JavaScript console. There is NO React, NO TypeScript, no components, no "
                ".tsx/.jsx files and no 'src/components' folder — never invent one. The UI "
                "is exactly two files: web_app.html (markup + CSS) and web_app.js (ALL UI "
                "logic — the graph, the node panel, settings, ingest, chat). The graph's "
                "node panel is the showNode function in web_app.js. The backend is Python "
                "under rosco/: web.py (server + endpoints), ingest.py, knowledge.py "
                "(captains + lessons), models.py, store.py, agent.py (this), adapters/. So "
                "a UI change is almost always web_app.js and/or web_app.html — never a "
                "component file. When code comes up, the repo's REAL file tree is given to "
                "you in LIVE DATA below; read filenames from THAT. If you don't have a "
                "file's contents yet, don't guess a name — say so and ask to read the exact "
                "path (e.g. 'read rosco/web_app.js'). For a big multi-file edit it's fair "
                "to say Claude Code in Ross's terminal is the surer path and offer to tee "
                "it up, rather than drafting a whole file blind.\n"
                "\nHOW YOU TALK — this is your voice with Ross:\n"
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
                "- You get the live data WITH the question (his mail, drive, calendar are "
                "fetched for the current turn when relevant, and shown as LIVE DATA). So "
                "when he asks you to pull/list something, DO it and answer in THIS reply "
                "from that data — never say 'say go and I'll pull it' and defer a read you "
                "can do now, and never reply with an empty '...'.\n"
                "- Warm and on his side, never chatty for its own sake.\n"
                "- Don't over-assume — he has told you that you can be a little too "
                "assumptive. When you're inferring what he wants, name the assumption "
                "and check it in a line instead of barreling ahead; but when a choice "
                "is small and has an obvious default, just make it and say what you did.\n"
                "\nTwo more things, quietly — never as a routine you announce, and "
                "NOT a read-back of their goal on every reply:\n"
                "1) If the person corrects you about how they work or what their words "
                "mean, take it in stride, then on its OWN line write one or more "
                "'LEARN: <one durable, reusable sentence to remember next time>'. Only "
                "for a genuine, reusable correction - never a one-off detail, and "
                "nothing at all if nothing was corrected.\n"
                "2) If they ask you to DO a writeable thing - draft/send an email, "
                "add a calendar event, post to a Google Chat space - NEVER claim you "
                "did it. Compose it in the reply, then on its OWN line emit exactly "
                "one JSON action the system will carry out:\n"
                "ACTION: {\"type\":\"gmail_draft\",\"to\":\"\",\"subject\":\"\",\"body\":\"\",\"reply_to_email\":<the list number they named, or omit>}\n"
                "ACTION: {\"type\":\"calendar_create\",\"summary\":\"\",\"start\":\"<local datetime like 2026-08-19T15:00:00, no offset>\",\"end\":\"<same>\",\"location\":\"\"}\n"
                "ACTION: {\"type\":\"calendar_series\",\"events\":[{\"summary\":\"\",\"start\":\"<local datetime>\",\"end\":\"<same>\",\"location\":\"\"}, ...]}  — a WHOLE set of events at once (e.g. a biweekly plan), confirmed together. Use this instead of many calendar_create when they want a recurring/multi-date plan; give every date explicitly in `events`.\n"
                "ACTION: {\"type\":\"chat_post\",\"space\":\"<space display name>\",\"text\":\"\"}\n"
                "ACTION: {\"type\":\"github_pr\",\"repo\":\"<repo name>\",\"path\":\"<file path>\",\"content\":\"<the FULL new file contents>\",\"message\":\"<commit message>\",\"title\":\"<PR title>\"}\n"
                "ACTION: {\"type\":\"ingest\",\"drive\":\"<a Drive file name>\"}  (or \"repo\"+\"path\" for a GitHub file, or \"text\" for a short note)\n"
                "ACTION: {\"type\":\"websearch\",\"query\":\"<concise search terms>\"}  — LOOK IT UP ON THE WEB when you need current or external facts you don't already have (prices, comparables/comps, addresses, who-does-X, how-others-do-it, recent events). Write GOOD SEARCH TERMS drawn from the CONVERSATION — NEVER the person's raw sentence. If they say \"you should have search now\" while you were about to look up venue rates, query \"event venue rental rates Fenton MO 63026\", NOT their message. Results come straight back (with urls to cite) for you to answer from, so ALWAYS reach for this instead of telling someone you can't look something up.\n"
                "ACTION: {\"type\":\"browser\",\"do\":\"navigate\",\"url\":\"...\"}  (or do:\"click\",\"target\":\"<the visible button/link text>\"; or do:\"type\",\"target\":\"<the field's label or placeholder>\",\"text\":\"...\"; or do:\"read\")\n"
                "ACTION: {\"type\":\"image\",\"prompt\":\"<what to depict>\"}  — GENERATE an image via Higgsfield. Use this when they ask you to make/generate/draw/create a picture or image. The system asks them to confirm (it spends), then makes it and shows it in chat. NEVER generate media for SteelHaven (the no-AI-media rule); it's for everything else. (The 'vision' model only READS images you're given; it cannot make one — use this action to create.)\n"
                "ACTION: {\"type\":\"email_watch\",\"state\":\"start\"}  — Ross is ABOUT TO go check his email (in the Gmail app, not here). Emit state:\"start\" when he signals he's starting an email session (\"about to check my email\", \"going through my inbox\", \"checking email now\"), and state:\"stop\" when he signals he's DONE (\"done with email\", \"finished my inbox\", \"all caught up\"). It snapshots his mailbox on start and, on stop, learns from what he actually read / archived / starred so the inbox ranking improves. Read-only on HIS OWN account, runs immediately, no confirm. Only emit it on a clear start/finish signal — never for an ordinary question about email.\n"
                "Use 'browser' when they ask you to open/go to a site or click/type on a "
                "page. EVERY browser step is gated — the system shows it and waits for "
                "their yes, even navigating. One step per reply: propose the next step "
                "only after they confirm the last. NEVER type a password, card number, or "
                "answer a CAPTCHA — say that stays theirs to do by hand.\n"
                "Use 'ingest' when they say ingest/learn/remember a doc: it QUEUES the "
                "content for their one-by-one review (it does NOT learn it directly) — "
                "the system fetches the source, so you don't paste the whole file.\n"
                "A github_pr opens a pull request they merge (you never merge). Give "
                "the COMPLETE new file in 'content' - best for a new or small file; "
                "for a big edit, say what you'd change and let them point you at it.\n"
                "A gmail_draft becomes a DRAFT in their Gmail (you never send); "
                "calendar_create/calendar_series and chat_post the system asks them to "
                "confirm first. Use the current date/time from LIVE DATA to resolve "
                "'Tuesday 3pm'. Only emit an ACTION when they actually asked you to do it.\n"
                "\nNO TOOL-CALLS: you have NO native tools or function-calling. NEVER emit "
                "<function_call>, <xai:function_call>, <tool_call>, <parameter> or any such "
                "markup — none of it runs and it just leaks into your reply as garbage. To "
                "DO something, use an ACTION above. To look up something you don't have "
                "(an address, a fact on the web), say plainly that you can't look it up "
                "yet — don't fake a search.")
        text = _strip_toolcalls((self.think(system, question) or "").strip())
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
        lessons = self._relevant(self.knows(), task)
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
