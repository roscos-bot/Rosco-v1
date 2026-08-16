"""What each business knows, as data - so every captain builds out the same way.

Two things live here per business:

  FACTS    starter lessons, told by Ross, that ground the captain when it thinks.
           Modest on purpose - the real corpus comes from ingesting Ross's own
           docs (ingest_text below). These are the floor, not the ceiling.

  GUARDRAILS  the hard, deterministic catches the captain's output must survive -
           the things that cannot be talked out of, per business. SteelHaven's
           are the brand-voice locks; RUM's are ATF/NFA compliance. They are the
           braces behind the model, which is also TOLD them through the facts.

Keeping this as data rather than code is the point: a new business, or a
correction to an old one, is an edit here or a file Ross ingests - never a new
seed_<business>() function to write and wire.

A guardrail rule is a tuple:
    ("forbid", "<squeezed needle>", "<why>")     - needle must not appear
    ("pair",   "<trigger regex>", "<require regex>", "<why>")
                                                 - if trigger appears, require must too
The forbid needle is matched against a squeezed draft (unicode-normalised,
letters/digits only) so spacing and unicode tricks cannot slip it past.
"""
from __future__ import annotations

import re

from . import roster
from .vault import TOLD, Vault

KNOWLEDGE: dict[str, dict] = {
    "steelhaven": {
        "facts": [
            "PermaHaven is the hero: a patent-pending, factory-panelized, 100% cold-formed-steel building SYSTEM - not a construction method. Assemblies arrive factory-built; no field framing.",
            "The core angle is cold-formed steel vs. wood: steel avoids rot, termites, mold, warping, fire and storm failure. Tagline: Steel-Strong, Smart-Secure.",
            "Real proof points, safe to cite: measured ~2.9 ACH50 blower-door, 0.3 pCi/L radon at The Duo (EPA action level is 4.0), R6 continuous exterior insulation, noncombustible CFS framing, documented QA.",
            "The Second Price(TM): purchase price vs. lifetime cost of ownership - first-time buyers' #1 fear is hidden post-purchase cost. Strongest differentiated lane.",
            "Audience: first-time buyers in the St. Louis metro and Midwest, people overlooked by the housing market. Voice: warm, plain-spoken, on the buyer's side - the honest ally, not a salesman.",
            "Never invent statistics. Never imply a home is radon-free. Do NOT mention FORTIFIED at all right now. Always pair a steel claim with continuous exterior insulation (steel conducts ~300-400x wood).",
            "Never use AI-generated media - it reads as fake and kills trust. Real jobsite photos and B-roll only.",
        ],
        "guardrails": [
            ("forbid", "fortif", "mentions FORTIFIED - off-limits in all copy right now"),
            ("forbid", "radonfree", "implies radon-free - never claim that"),
            ("pair", r"\bsteel\b", r"insulat",
             "a steel claim with no mention of continuous insulation - steel conducts, so always pair the two"),
        ],
    },
    "rum": {
        "facts": [
            "Romann Utility Machines (RUM Machines) is a firearms finishing and build house - the rebrand of 4Bush - operating as a Type 07 FFL / Class 3 SOT at 4075 W. Outer Rd.",
            "NFA / Title II items (suppressors, short-barreled rifles, machine guns) require an approved ATF tax stamp before transfer. Never imply otherwise, and never promise a transfer or wait time as a guarantee.",
            "The electronic A&D bound book is the legal record. It stays inside RUM; no other business touches it, and nothing is disposed before it is logged.",
            "Do not give legal advice on NFA eligibility. Explain the process and point customers to their own counsel.",
            "Approvers for RUM work are Ross and Lucas.",
        ],
        "guardrails": [
            ("forbid", "offthebooks", "'off the books' - never, this is an FFL"),
            ("forbid", "nopaperwork", "implies no paperwork - every transfer is logged"),
            ("forbid", "nobackgroundcheck", "implies skipping a background check - never"),
            ("forbid", "noffl", "implies transfer without an FFL - never"),
            ("pair", r"suppressor|silencer|\bsbr\b|short[\s-]?barrel|full[\s-]?auto|machine\s?gun|\bnfa\b",
             r"stamp|form\s?[41]|\bsot\b|\bffl\b",
             "an NFA/Title II item mentioned without the stamp or FFL - never imply it can transfer without one"),
        ],
    },
    "sugar-creek": {
        "facts": [
            "Sugar Creek Drones is a Missouri agricultural and right-of-way drone-spraying LLC (Ross with partner Brent Schott). Fleet: a DJI Agras T40 and two T60s.",
            "Operations run under FAA Part 137 (agricultural aircraft operations) and a Part 44807 exemption. The compliance paperwork is non-negotiable.",
            "Apply only per the product label and the applicator's license. Never advise an off-label application or a rate beyond the label.",
        ],
        "guardrails": [
            ("forbid", "offlabel", "'off-label' application - never advise it"),
        ],
    },
    "river-city": {
        "facts": [
            "River City Enterprises (RCE) is Ross's rental-property company; it keeps its own QBO books.",
            "Tenant names, addresses and payment status are personal information - share them only with the people who own the relationship.",
        ],
        "guardrails": [],
    },
    "4x4-explorers": {
        "facts": [
            "4x4 Explorers is an off-road club with its own site and dashboard, run under rossfusz@gmail.com, separate from the SteelHaven org.",
            "The monthly meeting is the first Thursday after the first Sunday past the 1st, around 7:30 PM.",
        ],
        "guardrails": [],
    },
    "spring-valley": {
        "facts": [
            "Spring Valley covers security, networking and electronics work (with Ed). Quotes and job status live here.",
        ],
        "guardrails": [],
    },
    "finance": {
        "facts": [
            "Finance holds the books and QBO across the businesses; bookkeeping runs under Nate Salah's firm.",
            "Do not present tax or investment guidance as professional advice - Ross's accountant and licensed advisors do that.",
        ],
        "guardrails": [
            ("forbid", "guaranteedreturn", "'guaranteed return' - never, that is not something to promise"),
        ],
    },
    "personal": {
        "facts": [
            "Personal covers the house (home automation and the alarm), Ross's calendar, and family logistics.",
            "Grace runs the house. Family (Augie, Courtney) get personal information only when it is about them.",
        ],
        "guardrails": [],
    },
}


def facts(business: str) -> list[str]:
    return list(KNOWLEDGE.get(business, {}).get("facts", []))


def guardrails(business: str) -> list[tuple]:
    return list(KNOWLEDGE.get(business, {}).get("guardrails", []))


def _captain(business: str) -> str | None:
    b = roster.business(business)
    return b.captain if b else None


def seed(vault: Vault, business: str) -> int:
    """Load a business's starter facts as TOLD lessons for its captain.

    TOLD, so this needs Ross's key on the log - a starter fact is his word, and
    an agent must never be able to plant one about itself.
    """
    captain = _captain(business)
    if captain is None:
        raise ValueError(f"unknown business {business!r}")
    fs = facts(business)
    for f in fs:
        vault.learn(captain, business, f, basis=TOLD, source="ross")
    return len(fs)


def _is_md_heading(block: str) -> bool:
    """An explicit markdown heading line ('# Heading' from an exported Doc)."""
    return "\n" not in block and bool(re.match(r"^#{1,6}\s+\S", block))


def _looks_titlish(block: str) -> bool:
    """A single short, few-word, punctuation-free line that COULD be a title.

    On its own this is ambiguous: 'Governing Principle' is a title, but so is the
    shape of a real one-line fact ('Radon measured 0.3 pCi/L', 'John Donati',
    '4075 W Outer Rd'). _chunks resolves the ambiguity with a lookahead - it only
    treats such a line as a heading when a real body actually follows it.
    """
    if "\n" in block:                              # a multi-line block is content
        return False
    return (len(block) <= 60 and len(block.split()) <= 8
            and not re.search(r"[.!?:,;]$", block))


def _is_heading(block: str) -> bool:
    """Kept for callers that ask in isolation: a markdown heading, or a titlish
    line. _chunks does NOT use this - it needs the lookahead in _looks_titlish."""
    return _is_md_heading(block) or _looks_titlish(block)


def _chunks(text: str, *, cap: int = 1000) -> list[str]:
    """Split a doc into lessons, each carrying the heading it sits under.

    Docs export with headings on their own line ('# Heading' from a Google Doc,
    a short title-like line from pasted notes). Splitting purely on blank lines
    turned every heading into its own contentless item - '# Governing Principle'
    with nothing under it read as 'a vague heading, no content'. So a markdown
    heading is NEVER emitted alone: it is held and prefixed onto the next real
    content block, so the lesson keeps the section it belongs to.

    A PLAIN short line is trickier - it has the shape of both a title and a real
    one-line fact. Treating every one as a heading silently dropped a trailing
    fact and merged runs of short facts into one garbled lesson. So a plain
    titlish line is only treated as a heading when the NEXT block is real content
    (not itself another titlish/heading line); otherwise it is emitted as its own
    fact. And any heading still pending at the end is emitted rather than dropped.
    """
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text or "") if b.strip()]
    out: list[str] = []
    pending = ""                                   # the heading waiting for its body
    for idx, block in enumerate(blocks):
        if _is_md_heading(block):
            is_heading = True
        elif _looks_titlish(block):
            nxt = blocks[idx + 1] if idx + 1 < len(blocks) else None
            # a title only if a real body follows - not the end, not another title
            is_heading = nxt is not None and not (
                _is_md_heading(nxt) or _looks_titlish(nxt))
        else:
            is_heading = False
        if is_heading:
            h = re.sub(r"^#+\s*", "", block).strip()
            pending = (pending + " › " + h) if pending else h   # chain sub-headings
            continue
        prefix = (pending + " — ") if pending else ""
        pending = ""                               # consumed by this block
        lines = block.splitlines()
        if any(re.match(r"^\s*[-*+]\s", ln) for ln in lines):
            for ln in lines:
                ln = re.sub(r"^\s*[-*+]\s+", "", ln)
                ln = re.sub(r"^#+\s*", "", ln).strip()
                if ln:
                    out.append((prefix + ln)[:500])
        else:
            out.append((prefix + re.sub(r"^#+\s*", "", block))[:500])
        if len(out) >= cap:
            break
    if pending:                                    # a trailing/only heading isn't lost
        out.append(pending[:500])
    return out[:cap]


def ingest_text(vault: Vault, business: str, text: str, *, source: str = "ingest") -> int:
    """Load a document into a business's captain vault, as TOLD lessons.

    Ross's own words, so TOLD - which means his key is required and a compromised
    node cannot ingest. The text is trusted BECAUSE it is his and it is signed;
    that is the same reason an agent's OWN drafts are never fed back as grounding
    but an ingested doc is.
    """
    captain = _captain(business)
    if captain is None:
        raise ValueError(f"unknown business {business!r}")
    n = 0
    for chunk in _chunks(text):
        vault.learn(captain, business, chunk, basis=TOLD, source=source)
        n += 1
    return n
