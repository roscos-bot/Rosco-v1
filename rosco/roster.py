"""The order of battle - who exists, what they command, and what they answer to.

Rank is not decoration here. It encodes two things the system actually uses:

WHO MAY BE ASKED WHAT. A Captain owns a business and can convene its bench. A
Lieutenant advises inside one business and cannot see another. A Quartermaster
touches books and nothing else. Reading the rank tells you the blast radius.

WHO ESCALATES TO WHOM. A bench specialist escalates to its Captain; a Captain
escalates to the Chief of Staff; the Chief of Staff escalates to Ross and
stops. Nothing skips a level, which is what stops a lawyer agent quietly
deciding something that belonged to the man who owns the company.

Ross holds no rank. He is the civil authority the whole structure answers to,
and the one thing in the system that cannot be delegated - see grants.give(),
which refuses any other author.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Ranks, senior first. The ladder is deliberately short: four rungs is enough to
# express command, advice, supply and technical specialism, and a longer one
# would invite distinctions nobody would enforce.
COMMANDER = "Commander"        # Ross. Not an agent. Grants everything.
ADMIRAL = "Admiral"            # Rosco. Ranks above every Captain; the only thing that sees across.
CAPTAIN = "Captain"            # a business agent. Commands one business.
LIEUTENANT = "Lieutenant"      # advises within a business: law, marketing.
QUARTERMASTER = "Quartermaster"  # books. Supply and accounts, nothing else.
WARRANT = "Warrant Officer"    # technical specialist. IT. Advises, does not command.

CHAIN = [COMMANDER, ADMIRAL, CAPTAIN, LIEUTENANT, QUARTERMASTER, WARRANT]


@dataclass(frozen=True)
class Agent:
    name: str
    rank: str
    business: str
    role: str
    reports_to: str

    @property
    def commands(self) -> bool:
        return self.rank in (ADMIRAL, CAPTAIN)


@dataclass(frozen=True)
class Business:
    slug: str
    title: str
    captain: str
    account: str          # the Google account its mail actually lives in
    own_domain: bool      # False means it shares rossfusz@gmail.com with six others
    code: str = ""        # a 3-letter tag (SHH, RUM, RCE…) shown beside the name


BUSINESSES = (
    Business("steelhaven", "SteelHaven Homes", "HavenMind", "ross@steelhaven.homes", True, "SHH"),
    Business("rum", "Romann Utility Machines", "CaptainMorgan", "ross@rumachines.com", True, "RUM"),
    Business("river-city", "River City Enterprises", "Twain", "rossfusz@gmail.com", False, "RCE"),
    Business("sugar-creek", "Sugar Creek Drones", "Harrier", "rossfusz@gmail.com", False, "SCD"),
    Business("4x4-explorers", "4x4 Explorers", "Scout", "rossfusz@gmail.com", False, "4XE"),
    Business("spring-valley", "Spring Valley", "Argus", "rossfusz@gmail.com", False, "SVP"),
    Business("finance", "Finance", "Ledger", "rossfusz@gmail.com", False, "FIN"),
    Business("personal", "Personal & Home", "Hearth", "rossfusz@gmail.com", False, "PSN"),
    # The system's own code and architecture - its own silo so ingesting Rosco-v1
    # to make Rosco a code expert never muddies a real business's brain. Captained
    # by Rosco (no duplicate agent, see roster()), and Rosco-the-chief reads it via
    # business '*', so what lands here is exactly what grounds Rosco on its code.
    Business("system", "Rosco's Vault (code & system)", "Rosco", "rossfusz@gmail.com", False, "SYS"),
)

# slug -> (law, marketing, books, it) bench-member NAMES; None = that seat is empty.
# rank/role/reports_to are DERIVED in roster() from _ROLES + the business, NOT
# stored here - populating this with (rank, business, role, reports_to) would make
# roster() mint four bogus agents.
_BENCH = {
    "steelhaven":    ("Steele", "Forge", "Nate Plumb", "Gage"),
    "rum":           ("Remington", "Flint", "Nate Chambers", "Bolt"),
    "river-city":    ("Banks", "Marlowe", "Nate Wharton", "Keyes"),
    "sugar-creek":   ("Fields", "Bloom", "Nate Bushel", "Swift"),
    "4x4-explorers": ("Rockwell", "Blaze", "Nate Gearing", "Winch"),
    "spring-valley": ("Wells", "Signal", "Nate Watts", "Ward"),
    "finance":       ("Sterling", None, "Nate Cash", None),
    "personal":      ("Abbott", None, "Nate Penny", "Porter"),
    "system":        (None, None, None, None),   # no bench - Rosco is the only one here
}

_ROLES = (("law", LIEUTENANT), ("marketing", LIEUTENANT),
          ("books", QUARTERMASTER), ("it", WARRANT))


def roster() -> list[Agent]:
    """Everyone, in order of precedence."""
    out = [Agent("Rosco", ADMIRAL, "*", "chief of staff", "ross")]
    for biz in BUSINESSES:
        # Rosco (the Admiral) is chief of staff over '*' and also holds the 'system'
        # code vault as captain - so skip minting a duplicate agent when a business's
        # captain IS Rosco. Every real business gets its own captain now, including
        # Personal -> Hearth (inbound to rossfusz@gmail is Hearth's, but flows to
        # Rosco to route). The grants.py enrichment runs against the READER, not the
        # agent, so it stays correct however the hats fall.
        if biz.captain != "Rosco":
            out.append(Agent(biz.captain, CAPTAIN, biz.slug, "commands the business", "Rosco"))
        # .get so a newly-added Business without a _BENCH entry simply gets an
        # empty bench (the `if name` below drops the None seats) instead of a
        # KeyError that would crash roster() -> mesh/agents/find on the next edit.
        names = _BENCH.get(biz.slug, (None, None, None, None))
        for (role, rank), name in zip(_ROLES, names):
            if name:
                out.append(Agent(name, rank, biz.slug, role, biz.captain))
    return out


def find(name: str) -> Agent | None:
    lowered = name.strip().lower()
    for a in roster():
        if a.name.lower() == lowered:
            return a
    return None


def bench(business: str) -> list[Agent]:
    """A Captain's own bench. It may convene these and nobody else's."""
    return [a for a in roster() if a.business == business and a.rank != CAPTAIN]


# The four domains a bench seat can own, matching _ROLES. A captain leans on the
# specialist whose domain a task falls in - THIS is what makes the bench real
# rather than a picture: delegation resolves a task to one of these, or (None)
# stays with the captain.
DOMAINS = ("law", "marketing", "books", "it")


def specialist_for(business: str, domain: str) -> Agent | None:
    """The bench member who owns `domain` in `business`, or None.

    None means either an unknown domain or an EMPTY seat (a business with no
    'marketing' bench, say) - and an empty seat is not an error, it just means
    the captain keeps that work itself. So a caller treats None as 'no delegate,
    the captain handles it', never as a failure. The captain is never returned
    here: delegation is one rung DOWN, and returning the captain would let a
    caller think it had delegated when it had not.
    """
    d = (domain or "").strip().lower()
    if d not in DOMAINS:
        return None
    for a in roster():
        if a.business == business and a.role == d and a.rank != CAPTAIN:
            return a
    return None


# The words that tip a task into one bench domain. Curated to be low-collision:
# multi-character, business-specific terms, matched on word boundaries so 'ad'
# never fires on 'add' and 'api' never on 'apiece'. Not exhaustive - it only has
# to catch the clear cases, because an unclear one deliberately stays with the
# captain.
_DOMAIN_HINTS = {
    "law": ("legal", "lawyer", "attorney", "contract", "lease", "permit",
            "license", "licence", "compliance", "atf", "ffl", "nfa", "form 4",
            "form 3", "form 1", "stamp", "easement", "zoning", "liability",
            "warranty", "insurance", "regulation", "ordinance", "part 137",
            "44807"),
    "marketing": ("post", "campaign", "social", "advert", "advertising", "copy",
                  "brand", "blog", "newsletter", "launch", "promo", "promotion",
                  "seo", "content", "flyer", "facebook", "instagram", "linkedin",
                  "tagline", "audience", "hashtag"),
    "books": ("invoice", "payment", "budget", "costing", "margin", "quote",
              "pricing", "payroll", "taxes", "qbo", "quickbooks", "bookkeeping",
              "receivable", "payable", "profit", "expense", "reconcile"),
    "it": ("website", "webpage", "deploy", "server", "database", "integration",
           "webhook", "dashboard", "netlify", "endpoint", "software", "codebase",
           "api"),
}


def domain_of(text: str) -> str | None:
    """Which bench domain a task falls in - law/marketing/books/it - or None.

    Deterministic and conservative on purpose: it delegates only on a clear,
    single-domain signal. Zero hits, or a TIE across domains, returns None so an
    ambiguous task stays with the captain rather than a coin-flip handing NFA
    paperwork to the marketing seat. Same discipline as the capability
    classifier: match by whole word, and when two readings are equally strong,
    refuse. A refusal here is not a failure - it just means the captain keeps it.
    """
    low = (text or "").lower()
    scored: dict[str, int] = {}
    for domain, hints in _DOMAIN_HINTS.items():
        n = sum(1 for kw in hints if re.search(rf"\b{re.escape(kw)}\b", low))
        if n:
            scored[domain] = n
    if not scored:
        return None
    top = max(scored.values())
    winners = [d for d, n in scored.items() if n == top]
    return winners[0] if len(winners) == 1 else None


def escalates_to(name: str) -> str:
    """One rung up. Nothing skips a level and nothing reaches Ross but Rosco."""
    a = find(name)
    if a is None:
        return "ross"
    return a.reports_to


def business(slug: str) -> Business | None:
    for b in BUSINESSES:
        if b.slug == slug:
            return b
    return None


def shared_mailbox_businesses() -> list[str]:
    """The seven that share one inbox.

    This list is why routing reads content rather than the account it arrived
    on - and why getting that wrong put a healthcare directive under a
    homebuilder the first time it was tried.
    """
    return [b.slug for b in BUSINESSES if not b.own_domain]
