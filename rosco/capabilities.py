"""What can be asked for. A closed list, per business.

The permission model works on capability strings, and until now nothing said
which strings were real. That gap is where the classifier would have done its
damage: an LLM turning "can you send me the latest numbers for the shop?" into
a free-text capability means grants.decide() enforces perfectly against a name
nobody ever granted, and every such request resolves to ASK forever - or worse,
lands on a neighbouring capability that WAS granted.

So the vocabulary is declared, exactly like the event kinds in keys.py. The
classifier picks from this list or it fails; it never invents a name. Four
audits have now found the same shape of bug - a wildcard consumer against an
exact producer - and a closed list on both sides is the pattern that stops it.

SENSITIVE CAPABILITIES NEVER RESOLVE BY INFERENCE. The bound book, payroll, the
books, transfers: for these, a confident guess is not good enough. They require
an unambiguous request or they go to Ross, however sure the model claims to be.
That is a deliberate annoyance tax on exactly the things Ross would most hate to
get wrong, and it is cheap because these are rare.

Nothing here is authoritative about Ross's actual businesses - it is a starting
vocabulary, seeded from what the repo and his notes already describe. Adding a
capability is a code change on purpose: a new thing people can ask for is a
decision, not configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Capability:
    name: str
    business: str
    what: str                              # plain words, shown to Ross in an ask
    sensitive: bool = False                # never resolved by inference
    phrases: tuple[str, ...] = field(default_factory=tuple)   # unambiguous asks

    @property
    def key(self) -> str:
        return f"{self.business}:{self.name}"


# The starting vocabulary. `phrases` are the wordings that count as unambiguous
# for a sensitive capability - deliberately narrow, because their whole job is
# to be hard to hit by accident.
CATALOGUE: tuple[Capability, ...] = (
    # --- SteelHaven Homes
    Capability("schedule", "steelhaven", "the build schedule and pour dates"),
    Capability("plans", "steelhaven", "drawings and plan sets"),
    Capability("bom", "steelhaven", "the bill of materials"),
    Capability("photos", "steelhaven", "jobsite photos and B-roll"),
    Capability("specs", "steelhaven", "assembly specs and test results"),
    Capability("marketing", "steelhaven", "social posts and campaign material"),
    Capability("invoices", "steelhaven", "invoices and payment status"),
    Capability("budget", "steelhaven", "job costing and margins", sensitive=True,
               phrases=("job costing", "budget", "margins", "cost breakdown")),

    # --- Romann Utility Machines
    Capability("stock", "rum", "what is on the shelf"),
    Capability("orders", "rum", "customer orders and their status"),
    Capability("pricing", "rum", "price lists and quotes"),
    Capability("bound-book", "rum", "the ATF acquisition & disposition record",
               sensitive=True,
               phrases=("bound book", "a&d", "acquisition and disposition",
                        "atf record")),
    Capability("transfers", "rum", "NFA transfers and stamp status", sensitive=True,
               phrases=("nfa transfer", "form 4", "form 3", "stamp status")),

    # --- Sugar Creek Drones
    Capability("spray-log", "sugar-creek", "spray records by field and date"),
    Capability("schedule", "sugar-creek", "who is flying what, and when"),
    Capability("compliance", "sugar-creek", "Part 137 and 44807 paperwork"),
    Capability("invoices", "sugar-creek", "invoices and payment status"),

    # --- River City Enterprises
    Capability("rent-roll", "river-city", "units, tenants and rent status"),
    Capability("maintenance", "river-city", "open maintenance items"),
    Capability("leases", "river-city", "lease documents and dates"),

    # --- 4x4 Explorers
    Capability("events", "4x4-explorers", "runs, meetings and the calendar"),
    Capability("membership", "4x4-explorers", "the member list"),

    # --- Spring Valley
    Capability("quotes", "spring-valley", "quotes for security and networking work"),
    Capability("projects", "spring-valley", "job status"),

    # --- Finance
    Capability("books", "finance", "the books and QBO", sensitive=True,
               phrases=("the books", "quickbooks", "qbo", "general ledger", "p&l")),
    Capability("payroll", "finance", "payroll", sensitive=True,
               phrases=("payroll", "wages", "salaries")),
    Capability("taxes", "finance", "tax filings and workpapers", sensitive=True,
               phrases=("tax return", "taxes", "filing", "workpapers")),

    # --- Personal & home
    Capability("house", "personal", "home automation and the alarm"),
    Capability("calendar", "personal", "Ross's calendar"),
    Capability("family", "personal", "family logistics"),
)


def businesses() -> list[str]:
    seen = []
    for c in CATALOGUE:
        if c.business not in seen:
            seen.append(c.business)
    return seen


def for_business(business: str) -> list[Capability]:
    return [c for c in CATALOGUE if c.business == business]


def find(business: str, name: str) -> Capability | None:
    b, n = (business or "").strip().lower(), (name or "").strip().lower()
    for c in CATALOGUE:
        if c.business == b and c.name == n:
            return c
    return None


def declared(business: str, name: str) -> bool:
    return find(business, name) is not None


def is_sensitive(business: str, name: str) -> bool:
    c = find(business, name)
    return bool(c and c.sensitive)


def unambiguous(business: str, name: str, text: str) -> bool:
    """Did they actually SAY the sensitive thing, rather than gesture at it?

    Only used to gate sensitive capabilities. A model that is 95% sure somebody
    meant the bound book is not the same as somebody writing "bound book", and
    the difference is worth an interruption every time.
    """
    c = find(business, name)
    if c is None:
        return False
    if not c.sensitive:
        return True
    low = (text or "").lower()
    return any(p in low for p in c.phrases)


def catalogue_for_prompt() -> str:
    """The list, as the classifier is shown it.

    Rendered rather than dumped so the model sees plain descriptions instead of
    identifiers it might pattern-match on. It is told what each thing IS; it is
    never told which are sensitive, because that is not its decision and naming
    them would only teach it which ones to reach for.
    """
    lines = []
    for b in businesses():
        lines.append(f"{b}:")
        for c in for_business(b):
            lines.append(f"  {c.name} - {c.what}")
    return "\n".join(lines)
