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

from dataclasses import dataclass

# Ranks, senior first. The ladder is deliberately short: four rungs is enough to
# express command, advice, supply and technical specialism, and a longer one
# would invite distinctions nobody would enforce.
COMMANDER = "Commander"        # Ross. Not an agent. Grants everything.
CHIEF = "Chief of Staff"       # Rosco. The only thing that sees across.
CAPTAIN = "Captain"            # a business agent. Commands one business.
LIEUTENANT = "Lieutenant"      # advises within a business: law, marketing.
QUARTERMASTER = "Quartermaster"  # books. Supply and accounts, nothing else.
WARRANT = "Warrant Officer"    # technical specialist. IT. Advises, does not command.

CHAIN = [COMMANDER, CHIEF, CAPTAIN, LIEUTENANT, QUARTERMASTER, WARRANT]


@dataclass(frozen=True)
class Agent:
    name: str
    rank: str
    business: str
    role: str
    reports_to: str

    @property
    def commands(self) -> bool:
        return self.rank in (CHIEF, CAPTAIN)


@dataclass(frozen=True)
class Business:
    slug: str
    title: str
    captain: str
    account: str          # the Google account its mail actually lives in
    own_domain: bool      # False means it shares rossfusz@gmail.com with five others


BUSINESSES = (
    Business("steelhaven", "SteelHaven Homes", "HavenMind", "ross@steelhaven.homes", True),
    Business("rum", "Romann Utility Machines", "CaptainMorgan", "ross@rumachines.com", True),
    Business("river-city", "River City Enterprises", "Twain", "rossfusz@gmail.com", False),
    Business("sugar-creek", "Sugar Creek Drones", "Harrier", "rossfusz@gmail.com", False),
    Business("4x4-explorers", "4x4 Explorers", "Scout", "rossfusz@gmail.com", False),
    Business("spring-valley", "Spring Valley", "Argus", "rossfusz@gmail.com", False),
    Business("finance", "Finance", "Ledger", "rossfusz@gmail.com", False),
    Business("personal", "Personal & Home", "Rosco", "rossfusz@gmail.com", False),
    # The system's own code and architecture - its own silo so ingesting Rosco-v1
    # to make Rosco a code expert never muddies a real business's brain. Captained
    # by Rosco (no duplicate agent, see roster()), and Rosco-the-chief reads it via
    # business '*', so what lands here is exactly what grounds Rosco on its code.
    Business("system", "Rosco System & Code", "Rosco", "rossfusz@gmail.com", False),
)

# name -> (rank, business, role, reports_to)
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
    out = [Agent("Rosco", CHIEF, "*", "chief of staff", "ross")]
    for biz in BUSINESSES:
        # Rosco wears two hats: Chief of Staff, and Captain of Personal. That is
        # deliberate - the personal business is the one Ross is himself in - but
        # it is the only doubling, and it is why the enrichment check in
        # grants.py runs against the READER rather than the agent.
        if biz.captain != "Rosco":
            out.append(Agent(biz.captain, CAPTAIN, biz.slug, "commands the business", "Rosco"))
        names = _BENCH[biz.slug]
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
    """The six that share one inbox.

    This list is why routing reads content rather than the account it arrived
    on - and why getting that wrong put a healthcare directive under a
    homebuilder the first time it was tried.
    """
    return [b.slug for b in BUSINESSES if not b.own_domain]
