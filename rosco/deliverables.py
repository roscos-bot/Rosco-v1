"""Where a finished file LANDS, once its business is known.

`_route_deliverable` (web.py) answers WHICH company's Drive a deliverable belongs
in. This answers WHICH FOLDER inside it.

The conventions are DECLARED here rather than invented per file by the model, for
the same reason capabilities.py declares what may be asked for: a folder tree a
model makes up drifts. Two plan sets a month apart land in 'Plans' and 'Plan
Sets', the photos go to 'Photos' then 'Jobsite Photos', and a year later nothing
is anywhere. A closed list per business is boring and stays put. Adding a folder
is a code change on purpose - it is a decision about how Ross's businesses are
organised, not configuration.

The rows are seeded from capabilities.py, because what a business can be ASKED
for is a good description of what it HAS: SteelHaven's plans/specs/photos/
schedule/bom/invoices/budget are already declared there. They are not identical
though - a capability is a permission concept and a folder is a place - so this
is a curated parallel, not a derivation.

ONE DELIBERATE DIFFERENCE FROM BUSINESS ROUTING. An unclear business ASKS; an
unclear folder does NOT. Landing in the wrong subfolder of the RIGHT Drive is a
drag-and-drop to fix and nobody outside sees it, while landing in the wrong
company's Drive is visible to that company and cannot be quietly undone. Asking
on every file would tax the common case to prevent a cheap mistake. So this
always answers, and reports how it decided; the confirmation preview shows that
answer, so Ross can name a different folder before anything moves.
"""
from __future__ import annotations

import re
from pathlib import PurePath

# Where a file goes when nothing matches. Named to be OBVIOUS in a Drive
# listing: 'Unfiled' invites a tidy-up, whereas a plausible-looking folder hides
# the fact that nothing actually recognised the file.
UNFILED = "Unfiled"

# slug -> ordered rows of (folder, token patterns). ORDER IS MEANINGFUL: the
# first match wins, so the more specific row goes first. Patterns are regexes on
# word boundaries, the same discipline as _BIZ_TOKENS - short tokens like 'bom'
# and 'dwg' must not fire inside 'bomb' or 'dwgs-old'.
FOLDERS: dict[str, tuple] = {
    "steelhaven": (
        ("Plans", (r"\bplans?\b", r"plan set", r"\bdrawings?\b", r"blueprint",
                   r"\belevations?\b", r"floor ?plan")),
        ("Specs", (r"\bspecs?\b", r"specification", r"\bassembly\b",
                   r"test results?", r"blower door", r"\br-?value\b")),
        ("Photos", (r"\bphotos?\b", r"\bb-?roll\b", r"\bjobsite\b", r"\bsite photo")),
        ("Schedule", (r"\bschedule\b", r"\bcpm\b", r"critical path", r"pour date",
                      r"\bmilestones?\b")),
        ("Bill of Materials", (r"\bbom\b", r"bill of materials?", r"\btakeoffs?\b",
                               r"material list")),
        ("Invoices", (r"\binvoices?\b", r"\bbilling\b", r"\bpayments?\b")),
        ("Marketing", (r"\bmarketing\b", r"\bcampaigns?\b", r"\bsocial\b",
                       r"\bflyer\b", r"\bbrochure\b")),
        ("Budget", (r"\bbudgets?\b", r"job costing", r"\bmargins?\b", r"cost breakdown")),
    ),
    "rum": (
        ("Drawings", (r"\bdrawings?\b", r"\bmodels?\b", r"\bprints?\b", r"\bdwg\b",
                      r"\bcad\b")),
        ("Orders", (r"\borders?\b", r"\bpurchase order\b", r"\bpo\b")),
        ("Pricing", (r"\bpricing\b", r"price list", r"\bquotes?\b")),
        ("Stock", (r"\bstock\b", r"\binventory\b", r"\bshelf\b")),
        ("Transfers", (r"\btransfers?\b", r"\bnfa\b", r"form ?[134]\b", r"\bstamps?\b")),
        ("Bound Book", (r"bound ?book", r"\ba&d\b", r"acquisition and disposition",
                        r"\batf\b")),
    ),
    "river-city": (
        ("Leases", (r"\bleases?\b", r"\btenancy\b", r"rental agreement")),
        ("Maintenance", (r"\bmaintenance\b", r"\brepairs?\b", r"work order",
                         r"\bpunch list\b")),
        ("Rent Roll", (r"rent ?roll", r"\brents?\b", r"\bunits?\b", r"\btenants?\b")),
    ),
    "sugar-creek": (
        ("Spray Logs", (r"spray ?log", r"\bspray\b", r"\bapplications?\b", r"\bfields?\b")),
        ("Compliance", (r"\bcompliance\b", r"part ?137", r"\b44807\b", r"\bwaivers?\b",
                        r"\bcertificates?\b")),
        ("Schedule", (r"\bschedule\b", r"\bflights?\b", r"\bmissions?\b")),
        ("Invoices", (r"\binvoices?\b", r"\bbilling\b", r"\bpayments?\b")),
    ),
    "4x4-explorers": (
        ("Events", (r"\bevents?\b", r"\bruns?\b", r"\bmeetings?\b", r"\btrail\b")),
        ("Membership", (r"\bmembers?\b", r"\bmembership\b", r"\broster\b")),
    ),
    "spring-valley": (
        ("Drawings", (r"\bdrawings?\b", r"\bdiagrams?\b", r"\brack\b", r"\bcabling\b",
                      r"\bfloor ?plan\b")),
        ("Quotes", (r"\bquotes?\b", r"\bproposals?\b", r"\bestimates?\b", r"\bbids?\b")),
        ("Projects", (r"\bprojects?\b", r"\bjobs?\b", r"\binstalls?\b")),
    ),
    "finance": (
        ("Taxes", (r"\btaxe?s?\b", r"tax return", r"\bfilings?\b", r"\bworkpapers?\b",
                   r"\b1099\b", r"\bw-?2\b", r"\bk-?1\b")),
        ("Payroll", (r"\bpayroll\b", r"\bwages\b", r"\bsalaries\b", r"\btimesheets?\b")),
        ("Books", (r"\bbooks\b", r"\bquickbooks\b", r"\bqbo\b", r"general ledger",
                   r"\bp&l\b", r"\breconciliations?\b", r"\bstatements?\b")),
    ),
    "personal": (
        ("House", (r"\bhouse\b", r"\bhome\b", r"\balarm\b", r"\bappliance\b",
                   r"\bwarranty\b", r"\bmanuals?\b")),
        ("Family", (r"\bfamily\b", r"\bschool\b", r"\bmedical\b", r"\bhealth\b",
                    r"\binsurance\b")),
        ("Documents", (r"\bdocuments?\b", r"\brecords?\b", r"\bcopy\b")),
    ),
}

# A file's TYPE is a real signal for a deliverable - "3D models and files to the
# right Drive" is what this exists for, and a .step is a drawing wherever it came
# from. Each row lists candidate folder labels in preference order; the first one
# the business actually DECLARES above is used, so this never invents a folder a
# business does not have.
_MODEL_EXT = (".step", ".stp", ".iges", ".igs", ".stl", ".f3d", ".sldprt",
              ".sldasm", ".ipt", ".iam", ".3mf", ".obj", ".dwg", ".dxf")
_IMAGE_EXT = (".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff", ".webp")

_BY_EXT = (
    (_MODEL_EXT, ("Drawings", "Plans")),
    (_IMAGE_EXT, ("Photos",)),
)


def folders(business: str) -> list[str]:
    """The declared folders for a business, in order. Empty for an unknown one."""
    return [f for f, _toks in FOLDERS.get((business or "").strip().lower(), ())]


def folder_for(business: str, name: str, context: str = "") -> tuple[str, str]:
    """(folder, why) for a deliverable. ALWAYS answers - it never asks.

    Words in the file name and the surrounding talk are tried first, then the
    file's type, then UNFILED. `why` is written to be shown to Ross in the
    confirmation, because a folder chosen silently is a folder he cannot correct.
    """
    slug = (business or "").strip().lower()
    rows = FOLDERS.get(slug, ())
    if not rows:
        return UNFILED, f"no folder conventions are declared for {slug or 'that business'}"

    stem = PurePath(str(name or "")).stem.replace("_", " ").replace("-", " ")
    hay = (stem + " " + (context or "")).lower()
    hits = [f for f, toks in rows if any(re.search(t, hay) for t in toks)]
    if hits:
        # Declared order breaks a tie rather than a coin-flip, and the tie is
        # DISCLOSED - a file called 'plans-and-budget' genuinely is both, and Ross
        # should see that it could have gone elsewhere.
        if len(hits) > 1:
            return hits[0], (f"it reads as {hits[0]} (also matched "
                             + ", ".join(hits[1:]) + ")")
        return hits[0], f"it reads as {hits[0]}"

    ext = PurePath(str(name or "")).suffix.lower()
    declared = folders(slug)
    for exts, candidates in _BY_EXT:
        if ext in exts:
            for cand in candidates:
                if cand in declared:
                    return cand, f"a {ext} file is a {cand.lower().rstrip('s')}"
    return UNFILED, "nothing in the name or the talk matched a folder"
