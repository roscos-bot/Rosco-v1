"""Folder conventions - where a deliverable lands inside the right Drive.

The business route (test_web) refuses to guess. This deliberately does NOT: a
file in the wrong subfolder of the RIGHT Drive is a drag-and-drop to fix and
nobody outside sees it, so folder_for always answers and discloses how it
decided. These tests hold that line from both ends - it must always return a
folder, and the folder must always be one the business actually declares.

Pure - no HTTP, no vault, no console.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco import capabilities as caps  # noqa: E402
from rosco import deliverables as d  # noqa: E402
from rosco.roster import BUSINESSES  # noqa: E402


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def main() -> int:
    fails = 0

    print("THE NAME PICKS THE FOLDER")
    for slug, fname, want in (
        ("steelhaven", "SHH-plan-set-rev3.pdf", "Plans"),
        ("steelhaven", "blower-door-test-results.pdf", "Specs"),
        ("steelhaven", "jobsite-photos-june.zip", "Photos"),
        ("steelhaven", "material-takeoff.xlsx", "Bill of Materials"),
        ("rum", "customer-order-1042.pdf", "Orders"),
        ("rum", "price-list-2026.xlsx", "Pricing"),
        ("rum", "form-4-stamp.pdf", "Transfers"),
        ("rum", "bound-book-export.csv", "Bound Book"),
        ("river-city", "unit-3b-lease.pdf", "Leases"),
        ("river-city", "work-order-furnace.pdf", "Maintenance"),
        ("sugar-creek", "spray-log-north-field.csv", "Spray Logs"),
        ("sugar-creek", "part-137-waiver.pdf", "Compliance"),
        ("4x4-explorers", "member-roster.csv", "Membership"),
        ("spring-valley", "camera-quote-acme.pdf", "Quotes"),
        ("finance", "2025-tax-return.pdf", "Taxes"),
        ("finance", "payroll-march.xlsx", "Payroll"),
        ("personal", "furnace-manual.pdf", "House"),
    ):
        fails += not check(f"{slug}: {fname} -> {want}", d.folder_for(slug, fname)[0], want)

    print("\nTHE FILE TYPE PICKS IT WHEN THE NAME SAYS NOTHING")
    fails += not check("a .step model is a drawing (rum)",
                       d.folder_for("rum", "hull-v2.step")[0], "Drawings")
    fails += not check("and lands in Plans where that is the declared name",
                       d.folder_for("steelhaven", "hull-v2.step")[0], "Plans")
    fails += not check("a .jpg is a photo", d.folder_for("steelhaven", "IMG_4021.jpg")[0],
                       "Photos")
    fails += not check("a type with no declared home falls through",
                       d.folder_for("finance", "IMG_4021.jpg")[0], d.UNFILED)

    print("\nTHE TALK AROUND IT COUNTS TOO")
    fails += not check("context files it when the name is opaque",
                       d.folder_for("river-city", "scan0001.pdf", "the new tenant's lease")[0],
                       "Leases")

    print("\nIT ALWAYS ANSWERS, AND DISCLOSES A TIE")
    fails += not check("an opaque name is Unfiled, not a guess",
                       d.folder_for("steelhaven", "scan0001.pdf")[0], d.UNFILED)
    fails += not check("and says so", "nothing in the name" in
                       d.folder_for("steelhaven", "scan0001.pdf")[1], True)
    both = d.folder_for("steelhaven", "plans-and-budget.pdf")
    fails += not check("a two-way file takes the declared-first folder", both[0], "Plans")
    fails += not check("and the tie is DISCLOSED, not hidden",
                       "also matched Budget" in both[1], True)
    fails += not check("an unknown business is Unfiled, never a crash",
                       d.folder_for("nosuchco", "plans.pdf")[0], d.UNFILED)
    fails += not check("a blank business too", d.folder_for("", "")[0], d.UNFILED)

    print("\nSHORT TOKENS SIT ON WORD BOUNDARIES")
    fails += not check("'bomb-shelter' does not read as a BOM",
                       d.folder_for("steelhaven", "bomb-shelter-notes.txt")[0], d.UNFILED)
    fails += not check("'apostrophe' does not read as a PO",
                       d.folder_for("rum", "apostrophe.txt")[0], d.UNFILED)

    print("\nEVERY ANSWER IS A FOLDER THE BUSINESS DECLARES")
    # The whole point of a closed list: it can only ever return something real.
    names = ["plans.pdf", "hull.step", "IMG_1.jpg", "scan0001.pdf", "payroll.xlsx",
             "lease.pdf", "spray-log.csv", "quote.pdf", "member-roster.csv",
             "bound-book.csv", "budget-and-plans-and-photos.pdf", "", "..", "a" * 300]
    bad = []
    for b in BUSINESSES:
        declared = set(d.folders(b.slug)) | {d.UNFILED}
        for n in names:
            got, why = d.folder_for(b.slug, n)
            if got not in declared:
                bad.append((b.slug, n, got))
            if not why:
                bad.append((b.slug, n, "no reason given"))
    fails += not check("no input yields an undeclared folder", bad, [])

    print("\nTHE CONVENTIONS COVER THE BUSINESSES THAT HAVE CAPABILITIES")
    # capabilities.py is the seed; a business declared there and given real work
    # should have somewhere to put a file. 'triage' is not a business.
    missing = [b for b in caps.businesses()
               if b != "triage" and not d.folders(b)]
    fails += not check("every capability-bearing business has folders", missing, [])
    # And nothing is declared for a business the roster does not know.
    unknown = [s for s in d.FOLDERS if s not in {b.slug for b in BUSINESSES}]
    fails += not check("no folders for a business that does not exist", unknown, [])

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
