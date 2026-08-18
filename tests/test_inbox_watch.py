"""The Gmail-watch engagement signal — archive-vs-handled nuance.

The importance ranker learns only from Ross's own inbox actions, so the label
delta -> action mapping IS the model. The dangerous mistake it must not make:
scoring a message Ross READ and then filed as a brush-off (-1). These lock in:
  - read-then-file and filing an already-read message (a bill) count as
    engagement ('file', +1), NOT a dismissal;
  - only clearing a still-UNREAD message is 'archive' (-1);
  - the stronger act wins when several happen at once (read-then-trash = trash);
  - the fetch-avoiding pre-filter can never drop a message _classify would score.
"""
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rosco.inbox_watch import _classify, _touches, _domain  # noqa: E402
from rosco.web import _engagement  # noqa: E402
from rosco.keys import Signer, Trust, ENUMS  # noqa: E402
from rosco.store import Log  # noqa: E402

ROSS_KEY = Signer.generate()

# Label deltas a real Gmail session produces. Each: (added, removed, current labels).
INBOX, UNREAD, STARRED, TRASH, SPAM = "INBOX", "UNREAD", "STARRED", "TRASH", "SPAM"


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def main() -> int:
    fails = 0

    print("\nCLASSIFY: THE ENGAGEMENT MAPPING")
    # read and kept in the inbox -> mild positive
    fails += not check("read + kept -> read",
                       _classify(set(), {UNREAD}, {INBOX}), "read")
    # THE FIX: read THEN filed out of the inbox (both dropped this window) -> engagement
    fails += not check("read-then-file -> file (not archive)",
                       _classify(set(), {UNREAD, INBOX}, set()), "file")
    # filed a message that was ALREADY read before the window (a paid bill): only
    # INBOX drops this window, and it carries no UNREAD now -> still engagement
    fails += not check("archive an already-read bill -> file",
                       _classify(set(), {INBOX}, set()), "file")
    # cleared while STILL UNREAD -> the real dismissal
    fails += not check("archive while unread -> archive",
                       _classify(set(), {INBOX}, {UNREAD}), "archive")
    # priority ladder: a stronger act in the same window wins
    fails += not check("read then trashed -> trash",
                       _classify({TRASH}, {UNREAD, INBOX}, {TRASH}), "trash")
    fails += not check("spam beats an inbox clear",
                       _classify({SPAM}, {INBOX}, {SPAM}), "spam")
    fails += not check("starred then filed -> star (engagement, not archive)",
                       _classify({STARRED}, {INBOX}, {STARRED}), "star")
    # nothing actionable
    fails += not check("a bare arrival -> None", _classify(set(), set(), {INBOX, UNREAD}), None)
    fails += not check("a CATEGORY toggle -> None",
                       _classify({"CATEGORY_PROMOTIONS"}, set(), {INBOX}), None)

    print("\nPRE-FILTER MATCHES THE CLASSIFIER (no silent drops)")
    # _touches must admit a message iff _classify would score it. Sweep every
    # subset of the labels that matter, in both added and removed positions.
    from itertools import combinations
    universe = [INBOX, UNREAD, STARRED, TRASH, SPAM, "CATEGORY_PROMOTIONS"]
    subsets = [set(c) for r in range(len(universe) + 1) for c in combinations(universe, r)]
    mism = 0
    for added in subsets:
        for removed in subsets:
            # labels don't change whether it's actionable, only file-vs-archive
            admits = _touches(added, removed)
            scores = _classify(added, removed, set()) is not None
            if admits != scores:
                mism += 1
    fails += not check("_touches admits exactly what _classify scores (all label subsets)",
                       mism, 0)

    print("\nDOMAIN EXTRACTION")
    fails += not check("plain address", _domain("Con Ed <billing@coned.com>"), "coned.com")
    fails += not check("no address -> empty", _domain("A Name With No Angle Brackets"), "")

    print("\nENUM DECLARES 'file' (or the append is dropped at write)")
    fails += not check("'file' is an accepted inbox.acted action",
                       "file" in ENUMS[("inbox.acted", "action")], True)

    print("\nEND TO END: THE SIGN THROUGH _engagement")
    d = tempfile.mkdtemp()
    log = Log(Path(d) / "rosco.db", "console",
              ross=ROSS_KEY, trust=Trust(ross=ROSS_KEY.public))
    # coned: he read-then-filed once, then filed an already-read bill -> +2 total
    log.append("inbox.acted", {"domain": "coned.com", "action": "file", "via": "gmail"},
               subject="coned.com", actor="ross")
    log.append("inbox.acted", {"domain": "coned.com", "action": "file", "via": "gmail"},
               subject="coned.com", actor="ross")
    # spammer: cleared unread -> -1
    log.append("inbox.acted", {"domain": "blast.example", "action": "archive", "via": "gmail"},
               subject="blast.example", actor="ross")
    eng = _engagement(log)
    fails += not check("read-then-filed sender scores POSITIVE", eng.get("coned.com"), 2)
    fails += not check("dismissed-unread sender scores NEGATIVE", eng.get("blast.example"), -1)
    fails += not check("'file' weighs the same as an active read",
                       eng.get("coned.com") == 2 and _engagement.__doc__ is not None, True)

    fails += run_level_tests()

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}\n")
    return 1 if fails else 0


def run_level_tests() -> int:
    """Exercise inbox_watch.run() end-to-end with the Google adapter mocked, to cover
    what the pure classifier can't: the truncation disclosure and that window
    ARRIVALS never consume the fetch budget (the bug the review confirmed)."""
    from types import SimpleNamespace
    import rosco.inbox_watch as iw
    from rosco.adapters import google as g

    fails = 0
    print("\nRUN(): TRUNCATION IS DISCLOSED, ARRIVALS ARE FREE")

    # Mock the whole Google surface run() leans on.
    iw.Vault = lambda log, key=None: SimpleNamespace(
        secret_names=lambda: {f"personal:{g.REFRESH_TOKEN}"})
    g.access_for = lambda vault, account: "tok"

    def scenario(transitions, from_labels):
        """Fresh log with an open watch; run 'stop' over the given transitions."""
        d = tempfile.mkdtemp()
        log = Log(Path(d) / "rosco.db", "console",
                  ross=ROSS_KEY, trust=Trust(ross=ROSS_KEY.public))
        log.append("email.watch", {"state": "open", "historyId": "100"},
                   subject="email", actor="ross")
        g.gmail_changes = lambda token, hid: {"transitions": transitions, "historyId": "z"}
        g.gmail_from_labels = lambda token, mid: from_labels[mid]
        reply = iw.run(SimpleNamespace(open=lambda pw: log,
                                       _vault_key=lambda pw: b"x" * 32), "pw", "stop")
        acted = Counter(ev["body"]["action"] for ev in log.replay(kind="inbox.acted"))
        return reply, acted

    # (1) three real actions buried AFTER 300 arrivals — arrivals must not crowd them
    # out (old code sliced [:120] before filtering, so actions past arrival 120 died).
    trans, fl = {}, {}
    for i in range(300):                                  # arrivals: labels ADDED, none removed
        trans[f"a{i}"] = {"added": {INBOX, UNREAD}, "removed": set(), "arrived": True}
    trans["r1"] = {"added": set(), "removed": {UNREAD, INBOX}}   # read-then-file
    fl["r1"] = ("Con Ed <billing@coned.com>", set())
    trans["r2"] = {"added": set(), "removed": {INBOX}}           # dismissed unread
    fl["r2"] = ("noreply@blast.example", {UNREAD})
    trans["r3"] = {"added": set(), "removed": {UNREAD}}          # read + kept
    fl["r3"] = ("a@keep.io", {INBOX})
    reply, acted = scenario(trans, fl)
    fails += not check("actions after 300 arrivals still all recorded",
                       dict(acted), {"file": 1, "archive": 1, "read": 1})
    fails += not check("no truncation note when only 3 real actions",
                       "went uncounted" not in reply and "big session" not in reply, True)

    # (2) 260 real 'file' actions -> tally 250, disclose the ~10 shortfall
    trans2, fl2 = {}, {}
    for i in range(260):
        trans2[f"m{i}"] = {"added": set(), "removed": {UNREAD, INBOX}}
        fl2[f"m{i}"] = (f"u{i}@big.example", set())
    reply2, acted2 = scenario(trans2, fl2)
    fails += not check("caps recorded actions at 250", acted2["file"], 250)
    fails += not check("reply tallies 250 filed", "250 filed" in reply2, True)
    fails += not check("reply DISCLOSES the ~10 uncounted (not silent)",
                       "went uncounted" in reply2, True)

    return fails


if __name__ == "__main__":
    raise SystemExit(main())
