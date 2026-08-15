"""The rules that must not be talked out of.

These are not unit tests in the usual sense - they are the safety properties
written down so a future change that breaks one fails loudly rather than
quietly widening what the system will do.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco.grants import (ANSWER, ASK, DECLINE, DO, GET, SELF, Grants,  # noqa: E402
                          Request)
from rosco.store import Log  # noqa: E402
from rosco.vault import INFERRED, OBSERVED, TOLD, Vault, derive_key  # noqa: E402


def fresh(node="shop"):
    d = tempfile.mkdtemp()
    return Log(Path(d) / "rosco.db", node)


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def main() -> int:
    fails = 0
    log = fresh()
    g = Grants(log)

    print("\nPERMISSION RULES")
    # Unknown is never yes.
    d = g.decide(Request("brent", "sugar-creek", "spray-log"))
    fails += not check("untaught request asks Ross", d.outcome, ASK)

    # Only Ross grants.
    try:
        g.give("lucas", "rum", "stock", by="lucas")
        fails += not check("a non-Ross grant is refused", "allowed", "refused")
    except PermissionError:
        fails += not check("a non-Ross grant is refused", "refused", "refused")

    # Nobody widens their own scope, even for their own business.
    try:
        g.give("john", "steelhaven", "books", by="john")
        fails += not check("John cannot grant himself SteelHaven", "allowed", "refused")
    except PermissionError:
        fails += not check("John cannot grant himself SteelHaven", "refused", "refused")

    # A taught grant resolves.
    g.give("brent", "sugar-creek", "spray-log", verb=GET, reason="he flies them")
    d = g.decide(Request("brent", "sugar-creek", "spray-log"))
    fails += not check("granted GET resolves to self-serve", d.outcome, SELF)

    # The silo holds across businesses.
    d = g.decide(Request("brent", "rum", "spray-log"))
    fails += not check("same person, other business, still asks", d.outcome, ASK)

    # Explicit deny is remembered and is not the same as silence.
    g.deny("kyle", "steelhaven", "books", reason="Velent only")
    d = g.decide(Request("kyle", "steelhaven", "books"))
    fails += not check("explicit deny declines", d.outcome, DECLINE)

    print("\nCHANNEL TRUST")
    g.give("lucas", "rum", "stock", verb=DO, reason="he works the counter")
    d = g.decide(Request("lucas", "rum", "stock", verb=DO, channel="telegram"))
    fails += not check("DO over Telegram is allowed", d.outcome, SELF)
    d = g.decide(Request("lucas", "rum", "stock", verb=DO, channel="email"))
    fails += not check("same DO over email escalates", d.outcome, ASK)
    g.give("vicki", "steelhaven", "schedule", verb=GET)
    d = g.decide(Request("vicki", "steelhaven", "schedule", channel="phone"))
    fails += not check("GET over phone downgrades to answered", d.outcome, ANSWER)

    print("\nREVOCATION")
    ev = g.give("ed", "spring-valley", "quotes")
    fails += not check("granted", g.decide(Request("ed", "spring-valley", "quotes")).outcome, SELF)
    g.revoke(ev["id"], reason="finished the job")
    fails += not check("revoked returns to asking",
                       g.decide(Request("ed", "spring-valley", "quotes")).outcome, ASK)

    print("\nROSS")
    fails += not check("Ross is never gated",
                       g.decide(Request("ross", "rum", "anything", verb=DO)).outcome, SELF)

    print("\nTHE LOG")
    problems = log.verify()
    fails += not check("hash chain is sound", problems, [])
    n_before = len(list(log.replay()))
    log.append("test.thing", {"a": 1})
    fails += not check("append grows the log", len(list(log.replay())), n_before + 1)
    fails += not check("chain still sound after append", log.verify(), [])

    # Tamper detection: edit a row behind the log's back.
    row = log.db.execute("SELECT id FROM events LIMIT 1").fetchone()
    log.db.execute("UPDATE events SET body='{\"a\":999}' WHERE id=?", (row["id"],))
    fails += not check("tampering is detected", len(log.verify()) > 0, True)

    print("\nSYNC")
    a = fresh("shop")
    b = fresh("home")
    ga = Grants(a)
    ga.give("lucas", "rum", "stock", verb=DO)
    ga.give("lucas", "rum", "orders", verb=GET)
    moved = b.absorb(a.since("shop", 0))
    fails += not check("peer events absorbed", moved, 2)
    fails += not check("absorbing twice is idempotent", b.absorb(a.since("shop", 0)), 0)
    fails += not check("decision matches on the other node",
                       Grants(b).decide(Request("lucas", "rum", "stock", verb=DO)).outcome, SELF)

    print("\nVAULT / LEARNING")
    v = Vault(a)
    l1 = v.learn("Remington", "rum", "Dix wants 60 days notice on the lease", basis=TOLD, source="ross")
    v.learn("Remington", "rum", "Suppressor transfers need the SOT on file", basis=OBSERVED)
    v.learn("Steele", "steelhaven", "PermaHaven is patent-pending", basis=INFERRED)
    rum = v.recall(business="rum")
    fails += not check("RUM lessons are RUM's", len(rum), 2)
    fails += not check("strongest basis sorts first", rum[0].basis, TOLD)
    fails += not check("other business is not visible",
                       [l.business for l in v.recall(business="steelhaven")], ["steelhaven"])

    v.correct(l1["id"], "Dix wants 90 days notice, not 60")
    live = [l.text for l in v.recall(business="rum")]
    fails += not check("correction replaces the belief",
                       any("90 days" in t for t in live) and not any("60 days" in t for t in live), True)
    fails += not check("the wrong belief is still readable",
                       any("60 days" in l.text for l in v.recall(business="rum", include_dead=True)), True)

    print("\nVAULT / SECRETS")
    key = derive_key("a passphrase Ross picks", b"rosco-salt-v1")
    sv = Vault(a, key=key)
    sv.put_secret("rum", "qbo_refresh", "tok-abc-123")
    fails += not check("secret round-trips", sv.get_secret("rum", "qbo_refresh"), "tok-abc-123")
    sv.put_secret("rum", "qbo_refresh", "tok-rotated-456")
    fails += not check("rotation returns the newest", sv.get_secret("rum", "qbo_refresh"), "tok-rotated-456")
    fails += not check("names list without the key",
                       Vault(a).secret_names("rum"), ["rum:qbo_refresh"])
    try:
        Vault(a).get_secret("rum", "qbo_refresh")
        fails += not check("no key means no plaintext", "read", "refused")
    except RuntimeError:
        fails += not check("no key means no plaintext", "refused", "refused")

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
