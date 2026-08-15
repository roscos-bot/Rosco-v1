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
from rosco.identity import CERTAIN, CLAIMED, UNKNOWN, People  # noqa: E402
from rosco.nodes import RENDEZVOUS, Nodes  # noqa: E402
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
    fails += not check("Ross is ungated on a strong channel",
                       g.decide(Request("ross", "rum", "anything", verb=DO,
                                        channel="telegram")).outcome, SELF)
    # The worst hole in the system if it regresses: a forged From: header
    # naming Ross would otherwise hand over everything at once.
    fails += not check("a forged Ross email does NOT bypass",
                       g.decide(Request("ross", "rum", "anything", verb=DO,
                                        channel="email")).outcome, ASK)
    fails += not check("nor does a phone call claiming to be him",
                       g.decide(Request("ross", "rum", "books", channel="phone")).outcome, ASK)

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

    print("\nIDENTITY")
    idl = fresh("home")
    p = People(idl)
    try:
        p.enrol("lucas", "telegram", "551", by="lucas")
        fails += not check("only Ross enrols", "allowed", "refused")
    except PermissionError:
        fails += not check("only Ross enrols", "refused", "refused")

    p.enrol("brent", "telegram", "8481123", note="his phone")
    p.enrol("brent", "email", "Brent@SugarCreek.com")
    fails += not check("paired strong channel is certain",
                       p.resolve("telegram", "8481123").confidence, CERTAIN)
    fails += not check("email is only ever a claim",
                       p.resolve("email", "brent@sugarcreek.com").confidence, CLAIMED)
    fails += not check("email matching is case-insensitive",
                       p.resolve("email", "BRENT@SUGARCREEK.COM").person, "brent")
    fails += not check("an unpaired telegram id is a stranger",
                       p.resolve("telegram", "9999").person, "")
    fails += not check("a stranger is never 'certain' of nobody",
                       p.resolve("telegram", "9999").confidence, UNKNOWN)

    # Phone shapes that are the same line.
    p.enrol("grace", "phone", "+1 (314) 555-0123")
    fails += not check("phone normalises across formats",
                       p.resolve("phone", "3145550123").person, "grace")
    fails += not check("a phone call is never proof",
                       p.resolve("phone", "3145550123").proven, False)

    # Ambiguity must never resolve to a pick.
    p.enrol("augie", "email", "family@fusz.com")
    p.enrol("courtney", "email", "family@fusz.com")
    amb = p.resolve("email", "family@fusz.com")
    fails += not check("two people behind one address is nobody", amb.person, "")
    fails += not check("and it says why", "refusing to choose" in amb.why, True)

    # Expiry - a recycled number belongs to a stranger.
    p.enrol("kyle", "phone", "6365550199", until="2026-01-01T00:00:00Z")
    fails += not check("a lapsed enrolment stops resolving",
                       p.resolve("phone", "6365550199", at="2026-08-14T00:00:00Z").person, "")
    fails += not check("and it resolved before it lapsed",
                       p.resolve("phone", "6365550199", at="2025-06-01T00:00:00Z").person, "kyle")

    # Retirement.
    h = p.enrol("ed", "telegram", "77123")
    fails += not check("enrolled", p.resolve("telegram", "77123").person, "ed")
    p.retire(h["id"], reason="job finished")
    fails += not check("retired handle stops resolving",
                       p.resolve("telegram", "77123").person, "")

    print("\nNODES")
    nl = fresh("home")
    nn = Nodes(nl)
    try:
        nn.register("rogue", "somewhere", by="rosco")
        fails += not check("only Ross registers a node", "allowed", "refused")
    except PermissionError:
        fails += not check("only Ross registers a node", "refused", "refused")

    nn.register("home", "Spring Valley", reach="10.0.1.10:7799")
    nn.register("shop", "RUM, W. Outer Rd", reach="10.0.2.10:7799")
    fails += not check("registered nodes are trusted", nn.trusted(), {"home", "shop"})

    # A peer offering its own chain.
    shop = fresh("shop")
    Grants(shop).give("lucas", "rum", "stock", verb=DO)
    rep = nn.sync_from(shop)
    fails += not check("peer chain absorbed", rep.chains.get("shop"), 1)
    fails += not check("sync is idempotent", nn.sync_from(shop).taken, 0)

    # An unregistered chain is refused, however it arrives.
    stranger = fresh("audit")
    Grants(stranger).give("nobody", "rum", "*", verb=DO)
    rep = nn.sync_from(stranger)
    fails += not check("an unregistered chain is refused", rep.taken, 0)
    fails += not check("and the refusal is reported", rep.clean, False)

    # Relay: the shop's events reach home THROUGH the cloud.
    nn.register("cloud", "VM", role=RENDEZVOUS, reach="rosco.example:7799")
    cloud = fresh("cloud")
    Nodes(cloud).register("shop", "RUM")           # cloud trusts shop too
    shop2 = fresh("shop2")                          # a second shop-side write
    Grants(shop).give("lucas", "rum", "orders")     # shop writes again, home is offline
    Nodes(cloud).sync_from(shop)                    # cloud picks it up
    rep = nn.sync_from(cloud)                       # home gets it via the cloud
    fails += not check("a chain relays through the rendezvous",
                       rep.chains.get("shop"), 1)
    fails += not check("relayed events still verify", nl.verify(), [])

    print("\nTHE LOG / HOSTILE PEERS")
    hl = fresh("home")
    other = fresh("shop")
    other.append("test.a", {"x": 1})
    rows = other.since("shop", 0)

    # An event stamped with OUR node name would let a peer rewrite our history.
    forged = dict(rows[0], node="home")
    try:
        hl.absorb([forged])
        fails += not check("an event claiming to be ours is refused", "taken", "refused")
    except ValueError:
        fails += not check("an event claiming to be ours is refused", "refused", "refused")

    # A tampered body must not survive the trip.
    bad = dict(rows[0], body={"x": 999})
    try:
        hl.absorb([bad])
        fails += not check("a tampered event is refused", "taken", "refused")
    except ValueError:
        fails += not check("a tampered event is refused", "refused", "refused")

    fails += not check("the honest event still absorbs", hl.absorb(rows), 1)
    fails += not check("chain sound after absorbing", hl.verify(), [])

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
