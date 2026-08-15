"""The rules that must not be talked out of.

These are not unit tests in the usual sense - they are the safety properties
written down so a future change that breaks one fails loudly rather than
quietly widening what the system will do.

Everything under HOSTILE marks something a real audit found in an earlier
version. Those are regressions waiting to happen; each one was live code once.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco.asks import (ALLOW_ALWAYS, ALLOW_ONCE, DENY_ALWAYS, Asks)  # noqa: E402
from rosco.grants import (ANSWER, ASK, DECLINE, DO, GET, SELF, Grants,  # noqa: E402
                          Request)
from rosco.identity import CERTAIN, CLAIMED, UNKNOWN, People  # noqa: E402
from rosco.keys import Signer, Trust  # noqa: E402
from rosco.models import (CHAT, CHEAP, LOCAL, OPENROUTER, SYSTEM, Models,  # noqa: E402
                          secret_name)
from rosco.nodes import RENDEZVOUS, Nodes  # noqa: E402
from rosco.store import Log, Unauthorised  # noqa: E402
from rosco.vault import INFERRED, OBSERVED, TOLD, Vault, derive_key  # noqa: E402

# Ross's console key. In production this lives on one machine and nowhere else.
ROSS_KEY = Signer.generate()


def fresh(node="shop", *, trust=None, ross=ROSS_KEY):
    """A node with its own key, trusting Ross."""
    d = tempfile.mkdtemp()
    return Log(Path(d) / "rosco.db", node,
               ross=ross, trust=trust if trust is not None else Trust(ross=ROSS_KEY.public))


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def refuses(name, fn, *exc):
    """Assert a call is refused. The default is the whole point of the system."""
    try:
        fn()
        return check(name, "allowed", "refused")
    except (exc or (PermissionError, ValueError, Unauthorised)):
        return check(name, "refused", "refused")


def main() -> int:
    fails = 0
    log = fresh()
    g = Grants(log)
    TG = "telegram"

    print("\nPERMISSION RULES")
    d = g.decide(Request("brent", "sugar-creek", "spray-log", channel=TG))
    fails += not check("untaught request asks Ross", d.outcome, ASK)
    fails += not refuses("a non-Ross grant is refused",
                         lambda: g.give("lucas", "rum", "stock", by="lucas"))
    fails += not refuses("John cannot grant himself SteelHaven",
                         lambda: g.give("john", "steelhaven", "books", by="john"))

    g.give("brent", "sugar-creek", "spray-log", verb=GET, reason="he flies them")
    fails += not check("granted GET resolves to self-serve",
                       g.decide(Request("brent", "sugar-creek", "spray-log",
                                        channel=TG)).outcome, SELF)
    fails += not check("same person, other business, still asks",
                       g.decide(Request("brent", "rum", "spray-log", channel=TG)).outcome, ASK)
    g.deny("kyle", "steelhaven", "books", reason="Velent only")
    fails += not check("explicit deny declines",
                       g.decide(Request("kyle", "steelhaven", "books", channel=TG)).outcome,
                       DECLINE)

    print("\nCHANNEL TRUST")
    g.give("lucas", "rum", "stock", verb=DO, reason="he works the counter")
    fails += not check("DO over Telegram is allowed",
                       g.decide(Request("lucas", "rum", "stock", verb=DO,
                                        channel=TG)).outcome, SELF)
    fails += not check("same DO over email escalates",
                       g.decide(Request("lucas", "rum", "stock", verb=DO,
                                        channel="email")).outcome, ASK)
    g.give("vicki", "steelhaven", "schedule", verb=GET)
    fails += not check("GET over phone downgrades to answered",
                       g.decide(Request("vicki", "steelhaven", "schedule",
                                        channel="phone")).outcome, ANSWER)
    # HOSTILE: trust used to be a deny-list, so any string that was not
    # literally 'email' or 'phone' - a typo, a new adapter, an attacker's
    # choice - was handled as unforgeable.
    fails += not check("an unclassified channel is not assumed safe",
                       g.decide(Request("lucas", "rum", "stock", verb=DO,
                                        channel="sms")).outcome, ASK)
    fails += not check("and neither is no channel at all",
                       g.decide(Request("lucas", "rum", "stock", verb=DO)).outcome, ASK)

    print("\nSPECIFICITY")
    # HOSTILE: a later wildcard allow used to override an earlier exact deny,
    # because the match compared dates before specificity.
    g.deny("john", "rum", "bound-book", reason="RUM only, ATF record")
    g.give("john", "rum", "*", verb=GET, reason="he runs SteelHaven, give him the rest")
    fails += not check("a wildcard allow does NOT overturn an exact deny",
                       g.decide(Request("john", "rum", "bound-book", channel=TG)).outcome,
                       DECLINE)
    fails += not check("but the wildcard still covers everything else",
                       g.decide(Request("john", "rum", "invoices", channel=TG)).outcome, SELF)
    g.give("john", "rum", "bound-book", verb=GET, reason="changed my mind")
    fails += not check("an exact allow does overturn an exact deny",
                       g.decide(Request("john", "rum", "bound-book", channel=TG)).outcome, SELF)
    # HOSTILE, the mirror case: specificity-only meant a LATER blanket deny was
    # inert against an EARLIER exact allow. "Cut him off entirely" left exactly
    # the capability that mattered still granted, silently.
    g.give("brent", "rum", "bound-book", verb=GET)
    fails += not check("granted the exact capability",
                       g.decide(Request("brent", "rum", "bound-book", channel=TG)).outcome,
                       SELF)
    g.deny("brent", "rum", "*", verb=GET, reason="off everything, now")
    fails += not check("a later blanket deny DOES cut off the exact allow",
                       g.decide(Request("brent", "rum", "bound-book", channel=TG)).outcome,
                       DECLINE)
    fails += not check("and everything else too",
                       g.decide(Request("brent", "rum", "invoices", channel=TG)).outcome,
                       DECLINE)
    g.give("brent", "rum", "invoices", verb=GET, reason="but he can still see invoices")
    fails += not check("a later exact allow carves back out",
                       g.decide(Request("brent", "rum", "invoices", channel=TG)).outcome,
                       SELF)
    fails += not check("without reopening the rest",
                       g.decide(Request("brent", "rum", "bound-book", channel=TG)).outcome,
                       DECLINE)

    print("\nCASE")
    # HOSTILE: identity lowercases people, grants did not - so a deny written
    # in the wrong case was inert and left the earlier allow in force.
    g.give("Grace", "personal", "House", verb=DO)
    fails += not check("a grant matches whatever the case",
                       g.decide(Request("grace", "personal", "house", verb=DO,
                                        channel=TG)).outcome, SELF)
    g.deny("GRACE", "Personal", "HOUSE", verb=DO, reason="not while I'm away")
    fails += not check("and so does the deny that overturns it",
                       g.decide(Request("grace", "personal", "house", verb=DO,
                                        channel=TG)).outcome, DECLINE)

    print("\nREVOCATION")
    ev = g.give("ed", "spring-valley", "quotes")
    fails += not check("granted",
                       g.decide(Request("ed", "spring-valley", "quotes", channel=TG)).outcome,
                       SELF)
    g.revoke(ev["id"], reason="finished the job")
    fails += not check("revoked returns to asking",
                       g.decide(Request("ed", "spring-valley", "quotes", channel=TG)).outcome,
                       ASK)

    print("\nROSS")
    fails += not check("Ross is ungated on a strong channel",
                       g.decide(Request("ross", "rum", "anything", verb=DO,
                                        channel=TG)).outcome, SELF)
    # HOSTILE: the owner bypass fired before any channel check, so a forged
    # From: header naming Ross handed over everything at once.
    fails += not check("a forged Ross email does NOT bypass",
                       g.decide(Request("ross", "rum", "anything", verb=DO,
                                        channel="email")).outcome, ASK)
    fails += not check("nor does a phone call claiming to be him",
                       g.decide(Request("ross", "rum", "books", channel="phone")).outcome, ASK)

    print("\nHOSTILE / THE UNIDENTIFIED SENDER")
    # The worst finding of the audit. identity.resolve() returns person="" for
    # a stranger, an ambiguous address and a lapsed enrolment alike. That empty
    # string fell through the listing filter and matched EVERY grant in the
    # business: unknown is never yes had become unknown is everyone.
    fails += not check("a nameless request matches nothing",
                       g.decide(Request("", "rum", "stock", verb=DO, channel=TG)).outcome, ASK)
    fails += not check("even with no business either",
                       g.decide(Request("", "", "stock", verb=DO, channel=TG)).outcome, ASK)
    fails += not check("a nameless GET matches nothing",
                       g.decide(Request("", "sugar-creek", "spray-log", channel=TG)).outcome,
                       ASK)
    fails += not check("and an unnamed capability asks too",
                       g.decide(Request("lucas", "rum", "", verb=DO, channel=TG)).outcome, ASK)
    fails += not check("listing with no filter still lists",
                       len(g.live()) > 0, True)
    fails += not check("listing the empty name lists nothing",
                       g.live(person=""), [])

    print("\nTHE LOG")
    fails += not check("hash chain is sound", log.verify(), [])
    n_before = len(list(log.replay()))
    log.append("node.seen", {"name": "shop", "high_water": {}})
    fails += not check("append grows the log", len(list(log.replay())), n_before + 1)
    fails += not check("chain still sound after append", log.verify(), [])

    print("\nHOSTILE / KIND SHADOWING")
    # The critical finding of the second audit. Grants.live() read
    # replay(kind="grant.*"), which is SQL LIKE - suffix-matching AND
    # case-insensitive - while the authority set was matched exactly. So a kind
    # nobody had declared was projected as a live grant with no signature from
    # Ross, and verify() and rejected() both reported clean. Every event kind is
    # declared now, and an undeclared one has nowhere to land.
    for bogus in ("grant.suggested", "GRANT.GIVEN", "grant.given2", "grant.given "):
        fails += not refuses(f"{bogus!r} cannot even be written",
                             lambda k=bogus: log.append(
                                 k, {"person": "mallory", "business": "rum",
                                     "capability": "*", "verb": DO, "allow": True,
                                     "outcome": SELF, "reason": "forged"},
                                 actor="ross"),
                             Unauthorised)
    # ...and if one reaches the table another way, it is not projected.
    log.db.execute(
        "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash,nsig,rsig)"
        " VALUES('shadow',9001,'shop','2020-01-01T00:00:00Z','grant.suggested','','ross',"
        "'{\"person\":\"mallory\",\"business\":\"rum\",\"capability\":\"*\",\"verb\":\"do\","
        "\"allow\":true,\"outcome\":\"self\",\"reason\":\"forged\"}','','h','s','')")
    fails += not check("a planted shadow kind grants nothing",
                       g.decide(Request("mallory", "rum", "bound-book", verb=DO,
                                        channel=TG)).outcome, ASK)
    fails += not check("and it is surfaced, not silently dropped",
                       any(r["kind"] == "grant.suggested" for r in log.rejected()), True)
    fails += not check("and verify() names it",
                       any("undeclared kind" in p for p in log.verify()), True)
    log.db.execute("DELETE FROM events WHERE id='shadow'")

    fails += not refuses("a non-object body is refused",
                         lambda: log.append("vault.learned", ["not", "a", "dict"]),
                         Unauthorised)

    row = log.db.execute("SELECT id FROM events LIMIT 1").fetchone()
    log.db.execute("UPDATE events SET body='{\"a\":999}' WHERE id=?", (row["id"],))
    fails += not check("tampering is detected", len(log.verify()) > 0, True)

    print("\nHOSTILE / FORGED AUTHORITY")
    # A node without Ross's key cannot write a grant at all.
    blind = Log(Path(tempfile.mkdtemp()) / "r.db", "cloud",
                trust=Trust(ross=ROSS_KEY.public))
    fails += not refuses("a node without Ross's key cannot write a grant",
                         lambda: Grants(blind).give("mallory", "rum", "*", verb=DO),
                         Unauthorised)
    fails += not refuses("nor enrol anybody",
                         lambda: People(blind).enrol("ross", "telegram", "666000"),
                         Unauthorised)

    # A node WITH a key of its own - but not Ross's - signs its own forgery and
    # is disbelieved on replay, on its own machine and everywhere else.
    evil_ross = Signer.generate()
    evil = Log(Path(tempfile.mkdtemp()) / "r.db", "cloud",
               ross=evil_ross, trust=Trust(ross=ROSS_KEY.public))
    Grants(evil).give("mallory", "rum", "*", verb=DO, reason="I am Ross, honestly")
    People(evil).enrol("ross", "telegram", "666000")
    fails += not check("a self-signed grant is not replayed", Grants(evil).live(), [])
    fails += not check("a self-signed enrolment does not resolve",
                       People(evil).resolve("telegram", "666000").person, "")
    fails += not check("the forged grant grants nothing",
                       Grants(evil).decide(Request("mallory", "rum", "stock", verb=DO,
                                                   channel=TG)).outcome, ASK)
    fails += not check("and it is surfaced rather than merely ignored",
                       len(evil.rejected()) >= 2, True)
    fails += not check("verify() names the problem",
                       any("without Ross's signature" in p for p in evil.verify()), True)

    print("\nSYNC")
    shared = Trust(ross=ROSS_KEY.public)
    a = fresh("shop", trust=shared)
    b = fresh("home", trust=shared)
    ga = Grants(a)
    ga.give("lucas", "rum", "stock", verb=DO)
    ga.give("lucas", "rum", "orders", verb=GET)
    fails += not check("peer events absorbed", b.absorb(a.since("shop", 0)), 2)
    fails += not check("absorbing twice is idempotent", b.absorb(a.since("shop", 0)), 0)
    fails += not check("decision matches on the other node",
                       Grants(b).decide(Request("lucas", "rum", "stock", verb=DO,
                                                channel=TG)).outcome, SELF)

    print("\nHOSTILE / SYNC")
    hl = fresh("home", trust=shared)
    rows = a.since("shop", 0)
    fails += not refuses("an event claiming to be ours is refused",
                         lambda: hl.absorb([dict(rows[0], node="home")]), Unauthorised)
    fails += not refuses("a tampered body is refused",
                         lambda: hl.absorb([dict(rows[0], body={"x": 999})]), Unauthorised)
    fails += not refuses("a re-hashed forgery is still refused (no signature)",
                         lambda: hl.absorb([_rehash(dict(rows[0]), {"x": 999})]),
                         Unauthorised)
    fails += not refuses("an unknown node is refused",
                         lambda: hl.absorb([dict(rows[0], node="ghost")]), Unauthorised)
    fails += not check("the honest events still absorb", hl.absorb(rows), 2)
    fails += not check("chain sound after absorbing", hl.verify(), [])

    # HOSTILE: high_water used MAX(seq), so one row at seq 9,000,000 raised the
    # mark past every real event and censored the rest of that chain forever.
    ghost = fresh("shop", trust=shared)
    ghost.db.execute(
        "INSERT INTO events(id,seq,node,ts,kind,subject,actor,body,prev,hash,nsig,rsig)"
        " VALUES('x',9000000,'shop','2026-01-01T00:00:00Z','junk','','','{}','','h','s','')")
    fails += not check("a stray high seq cannot censor a chain",
                       ghost.high_water()["shop"] < 9000000, True)

    print("\nVAULT / LEARNING")
    v = Vault(a)
    l1 = v.learn("Remington", "rum", "Dix wants 60 days notice on the lease",
                 basis=TOLD, source="ross")
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
                       any("90 days" in t for t in live) and not any("60 days" in t for t in live),
                       True)
    fails += not check("the wrong belief is still readable",
                       any("60 days" in l.text for l in v.recall(business="rum",
                                                                 include_dead=True)), True)
    # HOSTILE: a lesson claiming Ross said it needs his signature, or an agent
    # can put words in his mouth and then argue with him using them.
    fails += not refuses("an agent cannot claim Ross told it something",
                         lambda: Vault(blind).learn("x", "rum", "Ross said do it",
                                                    basis=TOLD), Unauthorised)
    fails += not check("but it may record what it observed",
                       bool(Vault(blind).learn("x", "rum", "saw it happen", basis=OBSERVED)),
                       True)
    # HOSTILE: a correction whose target had not replayed yet used to delete
    # both itself and the lesson.
    orphan = Vault(a)
    orphan.correct("no-such-lesson-id", "a correction of nothing")
    fails += not check("an orphan correction deletes nothing",
                       len(v.recall(business="rum")), 2)
    # HOSTILE: a correction OF A CORRECTION that sorted before its target was
    # dropped and its text lost. Resolution is a fixpoint now, so the result no
    # longer depends on which node's second the events landed in.
    base = v.learn("Steele", "chain", "first", basis=OBSERVED)
    c1 = v.correct(base["id"], "second")
    v.correct(c1["id"], "third")
    fails += not check("a three-deep correction chain resolves to the newest",
                       [l.text for l in v.recall(business="chain")], ["third"])
    # HOSTILE: vault.forgot was outside the authority set, so a compromised node
    # could erase a Ross-signed warning from every node's projection.
    fails += not refuses("an agent cannot forget a lesson",
                         lambda: v.forget(base["id"], by="rosco"))
    fails += not refuses("nor can a node without Ross's key",
                         lambda: Vault(blind).forget("anything"), Unauthorised)
    # HOSTILE: recall() defaulted a missing basis to TOLD while the signature
    # rule tested basis == "told" exactly, so an unsigned correction with no
    # basis at all was projected as "Ross said so".
    fails += not refuses("a correction with no basis needs Ross",
                         lambda: blind.append("vault.corrected",
                                              {"replaces": base["id"], "text": "x"}),
                         Unauthorised)
    fails += not refuses("and a miscased one does too",
                         lambda: blind.append("vault.corrected",
                                              {"replaces": base["id"], "text": "x",
                                               "basis": "TOLD"}),
                         Unauthorised)

    print("\nVAULT / SECRETS")
    key = derive_key("a passphrase Ross picks", b"rosco-salt-v1")
    sv = Vault(a, key=key)
    sv.put_secret("rum", "qbo_refresh", "tok-abc-123")
    fails += not check("secret round-trips", sv.get_secret("rum", "qbo_refresh"), "tok-abc-123")
    sv.put_secret("rum", "qbo_refresh", "tok-rotated-456")
    fails += not check("rotation returns the newest",
                       sv.get_secret("rum", "qbo_refresh"), "tok-rotated-456")
    fails += not check("names list without the key",
                       Vault(a).secret_names("rum"), ["rum:qbo_refresh"])
    fails += not refuses("no key means no plaintext",
                         lambda: Vault(a).get_secret("rum", "qbo_refresh"), RuntimeError)
    fails += not refuses("an agent cannot store a secret",
                         lambda: sv.put_secret("rum", "x", "y", by="rosco"))

    # HOSTILE: the MAC covered only nonce+blob, so an envelope was valid under
    # ANY name - RUM's QBO token could be relabelled as SteelHaven's Workspace
    # credential and would decrypt happily under the new label.
    sv.put_secret("steelhaven", "workspace", "steelhaven-secret")
    stolen = None
    for ev in a.replay(kind="vault.secret"):
        if ev["body"]["name"] == "qbo_refresh":
            stolen = ev["body"]
    a.append("vault.secret", {**stolen, "business": "steelhaven", "name": "workspace"},
             subject="steelhaven:workspace", actor="ross")
    fails += not refuses("a relabelled envelope does not decrypt",
                         lambda: sv.get_secret("steelhaven", "workspace"), ValueError)

    print("\nIDENTITY")
    idl = fresh("home")
    p = People(idl)
    fails += not refuses("only Ross enrols",
                         lambda: p.enrol("lucas", "telegram", "551", by="lucas"))
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
    p.enrol("grace", "phone", "+1 (314) 555-0123")
    fails += not check("phone normalises across formats",
                       p.resolve("phone", "3145550123").person, "grace")
    fails += not check("a phone call is never proof",
                       p.resolve("phone", "3145550123").proven, False)
    p.enrol("augie", "email", "family@fusz.com")
    p.enrol("courtney", "email", "family@fusz.com")
    amb = p.resolve("email", "family@fusz.com")
    fails += not check("two people behind one address is nobody", amb.person, "")
    fails += not check("and it says why", "refusing to choose" in amb.why, True)
    p.enrol("kyle", "phone", "6365550199", until="2026-01-01T00:00:00Z")
    fails += not check("a lapsed enrolment stops resolving",
                       p.resolve("phone", "6365550199", at="2026-08-14T00:00:00Z").person, "")
    fails += not check("and it resolved before it lapsed",
                       p.resolve("phone", "6365550199", at="2025-06-01T00:00:00Z").person,
                       "kyle")
    h = p.enrol("ed", "telegram", "77123")
    fails += not check("enrolled", p.resolve("telegram", "77123").person, "ed")
    p.retire(h["id"], reason="job finished")
    fails += not check("retired handle stops resolving",
                       p.resolve("telegram", "77123").person, "")

    # HOSTILE: re-enrolling to ADD an expiry left the older unexpiring row live,
    # so the expiry did nothing whatsoever.
    p.enrol("vicki", "phone", "6185550100")
    p.enrol("vicki", "phone", "6185550100", until="2026-06-01T00:00:00Z")
    fails += not check("re-enrolling with an expiry takes effect",
                       p.resolve("phone", "6185550100", at="2026-08-14T00:00:00Z").person, "")
    # HOSTILE: 'until' was compared as a raw string, so an offset time or a
    # bare date compared wrong and some values never expired.
    p.enrol("nate", "phone", "3145559000", until="2026-06-01T12:00:00+02:00")
    fails += not check("an offset expiry is normalised, not string-compared",
                       p.resolve("phone", "3145559000", at="2026-06-01T11:00:00Z").person, "")
    fails += not refuses("an unparseable expiry is refused at enrolment",
                         lambda: p.enrol("x", "phone", "1", until="whenever"))
    # HOSTILE: the first attempt at the re-enrolment fix sorted on
    # (timestamp, uuid). Timestamps are one-second, so re-enrolling within the
    # same second picked a winner at random and the audit found it still open.
    # Ten rounds, because a random tie-break passes once in a while by luck.
    stable = True
    for i in range(10):
        pi = People(fresh("home"))
        pi.enrol("dana", "phone", "3145551000")
        pi.enrol("dana", "phone", "3145551000", until="2026-06-01T00:00:00Z")
        if pi.resolve("phone", "3145551000", at="2026-08-14T00:00:00Z").person != "":
            stable = False
    fails += not check("re-enrolment in the same second is not a coin flip", stable, True)
    # HOSTILE: an enrolment on a channel with no trust tier attached a real
    # person's name to it on the strength of nothing.
    idl.append("identity.enrolled",
               {"person": "brent", "channel": "sms", "address": "555",
                "raw": "555", "note": "", "until": ""},
               subject="sms:555", actor="ross")
    fails += not check("an unclassified channel resolves to nobody",
                       p.resolve("sms", "555").person, "")

    print("\nNODES")
    shared2 = Trust(ross=ROSS_KEY.public)
    nl = fresh("home", trust=shared2)
    nn = Nodes(nl)
    fails += not refuses("only Ross registers a node",
                         lambda: nn.register("rogue", "somewhere", by="rosco"))
    nn.register("home", "Spring Valley", reach="10.0.1.10:7799")
    nn.register("shop", "RUM, W. Outer Rd", reach="10.0.2.10:7799")
    fails += not check("registered nodes are trusted", nn.trusted(), {"home", "shop"})

    shop = fresh("shop", trust=shared2)
    Grants(shop).give("lucas", "rum", "stock", verb=DO)
    fails += not check("peer chain absorbed", nn.sync_from(shop).chains.get("shop"), 1)
    fails += not check("sync is idempotent", nn.sync_from(shop).taken, 0)

    outsider = Trust(ross=ROSS_KEY.public)
    stranger = fresh("audit", trust=outsider)
    Grants(stranger).give("nobody", "rum", "*", verb=DO)
    shared2.add_node("audit", outsider.nodes["audit"])   # key known, node NOT registered
    rep = nn.sync_from(stranger)
    fails += not check("an unregistered chain is refused", rep.taken, 0)
    fails += not check("and the refusal is reported", rep.clean, False)

    nn.register("cloud", "VM", role=RENDEZVOUS, reach="rosco.example:7799")
    cloud = fresh("cloud", trust=shared2)
    Nodes(cloud).register("shop", "RUM")
    Grants(shop).give("lucas", "rum", "orders")
    Nodes(cloud).sync_from(shop)
    rep = nn.sync_from(cloud)
    fails += not check("a chain relays through the rendezvous", rep.chains.get("shop"), 1)
    fails += not check("relayed events still verify", nl.verify(), [])

    print("\nASKS")
    ql = fresh("home")
    qg, q = Grants(ql), Asks(ql, Grants(ql))
    r = Request("brent", "sugar-creek", "spray-log", channel=TG, detail="last week's log?")
    q.raise_(r, qg.decide(r))
    q.raise_(r, qg.decide(r))
    q.raise_(r, qg.decide(r))
    fails += not check("asking three times is one question", len(q.pending()), 1)
    fails += not check("and the count is kept", q.pending()[0].times, 3)
    fails += not refuses("an agent cannot answer the queue",
                         lambda: q.answer(q.pending()[0].id, ALLOW_ALWAYS, by="rosco"))
    aid = q.pending()[0].id
    q.answer(aid, ALLOW_ALWAYS, note="he flies them")
    fails += not check("answering for good writes the grant",
                       qg.decide(r).outcome, SELF)
    fails += not check("and empties the queue", q.pending(), [])
    fails += not refuses("the same ask cannot be answered twice",
                         lambda: q.answer(aid, ALLOW_ALWAYS))
    r2 = Request("kyle", "steelhaven", "books", channel=TG)
    q.raise_(r2, qg.decide(r2))
    q.answer(q.pending()[0].id, DENY_ALWAYS, note="Velent only")
    fails += not check("denying for good writes the deny",
                       qg.decide(r2).outcome, DECLINE)
    r3 = Request("ed", "spring-valley", "quotes", channel=TG)
    q.raise_(r3, qg.decide(r3))
    once = q.pending()[0].id
    q.answer(once, ALLOW_ONCE)
    fails += not check("answering once teaches nothing", qg.decide(r3).outcome, ASK)
    # HOSTILE: ALLOW_ONCE was never consumed, so 'just this time' read as
    # permission forever and nothing told the two apart.
    fails += not check("a one-off is good once", q.get(once).allowed, True)
    q.spend(once)
    fails += not check("and not twice", q.get(once).allowed, False)
    fails += not refuses("only an ASK belongs in the queue",
                         lambda: q.raise_(Request("ross", "rum", "x", channel=TG),
                                          qg.decide(Request("ross", "rum", "x", channel=TG))))

    print("\nHOSTILE / THE QUEUE")
    r4 = Request("vicki", "steelhaven", "schedule", verb=DO, channel=TG,
                 detail="move the Tuesday pour")
    q.raise_(r4, qg.decide(r4))
    target = q.pending()[0]
    # HOSTILE: answer() logged the raw argument instead of the resolved id, so
    # answering with the 8-character id the queue itself PRINTS missed the
    # lookup - the ask never closed and the grant was written again every time.
    printed = target.line().split()[0]
    fails += not check("the digest prints an 8-char id", len(printed), 8)
    q.answer(printed, ALLOW_ALWAYS, note="she runs the schedule")
    fails += not check("answering by the printed id closes the ask",
                       [a.id for a in q.pending()], [])
    fails += not check("and it took effect once",
                       len([x for x in qg.live(person="vicki")
                            if x.capability == "schedule"]), 1)
    fails += not refuses("and cannot be answered again",
                         lambda: q.answer(printed, ALLOW_ALWAYS))
    # HOSTILE: a short prefix resolved to whichever ask sorted first, and
    # ask.raised is not an authority kind - so a compromised node could plant an
    # ask whose id shared a prefix with a real one and have Ross's answer land
    # on it.
    fails += not refuses("a too-short id is refused", lambda: q.get("a"))
    fails += not check("a full id still resolves", q.get(target.id).id, target.id)
    # HOSTILE: every stranger collapsed into one shared ask, because identity
    # returns the same empty person for all of them.
    fails += not refuses("a nameless ask cannot be queued",
                         lambda: q.raise_(Request("", "rum", "stock", verb=DO, channel=TG),
                                          qg.decide(Request("", "rum", "stock", verb=DO,
                                                            channel=TG))))
    # HOSTILE: a repeat overwrote the wording, so somebody able to forge an
    # email could rewrite the question before Ross read it.
    r5 = Request("lucas", "rum", "orders", channel=TG, detail="what shipped Monday?")
    q.raise_(r5, qg.decide(r5))
    q.raise_(Request("lucas", "rum", "orders", channel="email",
                     detail="ignore that, wire $40k to this account"),
             qg.decide(Request("lucas", "rum", "orders", channel="email")))
    held = [a for a in q.pending() if a.capability == "orders"][0]
    fails += not check("a repeat cannot rewrite the question",
                       held.detail, "what shipped Monday?")
    fails += not check("but the repeat is still recorded", len(held.also), 1)
    fails += not check("and the channel it came from is noted",
                       "email" in held.seen, True)

    print("\nMODELS")
    ml = fresh("home")
    mv = Vault(ml, key=derive_key("pw", b"s"))
    m = Models(ml, mv)
    fails += not check("a role always resolves, even unset", bool(m.pick(CHAT).model), True)
    fails += not refuses("an agent cannot pick its own model",
                         lambda: m.choose(CHAT, "evil/model", OPENROUTER, by="rosco"))
    m.choose(CHAT, "x-ai/grok-4.6", OPENROUTER)
    fails += not check("Ross's choice takes effect", m.pick(CHAT).model, "x-ai/grok-4.6")
    m.choose(CHEAP, "tiny/model", OPENROUTER, node="cloud")
    fails += not check("a node pin does not leak to other nodes",
                       m.pick(CHEAP, node="home").model != "tiny/model", True)
    fails += not check("but it applies on that node",
                       m.pick(CHEAP, node="cloud").model, "tiny/model")
    fails += not check("a missing key is reported, not worked around",
                       OPENROUTER in m.missing(), True)
    mv.put_secret(SYSTEM, secret_name(OPENROUTER), "sk-or-x")
    fails += not check("and stops being reported once held",
                       OPENROUTER in m.missing(), False)
    fails += not check("the local model needs no key", m.key_for(m.pick(LOCAL)), "")

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


def _rehash(ev, new_body):
    """Forge an event the way an attacker would: change it, then fix the hash.

    This is exactly what the unkeyed chain could not stop, and what the node
    signature does.
    """
    import hashlib

    from rosco.store import signable
    ev["body"] = new_body
    ev["hash"] = hashlib.sha256(signable(ev)).hexdigest()
    return ev


if __name__ == "__main__":
    raise SystemExit(main())
