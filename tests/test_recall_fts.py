"""FTS + memoized recall — the correctness/security-critical memory core.

Proves four things that must hold after the fold was extracted and memoized:
  (a) memoized recall() == a fresh, uncached fold (no drift from caching);
  (b) the fold is actually reused on an unchanged log, and rebuilt when it grows;
  (c) rank() surfaces query-relevant lessons with proper (word-boundary,
      length-normalised) lexical ranking, and the lexical fallback still works;
  (d) _relevant prunes a large vault down to the query-relevant slice.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rosco.keys import Signer, Trust  # noqa: E402
from rosco.store import Log  # noqa: E402
from rosco import vault as vaultmod  # noqa: E402
from rosco.vault import (  # noqa: E402
    INFERRED, OBSERVED, TOLD, Lesson, Vault, _lexical_rank, _fts5_ok,
)

ROSS_KEY = Signer.generate()


def fresh(node="shop"):
    d = tempfile.mkdtemp()
    return Log(Path(d) / "rosco.db", node,
               ross=ROSS_KEY, trust=Trust(ross=ROSS_KEY.public))


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


def L(text, basis=OBSERVED):
    return Lesson(id="x", agent="Rosco", business="*", text=text,
                  basis=basis, learned=0.0, source="")


def main() -> int:
    fails = 0

    print("\nFTS AVAILABILITY")
    fails += not check("this python's sqlite has FTS5", _fts5_ok(), True)

    # ---- (a) memoized recall() == a fresh, uncached fold --------------------
    print("\nMEMOIZED RECALL == FRESH FOLD")
    log = fresh()
    v = Vault(log)
    v.learn("Rosco", "rum", "Dix wants 60 days notice on the lease", basis=OBSERVED)
    v.learn("Rosco", "rum", "Suppressor transfers need the SOT on file", basis=OBSERVED)
    v.learn("Rosco", "steelhaven", "PermaHaven is patent-pending", basis=INFERRED)
    base = v.learn("Rosco", "steelhaven", "The Duo measured 0.3 pCi/L radon", basis=OBSERVED)
    v.correct(base["id"], "The Duo measured 0.3 pCi/L radon at the open house",
              basis=OBSERVED, by="Rosco")

    # snapshot recall() across several filters WITH the cache warm
    warm = {
        "all": [l.text for l in v.recall()],
        "rum": [l.text for l in v.recall(business="rum")],
        "steelhaven": [l.text for l in v.recall(business="steelhaven")],
        "dead": [l.text for l in v.recall(business="steelhaven", include_dead=True)],
        "contains": [l.text for l in v.recall(contains="radon")],
    }
    # now blow the module cache away and recompute from a fresh Vault — same log,
    # cold cache. Results must be byte-identical to the warm ones.
    vaultmod._FOLD_CACHE.clear()
    v2 = Vault(log)
    cold = {
        "all": [l.text for l in v2.recall()],
        "rum": [l.text for l in v2.recall(business="rum")],
        "steelhaven": [l.text for l in v2.recall(business="steelhaven")],
        "dead": [l.text for l in v2.recall(business="steelhaven", include_dead=True)],
        "contains": [l.text for l in v2.recall(contains="radon")],
    }
    for k in warm:
        fails += not check(f"warm==cold recall [{k}]", warm[k], cold[k])
    fails += not check("correction supersedes the original in recall",
                       any("open house" in t for t in warm["steelhaven"]) and
                       not any(t == "The Duo measured 0.3 pCi/L radon" for t in warm["steelhaven"]),
                       True)
    fails += not check("superseded original still visible with include_dead",
                       any(t == "The Duo measured 0.3 pCi/L radon" for t in warm["dead"]), True)

    # ---- (b) the fold is reused, and rebuilt only when the log grows --------
    print("\nMEMOIZATION: HIT ON UNCHANGED LOG, MISS ON GROWTH")
    builds = {"n": 0}
    orig_build = Vault._build_fold

    def counting_build(self):
        builds["n"] += 1
        return orig_build(self)

    Vault._build_fold = counting_build
    try:
        vaultmod._FOLD_CACHE.clear()
        log2 = fresh()
        a = Vault(log2)
        a.learn("Rosco", "rum", "first fact", basis=OBSERVED)
        builds["n"] = 0
        # three recalls, different Vault objects, same unchanged log
        Vault(log2).recall()
        Vault(log2).recall(business="rum")
        Vault(log2).recall()
        fails += not check("unchanged log folds once across 3 recalls / 3 Vaults", builds["n"], 1)

        # a new vault.* event moves revision() -> next recall must rebuild
        a.learn("Rosco", "rum", "second fact", basis=OBSERVED)
        got = [l.text for l in Vault(log2).recall(business="rum")]
        fails += not check("append invalidates the cache (rebuild happened)", builds["n"], 2)
        fails += not check("the newly-learned fact is now recalled",
                           "second fact" in got, True)

        # a NON-vault event still moves MAX(rowid); recall must not go stale or crash
        log2.append("task.created", {"id": "t1", "text": "unrelated"},
                    subject="rum", actor="Rosco")
        got2 = [l.text for l in Vault(log2).recall(business="rum")]
        fails += not check("recall survives an unrelated append", sorted(got2),
                           ["first fact", "second fact"])
    finally:
        Vault._build_fold = orig_build

    # ---- (c) rank(): word-boundary precision, no-swamp, trust tilt, fallback
    print("\nRANK: LEXICAL QUALITY")
    v3 = Vault(fresh())

    # word-boundary: query "steel" matches the WORD steel, not the substring in
    # "SteelHaven". FTS tokenizes; the old text.count() would false-match both.
    ls = [L("SteelHaven Homes builds houses in Highland"),
          L("steel avoids rot and termites")]
    ranked = v3.rank(ls, "steel")
    fails += not check("FTS ranks the real 'steel' lesson first",
                       ranked[0].text, "steel avoids rot and termites")

    # no-swamp: a short exact hit should beat a long doc that never mentions the term.
    ls2 = [L("radon " * 40 + "and airtightness and insulation and blower door"),
           L("the lease has a termite clause")]
    ranked2 = v3.rank(ls2, "termite")
    fails += not check("query term wins over an unrelated long doc",
                       ranked2[0].text, "the lease has a termite clause")

    # trust tilt: two equally-matching lessons, TOLD ranks above INFERRED.
    ls3 = [L("radon barrier under the slab", basis=INFERRED),
           L("radon barrier under the slab", basis=TOLD)]
    ranked3 = v3.rank(ls3, "radon barrier")
    fails += not check("equal match -> higher trust basis first",
                       ranked3[0].basis, TOLD)

    # non-matching lessons are kept (appended), never dropped.
    ls4 = [L("about the lease"), L("about radon")]
    ranked4 = v3.rank(ls4, "radon")
    fails += not check("rank keeps all lessons (matches + rest)",
                       sorted(l.text for l in ranked4),
                       ["about radon", "about the lease"])
    fails += not check("rank surfaces the match first", ranked4[0].text, "about radon")

    # empty / stopword-only query -> pure trust order, nothing lost.
    ls5 = [L("alpha", basis=INFERRED), L("beta", basis=TOLD), L("gamma", basis=OBSERVED)]
    ranked5 = v3.rank(ls5, "the a of")
    fails += not check("no query terms -> trust order (told first)",
                       [l.basis for l in ranked5], [TOLD, OBSERVED, INFERRED])

    # the lexical fallback, exercised directly, must still rank the match first.
    lex = _lexical_rank(ls4, "radon")
    fails += not check("lexical fallback ranks the match first",
                       lex[0].text, "about radon")

    # ---- (d) _relevant prunes a large vault to the relevant slice ----------
    print("\n_RELEVANT: PRUNE A LARGE VAULT")
    from rosco import roster  # noqa: E402
    from rosco.agent import Agent, GROUNDING_CAP  # noqa: E402
    # pick any real captain from the roster so the Agent ctor is happy
    cap_agent = roster.roster()[0]
    ag = Agent(cap_agent.name, fresh(), think=lambda *a, **k: "")

    small = [L("just one fact about radon")]
    fails += not check("small vault returned whole", ag._relevant(small, "radon"), small)

    # build > cap chars of noise + one needle, all same basis so only text matters.
    needle = L("the blower door test measured 2.9 ACH50 airtightness")
    noise = [L(f"filler lesson number {i} about lumber and drywall and siding {i}")
             for i in range(400)]
    big = noise + [needle]
    total = sum(len(l.text) for l in big)
    fails += not check("test corpus really exceeds the cap", total > GROUNDING_CAP, True)
    pruned = ag._relevant(big, "ACH50 airtightness blower")
    fails += not check("pruned set fits the char budget",
                       sum(len(l.text) for l in pruned) <= GROUNDING_CAP + max(len(l.text) for l in big),
                       True)
    fails += not check("the query-relevant needle survives the prune",
                       any("ACH50" in l.text for l in pruned), True)
    fails += not check("prune actually dropped noise", len(pruned) < len(big), True)

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
