"""The Google own-domain identity guard — proves a token wired to the WRONG login
is refused before it can read another company's mailbox.

Background: the vault seals whatever refresh token the OAuth consent returned; it
can't know the token is the RIGHT company's. RUM's token got sealed under the
'steelhaven' slug and read RUM's mail under the SteelHaven label with no warning.
The read side now proves identity (live userinfo) and fails closed on a mismatch.

Pure/stubbed — whoami and access_for are monkeypatched, so no real HTTP.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco.adapters import google as g  # noqa: E402


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"   got {got!r} want {want!r}"))
    return ok


class FakeVault:
    """Just enough for access_for_verified: it only reads the refresh token."""
    def __init__(self, rt="rt"):
        self._rt = rt

    def get_secret(self, account, name):
        return self._rt if name == g.REFRESH_TOKEN else "x"


def _email(addr):
    return lambda _tok: {"email": addr}


def _boom(_tok):
    raise RuntimeError("userinfo down")


def _forbidden(_tok):
    raise AssertionError("whoami must NOT be called for a shared/personal slug")


def main() -> int:
    fails = 0

    print("EXPECTED DOMAIN (roster is the single source of truth)")
    fails += not check("steelhaven -> steelhaven.homes", g._expected_domain("steelhaven"), "steelhaven.homes")
    fails += not check("rum -> rumachines.com", g._expected_domain("rum"), "rumachines.com")
    fails += not check("personal -> '' (nothing to enforce)", g._expected_domain("personal"), "")
    fails += not check("unknown slug -> ''", g._expected_domain("nope"), "")

    print("\nACCOUNT EMAIL (live userinfo, cached on the refresh-token fingerprint)")
    g._whoami_cache.clear()
    calls = {"n": 0}

    def counting(_tok):
        calls["n"] += 1
        return {"email": "ross@steelhaven.homes"}
    g.whoami = counting
    fails += not check("resolves the token's real email", g.account_email("acc", "rtA"), "ross@steelhaven.homes")
    fails += not check("second call served from cache (no 2nd userinfo)",
                       (g.account_email("acc", "rtA"), calls["n"]), ("ross@steelhaven.homes", 1))
    g.whoami = _boom
    fails += not check("a userinfo blip trusts the last good cached email",
                       g.account_email("acc", "rtA"), "ross@steelhaven.homes")
    fails += not check("no cache + userinfo down -> '' (never guesses an identity)",
                       g.account_email("acc", "rt-never-seen"), "")

    print("\nACCESS_FOR_VERIFIED (prove the login before handing back the token)")
    g._whoami_cache.clear()
    g.access_for = lambda _v, _a: "live-token"
    g.whoami = _email("ross@rumachines.com")
    fails += not check("wrong login is BLOCKED and the actual email is surfaced",
                       g.access_for_verified(FakeVault("rt-rum"), "steelhaven", "steelhaven.homes"),
                       ("", "ross@rumachines.com"))
    g._whoami_cache.clear()
    g.whoami = _email("ross@steelhaven.homes")
    fails += not check("right login returns the token",
                       g.access_for_verified(FakeVault("rt-shh"), "steelhaven", "steelhaven.homes"),
                       ("live-token", ""))
    g.whoami = _forbidden
    fails += not check("personal (no expected domain) passes through, no userinfo call",
                       g.access_for_verified(FakeVault("rt-psn"), "personal", ""),
                       ("live-token", ""))
    g.access_for = lambda _v, _a: ""
    fails += not check("not connected -> ('', '')",
                       g.access_for_verified(FakeVault(), "steelhaven", "steelhaven.homes"),
                       ("", ""))

    print("\nACCESS_FOR_GUARDED (str contract; fail CLOSED on own-domain mismatch)")
    g._whoami_cache.clear()
    g.access_for = lambda _v, _a: "tok"
    g.whoami = _email("ross@rumachines.com")
    fails += not check("own-domain wrong login -> '' (fail closed, reads nothing)",
                       g.access_for_guarded(FakeVault("rt-1"), "steelhaven"), "")
    g._whoami_cache.clear()
    g.whoami = _email("ross@steelhaven.homes")
    fails += not check("own-domain right login -> the token",
                       g.access_for_guarded(FakeVault("rt-2"), "steelhaven"), "tok")
    g.whoami = _forbidden
    fails += not check("personal -> token pass-through (no userinfo call)",
                       g.access_for_guarded(FakeVault("rt-3"), "personal"), "tok")

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURES'}\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
