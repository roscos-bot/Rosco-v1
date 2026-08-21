"""Prove the Drive write path against REAL Google. Ross runs this; it needs the
passphrase, the network, and (with --write) it really does create things.

Everything in tests/ stubs Google, so the request SHAPES are verified but Google's
actual answers are not. This closes that gap. It is deliberately not in tests/:
it is not a unit of the safety suite, it cannot run unattended, and one of its
phases writes to a real Drive.

    python tools/live_drive_check.py                      # read-only, safe
    python tools/live_drive_check.py --account steelhaven # a different Drive
    python tools/live_drive_check.py --write              # also uploads one file
    python tools/live_drive_check.py --write --share a@b.com   # ...and shares it

READ-ONLY BY DEFAULT. Run it bare as often as you like: it resolves the token,
proves which Google account it really signs in as, checks the granted SCOPES, and
reads the Drive. Nothing is created until you pass --write, and nothing is ever
shared until you pass --share with an address.

WHAT --write LEAVES BEHIND. One folder named 'Rosco Live Check' and one small
text file in it. There is no delete in the connector on purpose - the agents
place files, they do not remove them - so tidy up in the Drive UI. The link is
printed for exactly that.
"""
from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosco import safehttp                      # noqa: E402
from rosco.adapters import google as g          # noqa: E402
from rosco.console import Console               # noqa: E402
from rosco.deliverables import folder_for, folders  # noqa: E402
from rosco.roster import business as biz_of     # noqa: E402
from rosco.vault import Vault                   # noqa: E402

FOLDER = "Rosco Live Check"
NEEDED_SCOPE = "https://www.googleapis.com/auth/drive"


def ok(msg):
    print(f"  ok    {msg}")


def bad(msg):
    print(f"  FAIL  {msg}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account", default="all",
                    help="vault slug to check, or 'all' for every connected "
                         "account in one pass (default: all)")
    ap.add_argument("--write", action="store_true",
                    help="actually create a folder and upload one small file")
    ap.add_argument("--share", default="",
                    help="also share the uploaded file with this ONE email address")
    args = ap.parse_args()

    console = Console()
    if not console.initialised:
        return bad("not initialised - run `python -m rosco init` first")
    # ONE passphrase prompt for the whole sweep. Every account resolves from the
    # same unlocked vault, so proving personal + rum + steelhaven costs one typing
    # of it rather than three.
    pw = getpass.getpass("passphrase: ")
    try:
        log = console.open(pw)
        vault = Vault(log, key=console._vault_key(pw))
    except Exception as e:
        return bad(f"could not unlock: {e}")

    held = set(Vault(log).secret_names())
    connected = [s for s in ("personal", "rum", "steelhaven")
                 if f"{s}:{g.REFRESH_TOKEN}" in held]
    if args.account.strip().lower() == "all":
        accounts = connected
        if not accounts:
            return bad("no account has a refresh token sealed - authorize one in Settings")
    else:
        accounts = [args.account.strip().lower()]

    total = 0
    for i, acct in enumerate(accounts):
        if i:
            print("\n" + "=" * 62)
        total += run_account(console, log, vault, held, acct, args)
    print("\n" + "=" * 62)
    print(f"SWEEP: {len(accounts)} account(s) checked, {total} failure(s)")
    print("=" * 62 + "\n")
    return 1 if total else 0


def run_account(console, log, vault, held, account, args) -> int:
    b = biz_of(account)
    if account != "personal" and b is None:
        return bad(f"{account!r} is not a business in the roster")
    if b is not None and not b.own_domain and account != "personal":
        print(f"note: {account} shares the personal mailbox; using 'personal'")
        account, b = "personal", None

    fails = 0
    print(f"\nACCOUNT: {account}")
    for name in (g.CLIENT_ID, g.CLIENT_SECRET, g.REFRESH_TOKEN):
        if f"{account}:{name}" not in held:
            return bad(f"{account}:{name} is not in the vault - authorize it in Settings first")
    ok("client id, secret and refresh token are all sealed")

    print("\n1. THE TOKEN, THROUGH THE SAME GUARD A WRITE USES")
    try:
        token = g.access_for_guarded(vault, account)
    except Exception as e:
        return bad(f"access_for_guarded raised: {e}")
    if not token:
        return bad(f"the guard refused: {account}'s credential does not sign in as "
                   f"{account}. Re-authorize it in Settings. (This is the guard "
                   f"working, not a bug.)")
    ok(f"a live access token came back ({len(token)} chars, not shown)")

    print("\n2. WHO IT REALLY IS")
    try:
        who = g.whoami(token)
        email = who.get("email", "") if isinstance(who, dict) else ""
    except Exception as e:
        return bad(f"userinfo failed: {e}")
    if not email:
        return bad("userinfo returned no email")
    ok(f"signs in as {email}")
    if b is not None and b.own_domain:
        want = b.account.split("@")[-1].lower()
        if email.split("@")[-1].lower() != want:
            fails += bad(f"but {account} expects the {want} domain")
        else:
            ok(f"which is the {want} domain {account} expects")

    print("\n3. THE SCOPES GOOGLE ACTUALLY GRANTED")
    # The one thing that silently breaks writes: a token minted before Drive was
    # a full scope still READS fine and 403s on the first upload. Ask up front.
    try:
        info = safehttp.call(
            "https://oauth2.googleapis.com/tokeninfo?access_token=" + token,
            method="GET", timeout=20)
        granted = str(info.get("scope", "")).split()
    except Exception as e:
        granted = []
        print(f"  note  couldn't read tokeninfo ({str(e)[:80]}); carrying on")
    scope_ok = True
    if granted:
        if NEEDED_SCOPE in granted:
            ok(f"{NEEDED_SCOPE} is granted - writes are permitted")
        else:
            scope_ok = False
            drive_ish = [s for s in granted if "drive" in s]
            fails += bad(f"NO full Drive scope. Granted drive scopes: {drive_ish or 'none'}. "
                         f"Re-authorize this account in Settings to pick up "
                         f"{NEEDED_SCOPE}.")

    print("\n4. READING THE DRIVE")
    try:
        recent = g.drive_recent(token, 5)
    except Exception as e:
        return bad(f"drive_recent failed: {e}")
    ok(f"listed {len(recent)} recent file(s)")
    for f in recent[:3]:
        print(f"        - {str(f.get('name',''))[:60]}")

    print("\n5. THE CONVENTIONS DECLARED FOR THIS ACCOUNT")
    declared = folders(account)
    print(f"        folders: {', '.join(declared) if declared else '(none)'}")
    for probe in ("plan-set-rev3.pdf", "hull-v2.step", "IMG_4021.jpg", "scan0001.pdf"):
        fold, why = folder_for(account, probe)
        print(f"        {probe:<22} -> {fold:<18} ({why})")

    if not args.write:
        print("\nREAD-ONLY: everything above is proven; nothing was created.")
        print("Add --write to prove the upload path for real.")
        return fails

    if not scope_ok:
        # The scope check exists precisely so a write is not attempted against a
        # token that cannot do it. Flagging and then uploading anyway would turn a
        # clear answer back into the confusing 403 this was meant to prevent.
        print("\nSKIPPING THE WRITE: the token lacks the Drive scope (see 3).")
        return fails

    print("\n6. FIND OR CREATE THE FOLDER  [WRITES]")
    try:
        hit = g.drive_find_folder(token, FOLDER)
        if hit and hit.get("id"):
            parent = hit["id"]
            ok(f"{FOLDER!r} already exists ({parent})")
        else:
            made = g.drive_create_folder(token, FOLDER)
            parent = made.get("id", "")
            if not parent:
                return bad("create returned no folder id")
            ok(f"created {FOLDER!r} ({parent})")
    except Exception as e:
        return bad(f"folder step failed: {e}")

    print("\n7. THE RESUMABLE UPLOAD  [WRITES]")
    # This is the phase the stubs could not prove: a real Location header, a real
    # session URL, and the raw-body PUT that safehttp gained for it.
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    name = f"rosco-live-check-{stamp.replace(':', '')}.txt"
    payload = (f"Written by tools/live_drive_check.py at {stamp}.\n"
               f"Account: {account}. Safe to delete.\n").encode()
    try:
        up = g.drive_upload(token, name, payload, "text/plain", parent)
    except Exception as e:
        return bad(f"upload failed: {e}")
    fid = up.get("id", "")
    if not fid:
        return bad(f"upload returned no id: {up}")
    ok(f"uploaded {name} ({len(payload)} bytes) -> {fid}")
    if up.get("webViewLink"):
        print(f"        {up['webViewLink']}")

    print("\n8. VERIFY IT IS REALLY THERE")
    try:
        listing = g.drive_folder_files(token, parent)
    except Exception as e:
        return bad(f"could not list the folder back: {e}")
    match = [f for f in listing if f.get("id") == fid]
    if not match:
        fails += bad(f"the uploaded file is NOT in {FOLDER!r} - it went somewhere else")
    else:
        ok(f"found it in {FOLDER!r}, named {match[0].get('name','')!r}")
        ok(f"the folder now holds {len(listing)} file(s)")

    if args.share:
        print("\n9. SHARE WITH ONE NAMED PERSON  [WRITES]")
        try:
            g.drive_share(token, fid, args.share)
            ok(f"shared with {args.share} as reader (no notification email sent)")
        except Exception as e:
            fails += bad(f"share failed: {e}")
    else:
        print("\n9. SHARING SKIPPED (no --share given)")

    print(f"\n{'all live checks passed' if not fails else str(fails) + ' FAILURES'}"
          f" for {account}")
    print(f"Tidy up: delete {FOLDER!r} from {email}'s Drive when you're done.")
    return fails


if __name__ == "__main__":
    raise SystemExit(main())
