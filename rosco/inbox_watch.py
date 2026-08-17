"""Bracketed Gmail-session learning — shared by the console chat AND Telegram.

Ross says "about to check my email" / "done"; Rosco snapshots the mailbox history
cursor on start and, on stop, diffs it and folds what he ACTUALLY did (read /
archive / star / trash) into the engagement signal the importance ranker uses. It
only ever reads Ross's OWN account — the forgery-resistant behaviour the ranker is
built on (a sender can't lift its own score; only Ross's real action moves it).

This lives here, not on the web ConsoleServer, for one reason: "about to check my
email" most naturally happens FROM THE PHONE. Telegram is a read/notify channel
(never an approval surface), and this is a pure read, so the same call backs both
surfaces — the console chat (model-driven) and the Telegram bot (phrase-driven).
"""
from __future__ import annotations

import re
from collections import Counter

from .adapters import google as g
from .vault import Vault

_DOMAIN = re.compile(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def _domain(frm: str) -> str:
    m = _DOMAIN.search(frm or "")
    return m.group(1).lower() if m else ""


def run(console, passphrase, state) -> str:
    """Open ('start') or close ('stop') a watch. Returns the Ross-facing reply."""
    log = console.open(passphrase)
    account = "personal"
    if f"{account}:{g.REFRESH_TOKEN}" not in set(Vault(log).secret_names()):
        return "(personal Google isn't connected — connect it in Settings first.)"
    try:
        token = g.access_for(Vault(log, key=console._vault_key(passphrase)), account)
    except Exception as e:
        return "(couldn't reach Google — " + str(e)[:120] + ")"
    if not token:
        return "(couldn't sign in to Google.)"
    state = (state or "").strip().lower()

    if state == "start":
        hid = g.gmail_history_id(token)
        if not hid:
            return "(couldn't read the mailbox cursor — try again in a moment.)"
        log.append("email.watch", {"state": "open", "historyId": hid},
                   subject="email", actor="ross")
        return ("\U0001f440 Watching your inbox — go ahead. Tell me when you're done "
                "and I'll note what you read, archived and starred.")

    # stop: find the latest still-open watch (a later 'closed' cancels an 'open')
    start_hid = ""
    for ev in log.replay(kind="email.watch"):
        b = ev.get("body") or {}
        if b.get("state") == "open":
            start_hid = str(b.get("historyId") or "")
        elif b.get("state") == "closed":
            start_hid = ""
    if not start_hid:
        return ("I wasn't watching — say \"about to check my email\" first, then "
                "\"done\" when you finish, and I'll learn from what you did.")
    try:
        changes = g.gmail_changes(token, start_hid)
    except Exception as e:
        return "(couldn't read the changes back — " + str(e)[:120] + ")"
    log.append("email.watch", {"state": "closed"}, subject="email", actor="ross")
    if changes is None:
        return ("That window was open too long for Gmail's change log, so I couldn't "
                "read it back. I've closed the watch — next time, say 'done' within "
                "the day and I'll catch it.")
    tally, recorded = Counter(), 0
    for mid, delta in list((changes.get("transitions") or {}).items())[:120]:
        added, removed = delta.get("added", set()), delta.get("removed", set())
        if "TRASH" in added:      action = "trash"
        elif "SPAM" in added:     action = "spam"
        elif "STARRED" in added:  action = "star"
        elif "INBOX" in removed:  action = "archive"     # cleared from the inbox
        elif "UNREAD" in removed: action = "read"        # opened / marked read, kept
        else:                     continue
        dom = _domain(g.gmail_from(token, mid))
        if not dom:
            continue
        try:
            log.append("inbox.acted", {"domain": dom, "action": action, "via": "gmail"},
                       subject=dom, actor="ross")
            recorded += 1
            tally[action] += 1
        except Exception:
            pass
    if not recorded:
        return "Done — I didn't spot anything to note (nothing read, archived or starred)."
    order = (("read", "read"), ("archive", "archived"), ("star", "starred"),
             ("trash", "trashed"), ("spam", "marked spam"))
    bits = [f"{tally[a]} {lab}" for a, lab in order if tally[a]]
    return ("✓ Noted what you did in email — " + ", ".join(bits)
            + ". I'll rank those senders by how you actually treat them.")


# Telegram has no model in the loop, so it recognises the bracket by phrase. Kept
# CONSERVATIVE on purpose: a short, clear announcement — not a request that merely
# mentions email ("check the email from John", "what's in my inbox?"). A miss just
# falls through to the doorway; the console chat, which IS model-driven, understands
# arbitrary wording. False start/stop is low-harm (a watch you can just re-close).
_MAIL = re.compile(r"\b(e-?mails?|inbox|gmail)\b")
_STOP = re.compile(r"\b(done|finished|caught up|wrapped up|inbox zero|all set)\b")
_START = re.compile(r"\b(check|checking|start|starting|going through|go through|"
                    r"read|reading|doing|do|into|open|opening|hop into|jump into)\b")
# Idioms that end an email session ON THEIR OWN (no mail word needed). Keeping this
# an explicit set — rather than 'any _STOP match with a short message' — is what
# stops "finished the report" from falsely closing a watch.
_BARE_STOP = {"done", "all done", "finished", "all finished", "caught up",
              "all caught up", "inbox zero", "wrapped up", "all set",
              "email done", "inbox done", "emails done"}


def intent(text) -> str | None:
    """'start' | 'stop' | None — the email-session bracket, from a short phrase."""
    t = (text or "").strip().lower().rstrip(" .!")
    if not t or "?" in t or len(t.split()) > 6:
        return None
    has_mail = bool(_MAIL.search(t))
    if t in _BARE_STOP or (_STOP.search(t) and has_mail):
        return "stop"
    if _START.search(t) and has_mail:
        return "start"
    return None
