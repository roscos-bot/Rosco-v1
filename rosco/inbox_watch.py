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


# Labels whose delta is worth attributing to a sender. Kept next to _classify so
# the two never drift: run() uses this to skip a fetch on pure no-ops (an arrival,
# a CATEGORY_* toggle), and _classify returns non-None on EXACTLY this set — so the
# pre-filter can only ever drop messages _classify would have ignored anyway.
def _touches(added: set, removed: set) -> bool:
    return bool(added & {"TRASH", "SPAM", "STARRED"} or {"INBOX", "UNREAD"} & removed)


def _classify(added: set, removed: set, labels: set):
    """One message's net label delta (+ its CURRENT labels) → an engagement action,
    or None to ignore. Pure and total, so the ranker's signal is unit-testable
    without touching Google.

    The order is a priority ladder — a stronger act wins over a weaker one that
    happened in the same window (reading something then trashing it is 'trash', not
    'read'). The subtle one is clearing the inbox: that only counts AGAINST a sender
    when Ross never read the message. Read-then-file (UNREAD dropped this window) and
    filing a message that was already read (a paid bill — no UNREAD left on it) are
    engagement ('file'); only a message still UNREAD was dismissed unseen ('archive').
    """
    if "TRASH" in added:      return "trash"
    if "SPAM" in added:       return "spam"
    if "STARRED" in added:    return "star"
    if "INBOX" in removed:
        return "file" if ("UNREAD" in removed or "UNREAD" not in labels) else "archive"
    if "UNREAD" in removed:   return "read"      # opened / marked read, kept in inbox
    return None


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
                "and I'll note what you read, filed, archived and starred.")

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
    # Filter to messages whose labels actually changed in a way we score BEFORE
    # capping, so window arrivals (the bulk of a busy session) don't burn the budget
    # — the old code sliced first and let no-ops crowd out real actions. The cap
    # itself sits near gmail_changes' own ~300-record page ceiling; a bulk inbox-zero
    # sweep is exactly when Ross acts most, so if it's still exceeded we DISCLOSE the
    # shortfall in the reply rather than dropping the tail silently (each kept item
    # is one metadata fetch, so this also bounds how long "done" can hang).
    _CAP = 250
    touched = [(mid, d) for mid, d in (changes.get("transitions") or {}).items()
               if _touches(d.get("added", set()), d.get("removed", set()))]
    dropped = max(0, len(touched) - _CAP)
    for mid, delta in touched[:_CAP]:
        added, removed = delta.get("added", set()), delta.get("removed", set())
        # One metadata fetch gives BOTH the sender and the message's current labels;
        # _classify needs the labels to tell a read-then-filed message from a
        # dismissed-unread one.
        frm, labels = g.gmail_from_labels(token, mid)
        dom = _domain(frm)
        if not dom:
            continue
        action = _classify(added, removed, labels)
        if action is None:                               # _touches guarantees not None
            continue
        try:
            log.append("inbox.acted", {"domain": dom, "action": action, "via": "gmail"},
                       subject=dom, actor="ross")
            recorded += 1
            tally[action] += 1
        except Exception:
            pass
    if not recorded:
        note = ""
        if dropped:
            note = (f" (That was a big session — {dropped}+ changes were past what I "
                    "could read back in one pass.)")
        return ("Done — I didn't spot anything to note (nothing read, filed, archived "
                "or starred)." + note)
    order = (("read", "read"), ("file", "filed"), ("star", "starred"),
             ("archive", "archived unread"), ("trash", "trashed"), ("spam", "marked spam"))
    bits = [f"{tally[a]} {lab}" for a, lab in order if tally[a]]
    reply = ("✓ Noted what you did in email — " + ", ".join(bits)
             + ". I'll rank those senders by how you actually treat them.")
    if dropped:
        reply += (f" (Heads up: that was a big session — I tallied the first {_CAP}; "
                  f"~{dropped} more went uncounted, so do it in smaller passes if you "
                  "want every one to land.)")
    return reply


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
