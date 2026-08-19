"""Auto-ingest SteelHaven's weekly tactical meeting transcripts — calendar-driven.

Google Meet drops a transcript Doc into the organiser's Drive a little while AFTER
a meeting ends. So rather than scan Drive on a blind timer, this is driven by the
CALENDAR: it looks for a tactical meeting that has ENDED and been given a grace
window (time for Meet to write the recap), and only then pulls the fresh
transcript from the SteelHaven Drive, distils it into a compact shorthand
(decisions, action items + owners, numbers, open threads — the gist Bessemer can
lean on, never the raw transcript), and learns it straight into the SteelHaven
vault. No review step: Ross asked for it to run on its own.

WHY IT IS STILL SAFE. The lesson is written OBSERVED, not TOLD — Rosco watched the
meeting; it is not putting words in Ross's mouth, and an OBSERVED write needs only
the node's own signature. Nothing here is outward-facing: it reads a transcript and
writes a note. Every ingest also appends a `meeting.ingested` marker, which is both
the dedup key (one per transcript file id, so a re-check never learns the same
meeting twice) and the ledger entry, so a no-review pipeline still leaves Ross an
honest record of exactly what got pulled in and when.

PREREQUISITES (until both are true, this is a well-behaved no-op):
  1. The SteelHaven Google account (ross@steelhaven.homes) is connected to Rosco —
     the calendar read AND the transcript pull both use its token.
  2. Meet transcripts are turned on for the SteelHaven Workspace, so a transcript
     Doc actually lands in Drive.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import knowledge, sources
from .adapters import google as g
from .vault import OBSERVED, Vault

STEELHAVEN = "steelhaven"
# The meeting-title fragment to watch, so the watcher keys off the tactical
# meeting and not every event/transcript in the workspace. "" would take any.
MATCH = "Tactical"
GRACE_MIN = 25               # minutes after a meeting ENDS before Meet's recap is ready
LOOKBACK_H = 6               # how far back a just-ended meeting still counts as "recent"
TRANSCRIPT_CAP = 24000       # chars of transcript fed to the distiller


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _past_grace(end_iso: str, now: datetime, grace_min: int) -> bool:
    """Has this event ended AND had its recap grace pass? A timed event is ready at
    end + grace; an all-day event is ready the day after. False on anything
    unparseable (better to wait than to pull an unwritten transcript)."""
    if not end_iso:
        return False
    try:
        s = end_iso.replace("Z", "+00:00")
        if "T" in s:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return now >= dt + timedelta(minutes=grace_min)
        return datetime.fromisoformat(s).date() < now.date()
    except Exception:
        return False


def _seen(log, vault=None) -> set:
    """Transcript file ids already ingested — the dedup set. Primarily the
    `meeting.ingested` ledger; but ALSO, belt-and-braces, the `meet:<id>` source of
    any already-learned SteelHaven lesson, so a transcript can never be re-learned
    even if its marker append ever failed (e.g. a stale process without the kind)."""
    out = set()
    for ev in log.replay(kind="meeting.ingested"):
        b = ev.get("body") or {}
        f = b.get("file") if isinstance(b, dict) else None
        if f:
            out.add(f)
    if vault is not None:
        try:
            for les in vault.recall(business=STEELHAVEN):
                src = les.source or ""
                if src.startswith("meet:"):
                    out.add(src[len("meet:"):])
        except Exception:
            pass
    return out


def _distill(models, meter, transcript: str) -> str:
    """A tight shorthand of one meeting — the durable knowledge, not the raw text.
    Empty string if no workhorse model is reachable (the caller then keeps a stub
    so the transcript is still cached and marked, never silently dropped)."""
    from .llm import NoModel, complete
    system = (
        "You are summarising a SteelHaven WEEKLY TACTICAL MEETING transcript into a "
        "compact, information-dense shorthand the SteelHaven agent will rely on "
        "later WITHOUT re-reading the transcript. Capture: decisions made; action "
        "items with their owner and due date; key numbers/dates; and open threads "
        "carried to next week. No filler, no quotes, no preamble — just the gist, a "
        "few tight lines.")
    try:
        return complete(models, "workhorse", system, transcript[:TRANSCRIPT_CAP],
                        meter=meter, max_tokens=500).strip()
    except NoModel:
        return ""
    except Exception:
        return ""


def ingest_new(console, passphrase, *, match: str = MATCH,
               grace_min: int = GRACE_MIN) -> dict:
    """Calendar-driven pull. If a tactical meeting has ended and had its recap
    grace, pull any new transcript from the SteelHaven Drive and learn it into the
    SteelHaven vault. Returns {connected, ready, waiting, ingested, skipped, names}.
    Best-effort throughout: an unconnected account or a hiccup is a clean no-op.

    The calendar answers 'should I look now?' (a tactical meeting just wrapped, its
    recap window has passed); Drive + the dedup ledger answer 'what's actually new?'
    """
    from .meter import Meter
    from .models import Models

    log = console.open(passphrase)
    vault = Vault(log, key=console._vault_key(passphrase))
    token = g.access_for(vault, STEELHAVEN)
    if not token:
        return {"connected": False, "ready": 0, "waiting": 0,
                "ingested": 0, "skipped": 0, "names": []}

    now = _utcnow()
    recent = g.calendar_recent_ended(token, match=match, hours_back=LOOKBACK_H)
    ready = [e for e in recent if _past_grace(e.get("end", ""), now, grace_min)]
    waiting = [e for e in recent
               if e.get("end") and not _past_grace(e["end"], now, grace_min)]
    if not ready:
        # No tactical meeting has finished-and-settled since last check — the
        # common case. `waiting` lets the caller show 'a meeting just ended, recap
        # pending' rather than looking idle.
        return {"connected": True, "ready": 0, "waiting": len(waiting),
                "ingested": 0, "skipped": 0, "names": []}

    models, meter = Models(log, vault), Meter(log)
    seen = _seen(log, vault)
    captain = knowledge._captain(STEELHAVEN) or "Bessemer"
    ingested = skipped = 0
    names: list[str] = []
    for f in g.drive_meet_transcripts(token, match=match):
        fid = f.get("id")
        name = f.get("name", "meeting")
        if not fid or fid in seen:
            skipped += 1
            continue
        try:
            text = g.drive_read(token, fid, f.get("mimeType", ""), max_chars=TRANSCRIPT_CAP)
        except Exception:
            text = ""
        if not (text or "").strip():
            skipped += 1
            continue
        shorthand = _distill(models, meter, text) or (name + " — transcript captured (no summary model).")
        try:
            vault.learn(captain, STEELHAVEN, shorthand, basis=OBSERVED, source=f"meet:{fid}")
            sources.save(console.home, f"meet:{fid}", text)   # offline copy of the transcript
            log.append("meeting.ingested", {"file": fid, "name": name},
                       subject=STEELHAVEN, actor="rosco")
            ingested += 1
            names.append(name)
        except Exception:
            skipped += 1
    return {"connected": True, "ready": len(ready), "waiting": len(waiting),
            "ingested": ingested, "skipped": skipped, "names": names}
