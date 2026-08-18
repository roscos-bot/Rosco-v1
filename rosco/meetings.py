"""Auto-ingest SteelHaven's weekly tactical meeting transcripts.

Google Meet drops a transcript Doc into the organiser's Drive after each meeting.
This watches the SteelHaven Workspace Drive for new ones, distils each into a
compact shorthand (decisions, action items + owners, numbers, open threads — the
gist HavenMind can lean on, never the raw transcript), and learns it straight into
the SteelHaven vault. No review step: Ross asked for it to run on its own.

WHY IT IS STILL SAFE. The lesson is written OBSERVED, not TOLD — Rosco watched the
meeting; it is not putting words in Ross's mouth, and an OBSERVED write needs only
the node's own signature (a TOLD one would need Ross's, and rightly). Nothing here
is outward-facing: it reads a transcript and writes a note. And every ingest also
appends a `meeting.ingested` marker, which is both the dedup key (one per
transcript file id, so a re-scan never learns the same meeting twice) and the
ledger entry, so a no-review pipeline still leaves Ross an honest record of exactly
what was pulled in and when.

PREREQUISITES (until both are true, this is a well-behaved no-op):
  1. The SteelHaven Google account (ross@steelhaven.homes) is connected to Rosco —
     access_for() returns '' otherwise and this returns connected=False.
  2. Meet transcripts are turned on for the SteelHaven Workspace, so a transcript
     Doc actually lands in Drive.
"""
from __future__ import annotations

from . import knowledge, sources
from .adapters import google as g
from .vault import OBSERVED, Vault

STEELHAVEN = "steelhaven"
# The meeting-title fragment to watch, so a weekly-tactical watcher doesn't pull
# every Meet in the workspace. "" would take every transcript.
MATCH = "Tactical"
TRANSCRIPT_CAP = 24000       # chars of transcript fed to the distiller


def _seen(log) -> set:
    """Transcript file ids already ingested — the dedup set, from the ledger."""
    out = set()
    for ev in log.replay(kind="meeting.ingested"):
        b = ev.get("body") or {}
        f = b.get("file") if isinstance(b, dict) else None
        if f:
            out.add(f)
    return out


def _distill(models, meter, transcript: str) -> str:
    """A tight shorthand of one meeting — the durable knowledge, not the raw text.
    Empty string if no workhorse model is reachable (then the caller keeps a stub
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


def ingest_new(console, passphrase, *, match: str = MATCH) -> dict:
    """Find NEW SteelHaven Meet transcripts and learn each into the SteelHaven
    vault. Returns {connected, ingested, skipped, names}. Best-effort throughout:
    a connector hiccup on one transcript skips that one, never the batch, and an
    unconnected account is a clean no-op, not an error."""
    from .meter import Meter
    from .models import Models

    log = console.open(passphrase)
    vault = Vault(log, key=console._vault_key(passphrase))
    token = g.access_for(vault, STEELHAVEN)
    if not token:
        return {"connected": False, "ingested": 0, "skipped": 0, "names": []}

    models, meter = Models(log, vault), Meter(log)
    seen = _seen(log)
    captain = knowledge._captain(STEELHAVEN) or "HavenMind"
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
    return {"connected": True, "ingested": ingested, "skipped": skipped, "names": names}
