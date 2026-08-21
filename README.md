# Rosco — a personal permission system with a face

Rosco is a single-user "second brain" and chief-of-staff: a fleet of ranked agents,
one per business, that **read, draft, and propose — but never send, publish, or
ship on their own**. A person does that. It runs entirely on your machine, behind
a passphrase, and answers to you at a local web console.

The whole system is a projection of one thing: an **append-only, hash-chained
event log**. Grants, learning, encrypted secrets, model choices — all of it is
events, replayed into state. Nothing is a mutable row you can quietly change; a
change is a new signed event, and the chain either verifies or it doesn't.

## Run it

```bash
python -m rosco init          # one-time: create the vault, set your passphrase
python -m rosco web           # the local console at http://127.0.0.1:8787
```

`rosco web` hot-reloads code edits **in place** — your unlocked session survives a
save, so you can develop against a live console without re-unlocking. Pass
`--no-reload` for a plain, stable process.

Data lives in `~/.rosco` (the log `rosco.db`, `trust.json`, the sealed key, the
salt) — **never** in this repo. Those files are the keys to everything and are
git-ignored.

## Layout

| Path | What it is |
|---|---|
| `rosco/store.py`, `keys.py` | the append-only log, the closed event vocabulary, signatures |
| `rosco/vault.py` | encrypted secrets + attributable, siloed lessons |
| `rosco/grants.py`, `identity.py`, `arrive.py`, `classify.py` | the doorway: who's asking, what for, may they |
| `rosco/agent.py`, `roster.py`, `knowledge.py` | the agents, their ranks, what each business knows |
| `rosco/models.py`, `llm.py`, `safehttp.py` | model choice per role, and the one hardened outbound path |
| `rosco/ingest.py` | reviewed ingestion — learn one item at a time |
| `rosco/adapters/google.py` | Google Workspace connector (Gmail / Drive / Calendar / Sheets / Contacts / Chat) |
| `rosco/web.py`, `web_app.html`, `web_app.js` | the localhost console: 3D mesh, queue, chat, settings |
| `tests/` | `test_core.py`, `test_web.py`, `test_recall_fts.py`, `test_inbox_watch.py`, `test_google_guard.py`, `test_drive_write.py` — the safety suites |

## The rules that don't bend

- **Agents propose, people ship.** Reads run live; every write only drafts (a
  Gmail draft) or proposes-then-waits-for-a-yes. Nothing outward-facing fires on
  its own.
- **Only the passphrase-holder acts, and it never touches disk.** The console is
  127.0.0.1-only, unlock-once, CSRF-gated, and treats the local browser as hostile
  terrain (DNS-rebind guard, no inline script).
- **Closed vocabularies.** An undeclared event kind, body shape, or capability is
  refused at write, replay, and absorb — a compromised node can't invent authority.
- **One hardened HTTP path** (`safehttp`): https-only, no redirects, no internal
  targets, size-capped — so a credential can't be walked off by a 3xx.

See `DESIGN.md` for the why, `SETUP.md` for first-run details, and `WORKSTREAMS.md`
for what's built and what's next.

## Tests

```bash
python tests/test_core.py
python tests/test_web.py
python tests/test_recall_fts.py
python tests/test_inbox_watch.py
python tests/test_google_guard.py
python tests/test_drive_write.py
```

Every one must print `ALL PASS`. The HOSTILE sections are regression tests for real
findings from the adversarial audits — don't weaken them without understanding
what they caught.
