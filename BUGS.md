# Bug hunt — 2026-08-15

An end-to-end review of Rosco (my 6 hands-on findings + a 9-agent subsystem
sweep, deduped). 24 distinct issues, 26 proven by actually running the code.
22 fixed across commits `3b5575d`, `119ff47`, `840367e`, `404652a`; 2 held for a
design decision (below). Every fix was re-verified with an isolated repro or the
test suite before commit.

## Fixed

### High
- **#1 Ingest dropped/merged short facts** — `knowledge.py` `_is_heading`/`_chunks`.
  A short, punctuation-free line (`0.3 pCi/L radon`, `John Donati`) was classed a
  heading and dropped (trailing) or merged into adjacent facts. Now a plain line
  is a heading only when real content follows; a trailing heading is emitted.
- **#2 `recall()` served a stale correction** — `vault.py`. The fixpoint budget
  shrank with `pending`, so a reverse-ordered correction chain depth ≥3 dropped
  the newest edit. Budget captured once up front.
- **#3 Trust ladder never learned from bulk/triage** — `ingest.py` / `web.py`.
  Scoring compared against the stale queue-time proposal (`''` for triage/drive,
  `system` for github-bulk). `decide()` now takes the preview's actual suggestion.
- **#4 Higgsfield returned a non-image URL as the image** — `higgsfield.py`.
  Image-extension URLs only; poll no longer ends on a `processing` self-link.

### Medium
- **#5** `_salvage_objects` crashed on malformed `confidence` — `web.py` (guarded).
- **#6** valid JSON without `i` dropped every proposal — `web.py` (positional fallback).
- **#7** adding a `Business` without a `_BENCH` entry crashed `roster()` — `roster.py` (`.get`).
- **#8** malformed POST body crashed the handler pre-auth — `web.py` (guard + non-dict reject).
- **#9** `Log` sqlite connection thread-affine — `store.py` (`check_same_thread=False`).
- **#10** local ollama vision hit `api.openai.com` — `llm.py` (OLLAMA branch added).
- **#11** `see()` retry missed cold-connect timeouts — fixed via #12's normalization.
- **#12** raw `URLError` escaped `safehttp` — normalized to TimeoutError/ValueError.
- **#13** stranger who sent a photo got a false "Passed to Ross" & wasn't logged — `telegram.py`.
- **#14** ingest capture had no dedup (flood) — `telegram.py` (text+source dedup).
- **#15** vision read non-idempotent on redelivery — `telegram.py` (at-most-once file_id log).
- **#16** graph drag fired a select — `web_app.js` (>5px movement guard).
- **#17** batch-review ✗ pre-selected the rejected business — `web_app.js` (defaults to skip).
- **#19** no request-body size cap — `web.py` (`MAX_BODY`, 413).

### Low
- **#21** ingest banner showed literal `U0001f4e5` — `web_app.js` (→ 📥).
- **#22** provider/ingest errors double-escaped (`esc()`→`textContent`) — `web_app.js` (×3).
- **#23** `chat_post` blank/ambiguous space posted to the first space — `web.py`.
- **#24** `ingest_autoplace` swallowed errors (false `ok:true`); `sources.have()` raised
  where save/load degrade; stale roster inbox counts + `_BENCH` comment.

## Held for a decision (NOT yet changed)
- **#18 `ACTION:gmail_draft` / `ingest` auto-execute from a model marker**, and
  connector-fetched Gmail/Drive/Chat bodies are fed to the model without a
  "data, not instructions" guard — a prompt-injection payload in a read email
  could steer the model to emit a draft that fires autonomously. Contradicts
  "agents propose, humans ship." `web.py` ~378. *Recommended:* gate gmail_draft
  behind the same confirm step as other writes + wrap connector content.
- **#20 `_relevant` lets low-trust INFERRED lessons crowd out firm TOLD facts**
  once the vault exceeds the 12k grounding cap — `agent.py` ~143. *Recommended:*
  reserve part of the budget for TOLD, or make the trust weight dominant.

## Follow-ups noted (not bugs)
- Telegram vision read still blocks the poll loop while it runs; now safe to move
  off-thread since #9 is fixed, but left synchronous (fast after image-shrink).
- `console.py` has an uncommitted `_google_context` feature (your own in-progress
  work) — left untouched. Its docstring carries the same stale "six" inbox count
  fixed in `roster.py`.
