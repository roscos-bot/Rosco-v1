# Running several agents at once

The remaining work splits cleanly, and most of it doesn't touch the permission
core. That matters: parallel sessions are safe when they own different files and
dangerous when they don't.

## How to actually spin them up

**One Claude Code session per workstream.** Open a new session, point it at this
repo, and give it the scope line from the table below. That is the whole
mechanism — there's no separate orchestration to set up.

**Use a git worktree if two sessions will be editing at the same time.** Each
gets its own checkout of the same repo, so neither sees the other's half-finished
edits and neither can lose work to a conflicting write:

```bash
git worktree add ../rosco-console -b console
```

Then start the session in `../rosco-console`. When the branch merges, remove it
with `git worktree remove ../rosco-console`.

**Within one session,** say "use a workflow" to get fan-out across many subagents
for a single job — that's what the audits have been. Or invoke a named agent from
`.claude/agents/` directly.

## The rule that keeps them from colliding

**One session owns `rosco/` core at a time.** `store.py`, `keys.py`, `grants.py`,
`identity.py`, `vault.py`, `asks.py`, `nodes.py` are load-bearing and heavily
cross-referenced; two sessions editing them in parallel will produce a merge that
passes tests and violates a safety property. Everything else is fair game
concurrently.

Every session runs `python tests/test_core.py` before committing. All checks
pass or nothing lands.

## The workstreams

| Stream | Owns | Depends on | Notes |
|---|---|---|---|
| **The console** | `console/` | core (read-only) | Where Ross reads the queue and answers it. Holds his signing key. Only localhost changes anything, so this is also where authority lives. |
| **Telegram adapter** | `adapters/telegram.py` | `arrive.py` | Turns Telegram updates into `Arrival`s. Proposes only — never edits the system. |
| **Enrolment + Twilio** | `enrol/` | `identity.py` (read) | SMS-delivered invite links, the bot handshake, Ross's console pairing. See DESIGN.md. |
| **Unseal protocol** | `seal/` | `vault.py` (read) | Sealed-node boot, Telegram authorisation, peer transport, per-node secret wrapping. |
| **Excel export** | `export/` | `store.py` (read) | Bound-book export. Serial numbers as text cells, signed, self-describing. Shop and house only, never the cloud VM. |
| **Capability vocabulary** | `capabilities.py` | — | The seeded list is a guess at Ross's businesses. Needs correcting against reality. Small file, low conflict risk. |
| **Auditing** | `scratch/` only | everything | Uses the `effect-auditor` agent. Writes no production code — reports, and a human applies. |

## Testing, specifically

`tests/test_core.py` is not a unit-test suite; it is the safety properties written
down. Everything under a `HOSTILE` heading was live code once — each is a real
defect a real audit found, kept so it fails loudly if it comes back.

Two rules for anyone adding to it:

**Test the property, not the implementation.** "A blanket deny cuts off the exact
allow" survives a rewrite of `_match()`. "`_match` sorts by specificity" does not.

**Test both halves of everything.** The deny bug survived two audits because the
suite only ever exercised the GET half. If a rule has a verb, test both verbs. If
it has a direction, test both directions. If it has a wildcard, test the wildcard
*and* the exact.

## Agents available

`.claude/agents/effect-auditor.md` — audits by effect rather than mechanism. This
is the technique that found every critical so far; the file explains why, with the
actual history. Use it after any change to the core, the log, identity, the queue,
or the doorway.
