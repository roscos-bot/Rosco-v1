# Rosco's Second Brain — the decisions, and why

Written 14 Aug 2026, from a long design conversation with Ross. This is the
document to read before changing anything structural. It records *why* things
are the shape they are, because most of these choices look arbitrary until you
know what they were protecting against.

---

## What this is

One agent Ross talks to, standing over eight businesses. Other people — Brent,
Lucas, John, Grace, the tax team — reach it through channels they already use
(Telegram, Google Chat, email, phone). It works out who they are, what they may
have, and does one of four things. It exists so people stop asking Ross for
things he would have said yes to anyway.

It **replaces Jarvis V6 only**. shhsocial, shhops, the RUM inventory system and
sv-projects all survive untouched. V6 gets cannibalised — its good ideas are
carried over deliberately, listed at the bottom.

---

## The five decisions everything else follows from

### 1. The log is the only truth

`store.py` is an append-only, hash-chained event log. Grants, lessons, secrets,
decisions — all events. Every other structure in the system is a *replay*, held
in memory, never authoritative.

**Why:** the system will be wrong about something and Ross will need to know why
it did what it did. A mutable store answers "what does it think now"; a log
answers "what did it think in March, who told it that, and what changed." The
second question is the one that gets asked when an agent tells Lucas something
confidently wrong.

**The chain is per node, not global.** Each site hashes only its own events.
A global chain would require three sites to agree an order before any of them
could write, which fails the moment the internet drops — and Ross specifically
wants each site to keep working offline.

### 2. Only Ross grants

`give()`, `deny()` and `revoke()` raise `PermissionError` if the author is not
Ross. Not John for SteelHaven. Not Lucas for RUM. Not a person widening their
own scope.

**Why:** Ross's words — *"one hard rule, if you don't know what to allow or
disallow you ask me and only me for approval."* Delegating the power to say yes
is how a system ends up with more access than anyone remembers agreeing to. The
check is in the write path, not in a UI, so there is no path around it.

### 3. Unknown is never yes

An untaught request returns `ASK` and waits. Indefinitely. There is no timeout
that becomes an approval, and no inference from a neighbouring capability —
"Brent may see the spray log" tells us nothing about the BOM.

**Why:** this is the expensive rule and it is worth it. The failure mode it
prevents is the system quietly generalising one grant into a class of grants
nobody authorised. It costs Ross interruptions early and gets quieter every
week as grants accumulate — they are permanent until revoked, by his choice.

### 4. Four outcomes, not two

| | |
|---|---|
| `SELF` | they do it themselves, inside their grant. Nobody is interrupted. |
| `ANSWER` | Rosco answers on Ross's behalf, because he would have said the same. |
| `ASK` | nobody knows. It waits for Ross, and only Ross. |
| `DECLINE` | explicitly refused, and remembered so it stops reaching him. |

**Why four:** allow/deny loses the two cases that matter most in practice.
`ANSWER` is the whole point of the system — Grace asking whether the house is
armed should get an answer, not a tool. And `DECLINE` must be distinguishable
from silence, or a refused person waits forever for a no that already exists.

### 5. Channels are not equally trusted

`STRONG` = telegram, chat, console. `WEAK` = email, phone.

- A weak channel carrying a `DO` → downgraded to `ASK`.
- A weak channel carrying a `GET` that would be `SELF` → downgraded to `ANSWER`.

**Why:** a Telegram id was paired by Ross and cannot be forged. A `From:` header
is a suggestion and caller ID is worse — both are trivially spoofed. Ross's
instruction was that weak channels get *"higher approval rates."* The
implementation makes that structural rather than a matter of an agent's judgement
in the moment.

---

## The vault

Learning and secrets, one permissioned store, scoped to a business.

Every agent learns and stores it here — Ross's requirement. Lessons are text,
not vectors, deliberately: `to_markdown()` renders what an agent has concluded
about a business so Ross can read it, disagree with a line, and have that
disagreement become a correction. **A memory he cannot inspect is one he cannot
govern.**

**Basis is recorded on every lesson** — `TOLD` (Ross said so) > `OBSERVED`
(watched it happen) > `INFERRED` (worked it out, may be wrong). An agent that
cannot tell these apart will eventually present its own guess back to Ross as
his own instruction. Corrections default to `TOLD` by Ross, because a correction
that inherited the weak basis of the thing it replaced would be argued with by
the very agent it was meant to fix.

**Secrets** are encrypted at rest (HMAC-SHA256 CTR keystream, key derived by
PBKDF2 at 600k rounds). `secret_names()` works *without* the key on purpose — a
health check should be able to report that RUM has no QBO token yet without
being able to read the ones that do exist.

Encryption records its own scheme in the envelope (`hmac-sha256-ctr/1`) so a
stronger one can be introduced later without rewriting stored values.

---

## The order of battle

Rank encodes **blast radius**, not seniority theatre.

| Rank | Who | Reach |
|---|---|---|
| Commander | **Ross** — holds no rank in the roster | grants everything; cannot delegate it |
| Chief of Staff | **Rosco** | the only thing that sees across businesses |
| Captain ×8 | HavenMind, CaptainMorgan, Twain, Harrier, Scout, Argus, Ledger, Rosco | commands one business, convenes its bench |
| Lieutenant | law, marketing | advises inside one business, cannot see another |
| Quartermaster | the Nates (books) | books only |
| Warrant Officer | IT | technical specialist; advises, does not command |

Nothing skips a rung. A bench specialist escalates to its Captain, a Captain to
Rosco, Rosco to Ross, and there it stops. That chain is what prevents a lawyer
agent quietly deciding something that belonged to the man who owns the company.

**Rosco wears two hats** — Chief of Staff and Captain of Personal. It is the
only doubling, and it is why the cross-business enrichment check runs against
the *person who will read the answer*, not the agent that produced it.

**Hard silos:**
- RUM's **bound book** stays in RUM. No other org touches it — ATF record, not
  a business record.
- Never publicise: the Velent merger, financials/ownership splits, the flooring
  warranty issue.
- Agents never sign outbound as a real person. "Nate Salah" is internal naming
  only; it must never appear on something a third party receives.

---

## The shared-mailbox problem

Two businesses have their own domain. **Six share `rossfusz@gmail.com`:**
River City, Sugar Creek, 4x4 Explorers, Spring Valley, Finance, Personal.

Routing therefore **reads content, not the account it arrived on**. Getting this
wrong once filed a healthcare directive under a homebuilder. When routing is
genuinely ambiguous the answer is `ASK` — same rule as everything else.

---

## Nodes

Three sites, each with a UniFi-backed server: **RUM shop (W. Outer Rd)**,
**Spring Valley (home)**, and probably **a cloud VM**. Each keeps a full local
SQLite log and stays useful with the internet down.

Sync is absorb-only and idempotent on primary key — `absorb()` returns the count
actually taken, and running it twice moves zero. Because chains are per node,
absorbing a peer's events never invalidates your own chain.

---

## Still open

Recorded here so they are not silently decided by whoever writes the code next:

- **Budget ceiling** for LLM spend — not set.
- **Which job first** once the core lands — not chosen.
- **"Relevant" for Augie and Courtney** — Ross said family gets personal access
  "if they are relevant." Undefined, so it currently means `ASK`.
- **Ranks for sub-sub-agents**, if the bench ever grows one.

## Not yet built

In the order the top-down instruction implies:

1. `identity.py` — channel → person. A Telegram id is strong evidence; a
   `From:` header is a claim. This module must express that difference.
2. `nodes.py` — site registry, sync scheduling, offline behaviour.
3. The interaction layer — **locally saved, changeable LLM choice** (Ross's
   requirement), with agents trialling new models and asking for a key when they
   find one worth having.
4. Ingest — populate the vault from `.md` / `.ml` files.
5. Deliverables — 3D models and files uploaded to the right Drive, organised,
   and shared to the person who asked.
6. Tools each org can call: shhops, shhsocial, accounting, QBO (including
   browser control at the *business agent* level for transaction classification).

## Carried over from V6, deliberately

Worth keeping, and why: **control tags** (a clean way to steer behaviour without
prompt surgery) · **mission fan-out** (the cabinet pattern) · **consent-first
actions** · **vault-as-substrate** · **`patches/apply_patches.py`** (self-editing
that goes through review rather than around it) · **conversation mode on
localhost**.

And the hard-won operational rule from V6, which applies here without change:
**only localhost changes anything.** Telegram and the other remote channels may
*propose* work — they create a project Ross then works with locally. They cannot
edit the system. That separation is what makes a spoofable channel safe to leave
open.
