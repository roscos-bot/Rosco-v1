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

**What the hash does and does not do.** It proves *integrity* — a missing or
altered row is detectable on replay. It proves nothing about *authorship*: it is
unkeyed, so anyone who can write the table can rewrite a chain and recompute
every hash forward in milliseconds. An earlier version of `nodes.py` claimed
otherwise and was wrong. Authorship comes from the signatures, not the chain.

### 2. Only Ross grants — and it is signed, not asserted

`give()`, `deny()` and `revoke()` raise `PermissionError` if the author is not
Ross. **And that is not enough on its own**, which an audit of the first version
established: a Python check holds inside one process and is worth nothing across
three machines, because `Log.append()` was unauthenticated. Anything able to
write an event could write one stamped `actor="ross"`, and every other node
replayed it as fact. One compromised site could mint itself a CERTAIN handle on
Ross's name and a grant to go with it.

So authority is cryptographic now, in two layers (`keys.py`):

- **Node signature, on every event.** Ed25519, from the node that wrote it. This
  is what makes relaying safe — the cloud VM can pass the shop's events along
  and cannot alter one, having no way to produce the shop's signature over the
  change.
- **Ross signature, on authority events.** Grants, enrolments, node
  registrations, model choices, answers to the queue, secrets — and any lesson
  claiming basis `told`, because "Ross said so" is a claim about Ross. His key
  lives on the console and nowhere else. Events claiming authority without it
  are dropped on replay and refused on sync.

**The root of trust is a file Ross carries.** `trust.json` holds his public key
and each node's, placed on every machine out of band — public keys can't be
distributed by the log they authenticate. Being manual is the point: adding a
node is something a human does deliberately, not something the network decides.

**Why:** Ross's words — *"one hard rule, if you don't know what to allow or
disallow you ask me and only me for approval."* Delegating the power to say yes
is how a system ends up with more access than anyone remembers agreeing to.

### 3. Unknown is never yes

An untaught request returns `ASK` and waits. Indefinitely. There is no timeout
that becomes an approval, and no inference from a neighbouring capability —
"Brent may see the spray log" tells us nothing about the BOM.

**An unidentified sender is also unknown.** `identity.resolve()` returns an empty
person for a stranger, an ambiguous address and a lapsed enrolment alike. In the
first version that empty string fell through the grant filter and matched *every*
grant in the business — "unknown is never yes" had become "unknown is everyone".
Both ends are now guarded, and `live()` distinguishes "no filter" from "the empty
name" in its type so the two can't be conflated again.

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
- **A channel in neither list → `ASK`.** This is an allow-list. The first version
  tested `channel in WEAK`, which meant every string that wasn't literally
  "email" or "phone" — a typo, a new adapter, a value an attacker chose — was
  handled as unforgeable. `Request.channel` no longer defaults to the strongest
  tier either; callers must say.

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

## Decisions Ross has made

- **First job: answer people.** Inbound on Telegram/Chat/email → identity →
  grants → answer, act, or queue. It's the thing he described wanting, and it
  exercises every part of the core, so it's how the design gets proven.
- **Models: OpenRouter plus a direct workhorse key.** One key for reach and
  trials, a direct provider for the volume. See `models.py`.
- **Vault unseal: Telegram tap.** Chosen over BitLocker+DPAPI, a TPM seal, and a
  YubiKey. It fights offline-first, so it is implemented to keep both — see
  below.

### How tap-to-unseal keeps offline-first

A sealed node **still runs**: it reads its log, resolves identity, enforces
grants, answers from learning, and queues work. What it cannot do while sealed is
touch a credential — no QBO, no Google, no posting. That's a much smaller loss
than "blind", and it means a node that reboots at 3am doesn't quietly resume
acting until Ross says so.

**The tap authorises; a peer transports.** Telegram never carries key material —
sending a passphrase through Telegram hands it to Telegram. A booting node asks
the network to be unsealed, Ross gets the push, and on his tap an already-unsealed
peer sends the key over the VPN. The console passphrase is the bootstrap for the
first node up, or a site that is genuinely alone.

**Secrets are wrapped per entitled node,** not encrypted under one shared key and
replicated everywhere. RUM's QBO token is wrapped for the shop; SteelHaven's
Workspace credentials for the house; the cloud VM is entitled to none and
therefore cannot open anything it relays.

## Enrolment — how people get into the book

Decided 14 Aug 2026. Ross doesn't type Telegram ids by hand; people enrol
themselves through a link. **SMS only for now** — no email invite path.

**The link proposes; it never enrols.** Attaching a handle to a person is handing
them that person's permissions one step removed, so it is a grant, and only Ross
writes those. The web node holds no key of his and physically cannot write an
`identity.enrolled` event.

Three event kinds:

| kind | proof | meaning |
|---|---|---|
| `identity.invited` | AUTHORED | Ross: "I'm inviting someone I'll call Brent." Holds a *hash* of the token, an expiry, single-use. |
| `identity.claimed` | NODE | The web node: "invite X completed; these channels were proven, by these methods." |
| `identity.enrolled` | AUTHORED | Ross confirms at the console. The real thing. |

**The flow:** Ross names the person and supplies their number → the system texts
the invite link → they open it (having thereby proven they hold the phone) → they
do the Telegram bot handshake, which proves control of an actual account id
rather than an address → Ross confirms at the console.

Texting the link rather than emailing it removes the interception hole entirely:
the invite only ever arrives on a number Ross nominated, so an attacker who sees
the link never had a way to receive it.

### Ross enrols himself differently — the bootstrap

Everyone else is enrolled *by* Ross, so Ross cannot be. His own pairing is a
bootstrap, and it is also the most security-critical handle in the system: his
Telegram id is what earns the ungated bypass in `grants.decide()`.

**The console generates a code and displays it. Nothing transmits it.** Ross
messages that code to the bot from his own Telegram account; the bot sees which
account id sent it, and the pairing is written at the console with his signing
key. Short expiry, single use.

The delivery method is the whole point. Every other channel that could carry the
code — SMS, email, Chat — is weaker than the handle being created, and would
become the soft path to the most powerful identity in the system. The console is
already the authority (it holds his key), so a code that never leaves it adds no
new attack surface.

It is the same bot handshake other people do. Only the delivery differs: console
for Ross, SMS for everyone else. One code path, two ways in.

**Re-pairing must be loud, and singular.** The system should refuse to hold two
live `ross` Telegram handles at once — a second must explicitly replace the
first, never sit quietly alongside it. Adding rather than replacing is how a
spare key gets left in the door.

**What this does not defend against, stated plainly:** somebody with console
access can pair their own Telegram as Ross. That is not a new hole — console
access already means possession of his signing key, at which point they can
write any grant they like directly. The console is the trust boundary; this
neither widens nor narrows it.

### SMS proves enrolment; it does not promote phone to STRONG

Two different claims, and it would be easy to slide from one to the other. At
enrolment, an SMS code binds the session to a human Ross vouched for — good.
Ongoing, phone stays WEAK in `grants.py`: caller ID is spoofable, SMS is
interceptable via SIM swap and SS7, and numbers get recycled. The phone gets
someone *enrolled*; Telegram is what lets them *act* without waiting.

### Constraint: no endpoint may text a user-supplied number

The number always comes from Ross's invite, never from a form field. An open
"send me a code" endpoint is a standard SMS-pumping fraud target — an attacker
funnels codes to premium-rate numbers they profit from and the bill lands here.
Keeping the number Ross-supplied kills that outright. **This is a security
property, not an inconvenience — do not "improve" it into a self-service field.**

Code hygiene: 6 digits, ~5 minute expiry, single use, capped attempts,
constant-time compare, hashed at rest. The log never holds a live code.

### What the user is told

> The channel you verify decides what you can do without waiting. Verify Telegram
> and you can act directly. Email and phone are recorded, but anything you ask
> through them waits for Ross — because a sender address and a caller ID can both
> be faked, and we treat them that way.

That is not reassurance-speak; it is exactly what `grants.decide()` does.

**Data minimisation:** the page collects channel identifiers and nothing else. No
date of birth, no address, no security questions. Knowledge-based verification
was considered and rejected — the answers are guessable, findable, or known to
precisely the people most likely to impersonate someone. Ross's out-of-band
knowledge is used at the *confirmation* step instead, where he already knows
whether he was expecting this.

**Ross's one-time setup:** a Twilio account, US A2P 10DLC brand and campaign
registration (unregistered application-to-person SMS gets filtered or blocked,
links especially, and it takes days), and the SID and auth token stored in the
vault under `system` at the console.

## Still open

Recorded here so they are not silently decided by whoever writes the code next:

- **Budget ceiling** for LLM spend — not set.
- **"Relevant" for Augie and Courtney** — Ross said family gets personal access
  "if they are relevant." Undefined, so it currently means `ASK`.
- **Ranks for sub-sub-agents**, if the bench ever grows one.
- **Enrolment data** — no real handles are in the book yet. This needs a console
  command Ross runs locally, not data pasted into a chat.

## Built

`store.py` · `keys.py` · `vault.py` · `grants.py` · `roster.py` · `identity.py` ·
`nodes.py` · `models.py` · `asks.py`, with 103 safety properties in
`tests/test_core.py`. Everything marked HOSTILE there was live code once.

## Not yet built

1. **The arrival pipeline** — channel adapter → `identity.resolve()` →
   `Request` → `grants.decide()` → act / answer / `asks.raise_()`. This is the
   first job, and the seam where an `Identity` must not be allowed to decay into
   a bare string.
2. **The console** — where Ross reads the queue and answers it. Only localhost
   changes anything, so this is also where his signing key lives.
3. **The unseal protocol** — sealed-node boot, Telegram authorisation, peer
   transport, per-node secret wrapping.
4. **Ingest** — populate the vault from `.md` / `.ml` files.
5. **Deliverables** — 3D models and files to the right Drive, organised, shared.
6. **Tools each org can call**: shhops, shhsocial, accounting, QBO (including
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
