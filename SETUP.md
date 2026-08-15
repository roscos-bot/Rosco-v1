# First run — turning Rosco on

Everything here you run yourself, at the console. The steps that create your
passphrase and store your keys are yours by design: the whole system rests on
those never leaving your head and your machine. Claude built the code and can
sit with you through this, but cannot type the passphrase or the keys — if it
did, they would no longer be secret.

Run all of this from `C:\Users\Ross\rosco`.

## 1. Create your key (once)

```
python -m rosco init
```

It asks for a passphrase, twice. Pick a strong one you'll remember — **there is
no reset.** This seals your signing key. From now on it's the one passphrase for
everything: unlocking the dashboard, answering the queue, granting, storing keys.

It prints a `trust.json` note. That file is the root of trust; you only copy it
to other machines when you add them (the shop, the cloud VM) — ignore it for a
single machine.

## 2. Pair your own phone (optional, for Telegram later)

```
python -m rosco pair
```

Shows a 6-digit code. You'll send that to your bot once the service is running
(step 5). Skip this until you've set the bot token.

## 3. Give Rosco a model to think with

Store your OpenRouter key (or Anthropic — whichever you want as the workhorse):

```
python -m rosco secret set system openrouter_api_key
```

It prompts for the value; paste your key. Then point the workhorse at a model:

```
python -m rosco model set workhorse anthropic/claude-sonnet-5 openrouter
```

Set a soft spend cap so nothing runs away:

```
python -m rosco budget set * 200
```

## 4. Open the dashboard

```
python -m rosco web
```

Then open **http://127.0.0.1:8787** in your browser and unlock with your
passphrase. You'll see the mesh (just the agent roster until you enrol people)
and an empty queue. This is the thing you sit in front of.

## 5. Let people reach it, over Telegram (optional)

Store the bot token, then run the service:

```
python -m rosco secret set system telegram_bot_token
python -m rosco serve
```

With `serve` running, send your pairing code from step 2 to the bot — your phone
is now recognised as you. Enrol other people as you go:

```
python -m rosco enrol brent telegram <their-telegram-id>
python -m rosco give brent sugar-creek spray-log
```

## 6. Wire in tools and repos as you need them

External tool (agents propose media, etc.):

```
python -m rosco tool add higgsfield https://cloud.higgsfield.ai/api --biz rum --secret higgsfield_api_key
python -m rosco secret set system higgsfield_api_key
```

A repo (agents branch + open PRs; you merge on GitHub):

```
python -m rosco github link rum fuzzeh84/rumachines
python -m rosco secret set system github_token
python -m rosco give steele rum git:propose --verb do
```

## The shortest path to "it works"

Steps **1, 3, 4**. That's `init`, a model key, and `web` — unlock the dashboard
and you're running. Everything else layers on when you want it.

## To just watch it work first, on throwaway data

```
python -m rosco.demo
```

No setup, no keys, deleted on exit — plays real messages through the real
decision engine so you can see the behaviour before committing to anything.
