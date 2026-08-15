"""The console. Where Ross is Ross.

Every rule in this system funnels to one machine: authority events need his
Ed25519 signature, and this is the program that holds the key that makes them.
"Only localhost changes anything" was the operating rule salvaged from V6, and
the console is that rule with a prompt.

THE KEY NEVER SITS ON DISK IN THE CLEAR. At init the console mints Ross's
signing key and seals it under a passphrase - PBKDF2 at 600k rounds, then the
same HMAC-CTR construction the vault uses, with the tag checked before a single
byte is believed. A stolen disk yields a blob; the passphrase is in Ross's head.

ONE PASSPHRASE, TWO KEYS, SEPARATED. The master key derived from the passphrase
is never used directly. The seal key and the vault key are each derived from it
by HMAC with distinct labels, so a break in how one is used cannot be replayed
against the other.

READING IS FREE, SIGNING IS NOT. The queue, the roster, the vault's lessons,
verify() - all readable without unsealing, because a sealed node still reads.
Only commands that write authority (answering, granting, enrolling, storing a
secret, choosing a model, registering a node) demand the passphrase. That keeps
the passphrase rare, which keeps it meaningful.

INIT REFUSES TO RUN TWICE. Regenerating the signing key would orphan every
authority event ever written - they would all fail verification against the new
public key. If Ross genuinely needs a new key, that is a migration with a
procedure, not a flag.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import sys
from pathlib import Path

from .asks import ANSWERS, Asks
from .grants import ANY, DO, GET, SCOPE_ALL, SCOPES, Grants
from .identity import People
from .keys import ROSS, Signer, Trust
from .meter import ALL, Meter
from .models import ROLES, SYSTEM, Models, secret_name
from .nodes import RENDEZVOUS, SITE, Nodes
from .store import Log, now
from .vault import Vault, derive_key

NODE = "console"
PAIR_TTL_SECONDS = 15 * 60

# ---- sealing Ross's key --------------------------------------------------

_MAGIC = b"RSK1"


def _subkey(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, label, hashlib.sha256).digest()


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def _seal(secret: bytes, key: bytes) -> bytes:
    nonce = os.urandom(16)
    blob = bytes(a ^ b for a, b in zip(secret, _stream(key, nonce, len(secret))))
    tag = hmac.new(key, _MAGIC + nonce + blob, hashlib.sha256).digest()
    return _MAGIC + nonce + tag + blob


def _unseal(sealed: bytes, key: bytes) -> bytes:
    if sealed[:4] != _MAGIC:
        raise ValueError("this is not a sealed key file")
    nonce, tag, blob = sealed[4:20], sealed[20:52], sealed[52:]
    want = hmac.new(key, _MAGIC + nonce + blob, hashlib.sha256).digest()
    if not hmac.compare_digest(want, tag):
        raise ValueError("wrong passphrase (or the sealed key was tampered with)")
    return bytes(a ^ b for a, b in zip(blob, _stream(key, nonce, len(blob))))


# ---- the console ---------------------------------------------------------


class Console:
    """Everything the console can do, callable without a terminal.

    main() is the argparse skin over this; tests drive the class directly with
    a passphrase argument instead of a prompt.
    """

    def __init__(self, home: str | Path | None = None) -> None:
        self.home = Path(home or os.environ.get("ROSCO_HOME")
                         or Path.home() / ".rosco")
        self.db = self.home / "rosco.db"
        self.trust_path = self.home / "trust.json"
        self.sealed_path = self.home / "ross.key.sealed"
        self.salt_path = self.home / "salt"
        self.pair_path = self.home / "pair.json"

    @property
    def initialised(self) -> bool:
        return self.sealed_path.exists()

    # ---- keys ------------------------------------------------------------

    def _master(self, passphrase: str) -> bytes:
        return derive_key(passphrase, self.salt_path.read_bytes())

    def _ross(self, passphrase: str) -> Signer:
        master = self._master(passphrase)
        raw = _unseal(self.sealed_path.read_bytes(), _subkey(master, b"ross-key-seal"))
        return Signer(raw)

    def _vault_key(self, passphrase: str) -> bytes:
        return _subkey(self._master(passphrase), b"vault-secrets")

    # ---- opening the log -------------------------------------------------

    def open(self, passphrase: str | None = None) -> Log:
        """The log, sealed or not.

        Without a passphrase the log reads everything and can write NODE-proof
        events; any attempt to write authority raises, which is the correct
        answer rather than a special case.
        """
        if not self.initialised:
            raise SystemExit("not initialised - run `rosco init` first")
        trust = Trust.load(self.trust_path)
        ross = self._ross(passphrase) if passphrase is not None else None
        log = Log(self.db, NODE, ross=ross, trust=trust)
        if not Trust.load(self.trust_path).knows(NODE):
            # First open minted the console's node key; persist its public half
            # so verify() on this and every other machine can check our rows.
            log.trust.save(self.trust_path)
        return log

    # ---- commands --------------------------------------------------------

    def init(self, passphrase: str) -> str:
        if self.initialised:
            raise SystemExit(
                "already initialised. Regenerating the signing key would orphan "
                "every authority event ever written - they would all fail against "
                "the new public key. A new key is a migration, not a re-run.")
        if len(passphrase) < 10:
            raise SystemExit("pick a longer passphrase - ten characters is the floor")
        self.home.mkdir(parents=True, exist_ok=True)
        self.salt_path.write_bytes(os.urandom(16))

        ross = Signer.generate()
        master = self._master(passphrase)
        self.sealed_path.write_bytes(_seal(ross.raw, _subkey(master, b"ross-key-seal")))

        trust = Trust(ross=ross.public)
        log = Log(self.db, NODE, ross=ross, trust=trust)
        Nodes(log).register(NODE, "Ross's console", role=SITE, reach="localhost")
        trust.save(self.trust_path)
        return (f"initialised at {self.home}\n"
                f"  ross public key  {ross.public[:16]}...\n"
                f"  node key         {log.signer.public[:16]}...\n"
                f"copy trust.json to every other node, by hand. That file is the "
                f"root of trust and the log cannot distribute it.")

    def status(self) -> str:
        log = self.open()
        problems = log.verify()
        bad = log.rejected()
        lines = ["ROSCO CONSOLE", ""]
        lines.append(Asks(log).digest())
        lines.append("")
        lines.append("nodes:")
        lines.append(Nodes(log).health())
        m = Models(log, Vault(log))
        gaps = m.missing(node=NODE)
        if gaps:
            lines.append("")
            for g in gaps:
                lines.append(f"  !! no API key for {g} - `rosco secret set system "
                             f"{secret_name(g)}`")
        meter = Meter(log)
        if meter.budgets() or meter.reading(ALL).calls:
            lines.append("")
            lines.append(meter.report())
        for al in meter.check_and_alert():
            lines.append(f"  !! {al.message()}")
        if problems:
            lines.append("")
            lines.append(f"  !! verify(): {len(problems)} problem(s) - run `rosco verify`")
        if bad:
            lines.append(f"  !! {len(bad)} rejected event(s) in the table - run `rosco verify`")
        return "\n".join(lines)

    def answer(self, passphrase: str, ask_id: str, answer: str, note: str = "") -> str:
        if answer not in ANSWERS:
            raise SystemExit(f"answer must be one of: {', '.join(ANSWERS)}")
        log = self.open(passphrase)
        q = Asks(log)
        a = q.get(ask_id)
        if a is None:
            raise SystemExit(f"no ask matches {ask_id!r}")
        q.answer(a.id, answer, note=note)
        return f"{a.person} / {a.business}:{a.capability} {a.verb} -> {answer}"

    def give(self, passphrase: str, person: str, business: str, capability: str,
             verb: str = GET, scope: str = SCOPE_ALL, reason: str = "") -> str:
        log = self.open(passphrase)
        Grants(log).give(person, business, capability, verb=verb, scope=scope,
                         reason=reason)
        tail = " (only rows about them)" if scope != SCOPE_ALL else ""
        return f"granted {person} {verb.upper()} on {business}:{capability}{tail}"

    def deny(self, passphrase: str, person: str, business: str, capability: str,
             verb: str = ANY, reason: str = "") -> str:
        log = self.open(passphrase)
        Grants(log).deny(person, business, capability, verb=verb, reason=reason)
        return f"denied {person} {verb.upper()} on {business}:{capability}"

    def revoke(self, passphrase: str, grant_id: str, reason: str = "") -> str:
        log = self.open(passphrase)
        hits = [g for g in Grants(log).live() if g.id.startswith(grant_id)]
        if len(hits) != 1:
            raise SystemExit(f"{grant_id!r} matches {len(hits)} live grants; "
                             f"run `rosco grants` and use a longer id")
        Grants(log).revoke(hits[0].id, reason=reason)
        g = hits[0]
        return f"revoked {g.person} {g.verb.upper()} on {g.business}:{g.capability}"

    def grants(self, person: str = "") -> str:
        log = self.open()
        rows = Grants(log).live(person=person or None)
        if not rows:
            return "no live grants"
        out = []
        for g in rows:
            kind = "ALLOW" if g.allow else "DENY "
            scope = " [their rows only]" if g.scope != SCOPE_ALL else ""
            out.append(f"  {g.id[:8]}  {kind} {g.person:10} {g.verb:4} "
                       f"{g.business}:{g.capability}{scope}  {g.reason[:40]}")
        return "\n".join(out)

    def enrol(self, passphrase: str, person: str, channel: str, address: str,
              until: str = "", note: str = "") -> str:
        log = self.open(passphrase)
        p = People(log)
        replaced = 0
        if person.strip().lower() == ROSS and channel == "telegram":
            # Singular by rule: two live handles on Ross's name is a spare key
            # left in the door. A new pairing replaces, never sits alongside.
            for h in p.handles(person=ROSS):
                if h.channel == "telegram":
                    p.retire(h.id, reason="replaced by a new pairing")
                    replaced += 1
        p.enrol(person, channel, address, until=until, note=note)
        tail = f" (replaced {replaced} earlier pairing)" if replaced else ""
        return f"enrolled {person} on {channel}{tail}\n" + p.whois(person)

    def retire(self, passphrase: str, handle_id: str, reason: str = "") -> str:
        log = self.open(passphrase)
        p = People(log)
        hits = [h for h in p.handles() if h.id.startswith(handle_id)]
        if len(hits) != 1:
            raise SystemExit(f"{handle_id!r} matches {len(hits)} handles")
        p.retire(hits[0].id, reason=reason)
        return f"retired {hits[0].person}'s {hits[0].channel} handle"

    def people(self, person: str = "") -> str:
        log = self.open()
        p = People(log)
        if person:
            return p.whois(person)
        names = sorted({h.person for h in p.handles()})
        if not names:
            return "nobody is enrolled yet"
        return "\n\n".join(p.whois(n) for n in names)

    def strangers(self) -> str:
        log = self.open()
        rows = People(log).strangers()
        if not rows:
            return "nobody unrecognised has knocked"
        out = []
        for ev in rows:
            b = ev["body"]
            out.append(f"  {ev['ts']}  {b.get('channel','?'):9} {b.get('raw','?'):24} "
                       f"{b.get('detail','')[:60]}")
        return "\n".join(out)

    # ---- pairing Ross's own telegram ------------------------------------

    def pair_start(self) -> str:
        """A code, shown here and sent nowhere.

        Every channel that could carry it is weaker than the handle it creates,
        so the code exists only on this screen. Ross messages it to the bot from
        his own account; the bot relays (code, telegram id) to pair_claim().
        """
        code = f"{pysecrets.randbelow(10**6):06d}"
        self.home.mkdir(parents=True, exist_ok=True)
        self.pair_path.write_text(json.dumps({
            "hash": hashlib.sha256(code.encode()).hexdigest(),
            "expires": _epoch() + PAIR_TTL_SECONDS,
        }), encoding="utf-8")
        return (f"pairing code: {code}\n"
                f"send exactly that to the bot from YOUR Telegram within 15 minutes.\n"
                f"the code is not stored and not transmitted - this screen is the "
                f"only place it exists.")

    def pair_claim(self, passphrase: str, code: str, telegram_id: str) -> str:
        if not self.pair_path.exists():
            raise SystemExit("no pairing in progress - run `rosco pair` first")
        d = json.loads(self.pair_path.read_text(encoding="utf-8"))
        self.pair_path.unlink()          # single use, success or not
        if _epoch() > d["expires"]:
            raise SystemExit("that pairing code expired; start again")
        if not hmac.compare_digest(
                hashlib.sha256(code.strip().encode()).hexdigest(), d["hash"]):
            raise SystemExit("wrong code; start again")
        return self.enrol(passphrase, ROSS, "telegram", telegram_id,
                          note="paired at the console")

    # ---- secrets / models / nodes / vault -------------------------------

    def secret_set(self, passphrase: str, business: str, name: str, value: str) -> str:
        log = self.open(passphrase)
        Vault(log, key=self._vault_key(passphrase)).put_secret(business, name, value)
        return f"stored {business}:{name} ({len(value)} chars, encrypted)"

    def secret_list(self) -> str:
        held = Vault(self.open()).secret_names()
        return "\n".join(f"  {h}" for h in held) or "no secrets held"

    def model_set(self, passphrase: str, role: str, model: str, provider: str,
                  node: str = "", why: str = "") -> str:
        log = self.open(passphrase)
        Models(log).choose(role, model, provider, node=node, why=why)
        return f"{role} -> {model} via {provider}" + (f" on {node}" if node else "")

    def model_list(self) -> str:
        log = self.open()
        return Models(log, Vault(log)).report(node=NODE)

    def node_add(self, passphrase: str, name: str, site: str,
                 role: str = SITE, reach: str = "") -> str:
        log = self.open(passphrase)
        Nodes(log).register(name, site, role=role, reach=reach)
        return (f"registered {name} ({site}). Now put its public key in "
                f"trust.json on every machine, by hand.")

    def budget_set(self, passphrase: str, scope: str, monthly_usd: str) -> str:
        log = self.open(passphrase)
        Meter(log).set_budget(scope, float(monthly_usd))
        return (f"soft cap: ${float(monthly_usd):,.2f}/month on "
                f"{scope if scope != ALL else 'all providers'}. "
                f"Nothing will be blocked; you'll be warned at 80% and 100%.")

    def budget_show(self) -> str:
        return Meter(self.open()).report()

    def doorway(self, passphrase: str | None = None):
        """The doorway, wired to the chosen model and the spend meter.

        This is what an adapter (Telegram, email) hands arrivals to. It needs
        the vault key to read provider credentials, so a sealed doorway falls
        back to Keywords - which sends nearly everything to Ross, the right
        behaviour for a node that cannot reach a model.
        """
        from .arrive import Doorway, Keywords
        from .classify import ModelClassifier

        log = self.open(passphrase)
        meter = Meter(log)
        if passphrase is not None:
            models = Models(log, Vault(log, key=self._vault_key(passphrase)))
            classifier = ModelClassifier(models, meter=meter, node=NODE)
        else:
            classifier = Keywords()
        return Doorway(log, classifier)

    def vault_read(self, business: str) -> str:
        return Vault(self.open()).to_markdown(business)

    def verify(self) -> str:
        log = self.open()
        problems = log.verify()
        bad = log.rejected()
        out = []
        if not problems and not bad:
            out.append("every chain sound, every signature good")
        for p in problems:
            out.append(f"  !! {p}")
        for ev in bad:
            out.append(f"  !! rejected: {ev.get('node')}#{ev.get('seq')} "
                       f"{ev.get('kind')} ({ev.get('problem')})")
        return "\n".join(out)


def _epoch() -> int:
    import time
    return int(time.time())


# ---- the terminal skin ---------------------------------------------------


def _ask_pass(confirm: bool = False) -> str:
    p = getpass.getpass("passphrase: ")
    if confirm and getpass.getpass("again: ") != p:
        raise SystemExit("passphrases did not match")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="rosco", description="Rosco's console - the only place authority lives")
    ap.add_argument("--home", help="data directory (default ~/.rosco or $ROSCO_HOME)")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("init", help="first run: mint and seal Ross's signing key")
    sub.add_parser("status", help="the queue, the nodes, what is missing")
    sub.add_parser("queue", help="what is waiting on Ross")

    a = sub.add_parser("answer", help="answer an ask")
    a.add_argument("id"); a.add_argument("verdict", choices=ANSWERS)
    a.add_argument("-n", "--note", default="")

    g = sub.add_parser("give", help="grant a capability")
    g.add_argument("person"); g.add_argument("business"); g.add_argument("capability")
    g.add_argument("--verb", choices=(GET, DO), default=GET)
    g.add_argument("--scope", choices=SCOPES, default=SCOPE_ALL)
    g.add_argument("-r", "--reason", default="")

    d = sub.add_parser("deny", help="refuse a capability (defaults to both verbs)")
    d.add_argument("person"); d.add_argument("business"); d.add_argument("capability")
    d.add_argument("--verb", choices=(GET, DO, ANY), default=ANY)
    d.add_argument("-r", "--reason", default="")

    r = sub.add_parser("revoke", help="withdraw a grant by id")
    r.add_argument("id"); r.add_argument("-r", "--reason", default="")

    gr = sub.add_parser("grants", help="every grant in force")
    gr.add_argument("person", nargs="?", default="")

    e = sub.add_parser("enrol", help="attach a channel address to a person")
    e.add_argument("person"); e.add_argument("channel"); e.add_argument("address")
    e.add_argument("--until", default=""); e.add_argument("--note", default="")

    rt = sub.add_parser("retire", help="stop an address resolving")
    rt.add_argument("id"); rt.add_argument("-r", "--reason", default="")

    pe = sub.add_parser("people", help="who is enrolled, and how they reach us")
    pe.add_argument("person", nargs="?", default="")

    sub.add_parser("strangers", help="unrecognised arrivals")
    sub.add_parser("pair", help="pair Ross's own Telegram (code shown here only)")
    pc = sub.add_parser("pair-claim", help="complete a pairing (normally the bot's job)")
    pc.add_argument("code"); pc.add_argument("telegram_id")

    ss = sub.add_parser("secret", help="credentials")
    ssub = ss.add_subparsers(dest="scmd")
    st = ssub.add_parser("set"); st.add_argument("business"); st.add_argument("name")
    ssub.add_parser("list")

    mo = sub.add_parser("model", help="which model answers")
    msub = mo.add_subparsers(dest="mcmd")
    ms = msub.add_parser("set"); ms.add_argument("role", choices=ROLES)
    ms.add_argument("model"); ms.add_argument("provider")
    ms.add_argument("--node", default=""); ms.add_argument("--why", default="")
    msub.add_parser("list")

    no = sub.add_parser("node", help="the sites")
    no.add_argument("name", nargs="?"); no.add_argument("site", nargs="?")
    no.add_argument("--role", choices=(SITE, RENDEZVOUS), default=SITE)
    no.add_argument("--reach", default="")

    bu = sub.add_parser("budget", help="soft monthly spend cap (never blocks)")
    bsub = bu.add_subparsers(dest="bcmd")
    bs = bsub.add_parser("set")
    bs.add_argument("scope", help="a provider name, or * for all")
    bs.add_argument("usd", help="monthly dollars")

    va = sub.add_parser("vault", help="what the agents have learned")
    va.add_argument("business")

    sub.add_parser("verify", help="walk every chain and signature")

    args = ap.parse_args(argv)
    c = Console(args.home)

    try:
        if args.cmd == "init":
            print(c.init(_ask_pass(confirm=True)))
        elif args.cmd in (None, "status"):
            print(c.status())
        elif args.cmd == "queue":
            print(Asks(c.open()).digest())
        elif args.cmd == "answer":
            print(c.answer(_ask_pass(), args.id, args.verdict, args.note))
        elif args.cmd == "give":
            print(c.give(_ask_pass(), args.person, args.business, args.capability,
                         verb=args.verb, scope=args.scope, reason=args.reason))
        elif args.cmd == "deny":
            print(c.deny(_ask_pass(), args.person, args.business, args.capability,
                         verb=args.verb, reason=args.reason))
        elif args.cmd == "revoke":
            print(c.revoke(_ask_pass(), args.id, reason=args.reason))
        elif args.cmd == "grants":
            print(c.grants(args.person))
        elif args.cmd == "enrol":
            print(c.enrol(_ask_pass(), args.person, args.channel, args.address,
                          until=args.until, note=args.note))
        elif args.cmd == "retire":
            print(c.retire(_ask_pass(), args.id, reason=args.reason))
        elif args.cmd == "people":
            print(c.people(args.person))
        elif args.cmd == "strangers":
            print(c.strangers())
        elif args.cmd == "pair":
            print(c.pair_start())
        elif args.cmd == "pair-claim":
            print(c.pair_claim(_ask_pass(), args.code, args.telegram_id))
        elif args.cmd == "secret":
            if args.scmd == "set":
                value = getpass.getpass(f"value for {args.business}:{args.name}: ")
                print(c.secret_set(_ask_pass(), args.business, args.name, value))
            else:
                print(c.secret_list())
        elif args.cmd == "model":
            if args.mcmd == "set":
                print(c.model_set(_ask_pass(), args.role, args.model, args.provider,
                                  node=args.node, why=args.why))
            else:
                print(c.model_list())
        elif args.cmd == "node":
            if args.name and args.site:
                print(c.node_add(_ask_pass(), args.name, args.site,
                                 role=args.role, reach=args.reach))
            else:
                print(Nodes(c.open()).health())
        elif args.cmd == "budget":
            if args.bcmd == "set":
                print(c.budget_set(_ask_pass(), args.scope, args.usd))
            else:
                print(c.budget_show())
        elif args.cmd == "vault":
            print(c.vault_read(args.business))
        elif args.cmd == "verify":
            print(c.verify())
        else:
            ap.print_help()
    except ValueError as e:
        raise SystemExit(f"refused: {e}") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
