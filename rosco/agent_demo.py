"""`python -m rosco.agent_demo` - watch Bessemer work, on throwaway data.

Builds a complete system in a temp dir, teaches Bessemer SteelHaven (the real
brand facts, told by Ross), then runs it on two tasks through the real Agent
loop - grounding, thinking, the brand-guardrail check, learning, proposing. Only
the model is a stub, so it runs with no API key; everything else is the actual
runtime. It touches no real data and deletes itself on the way out.

The second task is deliberately one the stub botches, so you can watch the
guardrails catch a bad draft before it ever reaches Ross.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .agent import Agent
from .console import Console
from .knowledge import seed
from .vault import Vault

PW = "the demo passphrase, long enough"


# A stand-in for the model. Real Agent, real loop; this just returns canned copy
# so the demo needs no key. One good draft, one that trips the guardrails.
def stub(system: str, user: str) -> str:
    if "fortified" in user.lower() or "insurance" in user.lower():
        # deliberately flawed: names FORTIFIED and makes a steel claim with no
        # insulation - the two things Bessemer must never ship.
        return ("Your home should be built to last. Our steel framing means lower "
                "insurance premiums, and we build to FORTIFIED standards so storms "
                "don't stand a chance. Steel-Strong.")
    return (
        "Buying your first home shouldn't mean inheriting someone else's shortcuts.\n\n"
        "Wood rots. It warps, it feeds termites, it burns. The frame you never see "
        "is the one that decides what your house costs you for the next thirty years.\n\n"
        "PermaHaven is different: a 100% cold-formed-steel system, built in the "
        "factory and stood up on your lot. Noncombustible. Dimensionally stable. "
        "Paired with R6 continuous exterior insulation so the steel works with you, "
        "not against you. We measured The Duo at ~2.9 ACH50 and 0.3 pCi/L radon.\n\n"
        "That's The Second Price - not what you pay to move in, but what you pay to "
        "live there. Steel-Strong, Smart-Secure.")


def line(label=""):
    print(f"\n\033[1m{'─' * 4} {label} {'─' * max(0, 62 - len(label))}\033[0m")


def main() -> int:
    home = Path(tempfile.mkdtemp()) / "rosco-agent-demo"
    try:
        c = Console(home)
        print("\033[1mBESSEMER - watch an agent work, on throwaway data\033[0m")
        c.init(PW)
        log = c.open(PW)

        line("Teach Bessemer its business")
        n = seed(Vault(log), "steelhaven")
        print(f"  ingested {n} SteelHaven brand facts into the vault (told by Ross)")

        agent = Agent("Bessemer", log, think=stub)

        line("Task 1 — a first-time-buyer post")
        r = agent.work("Draft a Facebook post for first-time buyers on why steel "
                       "framing beats wood.", narrate=lambda s: print("  " + s))
        print("\n  \033[36m--- Bessemer's draft ---\033[0m")
        for ln in r.draft.splitlines():
            print("  " + ln)
        print(f"\n  grounded on {r.grounded_on} lessons · "
              f"guardrails {'CLEAN' if not r.warnings else 'FLAGGED'} · "
              f"proposed to Ross: {r.proposed}")

        line("Task 2 — one the model botches")
        r2 = agent.work("Write something about how our steel framing lowers "
                        "insurance because it's FORTIFIED.",
                        narrate=lambda s: print("  " + s))
        print("\n  \033[36m--- draft ---\033[0m")
        for ln in r2.draft.splitlines():
            print("  " + ln)
        print("\n  \033[31mBessemer caught it before Ross ever saw it:\033[0m")
        for w in r2.warnings:
            print(f"    !! {w}")

        line("What Bessemer knows now")
        lessons = agent.knows()
        print(f"  {len(lessons)} lessons in the vault "
              f"({n} told, {len(lessons) - n} observed from doing the work):")
        for l in lessons[-2:]:
            print(f"    · [{l.basis}] {l.text[:70]}")

        line("On the log")
        produced = list(log.replay(kind="agent.produced"))
        print(f"  {len(produced)} proposals recorded — each a draft for Ross, "
              f"nothing published.")
        print("\n\033[2m  throwaway data deleted. For real: rosco ingest steelhaven, "
              "then rosco agent Bessemer \"<task>\"\033[0m\n")
        return 0
    finally:
        shutil.rmtree(home.parent, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
