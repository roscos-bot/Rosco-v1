"""What the models are costing, and a soft line Ross gets warned about.

Ross asked for a soft cap: keep working, tell me when I cross a threshold. So
this never stops a call. It records what each call cost, sums the month, and
when spend crosses a line Ross set, it says so once - not on every call after.

WHY SOFT AND NOT HARD. A hard cap that cuts model access mid-day turns a busy
Tuesday into a silent one, and "the system went quiet and nobody knew why" is a
worse failure than a bigger bill. The whole point of this system is that it
degrades to ASKING, and asking still needs a model to read the message. A ceiling
that blocks that defeats the thing it was protecting.

SPEND IS A FACT; DOLLARS ARE AN ESTIMATE. Every model call reports its token
counts, and those are recorded verbatim - they are not guessed. Turning tokens
into dollars needs a price table, and prices change, so PRICES here is marked
approximate and matched loosely by tier. An unknown model is priced HIGH and
flagged, never silently treated as free - a budget tool that under-counts is
worse than useless.

WHO WRITES WHAT. Ross sets the cap (authority - it is a policy decision, and
`budget.set` carries his signature). Agents record spend (`model.billed`, a plain
node fact - they are the ones spending). A compromised node can inflate spend and
trigger a spurious warning; it cannot suppress one, because the log only grows,
and a false "you're over budget" ping is a cheap failure for a soft cap. It
cannot make the system stop, because nothing here stops the system.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .keys import ROSS
from .models import OLLAMA
from .store import Log, now

# Rough $/1M tokens (input, output). ESTIMATES - check each provider's current
# pricing page. They change, this is a soft cap, and approximate is the honest
# promise. Matched by keyword so 'anthropic/claude-opus-5' and 'claude-opus-5'
# price alike. Order matters: first substring hit wins.
PRICES: tuple[tuple[str, tuple[float, float]], ...] = (
    ("opus", (15.0, 75.0)),
    ("sonnet", (3.0, 15.0)),
    ("haiku", (0.80, 4.0)),
    ("gpt-5", (5.0, 15.0)),
    ("gpt", (2.5, 10.0)),
    ("grok", (3.0, 15.0)),
    ("gemini", (1.25, 5.0)),
    ("deepseek", (0.50, 1.50)),
    ("llama", (0.0, 0.0)),          # small open models, usually run cheap or local
)

# An unknown model is expensive until proven otherwise. Under-counting is the one
# thing a budget must not do quietly.
FALLBACK = (10.0, 30.0)

# Default lines, as fractions of the cap. 0.8 is a warning; 1.0 is "you said
# this was the number and here it is".
ALERT_AT = (0.8, 1.0)

ALL = "*"


def price(provider: str, model: str) -> tuple[tuple[float, float], bool]:
    """(input_rate, output_rate) per million tokens, and whether it was known."""
    if provider == OLLAMA:
        return (0.0, 0.0), True          # on the machine; the electricity is not our bill
    low = (model or "").lower()
    for key, rates in PRICES:
        if key in low:
            return rates, True
    return FALLBACK, False


def cost(provider: str, model: str, prompt_tokens: int, completion_tokens: int
         ) -> tuple[float, bool]:
    (pin, pout), known = price(provider, model)
    dollars = (prompt_tokens / 1_000_000) * pin + (completion_tokens / 1_000_000) * pout
    return dollars, known


@dataclass
class Budget:
    scope: str                         # a provider name, or ALL for everything
    monthly_usd: float
    alert_at: tuple[float, ...] = ALERT_AT
    set_at: str = ""


@dataclass
class Reading:
    scope: str
    cap: float
    spent: float
    unpriced: int = 0                  # calls whose model had no price entry
    calls: int = 0

    @property
    def pct(self) -> float:
        return (self.spent / self.cap) if self.cap else 0.0

    @property
    def over(self) -> bool:
        return self.cap > 0 and self.spent >= self.cap

    def line(self) -> str:
        bar = f"${self.spent:,.2f} / ${self.cap:,.2f}"
        tail = f"  ({self.unpriced} unpriced call(s) - estimate low)" if self.unpriced else ""
        flag = "  !! OVER" if self.over else (f"  ({self.pct:.0%})" if self.cap else "")
        return f"  {self.scope:12} {bar}{flag}{tail}"


@dataclass
class Alert:
    scope: str
    period: str
    threshold: float
    cap: float
    spent: float

    def message(self) -> str:
        when = "reached" if self.threshold >= 1.0 else f"crossed {self.threshold:.0%} of"
        return (f"Model spend {when} the {self.scope} budget for {self.period}: "
                f"${self.spent:,.2f} of ${self.cap:,.2f}. Nothing has stopped - "
                f"this is a heads-up.")


class Meter:
    """Spend, budgets and the soft line, all projected from the log."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing ---------------------------------------------------------

    def set_budget(self, scope: str, monthly_usd: float, *,
                   alert_at: tuple[float, ...] = ALERT_AT, by: str = ROSS) -> dict:
        """Ross sets a soft monthly cap. His call, so it carries his signature."""
        if by != ROSS:
            raise PermissionError(f"only Ross sets a budget; {by!r} tried to")
        try:
            amount = float(monthly_usd)
        except (TypeError, ValueError):
            raise ValueError(f"a budget is a dollar amount, got {monthly_usd!r}") from None
        if amount <= 0:
            raise ValueError("a budget must be a positive dollar amount")
        lines = tuple(sorted(float(a) for a in alert_at if 0 < float(a) <= 2))
        return self.log.append(
            "budget.set",
            {"scope": (scope or ALL).strip().lower(), "monthly_usd": amount,
             "alert_at": list(lines or ALERT_AT)},
            subject=(scope or ALL).strip().lower(), actor=ROSS,
        )

    def record(self, provider: str, model: str, role: str,
               prompt_tokens: int, completion_tokens: int, *,
               by: str = "rosco", at: str = "") -> dict:
        """Note what one model call cost. A plain fact; agents write it."""
        pt = max(0, int(prompt_tokens or 0))
        ct = max(0, int(completion_tokens or 0))
        dollars, known = cost(provider, model, pt, ct)
        return self.log.append(
            "model.billed",
            {"provider": provider, "model": model, "role": role,
             "prompt_tokens": pt, "completion_tokens": ct,
             "usd": round(dollars, 6), "priced": known},
            subject=provider, actor=by, ts=at,
        )

    # ---- reading ---------------------------------------------------------

    def budgets(self) -> dict[str, Budget]:
        out: dict[str, Budget] = {}
        for ev in self.log.replay(kind="budget.set"):
            b = ev["body"]
            out[b["scope"]] = Budget(
                scope=b["scope"], monthly_usd=float(b["monthly_usd"]),
                alert_at=tuple(b.get("alert_at") or ALERT_AT), set_at=ev["ts"],
            )
        return out

    def _month(self, at: str = "") -> str:
        return (at or now())[:7]

    def reading(self, scope: str, *, month: str = "") -> Reading:
        """Spend against one budget's scope, this month."""
        m = month or self._month()
        buds = self.budgets()
        cap = buds[scope].monthly_usd if scope in buds else 0.0
        spent = unpriced = calls = 0.0
        for ev in self.log.replay(kind="model.billed"):
            if not ev["ts"].startswith(m):
                continue
            b = ev["body"]
            if scope != ALL and b.get("provider") != scope:
                continue
            spent += float(b.get("usd", 0))
            calls += 1
            if not b.get("priced", True):
                unpriced += 1
        return Reading(scope, cap, round(spent, 4), int(unpriced), int(calls))

    def state(self, *, month: str = "") -> list[Reading]:
        """Every budget's current standing, worst first."""
        rows = [self.reading(s, month=month) for s in self.budgets()]
        rows.sort(key=lambda r: -r.pct)
        return rows

    def check_and_alert(self, *, month: str = "", by: str = "rosco") -> list[Alert]:
        """Fire any threshold newly crossed, once each.

        Records a `spend.alerted` per (scope, month, threshold) so the same line
        does not re-warn on every call after it is passed. Returns only the
        alerts raised on this call, for whatever is going to deliver them.
        """
        m = month or self._month()
        already = set()
        for ev in self.log.replay(kind="spend.alerted"):
            b = ev["body"]
            already.add((b["scope"], b["period"], float(b["threshold"])))

        fired: list[Alert] = []
        for bud in self.budgets().values():
            r = self.reading(bud.scope, month=m)
            if not r.cap:
                continue
            for th in bud.alert_at:
                if r.pct >= th and (bud.scope, m, th) not in already:
                    self.log.append(
                        "spend.alerted",
                        {"scope": bud.scope, "period": m, "threshold": th,
                         "cap": r.cap, "usd": r.spent},
                        subject=bud.scope, actor=by, ts="",
                    )
                    fired.append(Alert(bud.scope, m, th, r.cap, r.spent))
        return fired

    def report(self, *, month: str = "") -> str:
        """What the console shows. Reads clean; never mistaken for a hard stop."""
        rows = self.state(month=month)
        if not rows:
            spent = self.reading(ALL, month=month)
            if spent.calls:
                return (f"no budget set. spent ${spent.spent:,.2f} across "
                        f"{spent.calls} call(s) this month - set one with "
                        f"`rosco budget set * <usd>`")
            return "no budget set, and nothing spent yet this month"
        out = [f"model spend, {month or self._month()} (soft caps - nothing is blocked):"]
        out += [r.line() for r in rows]
        return "\n".join(out)
