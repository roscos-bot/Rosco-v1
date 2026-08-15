"""Talking to a model. One place, hardened, metered.

Every call to think goes through here: it resolves the role to a model (via
models.py, so the choice stays Ross's and swappable), reads the provider key
from the vault, calls over safehttp (https, no redirects - so an API key cannot
be walked off by a redirect any more than a tool credential can), and records
what the call cost against the soft cap.

No key means no answer, never a worse one - the same rule the classifier holds.
A role whose provider has no stored credential raises NoModel, and the caller
surfaces that to Ross rather than quietly reaching for something cheaper.
"""
from __future__ import annotations

from . import safehttp
from .models import (ANTHROPIC, OLLAMA, OPENAI, OPENROUTER, WORKHORSE, Models,
                     secret_name)


class NoModel(RuntimeError):
    """The chosen role has no reachable model - usually a missing key."""


def complete(models: Models, role: str, system: str, user: str, *,
             node: str = "", meter=None, max_tokens: int = 800,
             temperature: float = 0.4) -> str:
    choice = models.pick(role, node=node)
    key = models.key_for(choice)          # "" for ollama, None if missing
    if key is None:
        raise NoModel(
            f"no key for {choice.provider}; the {role} model cannot run. "
            f"rosco secret set system {secret_name(choice.provider)}")
    text, pt, ct = _provider_call(choice.provider, choice.model, key,
                                  system, user, max_tokens, temperature)
    if meter is not None:
        try:
            meter.record(choice.provider, choice.model, role, pt, ct)
        except Exception:
            pass                          # metering must never break the work
    return text


def _provider_call(provider, model, key, system, user, max_tokens, temperature):
    """(text, prompt_tokens, completion_tokens). safehttp gives every call the
    no-redirect protection, so a credential never follows a 3xx to a new host."""
    if provider == ANTHROPIC:
        d = safehttp.call(
            "https://api.anthropic.com/v1/messages", method="POST",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            payload={"model": model, "max_tokens": max_tokens, "system": system,
                     "messages": [{"role": "user", "content": user}]})
        text = "".join(p.get("text", "") for p in (d.get("content") or [])
                       if isinstance(p, dict))
        u = d.get("usage") or {}
        return text, int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))

    if provider == OLLAMA:
        d = safehttp.call(
            "http://localhost:11434/api/chat", method="POST",
            payload={"model": model, "stream": False,
                     "messages": [{"role": "system", "content": system},
                                  {"role": "user", "content": user}]})
        return ((d.get("message") or {}).get("content", ""),
                int(d.get("prompt_eval_count", 0)), int(d.get("eval_count", 0)))

    url = ("https://openrouter.ai/api/v1/chat/completions" if provider == OPENROUTER
           else "https://api.openai.com/v1/chat/completions")
    d = safehttp.call(
        url, method="POST", bearer=key,
        payload={"model": model, "max_tokens": max_tokens, "temperature": temperature,
                 "messages": [{"role": "system", "content": system},
                              {"role": "user", "content": user}]})
    u = d.get("usage") or {}
    choices = d.get("choices") or []
    text = (choices[0].get("message") or {}).get("content", "") if choices else ""
    return text, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
