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
from .models import (ANTHROPIC, GEMINI, OLLAMA, OPENAI, OPENROUTER, WORKHORSE,
                     Models, secret_name)


class NoModel(RuntimeError):
    """The chosen role has no reachable model - usually a missing key."""


def complete(models: Models, role: str, system: str, user: str, *,
             node: str = "", agent: str = "", meter=None, max_tokens: int = 800,
             temperature: float = 0.4) -> str:
    choice = models.pick(role, node=node)
    if agent:                             # an agent pinned to its own model wins
        pinned = models.pin_for(agent)    # over the role default - Ross's call
        if pinned is not None:
            choice = pinned
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


def _provider_call(provider, model, key, system, user, max_tokens, temperature,
                   *, timeout: int = 60, force_json: bool = False):
    """(text, prompt_tokens, completion_tokens). safehttp gives every call the
    no-redirect + https + no-internal + size-cap protection, so a model API key
    never follows a 3xx to a new host. This is the ONE way to reach a model - the
    classifier uses it too, so the hardening cannot be adjacent-doored again."""
    if provider == ANTHROPIC:
        d = safehttp.call(
            "https://api.anthropic.com/v1/messages", method="POST", timeout=timeout,
            headers={"x-api-key": key.strip(), "anthropic-version": "2023-06-01"},
            payload={"model": model, "max_tokens": max_tokens, "system": system,
                     "messages": [{"role": "user", "content": user}]})
        text = "".join(p.get("text", "") for p in (d.get("content") or [])
                       if isinstance(p, dict))
        u = d.get("usage") or {}
        return text, int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))

    if provider == GEMINI:
        # Gemini's own shape: system_instruction + contents, key in a header. A
        # different API from the OpenAI-style ones below, hence its own branch.
        d = safehttp.call(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            method="POST", timeout=timeout,
            headers={"x-goog-api-key": key.strip()},
            payload={"system_instruction": {"parts": [{"text": system}]},
                     "contents": [{"role": "user", "parts": [{"text": user}]}],
                     "generationConfig": {"maxOutputTokens": max_tokens,
                                          "temperature": temperature}})
        cand = d.get("candidates") or []
        text = ""
        if cand:
            parts = ((cand[0].get("content") or {}).get("parts") or [])
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        u = d.get("usageMetadata") or {}
        return (text, int(u.get("promptTokenCount", 0)),
                int(u.get("candidatesTokenCount", 0)))

    if provider == OLLAMA:
        body = {"model": model, "stream": False,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if force_json:
            body["format"] = "json"
        d = safehttp.call("http://localhost:11434/api/chat", method="POST",
                          timeout=timeout, payload=body)
        return ((d.get("message") or {}).get("content", ""),
                int(d.get("prompt_eval_count", 0)), int(d.get("eval_count", 0)))

    url = ("https://openrouter.ai/api/v1/chat/completions" if provider == OPENROUTER
           else "https://api.openai.com/v1/chat/completions")
    d = safehttp.call(
        url, method="POST", bearer=key, timeout=timeout,
        payload={"model": model, "max_tokens": max_tokens, "temperature": temperature,
                 "messages": [{"role": "system", "content": system},
                              {"role": "user", "content": user}]})
    u = d.get("usage") or {}
    choices = d.get("choices") or []
    text = (choices[0].get("message") or {}).get("content", "") if choices else ""
    return text, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
