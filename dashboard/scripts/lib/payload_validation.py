#!/usr/bin/env python3
"""
payload_validation.py

Shared acceptance criteria for LLM-generated held-out payloads, applied by
both the Code Llama and DeepSeek generators.

Chapter 3, Section 3.5 is explicit: "Generated outputs will not be treated as
valid attacks automatically; each record must pass the study validation and
cleaning criteria." and "The exact generated files retained after validation
and deduplication will be frozen and used as the authoritative test corpus."

This module encodes those criteria in one auditable place. Every rejection is
logged with a reason so the final accepted/rejected counts (required by the
Scope section) can be reported truthfully.

The checks are deliberately conservative structural filters -- they confirm a
payload is a plausible, non-trivial SQLi/XSS attempt of the requested family.
They do NOT execute anything. Nothing here reaches a live system.
"""
from __future__ import annotations

import re
import unicodedata

MIN_LEN = 4
MAX_LEN = 2000            # anything longer is almost always the model rambling

# Structural signatures per attack type. A payload must trip at least one
# for its declared type. These are acceptance filters, not the detector's
# features -- kept separate on purpose.
_SQLI_SIGNS = [
    re.compile(r"\b(select|union|insert|update|delete|drop|exec|declare)\b", re.I),
    # Tautology / boolean probe. Covers AND as well as OR: `AND 1=1` and
    # `AND 1=2` are the canonical boolean_blind pair, and matching only OR
    # rejected that whole family's bare form as `no_sqli_signature`.
    re.compile(r"\b(or|and)\b\s*[\'\"]?\s*\d+\s*=\s*\d+", re.I),  # or/and 1=1
    re.compile(r"\b(sleep|waitfor|pg_sleep|benchmark)\b", re.I),
    re.compile(r"\b(extractvalue|updatexml|convert)\b", re.I),
    re.compile(r"(--|#|/\*)"),                                  # comment tokens
    re.compile(r"['\"]\s*(or|and)\b", re.I),
    re.compile(r"0x[0-9a-f]{2,}", re.I),                        # hex literal
]
_XSS_SIGNS = [
    re.compile(r"<\s*[a-z][a-z0-9]*", re.I),                    # tag open
    re.compile(r"\bon[a-z]+\s*=", re.I),                        # event handler
    re.compile(r"javascript:", re.I),
    re.compile(r"\b(alert|prompt|confirm|eval|fromcharcode)\s*\(", re.I),
    re.compile(r"(%3c|%3e|&#x?\d)", re.I),                      # encoded < > / entity
    re.compile(r"\b(document|window)\.\w", re.I),
]

# Reasoning / chain-of-thought leakage. Reasoning models (notably the
# abliterated DeepSeek-R1 build) emit their working alongside the payload.
# Observed on the committed corpus: 21% of accepted DeepSeek rows were prose,
# labelled as attacks, which depresses the reported detection rate because
# text ABOUT an attack is counted as a missed attack.
_THINK_TAG = re.compile(r"</?think\s*>", re.I)

_REASONING = re.compile(
    r"("
    r"\b(let me|let's|i'll|i will|i can|i could|i should|i need to|"
    r"i'm going to|i am going to|here's|here is|first,|next,|then,|"
    r"lastly,|finally,|for example|for instance|another one|"
    r"note that|keep in mind|as you can see|to summar)"
    r"|"
    r"\b(we can|we could|we should|you can use|you could use|this (payload|example|one))\b"
    r")", re.I)

# Sentence-shaped: ends in a full stop after several words, or contains a
# clause separator typical of explanation rather than injection.
_SENTENCE_SHAPE = re.compile(r"[a-z]{3,}\s+[a-z]{3,}\s+[a-z]{3,}.*\.\s*$", re.I)

# Refusals / meta-chatter the model may emit instead of a payload.
_REFUSAL = re.compile(
    r"(i (cannot|can't|won't|am unable)|i'm sorry|as an ai|cannot assist|"
    r"i must decline|not able to help|against my)", re.I)


def clean(text: str) -> str:
    """Trim, drop surrounding quotes, normalise line endings. NFKC is NOT
    applied here -- the corpus must retain any homoglyph obfuscation the model
    produced, because defeating that is precisely what the detector claims."""
    t = text.strip()
    t = t.replace("\r\n", "\n").strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"`":
        t = t[1:-1].strip()
    return t


def validate(payload: str, attack_type: str) -> tuple[bool, str]:
    """Return (accepted, reason). reason is '' when accepted, else why it was
    rejected -- logged verbatim into the rejects file for the count report."""
    if not payload:
        return False, "empty"
    if _REFUSAL.search(payload):
        return False, "model_refusal"
    n = len(payload)
    if n < MIN_LEN:
        return False, f"too_short({n})"
    if n > MAX_LEN:
        return False, f"too_long({n})"
    # a control-char-only or whitespace-only string is not a payload
    if not payload.strip():
        return False, "whitespace_only"
    # --- reasoning / chain-of-thought leakage ---------------------------
    # Checked BEFORE the signature test: prose that quotes a payload would
    # otherwise satisfy the signature and be accepted as an attack.
    if _THINK_TAG.search(payload):
        return False, "reasoning_think_tag"
    stripped = payload.strip()
    if stripped.lower() in ("<think>", "</think>"):
        return False, "reasoning_think_tag"
    if _REASONING.search(payload):
        return False, "reasoning_prose"
    # A payload is an injection string, not a sentence. Require that it is not
    # sentence-shaped once it exceeds a few words.
    words = stripped.split()
    if len(words) >= 6 and _SENTENCE_SHAPE.search(stripped):
        return False, "reasoning_sentence_shape"

    signs = _SQLI_SIGNS if attack_type == "sqli" else _XSS_SIGNS
    if not any(rx.search(payload) for rx in signs):
        return False, f"no_{attack_type}_signature"
    # reject obvious prose: mostly alphabetic words separated by spaces with
    # no attack punctuation is likely an explanation, not a payload.
    letters = sum(c.isalpha() for c in payload)
    specials = sum(1 for c in payload if not c.isalnum() and not c.isspace())
    if letters > 40 and specials == 0:
        return False, "prose_no_special_chars"
    return True, ""


def normalized_key(payload: str) -> str:
    """Dedup key: NFKC + casefold + collapse whitespace. Two payloads that
    differ only by case or spacing count as the same record for dedup, which
    is stricter than exact-match dedup and matches Section 3.5's intent."""
    t = unicodedata.normalize("NFKC", payload).casefold()
    t = re.sub(r"\s+", " ", t).strip()
    return t
