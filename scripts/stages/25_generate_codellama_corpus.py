#!/usr/bin/env python3
"""
25_generate_codellama_corpus.py   (Chapter 3, Section 3.5 -- baseline generator)

Produces the held-out Code Llama 13B adversarial subset the thesis specifies:
~500 SQLi + ~500 XSS novel payloads, in 25 batches of 20 per attack type,
with the documented seed varied per batch for controlled diversity.

This is the BULK, family-structured generator. It is NOT the 23-payload
variant rewriter (11_generate_evasion_corpus.py). None of these payloads is
ever used for training, feature selection, vocabulary, tuning, stacking, or
threshold selection -- they are held-out test data only.

BACKEND: an Ollama server. Point it at an Azure GPU VM by changing --host
(see AZURE_RUNBOOK.md); the API is identical to localhost.

CONTROLLED GENERATION (Section 3.5): temperature=0, top_k=1 (enforced by
azure_ollama_client.OllamaClient), seed varied per batch, exact model tag and
digest recorded into the run manifest.

OUTPUTS (under data/eval/):
  codellama_holdout.csv          accepted payloads (frozen test corpus)
  codellama_rejects.csv          rejected payloads + reason (for the count report)
  codellama_run_manifest.json    model tag/digest, seeds, per-family counts,
                                 acceptance rate, timestamp, backend host

USAGE (from dashboard/):
  # local
  python scripts/25_generate_codellama_corpus.py --model codellama:13b
  # Azure VM over an SSH tunnel (localhost:11434 -> VM:11434)
  python scripts/25_generate_codellama_corpus.py --model codellama:13b --host localhost
  # smaller smoke run before committing GPU hours
  python scripts/25_generate_codellama_corpus.py --model codellama:13b --batches 2
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from azure_ollama_client import OllamaClient, sha256_of, strip_fences   # noqa: E402
from payload_validation import clean, validate, normalized_key          # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
OUT = ROOT / "data" / "eval"
OUT.mkdir(parents=True, exist_ok=True)

BASE_SEED = 42            # Section 3.5 documented seed; varied per batch below
DEFAULT_BATCHES = 25
BATCH_SIZE = 20

# Section 3.5: "SQLi generation will cover boolean-based blind, UNION-based,
# time-based blind, error-based, hexadecimal obfuscation, and stacked-query
# techniques. XSS generation will cover reflected, stored, DOM-based, and
# attribute-based patterns."
SQLI_FAMILIES = ["boolean_blind", "union_based", "time_based_blind",
                 "error_based", "hex_obfuscation", "stacked_query"]
XSS_FAMILIES = ["reflected", "stored", "dom_based", "attribute_based"]

SYSTEM_PROMPT = (
    "You are a security researcher building a held-out WAF/IDS evaluation "
    "corpus for a DEFENSIVE research project in an isolated offline lab. You "
    "produce single, novel attack payloads used only to test a detector that "
    "is already trained. Output rules:\n"
    "1. Output ONLY a JSON array of strings, each string one raw payload.\n"
    "2. No markdown, no commentary, no numbering -- JSON array only.\n"
    "3. Each payload must be a functional example of the requested technique.\n"
    "4. Vary structure across the array: different keywords, spacing, encoding, "
    "and obfuscation, so no two payloads are near-identical.\n"
    "5. Do not include explanations inside the payloads."
)

_FAMILY_BRIEF = {
    "boolean_blind": "boolean-based blind SQL injection (true/false inference, e.g. AND 1=1 / AND 1=2 style)",
    "union_based": "UNION-based SQL injection selecting attacker-chosen columns",
    "time_based_blind": "time-based blind SQL injection using sleep/delay functions",
    "error_based": "error-based SQL injection leaking data via database error functions",
    "hex_obfuscation": "SQL injection using hexadecimal-encoded values and mixed encoding",
    "stacked_query": "stacked-query SQL injection terminating one statement and running another",
    "reflected": "reflected XSS echoed back in an HTTP response",
    "stored": "stored XSS payload intended to persist and fire for later visitors",
    "dom_based": "DOM-based XSS executing through client-side DOM writes",
    "attribute_based": "attribute-injection XSS breaking out of an HTML attribute with an event handler",
}


def build_prompt(attack_type: str, family: str, k: int) -> str:
    return (
        f"Generate {k} distinct {family.replace('_', ' ')} payloads.\n"
        f"Technique: {_FAMILY_BRIEF[family]}.\n"
        f"Attack type: {attack_type.upper()}.\n"
        f"Output ONLY a JSON array of {k} raw payload strings:"
    )


def parse_array(raw: str) -> list[str]:
    raw = strip_fences(raw)
    # Try strict JSON array first.
    try:
        val = json.loads(raw)
        if isinstance(val, list):
            return [str(x) for x in val]
    except json.JSONDecodeError:
        pass
    # Fallback: some models emit one payload per line. Salvage them so a
    # malformed wrapper does not waste the whole batch's GPU time.
    lines = [l.strip().strip(",").strip() for l in raw.splitlines() if l.strip()]
    salvaged = []
    for l in lines:
        if l in ("[", "]"):
            continue
        if len(l) >= 2 and l[0] == l[-1] and l[0] in "'\"":
            l = l[1:-1]
        salvaged.append(l)
    return salvaged


def generate_for_type(client, model, attack_type, families, batches, target, seen):
    accepted, rejected = [], []
    fam_i = 0
    for b in range(batches):
        if len(accepted) >= target:
            break
        family = families[fam_i % len(families)]
        fam_i += 1
        seed = BASE_SEED + b                     # documented per-batch variation
        prompt = build_prompt(attack_type, family, BATCH_SIZE)
        print(f"  [{attack_type}] batch {b+1}/{batches}  family={family}  seed={seed}")
        try:
            raw = client.generate(model, prompt, SYSTEM_PROMPT, seed)
        except RuntimeError as e:
            print(f"    {e}")
            rejected.append(("", attack_type, family, seed, "generation_failed"))
            continue
        for cand in parse_array(raw):
            p = clean(cand)
            ok, reason = validate(p, attack_type)
            if not ok:
                rejected.append((p, attack_type, family, seed, reason))
                continue
            key = normalized_key(p)
            if key in seen:
                rejected.append((p, attack_type, family, seed, "duplicate"))
                continue
            seen.add(key)
            accepted.append((p, attack_type, family, seed))
            if len(accepted) >= target:
                break
    return accepted, rejected


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="codellama:13b")
    ap.add_argument("--host", default="localhost",
                    help="Ollama host. Use localhost with an SSH tunnel to the Azure VM.")
    ap.add_argument("--port", type=int, default=11434)
    ap.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    ap.add_argument("--target-per-type", type=int, default=500)
    ap.add_argument("--auth-token", default=None,
                    help="Optional bearer token if the VM is behind an authenticating proxy.")
    args = ap.parse_args()

    client = OllamaClient(host=args.host, port=args.port, auth_token=args.auth_token)
    rec = client.check_model(args.model)

    t0 = time.time()
    seen: set[str] = set()
    print(f"\nGenerating SQLi (target {args.target_per_type}) ...")
    sqli_ok, sqli_bad = generate_for_type(
        client, args.model, "sqli", SQLI_FAMILIES, args.batches, args.target_per_type, seen)
    print(f"Generating XSS  (target {args.target_per_type}) ...")
    xss_ok, xss_bad = generate_for_type(
        client, args.model, "xss", XSS_FAMILIES, args.batches, args.target_per_type, seen)

    accepted = sqli_ok + xss_ok
    rejected = sqli_bad + xss_bad

    # ── write accepted corpus (frozen test data) ─────────────────────────────
    corpus = OUT / "codellama_holdout.csv"
    with open(corpus, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "attack_type", "attack_family", "seed",
                    "label", "generator", "model_tag", "payload_sha256"])
        for p, atype, fam, seed in accepted:
            w.writerow([p, atype, fam, seed, 1, "codellama",
                        args.model, sha256_of(p)])

    rej = OUT / "codellama_rejects.csv"
    with open(rej, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "attack_type", "attack_family", "seed", "reject_reason"])
        w.writerows(rejected)

    # ── run manifest (Section 3.5 preservation requirement) ──────────────────
    def fam_counts(rows):
        c: dict[str, int] = {}
        for _, _, fam, _ in rows:
            c[fam] = c.get(fam, 0) + 1
        return c

    manifest = {
        "generator": "codellama",
        "model_tag": args.model,
        "model_digest": rec.get("digest", ""),
        "backend_host": f"{args.host}:{args.port}",
        "base_seed": BASE_SEED,
        "batches_per_type": args.batches,
        "batch_size": BATCH_SIZE,
        "controlled_generation": {"temperature": 0.0, "top_k": 1, "top_p": 1.0},
        "target_per_type": args.target_per_type,
        "accepted": {"sqli": len(sqli_ok), "xss": len(xss_ok), "total": len(accepted)},
        "rejected_total": len(rejected),
        "acceptance_rate": round(len(accepted) / max(len(accepted) + len(rejected), 1), 4),
        "family_counts": {"sqli": fam_counts(sqli_ok), "xss": fam_counts(xss_ok)},
        "elapsed_seconds": round(time.time() - t0, 1),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Held-out only. Never used for training, tuning, or threshold selection.",
    }
    with open(OUT / "codellama_run_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 64)
    print(f"Accepted: {len(accepted)}  (SQLi {len(sqli_ok)} / XSS {len(xss_ok)})")
    print(f"Rejected: {len(rejected)}  acceptance rate {manifest['acceptance_rate']*100:.1f}%")
    print(f"Corpus  : {corpus}")
    print(f"Manifest: {OUT / 'codellama_run_manifest.json'}")
    print("=" * 64)


if __name__ == "__main__":
    main()
