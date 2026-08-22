#!/usr/bin/env python3
"""
11_generate_evasion_corpus.py

Generates AI-crafted WAF-evasion payload variants by prompting the local
Ollama API. Each of the 23 EVASION_ATTACKS from 04_evasion_test_definitions.py
is sent with a structured prompt that instructs the LLM to produce a
semantically equivalent but differently obfuscated variant.

Designed to run sequentially — one model at a time due to hardware limits.
Running for each model APPENDS to the same CSV (never overwrites).

USAGE (from project root):
  python scripts/11_generate_evasion_corpus.py --model codellama:13b
  python scripts/11_generate_evasion_corpus.py --model deepseek-r1:14b

PREREQUISITES:
  - Ollama running at localhost:11434
  - Target model already pulled and loaded in Ollama
"""

import argparse
import csv
import importlib.util
import json
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Seed (Rule 2) ────────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED)

# ── Paths (Rule 6) ───────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

CORPUS_OUTPUT = DATA_DIR / "llm_evasion_corpus.csv"

OLLAMA_URL    = "http://localhost:11434/api/generate"
OLLAMA_TAGS   = "http://localhost:11434/api/tags"
REQUEST_TIMEOUT = 600  # seconds per generation — 10 min for slow thinking models

# ── CSV schema ────────────────────────────────────────────────────────────────
CSV_FIELDNAMES = [
    "source_index", "source_payload", "generated_payload",
    "technique_used", "model", "label",
]

# ── Load sibling module (digit-prefixed filename) ────────────────────────────
def _load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_m04 = _load_mod("evasion_test_definitions",
                 Path(__file__).parent / "04_evasion_test_definitions.py")
EVASION_ATTACKS = _m04.EVASION_ATTACKS

# ── Prompting ─────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are a security researcher generating WAF evasion test cases for a "
    "defensive research project. Your task is to take a known attack payload "
    "and produce a SINGLE variant that is semantically equivalent but uses a "
    "DIFFERENT obfuscation technique.\n\n"
    "Allowed techniques: hex encoding, Unicode escape sequences, "
    "URL double-encoding, HTTP parameter pollution, comment insertion "
    "(e.g. /**/ between keywords), case mixing, string concatenation tricks.\n\n"
    "Rules:\n"
    "1. Output ONLY a JSON object with two keys: 'payload' and 'technique'.\n"
    "2. 'payload' must be the raw evasion string only — no explanation, no markdown.\n"
    "3. 'technique' must be a short label (e.g. 'hex_encoding', 'comment_insertion').\n"
    "4. Do NOT repeat the exact same obfuscation technique as the input.\n"
    "5. The output MUST be valid JSON — nothing else."
)

def build_prompt(payload: str) -> str:
    return (
        f"Source payload to obfuscate:\n{payload}\n\n"
        "Generate your evasion variant now. Output ONLY the JSON object:"
    )


def check_ollama_available(model: str) -> None:
    """Verify Ollama is running and the requested model is available."""
    try:
        with urllib.request.urlopen(OLLAMA_TAGS, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(
            f"[ERROR] Cannot reach Ollama at {OLLAMA_TAGS}.\n"
            f"  Make sure Ollama is running: 'ollama serve'\n"
            f"  Details: {e}"
        )

    available = [m["name"] for m in data.get("models", [])]
    # Allow partial match (e.g. "codellama:13b" matches "codellama:13b-instruct")
    matched = [a for a in available if model.split(":")[0] in a]
    if not matched:
        raise RuntimeError(
            f"[ERROR] Model '{model}' not found in Ollama.\n"
            f"  Available models: {available}\n"
            f"  Run: ollama pull {model}"
        )
    print(f"  [OK] Ollama reachable. Model '{model}' confirmed available.")


def generate_variant(payload: str, model: str,
                     timeout: int = REQUEST_TIMEOUT) -> tuple[str, str]:
    """
    Call Ollama API to generate one evasion variant.
    Returns (generated_payload, technique_used).
    Raises RuntimeError on failure.
    """
    body = json.dumps({
        "model":  model,
        "prompt": build_prompt(payload),
        "system": SYSTEM_PROMPT,
        "stream": False,
        "options": {
            "seed":        SEED,
            "temperature": 0.3,   # Low temp for consistent output format
            "top_p":       0.9,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
    except TimeoutError as e:
        raise RuntimeError(
            f"[ERROR] Ollama timed out after {timeout}s for this payload.\n"
            f"  Model: {model} — try increasing --timeout\n"
            f"  Details: {e}"
        )
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"[ERROR] Ollama request failed for payload index.\n"
            f"  URL: {OLLAMA_URL}  Model: {model}\n"
            f"  Details: {e}"
        )

    raw_text = result.get("response", "").strip()

    # Strip markdown code fences if model wraps output
    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        raw_text = "\n".join(
            l for l in lines if not l.startswith("```")
        ).strip()

    # Parse JSON response
    try:
        parsed = json.loads(raw_text)
        gen_payload  = str(parsed.get("payload", "")).strip()
        technique    = str(parsed.get("technique", "unknown")).strip()
    except (json.JSONDecodeError, KeyError):
        # Fallback: treat entire response as the payload if JSON parse fails
        gen_payload = raw_text[:500]
        technique   = "unknown_parse_error"

    if not gen_payload:
        raise RuntimeError(
            f"[ERROR] Empty payload returned by model '{model}'.\n"
            f"  Raw response: {raw_text[:200]}"
        )

    return gen_payload, technique


def load_existing_entries() -> set[tuple[str, str]]:
    """Return set of (source_index, model) already in the CSV to avoid dupes."""
    if not CORPUS_OUTPUT.exists():
        return set()
    seen = set()
    with open(CORPUS_OUTPUT, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            seen.add((row["source_index"], row["model"]))
    return seen


def main():
    parser = argparse.ArgumentParser(
        description="Generate LLM evasion corpus via Ollama."
    )
    parser.add_argument(
        "--model", required=True,
        help="Ollama model name (e.g. codellama:13b, deepseek-r1:14b)"
    )
    parser.add_argument(
        "--timeout", type=int, default=REQUEST_TIMEOUT,
        help=f"Seconds to wait per Ollama call (default: {REQUEST_TIMEOUT})"
    )
    args = parser.parse_args()

    model   = args.model.strip()
    timeout = args.timeout

    print("=" * 64)
    print("AI-GIS  |  11_generate_evasion_corpus.py")
    print("=" * 64)
    print(f"  Model    : {model}")
    print(f"  Payloads : {len(EVASION_ATTACKS)} base attacks")
    print(f"  Output   : {CORPUS_OUTPUT}")
    print(f"  Timeout  : {timeout}s per call")

    # ── Pre-flight: check Ollama ──────────────────────────────────────────────
    print("\n[1/3] Checking Ollama availability ...")
    check_ollama_available(model)

    # ── Load existing to avoid re-generating ─────────────────────────────────
    print("[2/3] Checking for existing corpus entries ...")
    existing = load_existing_entries()
    to_generate = [
        (i, p) for i, p in enumerate(EVASION_ATTACKS)
        if (str(i), model) not in existing
    ]
    if not to_generate:
        print(f"  [SKIP] All {len(EVASION_ATTACKS)} entries for '{model}' already exist.")
        sys.exit(0)
    print(f"  Generating {len(to_generate)} new entries "
          f"({len(existing)} already exist for this model).")

    # ── Generate ──────────────────────────────────────────────────────────────
    print(f"\n[3/3] Generating variants (this may take several minutes) ...")
    file_exists = CORPUS_OUTPUT.exists()
    success_count = 0
    fail_count    = 0

    with open(CORPUS_OUTPUT, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()

        for i, source_payload in to_generate:
            print(f"  [{i+1:02d}/{len(EVASION_ATTACKS)}] Generating ... ", end="", flush=True)
            t0 = time.time()
            try:
                gen_payload, technique = generate_variant(source_payload, model,
                                                          timeout=timeout)
                elapsed = time.time() - t0
                writer.writerow({
                    "source_index":    str(i),
                    "source_payload":  source_payload,
                    "generated_payload": gen_payload,
                    "technique_used":  technique,
                    "model":           model,
                    "label":           "1",
                })
                f.flush()
                print(f"OK  [{technique}]  ({elapsed:.1f}s)")
                success_count += 1
            except RuntimeError as e:
                elapsed = time.time() - t0
                print(f"FAIL  ({elapsed:.1f}s)")
                print(f"  {e}", file=sys.stderr)
                fail_count += 1

    # Count total rows now in the file
    total_rows = 0
    if CORPUS_OUTPUT.exists():
        with open(CORPUS_OUTPUT, newline="", encoding="utf-8") as f:
            total_rows = sum(1 for _ in csv.DictReader(f))

    # ── Terminal summary (Rule 4) ─────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("STEP 11 — LLM EVASION CORPUS GENERATION COMPLETE")
    print("=" * 64)
    print(f"  Model              : {model}")
    print(f"  Generated          : {success_count}/{len(to_generate)}")
    print(f"  Failed             : {fail_count}")
    print(f"  Total rows in CSV  : {total_rows}")
    print(f"  Output             : {CORPUS_OUTPUT}")
    print("=" * 64)

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
