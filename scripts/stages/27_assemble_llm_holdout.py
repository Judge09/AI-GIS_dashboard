#!/usr/bin/env python3
"""
27_assemble_llm_holdout.py   (Chapter 3, Section 3.5 -> Chapter 4 input)

Merges the two LLM-generated attack subsets with a held-out benign batch into
the single ~2,200-row held-out benchmark the thesis specifies:

  500 Code Llama SQLi + 500 Code Llama XSS
  300 DeepSeek SQLi   + 300 DeepSeek XSS
  ~600 held-out benign
  ------------------------------------------
  ~2,200 total

It preserves the generator label on every attack row so Chapter 4 can report
Code Llama and DeepSeek results SEPARATELY (the disaggregation Section 3.5
requires because of the DeepSeek/ModSecurity circularity).

It does NOT invent benign traffic. If fewer benign rows are available than the
--benign-target, it uses what exists and prints a clear shortfall warning, so
the reported composition is honest rather than padded.

INPUTS (produced by 25_* and 26_*):
  data/eval/codellama_holdout.csv
  data/eval/deepseek_holdout.csv
  data/eval/holdout_eval.csv        (benign rows reused as the held-out benign set)

OUTPUT:
  data/eval/llm_holdout_full.csv    columns: text,label,attack_type,generator
  data/eval/llm_holdout_manifest.json

USAGE (from dashboard/):
  python scripts/27_assemble_llm_holdout.py
  python scripts/27_assemble_llm_holdout.py --benign-target 600

AFTER THIS, evaluate with the existing scripts by pointing them at the new CSV:
  python scripts/19_eval_by_type.py  --csv data/eval/llm_holdout_full.csv ...
  python scripts/21_modsec_holdout.py --csv data/eval/llm_holdout_full.csv ...
(both already accept a --csv flag; see AZURE_RUNBOOK.md step 7).
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
EVAL = ROOT / "data" / "eval"


def read_attacks(path: Path, generator: str) -> list[dict]:
    if not path.exists():
        print(f"  [WARN] {path.name} missing -- run its generator first. Skipping.")
        return []
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append({"text": r["payload"], "label": 1,
                        "attack_type": r.get("attack_type", "unknown"),
                        "generator": generator})
    print(f"  [OK] {path.name}: {len(out)} attack rows")
    return out


def read_benign(path: Path, target: int) -> list[dict]:
    if not path.exists():
        print(f"  [WARN] {path.name} missing -- no benign rows available.")
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if str(r.get("label")) == "0":
                rows.append({"text": r["text"], "label": 0,
                             "attack_type": "benign", "generator": "held_out_benign"})
    if len(rows) < target:
        print(f"  [SHORTFALL] only {len(rows)} benign rows available, "
              f"target was {target}. Using all {len(rows)} and reporting the shortfall.")
    return rows[:target]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign-target", type=int, default=600)
    ap.add_argument("--out", default=str(EVAL / "llm_holdout_full.csv"))
    args = ap.parse_args()

    print("Assembling LLM-generated held-out benchmark ...")
    codellama = read_attacks(EVAL / "codellama_holdout.csv", "codellama")
    deepseek = read_attacks(EVAL / "deepseek_holdout.csv", "deepseek-r1")
    benign = read_benign(EVAL / "holdout_eval.csv", args.benign_target)

    all_rows = codellama + deepseek + benign
    if not codellama and not deepseek:
        print("\n[ERROR] No generated attack rows found. Run 25_* and 26_* first.")
        raise SystemExit(2)

    out = Path(args.out)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "label", "attack_type", "generator"])
        w.writeheader()
        w.writerows(all_rows)

    gen_c = Counter(r["generator"] for r in all_rows)
    type_c = Counter(f'{r["generator"]}/{r["attack_type"]}'
                     for r in all_rows if r["label"] == 1)
    manifest = {
        "assembled_utc": datetime.now(timezone.utc).isoformat(),
        "total_rows": len(all_rows),
        "attacks": sum(1 for r in all_rows if r["label"] == 1),
        "benign": sum(1 for r in all_rows if r["label"] == 0),
        "benign_target": args.benign_target,
        "benign_shortfall": max(0, args.benign_target - sum(1 for r in all_rows if r["label"] == 0)),
        "by_generator": dict(gen_c),
        "attacks_by_generator_type": dict(type_c),
        "target_composition_section_3_5": {
            "codellama_sqli": 500, "codellama_xss": 500,
            "deepseek_sqli": 300, "deepseek_xss": 300, "benign": 600, "total": 2200},
        "output_csv": str(out),
        "note": ("Generator label retained on every attack row so Chapter 4 can "
                 "report Code Llama and DeepSeek separately (Section 3.5)."),
    }
    with open(EVAL / "llm_holdout_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 60)
    print(f"Total: {len(all_rows)}  "
          f"(attacks {manifest['attacks']} / benign {manifest['benign']})")
    for k, v in gen_c.items():
        print(f"  {k:20s} {v}")
    if manifest["benign_shortfall"]:
        print(f"  benign shortfall vs target: {manifest['benign_shortfall']}")
    print(f"Written: {out}")
    print("=" * 60)


if __name__ == "__main__":
    main()
