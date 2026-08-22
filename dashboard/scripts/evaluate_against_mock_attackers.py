#!/usr/bin/env python3
"""
evaluate_against_mock_attackers.py

*** TEMPORARY RESULTS -- MOCK DATA, NOT REAL LLM OUTPUT ***
See mock_ai_attacker.py's docstring for what this is and isn't.

Loads the already-trained RF v2 / LSTM / meta-learner from a pipeline run
and evaluates catch rate separately for the "normal" (CodeLlama-style) and
"polymorphic" (DeepSeek-style) mock profiles -- this is the actual shape
of the comparison your thesis needs (does catch rate drop on the harder,
more mutated profile?), just run on placeholder data so the evaluation
code path is proven out before the real Ollama payloads exist.

USAGE:
  python3 evaluate_against_mock_attackers.py \
      --models-dir /home/claude/run2 \
      --data-dir /home/claude/run2/prepared \
      --normal-file mock_codellama_normal.jsonl \
      --polymorphic-file mock_deepseek_polymorphic.jsonl
"""

import argparse
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from tensorflow import keras

sys.path.insert(0, str(Path(__file__).parent))
from evasion_resistance_check import engineer_rf_features
from build_rf_features_v2 import structural_features


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def load_mock_file(path):
    return [json.loads(l) for l in open(path)]


def build_v2_features(texts, v2_cols, vectorizer):
    struct_df = pd.DataFrame([structural_features(t) for t in texts])
    agg_df = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ngram_df = pd.DataFrame(vectorizer.transform(texts).toarray(),
                             columns=[f"ngram_{i}" for i in range(300)])
    combined = pd.concat([agg_df.reset_index(drop=True), struct_df.reset_index(drop=True),
                           ngram_df.reset_index(drop=True)], axis=1)
    return combined[v2_cols]


def evaluate_profile(records, rf, lstm, meta, v2_cols, vectorizer):
    texts = [r["payload"] for r in records]
    Xv2 = build_v2_features(texts, v2_cols, vectorizer)
    Xlstm = np.stack([ordinal_encode(t) for t in texts])

    rf_proba = rf.predict_proba(Xv2)[:, 1]
    lstm_proba = lstm.predict(Xlstm, verbose=0).flatten()
    stacked_proba = meta.predict_proba(np.column_stack([rf_proba, lstm_proba]))[:, 1]

    result = {
        "n": len(records),
        "rf_caught": int((rf_proba >= 0.5).sum()),
        "lstm_caught": int((lstm_proba >= 0.5).sum()),
        "stacked_caught": int((stacked_proba >= 0.5).sum()),
    }

    by_family = {}
    families = sorted(set(r["family"] for r in records))
    for fam in families:
        idx = [i for i, r in enumerate(records) if r["family"] == fam]
        if not idx:
            continue
        by_family[fam] = {
            "n": len(idx),
            "stacked_caught": int((stacked_proba[idx] >= 0.5).sum()),
        }
    result["by_family"] = by_family
    result["per_example"] = [
        {"payload": t, "family": r["family"], "rf_proba": round(float(rp), 4),
         "lstm_proba": round(float(lp), 4), "stacked_proba": round(float(sp), 4)}
        for t, r, rp, lp, sp in zip(texts, records, rf_proba, lstm_proba, stacked_proba)
    ]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--normal-file", type=Path, required=True)
    ap.add_argument("--polymorphic-file", type=Path, required=True)
    ap.add_argument("-o", "--output", type=Path, default=Path("mock_attacker_results.json"))
    args = ap.parse_args()

    print("Loading trained models...")
    with open(args.models_dir / "rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(args.models_dir / "meta.pkl", "rb") as f:
        meta = pickle.load(f)
    lstm = keras.models.load_model(args.models_dir / "lstm_best.keras")
    with open(args.data_dir / "ngram_vectorizer.pkl", "rb") as f:
        vectorizer = pickle.load(f)
    v2_cols = list(pd.read_csv(args.data_dir / "rf_train_v2.csv").drop(columns=["label"]).columns)

    normal_records = load_mock_file(args.normal_file)
    poly_records = load_mock_file(args.polymorphic_file)

    print(f"Evaluating {len(normal_records)} 'normal' (CodeLlama-style) mock payloads...")
    normal_result = evaluate_profile(normal_records, rf, lstm, meta, v2_cols, vectorizer)

    print(f"Evaluating {len(poly_records)} 'polymorphic' (DeepSeek-style) mock payloads...")
    poly_result = evaluate_profile(poly_records, rf, lstm, meta, v2_cols, vectorizer)

    print("\n" + "=" * 60)
    print("TEMPORARY RESULTS -- MOCK DATA, NOT REAL LLM OUTPUT")
    print("=" * 60)
    for name, res in [("NORMAL (CodeLlama-style placeholder)", normal_result),
                       ("POLYMORPHIC (DeepSeek-style placeholder)", poly_result)]:
        n = res["n"]
        print(f"\n{name} -- {n} payloads")
        print(f"  RF v2:    {res['rf_caught']}/{n} ({res['rf_caught']/n*100:.1f}%)")
        print(f"  LSTM:     {res['lstm_caught']}/{n} ({res['lstm_caught']/n*100:.1f}%)")
        print(f"  Stacked:  {res['stacked_caught']}/{n} ({res['stacked_caught']/n*100:.1f}%)")

    print(f"\nDelta (polymorphic - normal), stacked catch rate: "
          f"{poly_result['stacked_caught']/poly_result['n']*100 - normal_result['stacked_caught']/normal_result['n']*100:+.1f} points")

    with open(args.output, "w") as f:
        json.dump({"normal": normal_result, "polymorphic": poly_result}, f, indent=2)
    print(f"\nSaved full results to {args.output}")


if __name__ == "__main__":
    main()
