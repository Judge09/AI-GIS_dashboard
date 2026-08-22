#!/usr/bin/env python3
"""
15_evaluate_llm_corpus.py

Scores the LLM-generated evasion corpus (from 11_generate_evasion_corpus.py)
against the committed AI-GIS models: RF v2, LSTM, and the stacked meta-learner.

This closes the gap the project README calls the biggest one — every earlier
evasion number used 23 hand-written attacks, not machine-generated variants.

Outputs:
  reports/llm_corpus_results.json

USAGE (from the dashboard/ directory):
  python scripts/15_evaluate_llm_corpus.py
"""

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
np.random.seed(SEED)

PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR  = PROJECT_ROOT / "scripts"
MODELS_DIR   = PROJECT_ROOT / "models"
DATA_DIR     = PROJECT_ROOT / "data"
REPORTS_DIR  = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

CORPUS_PATH = DATA_DIR / "llm_evasion_corpus.csv"
OUTPUT_PATH = REPORTS_DIR / "llm_corpus_results.json"

sys.path.insert(0, str(SCRIPTS_DIR))
from evasion_resistance_check import engineer_rf_features  # noqa: E402
from build_rf_features_v2 import structural_features       # noqa: E402


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def main():
    if not CORPUS_PATH.exists():
        raise SystemExit(
            f"[ERROR] Corpus not found: {CORPUS_PATH}\n"
            f"  Generate it first:\n"
            f"    python scripts/11_generate_evasion_corpus.py --model <ollama-model>"
        )

    print("=" * 64)
    print("AI-GIS  |  15_evaluate_llm_corpus.py")
    print("=" * 64)
    print("[1/3] Loading models ...")

    with open(MODELS_DIR / "rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(MODELS_DIR / "meta.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(MODELS_DIR / "ngram_vectorizer.pkl", "rb") as f:
        vec = pickle.load(f)

    from tensorflow import keras
    lstm = keras.models.load_model(MODELS_DIR / "lstm_best.keras")

    v2_cols = list(pd.read_csv(DATA_DIR / "prepared" / "rf_train_v2.csv")
                   .drop(columns=["label"]).columns)

    print("[2/3] Scoring corpus ...")
    df = pd.read_csv(CORPUS_PATH)
    texts = df["generated_payload"].astype(str).tolist()

    struct = pd.DataFrame([structural_features(t) for t in texts])
    agg    = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ngram  = pd.DataFrame(vec.transform(texts).toarray(),
                          columns=[f"ngram_{i}" for i in range(300)])
    X = pd.concat([agg.reset_index(drop=True),
                   struct.reset_index(drop=True),
                   ngram.reset_index(drop=True)], axis=1)[v2_cols]

    rf_proba   = rf.predict_proba(X)[:, 1]
    lstm_proba = lstm.predict(np.stack([ordinal_encode(t) for t in texts]),
                              verbose=0).flatten()
    stack_proba = meta.predict_proba(np.column_stack([rf_proba, lstm_proba]))[:, 1]

    print("[3/3] Aggregating ...")
    total = len(texts)

    def summarise(name, proba):
        caught = int((proba >= 0.5).sum())
        return {
            "model": name,
            "total": total,
            "caught": caught,
            "missed": total - caught,
            "detection_rate": round(caught / total, 4) if total else 0.0,
            "mean_confidence": round(float(proba.mean()), 4),
        }

    per_technique = {}
    for tech, grp in df.assign(_s=stack_proba).groupby("technique_used"):
        caught = int((grp["_s"] >= 0.5).sum())
        per_technique[tech] = {
            "total": len(grp),
            "caught": caught,
            "detection_rate": round(caught / len(grp), 4),
        }

    per_example = [
        {
            "source_payload": df.iloc[i]["source_payload"],
            "generated_payload": texts[i],
            "technique": df.iloc[i]["technique_used"],
            "rf_proba": round(float(rf_proba[i]), 4),
            "lstm_proba": round(float(lstm_proba[i]), 4),
            "stacked_proba": round(float(stack_proba[i]), 4),
            "caught": bool(stack_proba[i] >= 0.5),
        }
        for i in range(total)
    ]

    results = {
        "description": "AI-GIS evaluated on the LLM-generated evasion corpus",
        "corpus": {
            "path": CORPUS_PATH.name,
            "rows": total,
            "generator_model": str(df["model"].iloc[0]) if total else None,
        },
        "summary": {
            "rf": summarise("RF v2", rf_proba),
            "lstm": summarise("LSTM", lstm_proba),
            "stacked": summarise("Stacked", stack_proba),
        },
        "per_technique": per_technique,
        "per_example": per_example,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print()
    print("=" * 64)
    print("STEP 15 - LLM CORPUS EVALUATION COMPLETE")
    print("=" * 64)
    for key in ("rf", "lstm", "stacked"):
        s = results["summary"][key]
        print(f"  {s['model']:10s}: {s['caught']}/{s['total']} caught "
              f"({s['detection_rate']*100:.1f}%)")
    print(f"  Exported : {OUTPUT_PATH}")
    print("=" * 64)


if __name__ == "__main__":
    main()
