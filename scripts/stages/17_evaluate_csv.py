#!/usr/bin/env python3
"""
17_evaluate_csv.py  (Improvement Plan — Task 2)

The RULER. Scores any labelled CSV through RF v2 + LSTM + the stacked
meta-learner, exactly as the live app does, and prints detection rate + FPR for
each model. Use this to record BEFORE/AFTER numbers around every change in
Tasks 3-5.

Input CSV must have columns:  text,label   (label 1=attack, 0=benign)

USAGE (from dashboard/):
  python scripts/17_evaluate_csv.py                       # defaults to the hold-out set
  python scripts/17_evaluate_csv.py --csv path/to.csv
  python scripts/17_evaluate_csv.py --csv path/to.csv --out reports/my_run.json

Read-only w.r.t. the models — it never writes to models/.
"""
import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
from evasion_resistance_check import engineer_rf_features  # noqa: F401
from rf_inference import build_rf_frame, load_word_vectorizer, rf_feature_columns  # noqa: E402
from build_rf_features_v2 import structural_features       # noqa: E402
from text_normalize import normalize_text                   # noqa: E402


_WORD_VEC = None


def load_models():
    with open(ROOT / "models/current/rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(ROOT / "models/current/meta.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(ROOT / "models/current/ngram_vectorizer.pkl", "rb") as f:
        vec = pickle.load(f)
    from tensorflow import keras
    lstm = keras.models.load_model(ROOT / "models/current/lstm_best.keras")
    global _WORD_VEC
    _WORD_VEC = load_word_vectorizer(ROOT / "models" / "current")
    global _LSTM_FOR_MAXLEN
    _LSTM_FOR_MAXLEN = lstm
    v2_cols = rf_feature_columns(rf, ROOT / "data/prepared/rf_train_v2.csv")
    return rf, meta, vec, lstm, v2_cols


# Set by each script once its Keras model is loaded; ordinal_encode() reads it
# so the encoding width always matches the model actually being scored.
_LSTM_FOR_MAXLEN = None


def _lstm_maxlen(default=400):
    m = _LSTM_FOR_MAXLEN
    if m is not None:
        try:
            return int(m.input_shape[1])
        except Exception:
            pass
    return default

def ordinal_encode(text, max_len=None):
    # Width comes from the loaded model (lstm.input_shape[1]) via _lstm_maxlen();
    # it used to be a hardcoded 200 duplicated in every eval script, so raising
    # MAXLEN in the trainer would have silently fed 200-wide arrays to a wider model.
    if max_len is None:
        max_len = _lstm_maxlen()
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def score_all(texts, rf, meta, vec, lstm, v2_cols):
    texts = [normalize_text(t) for t in texts]   # match training + live app
    X = build_rf_frame(texts, vec, v2_cols, word_vec=_WORD_VEC)
    rf_p   = rf.predict_proba(X)[:, 1]
    lstm_p = lstm.predict(np.stack([ordinal_encode(t) for t in texts]),
                          verbose=0).flatten()
    stack_p = meta.predict_proba(np.column_stack([rf_p, lstm_p]))[:, 1]
    return rf_p, lstm_p, stack_p


def metrics(y, proba, thr=0.5):
    pred = (proba >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    n_atk = tp + fn
    n_ben = tn + fp
    return {
        "attacks_total": n_atk, "attacks_caught": tp, "attacks_missed": fn,
        "benign_total": n_ben, "false_positives": fp,
        "detection_rate": round(tp / n_atk, 4) if n_atk else None,
        "fpr": round(fp / n_ben, 4) if n_ben else None,
    }


def main():
    ap = argparse.ArgumentParser(description="Score a labelled CSV through the AI-GIS models.")
    ap.add_argument("--csv", default=str(ROOT / "data" / "eval" / "holdout_eval.csv"),
                    help="CSV with text,label columns (default: hold-out eval set)")
    ap.add_argument("--out", default=str(ROOT / "reports" / "holdout_eval_results.json"),
                    help="Where to write the JSON summary")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(f"[ERROR] CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    if not {"text", "label"}.issubset(df.columns):
        raise SystemExit(f"[ERROR] {csv_path.name} must have columns: text,label")
    df = df.dropna(subset=["text"])
    texts = df["text"].astype(str).tolist()
    y = df["label"].astype(int).to_numpy()

    print("=" * 68)
    print(f"AI-GIS  |  17_evaluate_csv.py   ({csv_path.name}: {len(texts)} rows)")
    print("=" * 68)
    print("[1/2] Loading models ...")
    rf, meta, vec, lstm, v2_cols = load_models()

    print("[2/2] Scoring ...")
    rf_p, lstm_p, stack_p = score_all(texts, rf, meta, vec, lstm, v2_cols)

    result = {
        "input": csv_path.name,
        "rows": len(texts),
        "rf": metrics(y, rf_p),
        "lstm": metrics(y, lstm_p),
        "stacked": metrics(y, stack_p),
    }
    # record the individual misses so later steps can see what's still wrong
    result["missed_attacks"] = [
        texts[i] for i in range(len(texts))
        if y[i] == 1 and stack_p[i] < 0.5
    ]
    result["false_alarms"] = [
        texts[i] for i in range(len(texts))
        if y[i] == 0 and stack_p[i] >= 0.5
    ]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                        encoding="utf-8")

    print()
    print("=" * 68)
    print("RESULTS  (threshold 0.5)")
    print("=" * 68)
    hdr = f"  {'model':10s} {'caught':>12s} {'det.rate':>9s} {'FP':>10s} {'FPR':>8s}"
    print(hdr)
    print("  " + "-" * 62)
    for key in ("rf", "lstm", "stacked"):
        m = result[key]
        print(f"  {key:10s} "
              f"{m['attacks_caught']:>4}/{m['attacks_total']:<7} "
              f"{(m['detection_rate'] or 0)*100:>7.1f}% "
              f"{m['false_positives']:>4}/{m['benign_total']:<5} "
              f"{(m['fpr'] or 0)*100:>6.1f}%")
    print("  " + "-" * 62)
    print(f"  Stacked missed {len(result['missed_attacks'])} attacks, "
          f"raised {len(result['false_alarms'])} false alarms.")
    print(f"  Full detail written to: {out_path}")
    print("=" * 68)


if __name__ == "__main__":
    main()
