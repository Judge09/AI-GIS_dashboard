#!/usr/bin/env python3
"""
13_statistical_significance.py

Performs rigorous statistical testing on the test set predictions to prove
that the Stacked Ensemble's performance gains are statistically significant
compared to the base models (RF and LSTM).

Requirements (Chapter 3 methodology):
  1. Bootstrap 95% Confidence Intervals for F1, FPR, and AUC-ROC (1,000 resamples).
  2. McNemar's Test (alpha=0.05) to compare the pass/fail agreement matrices
     of the Stacked Ensemble against both base models.

Outputs:
  reports/statistical_significance.json

USAGE (from project root):
  python scripts/13_statistical_significance.py
"""

import importlib.util
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score, confusion_matrix
import scipy.stats

# ── Seed (Rule 2) ────────────────────────────────────────────────────────────
import random
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ── Paths (Rule 6) ───────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR     = PROJECT_ROOT / "data" / "prepared"
MODELS_DIR   = PROJECT_ROOT / "models"
REPORTS_DIR  = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
STATS_OUTPUT = REPORTS_DIR / "statistical_significance.json"


# ── Statistics Helpers ────────────────────────────────────────────────────────
def mcnemar_test(y_true, y_pred1, y_pred2):
    """
    Computes McNemar's test (with continuity correction) for two models.
    y_pred1 and y_pred2 are binary predictions (0 or 1).
    """
    correct1 = (y_pred1 == y_true)
    correct2 = (y_pred2 == y_true)

    # b: model 1 correct, model 2 wrong
    b = np.sum(correct1 & ~correct2)
    # c: model 1 wrong, model 2 correct
    c = np.sum(~correct1 & correct2)

    if b + c == 0:
        return {"chi2": 0.0, "p_value": 1.0, "significant": False, "b": int(b), "c": int(c)}

    # McNemar with continuity correction
    chi2_stat = ((abs(b - c) - 1.0) ** 2) / (b + c)
    p_value = 1.0 - scipy.stats.chi2.cdf(chi2_stat, 1)

    return {
        "chi2": round(float(chi2_stat), 4),
        "p_value": float(p_value),
        "significant": bool(p_value < 0.05),
        "b": int(b),
        "c": int(c)
    }


def compute_fpr(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def bootstrap_ci(y_true, y_proba, n_iterations=1000, alpha=0.05):
    """
    Computes 95% Confidence Intervals via bootstrapping.
    """
    n_size = len(y_true)
    f1_scores = []
    fpr_scores = []
    auc_scores = []

    y_pred = (y_proba >= 0.5).astype(int)

    for i in range(n_iterations):
        # Sample with replacement
        indices = np.random.randint(0, n_size, n_size)
        sample_y_true = y_true[indices]
        sample_y_pred = y_pred[indices]
        sample_y_proba = y_proba[indices]
        
        # Only compute if sample has both classes (rarely an issue with large N)
        if len(np.unique(sample_y_true)) > 1:
            f1_scores.append(f1_score(sample_y_true, sample_y_pred, zero_division=0))
            fpr_scores.append(compute_fpr(sample_y_true, sample_y_pred))
            auc_scores.append(roc_auc_score(sample_y_true, sample_y_proba))

    def get_ci(scores):
        if not scores:
            return {"mean": 0.0, "lower": 0.0, "upper": 0.0, "margin": 0.0}
        lower = np.percentile(scores, (alpha / 2.0) * 100)
        upper = np.percentile(scores, (1 - alpha / 2.0) * 100)
        mean_val = np.mean(scores)
        margin = max(abs(mean_val - lower), abs(upper - mean_val))
        return {
            "mean": round(float(mean_val), 4),
            "lower": round(float(lower), 4),
            "upper": round(float(upper), 4),
            "margin": round(float(margin), 4)
        }

    return {
        "f1": get_ci(f1_scores),
        "fpr": get_ci(fpr_scores),
        "auc_roc": get_ci(auc_scores),
        "iterations": len(f1_scores)
    }


def main():
    # ── TensorFlow import ─────────────────────────────────────────────────────
    try:
        import tensorflow as tf
        tf.random.set_seed(SEED)
        from tensorflow import keras
    except ImportError:
        print("[ERROR] TensorFlow not installed.", file=sys.stderr)
        sys.exit(1)

    print("=" * 64)
    print("AI-GIS  |  13_statistical_significance.py")
    print("=" * 64)
    print("  Task: Bootstrap 95% CIs and McNemar's Test (alpha=0.05)")

    # ── Verify required artifacts (Rule 4) ────────────────────────────────────
    required = {
        "RF v2 model":       MODELS_DIR / "rf2.pkl",
        "LSTM checkpoint":   MODELS_DIR / "lstm_best.keras",
        "RF val v2":         DATA_DIR   / "rf_val_v2.csv",
        "RF test v2":        DATA_DIR   / "rf_test_v2.csv",
        "LSTM val":          DATA_DIR   / "lstm_val.npz",
        "LSTM test":         DATA_DIR   / "lstm_test.npz",
    }
    missing = [k for k, v in required.items() if not v.exists()]
    if missing:
        raise RuntimeError(f"[ERROR] Missing files: {', '.join(missing)}")

    # ── Load artifacts ────────────────────────────────────────────────────────
    print("\n[1/4] Loading trained models and data splits ...")
    with open(MODELS_DIR / "rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    lstm = keras.models.load_model(str(MODELS_DIR / "lstm_best.keras"))

    val_v2   = pd.read_csv(DATA_DIR / "rf_val_v2.csv")
    test_v2  = pd.read_csv(DATA_DIR / "rf_test_v2.csv")
    Xval,  yval  = val_v2.drop(columns=["label"]),   val_v2["label"].values
    Xtest, ytest = test_v2.drop(columns=["label"]),  test_v2["label"].values
    
    lstm_val  = np.load(DATA_DIR / "lstm_val.npz")
    lstm_test = np.load(DATA_DIR / "lstm_test.npz")

    # ── Compute base probabilities ────────────────────────────────────────────
    print("[2/4] Generating predictions on the test set ...")
    rf_val_proba    = rf.predict_proba(Xval)[:, 1]
    rf_test_proba   = rf.predict_proba(Xtest)[:, 1]
    lstm_val_proba  = lstm.predict(lstm_val["X"],  verbose=0).flatten()
    lstm_test_proba = lstm.predict(lstm_test["X"], verbose=0).flatten()

    meta = LogisticRegression(random_state=SEED)
    meta.fit(np.column_stack([rf_val_proba, lstm_val_proba]), yval)
    stacked_test_proba = meta.predict_proba(np.column_stack([rf_test_proba, lstm_test_proba]))[:, 1]

    # Binary predictions for McNemar
    rf_pred      = (rf_test_proba >= 0.5).astype(int)
    lstm_pred    = (lstm_test_proba >= 0.5).astype(int)
    stacked_pred = (stacked_test_proba >= 0.5).astype(int)

    # ── Bootstrap CIs ─────────────────────────────────────────────────────────
    print("[3/4] Computing 95% Confidence Intervals (1,000 resamples) ...")
    t0 = time.time()
    stacked_ci = bootstrap_ci(ytest, stacked_test_proba, n_iterations=1000)
    print(f"  Done in {time.time() - t0:.1f}s")

    # ── McNemar's Test ────────────────────────────────────────────────────────
    print("[4/4] Computing McNemar's Tests (alpha=0.05) ...")
    mcnemar_stacked_vs_rf   = mcnemar_test(ytest, stacked_pred, rf_pred)
    mcnemar_stacked_vs_lstm = mcnemar_test(ytest, stacked_pred, lstm_pred)

    # ── Export & Summary ──────────────────────────────────────────────────────
    results = {
        "description": "Chapter 3 Statistical Significance Results",
        "bootstrap_95_ci": {
            "model": "Stacked Ensemble",
            "iterations": stacked_ci["iterations"],
            "f1": stacked_ci["f1"],
            "fpr": stacked_ci["fpr"],
            "auc_roc": stacked_ci["auc_roc"]
        },
        "mcnemars_test_alpha_0_05": {
            "stacked_vs_rf": mcnemar_stacked_vs_rf,
            "stacked_vs_lstm": mcnemar_stacked_vs_lstm
        }
    }
    with open(STATS_OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    f1 = stacked_ci["f1"]
    fpr = stacked_ci["fpr"]
    
    print("\n" + "=" * 64)
    print("STEP 13 — STATISTICAL SIGNIFICANCE RESULTS")
    print("=" * 64)
    print(f"  Bootstrap 95% CI (Stacked Ensemble):")
    print(f"    F1-Score : {f1['mean']:.4f} ± {f1['margin']:.4f}  [{f1['lower']:.4f} - {f1['upper']:.4f}]")
    print(f"    FPR      : {fpr['mean']:.4f} ± {fpr['margin']:.4f}  [{fpr['lower']:.4f} - {fpr['upper']:.4f}]")
    print("\n  McNemar's Test (Is Stacked significantly better?):")
    print(f"    vs RF    : p-value = {mcnemar_stacked_vs_rf['p_value']:.2e}  (Sig? {mcnemar_stacked_vs_rf['significant']})")
    print(f"    vs LSTM  : p-value = {mcnemar_stacked_vs_lstm['p_value']:.2e}  (Sig? {mcnemar_stacked_vs_lstm['significant']})")
    print(f"\n  Exported   : {STATS_OUTPUT}")
    print("=" * 64)

if __name__ == "__main__":
    main()
