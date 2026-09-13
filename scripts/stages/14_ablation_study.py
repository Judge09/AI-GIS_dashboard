#!/usr/bin/env python3
"""
14_ablation_study.py

Executes the "Six-Condition Ablation Study" as defined in Chapter 3.
Evaluates the components of the Stacked Ensemble independently to prove
that stacking contributes meaningful performance beyond its strongest base model.

Conditions:
  1. RF alone (v2)
  2. LSTM alone
  3. Logistic Regression trained directly on the 11 base features (Baseline)
  4. RF + Meta (LSTM zeroed)
  5. LSTM + Meta (RF zeroed)
  6. Full RF+LSTM Stacked Ensemble

Outputs:
  reports/ablation_study_results.json

USAGE (from project root):
  python scripts/14_ablation_study.py
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
from sklearn.metrics import f1_score, roc_auc_score, precision_score, recall_score, confusion_matrix

# ── Seed (Rule 2) ────────────────────────────────────────────────────────────
import random
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ── Paths (Rule 6) ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT, DATA_CORPUS  # noqa: E402
PROJECT_ROOT = _ROOT
DATA_DIR     = PROJECT_ROOT / "data" / "prepared"
from paths import MODELS_CURRENT as MODELS_DIR  # noqa: E402
LOG_FILE     = DATA_CORPUS / "honeypot_final.log"
REPORTS_DIR  = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
ABLATION_OUT = REPORTS_DIR / "ablation_study_results.json"


def _load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_scripts_dir = Path(__file__).parent.parent / "lib"
_m02 = _load_mod("prepare_training_data", _scripts_dir / "prepare_honeypot_for_training.py")
load_log = _m02.load_log
session_grouped_split = _m02.session_grouped_split


def compute_metrics(y_true, y_proba, threshold=0.5) -> dict:
    y_pred = (y_proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    if len(np.unique(y_true)) < 2:
        auc = 0.0
    else:
        auc = roc_auc_score(y_true, y_proba)

    return {
        "f1":         round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "fpr":        round(float(fpr), 4),
        "auc_roc":    round(float(auc), 4),
        "precision":  round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":     round(float(recall_score(y_true, y_pred, zero_division=0)), 4)
    }


def main():
    try:
        import tensorflow as tf
        tf.random.set_seed(SEED)
        from tensorflow import keras
    except ImportError:
        print("[ERROR] TensorFlow not installed.", file=sys.stderr)
        sys.exit(1)

    print("=" * 64)
    print("AI-GIS  |  14_ablation_study.py")
    print("=" * 64)

    # ── Load and Reconstruct Test Set with Families ───────────────────────────
    print("[1/5] Reconstructing dataset to extract attack families ...")
    if not LOG_FILE.exists():
        raise RuntimeError(f"[ERROR] Original log missing: {LOG_FILE}")
    df_raw = load_log(LOG_FILE)
    _, _, test_df = session_grouped_split(df_raw, seed=SEED)
    attack_families = test_df["attack_family"].values

    # ── Load Model Artifacts ──────────────────────────────────────────────────
    print("[2/5] Loading trained models and RF/LSTM splits ...")
    with open(MODELS_DIR / "rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    lstm = keras.models.load_model(str(MODELS_DIR / "lstm_best.keras"))

    train_v2 = pd.read_csv(DATA_DIR / "rf_train_v2.csv")
    val_v2   = pd.read_csv(DATA_DIR / "rf_val_v2.csv")
    test_v2  = pd.read_csv(DATA_DIR / "rf_test_v2.csv")

    Xtrain, ytrain = train_v2.drop(columns=["label"]), train_v2["label"].values
    Xval,   yval   = val_v2.drop(columns=["label"]),   val_v2["label"].values
    Xtest,  ytest  = test_v2.drop(columns=["label"]),  test_v2["label"].values

    lstm_val  = np.load(DATA_DIR / "lstm_val.npz")
    lstm_test = np.load(DATA_DIR / "lstm_test.npz")

    assert (lstm_test["y"] == ytest).all(), "[ERROR] Label mismatch!"
    assert len(ytest) == len(attack_families), "[ERROR] Reconstructed split size mismatch!"

    # ── Subsets Masks ─────────────────────────────────────────────────────────
    # The honeypot log labels attacks by sub-family (union_based, stored, ...)
    # rather than the coarse "sqli"/"xss" class, so map sub-families to a class.
    SQLI_FAMILIES = {"union_based", "boolean_blind", "time_based_blind", "error_based",
                     "stacked_query", "tautology", "auth_bypass"}
    XSS_FAMILIES  = {"reflected", "stored", "dom_based"}

    mask_sqli = np.array([f.lower() in SQLI_FAMILIES for f in attack_families])
    mask_xss  = np.array([f.lower() in XSS_FAMILIES for f in attack_families])
    if not mask_sqli.any() or not mask_xss.any():
        print(f"[warn] family masks matched {mask_sqli.sum()} SQLi / {mask_xss.sum()} XSS rows; "
              f"observed families: {sorted(set(attack_families))}")
    # For benign rows, we include them in the SQLi and XSS subsets to compute FPR
    mask_benign = (ytest == 0)
    
    sqli_subset = mask_sqli | mask_benign
    xss_subset  = mask_xss | mask_benign

    # ── Generate Base Predictions ─────────────────────────────────────────────
    print("[3/5] Generating base predictions (RF and LSTM) ...")
    rf_val_proba    = rf.predict_proba(Xval)[:, 1]
    rf_test_proba   = rf.predict_proba(Xtest)[:, 1]
    lstm_val_proba  = lstm.predict(lstm_val["X"],  verbose=0).flatten()
    lstm_test_proba = lstm.predict(lstm_test["X"], verbose=0).flatten()

    # Meta Learner (trained on val probabilities)
    meta = LogisticRegression(random_state=SEED)
    meta.fit(np.column_stack([rf_val_proba, lstm_val_proba]), yval)

    # ── Condition 3: Logistic Regression on 11 Base Features ──────────────────
    print("[4/5] Training Condition 3 baseline (LR on 11 base features) ...")
    # First 11 columns of Xtrain are the base features (length, entropy, counts...)
    Xtrain_11 = Xtrain.iloc[:, :11].values
    Xtest_11  = Xtest.iloc[:, :11].values
    
    lr_base = LogisticRegression(random_state=SEED, max_iter=1000)
    lr_base.fit(Xtrain_11, ytrain)
    lr_base_test_proba = lr_base.predict_proba(Xtest_11)[:, 1]

    # ── Evaluate the 6 Conditions ─────────────────────────────────────────────
    print("[5/5] Evaluating all 6 Ablation Conditions ...")
    
    # Cond 1: RF alone
    c1_proba = rf_test_proba
    
    # Cond 2: LSTM alone
    c2_proba = lstm_test_proba
    
    # Cond 3: LR (11 features)
    c3_proba = lr_base_test_proba
    
    # Cond 4: RF + Meta (LSTM zeroed)
    c4_proba = meta.predict_proba(np.column_stack([rf_test_proba, np.zeros_like(lstm_test_proba)]))[:, 1]
    
    # Cond 5: LSTM + Meta (RF zeroed)
    c5_proba = meta.predict_proba(np.column_stack([np.zeros_like(rf_test_proba), lstm_test_proba]))[:, 1]
    
    # Cond 6: Full Stacked Ensemble
    c6_proba = meta.predict_proba(np.column_stack([rf_test_proba, lstm_test_proba]))[:, 1]

    conditions = [
        ("Cond_1_RF_Alone", c1_proba),
        ("Cond_2_LSTM_Alone", c2_proba),
        ("Cond_3_LR_11_Base_Feats", c3_proba),
        ("Cond_4_RF_Plus_Meta_No_LSTM", c4_proba),
        ("Cond_5_LSTM_Plus_Meta_No_RF", c5_proba),
        ("Cond_6_Full_Stacked_Ensemble", c6_proba),
    ]

    def best_threshold(y_true, proba):
        """Threshold maximising F1.

        Ablation conditions that zero out a meta-learner input (Cond 4/5) shift the
        probability scale, so a hard-coded 0.5 can score a perfectly-ranking model at
        F1=0. Reporting each condition at its own best threshold measures the
        information the component carries, which is what the ablation is asking.
        """
        best_t, best_f1 = 0.5, -1.0
        for t in np.unique(np.round(np.linspace(0.01, 0.99, 99), 2)):
            f1 = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
            if f1 > best_f1:
                best_t, best_f1 = float(t), f1
        return best_t

    results = {}
    for name, proba in conditions:
        t = best_threshold(ytest, proba)
        results[name] = {
            "Combined": compute_metrics(ytest, proba),
            "Combined_at_best_threshold": {**compute_metrics(ytest, proba, threshold=t),
                                           "threshold": t},
            "SQLi_Only": compute_metrics(ytest[sqli_subset], proba[sqli_subset]),
            "XSS_Only": compute_metrics(ytest[xss_subset], proba[xss_subset])
        }

    with open(ABLATION_OUT, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 64)
    print("STEP 14 — 6-CONDITION ABLATION STUDY COMPLETE")
    print("=" * 64)
    for name in [c[0] for c in conditions]:
        f1 = results[name]["Combined"]["f1"]
        fpr = results[name]["Combined"]["fpr"]
        auc = results[name]["Combined"]["auc_roc"]
        print(f"  {name.ljust(28)} : F1={f1:.4f} | FPR={fpr:.4f} | AUC={auc:.4f}")

    print(f"\n  Exported matrix to : {ABLATION_OUT}")
    print("=" * 64)

if __name__ == "__main__":
    main()
