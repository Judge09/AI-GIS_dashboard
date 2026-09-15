#!/usr/bin/env python3
"""
20_significance_holdout.py  (Adviser item 2: central RQ / SOP3)

Re-runs model-vs-model significance on the 396-row ADVERSARIAL hold-out rather
than the saturated clean test split, where every model sits at F1 ~= 0.999 and
McNemar has almost no power.

Reports, for each pair:
  - McNemar exact binomial test (correct for small discordant counts)
  - the discordant cells b / c themselves
  - EFFECT SIZES, which the adviser asked for alongside p-values:
      * odds ratio b/c
      * risk difference in error rate, with a bootstrap 95% CI
      * Cohen's g  (|b/(b+c) - 0.5|), the effect size proper to McNemar
  - paired bootstrap CI on the DIFFERENCE in FPR and detection rate

USAGE (from dashboard/):  python scripts/20_significance_holdout.py
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from build_rf_features_v2 import structural_features, SEMANTIC_META_COLS  # noqa: E402
from text_normalize import normalize_text                   # noqa: E402

from scipy import stats

BOOT = 2000
SEED = 42
rng = np.random.default_rng(SEED)


def load_models():
    with open(ROOT / "models/rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(ROOT / "models/meta.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(ROOT / "models/ngram_vectorizer.pkl", "rb") as f:
        vec = pickle.load(f)
    from tensorflow import keras
    lstm = keras.models.load_model(ROOT / "models/lstm_best.keras")
    v2_cols = list(pd.read_csv(ROOT / "data/prepared/rf_train_v2.csv")
                   .drop(columns=["label"]).columns)
    return rf, meta, vec, lstm, v2_cols


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def score_all(texts, rf, meta, vec, lstm, v2_cols):
    texts = [normalize_text(t) for t in texts]
    struct = pd.DataFrame([structural_features(t) for t in texts])
    agg = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ng = pd.DataFrame(
        vec.transform(texts).toarray(),
        columns=[f"ngram_{i}" for i in range(len(vec.get_feature_names_out()))])
    X = pd.concat([agg.reset_index(drop=True), struct.reset_index(drop=True),
                   ng.reset_index(drop=True)], axis=1)
    X = X.reindex(columns=v2_cols, fill_value=0)
    rf_p = rf.predict_proba(X)[:, 1]
    E = np.stack([ordinal_encode(t) for t in texts])
    lstm_p = lstm.predict(E, verbose=0).flatten()
    sem_p = X[SEMANTIC_META_COLS].to_numpy()
    st_p = meta.predict_proba(np.column_stack([rf_p, lstm_p, sem_p]))[:, 1]
    return rf_p, lstm_p, st_p


def mcnemar_with_effect(correct_a, correct_b, name_a, name_b):
    """correct_* are boolean arrays: was that model right on each row."""
    b = int(np.sum(correct_a & ~correct_b))   # a right, b wrong
    c = int(np.sum(~correct_a & correct_b))   # a wrong, b right
    n_disc = b + c

    # exact binomial: correct when discordant counts are small
    if n_disc == 0:
        p = 1.0
    else:
        p = float(stats.binomtest(b, n_disc, 0.5).pvalue)

    odds_ratio = (b / c) if c > 0 else float("inf") if b > 0 else float("nan")
    prop = (b / n_disc) if n_disc else 0.5
    cohens_g = abs(prop - 0.5)

    # bootstrap CI on the error-rate difference (paired, resample rows)
    n = len(correct_a)
    err_a = ~correct_a
    err_b = ~correct_b
    diffs = []
    for _ in range(BOOT):
        idx = rng.integers(0, n, n)
        diffs.append(err_a[idx].mean() - err_b[idx].mean())
    diffs = np.array(diffs)
    lo, hi = np.percentile(diffs, [2.5, 97.5])

    return {
        "comparison": f"{name_a} vs {name_b}",
        "b_a_right_b_wrong": b,
        "c_a_wrong_b_right": c,
        "n_discordant": n_disc,
        "p_value_exact": round(p, 4),
        "significant_at_0.05": bool(p < 0.05),
        "odds_ratio_b_over_c": (round(odds_ratio, 3)
                                if np.isfinite(odds_ratio) else str(odds_ratio)),
        "cohens_g": round(cohens_g, 4),
        "error_rate_diff": round(float(err_a.mean() - err_b.mean()), 4),
        "error_rate_diff_95ci": [round(float(lo), 4), round(float(hi), 4)],
    }


def boot_metric_diff(y, pa, pb, metric, thr=0.5):
    """Paired bootstrap CI on the difference in a metric between two models."""
    y = np.asarray(y)
    n = len(y)
    out = []
    for _ in range(BOOT):
        idx = rng.integers(0, n, n)
        yy, aa, bb = y[idx], pa[idx] >= thr, pb[idx] >= thr
        if metric == "fpr":
            neg = yy == 0
            if neg.sum() == 0:
                continue
            out.append(aa[neg].mean() - bb[neg].mean())
        else:
            pos = yy == 1
            if pos.sum() == 0:
                continue
            out.append(aa[pos].mean() - bb[pos].mean())
    out = np.array(out)
    return [round(float(np.percentile(out, 2.5)), 4),
            round(float(np.percentile(out, 97.5)), 4)]


def main():
    print("=" * 72)
    print("20_significance_holdout.py  -  significance on the ADVERSARIAL set")
    print("=" * 72)

    df = pd.read_csv(ROOT / "data/eval/holdout_eval.csv")
    y = df["label"].astype(int).to_numpy()

    print(f"\nHold-out: {len(df)} rows ({int((y == 1).sum())} attack / "
          f"{int((y == 0).sum())} benign)")
    print("Loading models + scoring ...")
    rf, meta, vec, lstm, v2_cols = load_models()
    rf_p, lstm_p, st_p = score_all(df["text"].tolist(), rf, meta, vec, lstm, v2_cols)

    preds = {"rf": rf_p, "lstm": lstm_p, "stacked": st_p}
    correct = {k: ((v >= 0.5).astype(int) == y) for k, v in preds.items()}

    results = {"dataset": "holdout_eval.csv (396 rows, adversarial)",
               "n": int(len(df)), "bootstrap_iterations": BOOT, "test": "McNemar exact binomial"}

    print(f"\n{'=' * 72}\nPER-MODEL ERROR COUNTS\n{'=' * 72}")
    for k in ["rf", "lstm", "stacked"]:
        errs = int((~correct[k]).sum())
        print(f"  {k:10s} errors={errs:3d}/{len(df)}  accuracy={correct[k].mean() * 100:.2f}%")
        results[f"{k}_errors"] = errs

    print(f"\n{'=' * 72}\nPAIRWISE McNEMAR + EFFECT SIZES\n{'=' * 72}")
    pairs = [("stacked", "rf"), ("stacked", "lstm"), ("rf", "lstm")]
    results["pairwise"] = []
    for a, b in pairs:
        r = mcnemar_with_effect(correct[a], correct[b], a, b)
        r["fpr_diff_95ci"] = boot_metric_diff(y, preds[a], preds[b], "fpr")
        r["detection_diff_95ci"] = boot_metric_diff(y, preds[a], preds[b], "det")
        results["pairwise"].append(r)
        print(f"\n  {r['comparison']}")
        print(f"    discordant: b={r['b_a_right_b_wrong']} (a right, b wrong)  "
              f"c={r['c_a_wrong_b_right']} (a wrong, b right)")
        print(f"    p (exact)          = {r['p_value_exact']}   "
              f"significant={r['significant_at_0.05']}")
        print(f"    odds ratio b/c     = {r['odds_ratio_b_over_c']}")
        print(f"    Cohen's g          = {r['cohens_g']}")
        print(f"    error-rate diff    = {r['error_rate_diff']}  "
              f"95% CI {r['error_rate_diff_95ci']}")
        print(f"    FPR diff 95% CI    = {r['fpr_diff_95ci']}")
        print(f"    detection diff CI  = {r['detection_diff_95ci']}")

    out = ROOT / "reports" / "significance_holdout.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\n  JSON written to: {out}")
    print("=" * 72)


if __name__ == "__main__":
    main()
