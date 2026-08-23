#!/usr/bin/env python3
"""
22_multirun_variance.py  (Adviser item 6: RO2)

Single unseeded runs are not defensible as final numbers. This script seeds
TensorFlow, NumPy and Python, retrains the whole stack N times with a DIFFERENT
seed each run, evaluates every run on the 396-row hold-out, and reports
mean +/- SD for detection rate, FPR, F1 and AUC.

Everything else is held fixed: the same log, the same session-grouped split
method, the same architecture. Only the seed moves, so the spread measures
training nondeterminism, not data variation.

USAGE (from dashboard/):
  python scripts/22_multirun_variance.py --runs 3 --epochs 6
  python scripts/22_multirun_variance.py --runs 5 --epochs 6 --two-layer

Writes reports/multirun_variance.json. Does NOT overwrite models/ -- it trains
in memory so the shipped model is untouched.
"""
import argparse
import json
import os
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from build_rf_features_v2 import structural_features        # noqa: E402
from text_normalize import normalize_text                   # noqa: E402
import prepare_honeypot_for_training as _prep               # noqa: E402

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score

MAXLEN = 200
NGRAM_N = 300

RF_COLS = ["payload_len", "entropy", "num_special_chars", "num_digits",
           "num_uppercase", "param_count", "is_post", "has_sqli_keyword",
           "has_xss_keyword", "quote_count", "comment_token_count",
           "has_tautology_pattern", "has_quote_before_sql_keyword",
           "has_comment_after_quote", "has_html_tag_open",
           "has_event_handler_pattern", "longest_special_run",
           "special_char_ratio", "quote_ratio"]


def ordinal_encode(text, max_len=MAXLEN):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def rf_matrix(texts, vec):
    st = pd.DataFrame([structural_features(t) for t in texts])
    ag = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    base = pd.concat([ag.reset_index(drop=True), st.reset_index(drop=True)], axis=1)
    ng = pd.DataFrame(vec.transform(texts).toarray(),
                      columns=[f"ngram_{i}" for i in range(len(vec.get_feature_names_out()))])
    return pd.concat([base[RF_COLS], ng.reset_index(drop=True)], axis=1)


def build_lstm(seed, two_layer=False):
    from tensorflow import keras
    from tensorflow.keras import layers
    init = keras.initializers.GlorotUniform(seed=seed)
    if two_layer:
        m = keras.Sequential([
            layers.Input(shape=(MAXLEN,)),
            layers.Embedding(128, 32, mask_zero=True),
            layers.LSTM(64, return_sequences=True, kernel_initializer=init),
            layers.Dropout(0.3, seed=seed),
            layers.LSTM(32, kernel_initializer=init),
            layers.Dropout(0.3, seed=seed),
            layers.Dense(1, activation="sigmoid"),
        ])
    else:
        m = keras.Sequential([
            layers.Input(shape=(MAXLEN,)),
            layers.Embedding(128, 32, mask_zero=True),
            layers.LSTM(64, kernel_initializer=init),
            layers.Dropout(0.3, seed=seed),
            layers.Dense(1, activation="sigmoid"),
        ])
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss="binary_crossentropy",
              metrics=[keras.metrics.AUC(name="auc")])
    return m


def metrics(y, p, thr=0.5):
    y = np.asarray(y)
    pred = (np.asarray(p) >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {
        "detection_rate": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "f1": round(float(f1_score(y, pred)), 4),
        "auc": round(float(roc_auc_score(y, p)), 4),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def one_run(seed, epochs, two_layer, hold, log_df):
    import tensorflow as tf
    from tensorflow import keras

    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)
    keras.backend.clear_session()

    tr, va, te = _prep.session_grouped_split(log_df, 42)   # split fixed at 42
    tr_txt = tr["_payload_text"].tolist()
    va_txt = va["_payload_text"].tolist()
    ytr = tr["label"].to_numpy()
    yva = va["label"].to_numpy()

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                          max_features=NGRAM_N, lowercase=False)
    vec.fit(tr_txt)

    Xtr = rf_matrix(tr_txt, vec)
    Xva = rf_matrix(va_txt, vec)
    rf = RandomForestClassifier(n_estimators=200, max_depth=20,
                                class_weight="balanced",
                                random_state=seed, n_jobs=-1)
    rf.fit(Xtr, ytr)

    Etr = np.stack([ordinal_encode(t) for t in tr_txt])
    Eva = np.stack([ordinal_encode(t) for t in va_txt])
    lstm = build_lstm(seed, two_layer)
    lstm.fit(Etr, ytr, validation_data=(Eva, yva), epochs=epochs,
             batch_size=128, verbose=0)

    meta = LogisticRegression()
    meta.fit(np.column_stack([rf.predict_proba(Xva)[:, 1],
                              lstm.predict(Eva, verbose=0).flatten()]), yva)

    # evaluate on the hold-out
    h_txt = [normalize_text(t) for t in hold["text"].tolist()]
    yh = hold["label"].astype(int).to_numpy()
    Xh = rf_matrix(h_txt, vec)
    rf_p = rf.predict_proba(Xh)[:, 1]
    Eh = np.stack([ordinal_encode(t) for t in h_txt])
    ls_p = lstm.predict(Eh, verbose=0).flatten()
    st_p = meta.predict_proba(np.column_stack([rf_p, ls_p]))[:, 1]

    return {"rf": metrics(yh, rf_p), "lstm": metrics(yh, ls_p),
            "stacked": metrics(yh, st_p)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--two-layer", action="store_true",
                    help="use the original 2-layer stacked LSTM")
    ap.add_argument("--out", default=str(ROOT / "reports/multirun_variance.json"))
    args = ap.parse_args()

    print("=" * 70)
    print(f"22_multirun_variance.py  -  {args.runs} seeded runs, "
          f"{'2-layer' if args.two_layer else '1-layer'} LSTM")
    print("=" * 70)

    log_df = _prep.load_log(ROOT / "data/honeypot_final.log")
    log_df["_payload_text"] = log_df["_payload_text"].astype(str).map(normalize_text)
    hold = pd.read_csv(ROOT / "data/eval/holdout_eval.csv")

    seeds = [42 + i for i in range(args.runs)]
    runs = []
    for i, s in enumerate(seeds, 1):
        print(f"\n--- run {i}/{args.runs} (seed={s}) ---", flush=True)
        r = one_run(s, args.epochs, args.two_layer, hold, log_df)
        r["seed"] = s
        runs.append(r)
        for m in ["rf", "lstm", "stacked"]:
            print(f"    {m:8s} det={r[m]['detection_rate'] * 100:5.1f}%  "
                  f"fpr={r[m]['fpr'] * 100:5.1f}%  f1={r[m]['f1']:.4f}  "
                  f"auc={r[m]['auc']:.4f}", flush=True)

    summary = {"runs": args.runs, "epochs": args.epochs,
               "architecture": "2-layer" if args.two_layer else "1-layer",
               "seeds": seeds, "per_run": runs, "summary": {}}

    print(f"\n{'=' * 70}\nMEAN +/- SD over {args.runs} runs (396-row hold-out)\n{'=' * 70}")
    print(f"  {'model':10s} {'detection':>18s} {'FPR':>18s} {'F1':>16s} {'AUC':>16s}")
    print("  " + "-" * 78)
    for m in ["rf", "lstm", "stacked"]:
        row = {}
        for k in ["detection_rate", "fpr", "f1", "auc"]:
            vals = np.array([r[m][k] for r in runs], dtype=float)
            row[k] = {"mean": round(float(vals.mean()), 4),
                      "sd": round(float(vals.std(ddof=1)) if len(vals) > 1 else 0.0, 4),
                      "min": round(float(vals.min()), 4),
                      "max": round(float(vals.max()), 4)}
        summary["summary"][m] = row
        print(f"  {m:10s} "
              f"{row['detection_rate']['mean'] * 100:8.2f} +/- {row['detection_rate']['sd'] * 100:4.2f}%  "
              f"{row['fpr']['mean'] * 100:8.2f} +/- {row['fpr']['sd'] * 100:4.2f}%  "
              f"{row['f1']['mean']:7.4f} +/- {row['f1']['sd']:.4f}  "
              f"{row['auc']['mean']:7.4f} +/- {row['auc']['sd']:.4f}")

    Path(args.out).write_text(json.dumps(summary, indent=2))
    print(f"\n  JSON written to: {args.out}")
    print("=" * 70)


if __name__ == "__main__":
    main()
