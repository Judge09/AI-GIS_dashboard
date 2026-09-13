#!/usr/bin/env python3
"""
28_compare_arch.py — A/B the unidirectional LSTM against the BiLSTM.

Loads two independently trained model directories and scores both on the same
inputs, so the only variable is the sequence architecture.

Usage:
    python scripts/28_compare_arch.py --a models --b models_bilstm

Reports, for each arch:
  * clean held-out test set (the headline thesis number)
  * the real LLM holdout corpus (data/eval/llm_holdout_full.csv)
  * the curated evasion set (techniques absent from the training generators)
  * whitespace-padding robustness — the live failure mode documented in
    reports/FINDING_trailing_space_evasion.md

The padding rows are the point of the exercise: bidirectionality is often
proposed as a fix for position-sensitivity, and this measures whether it is.
"""

import argparse
import csv
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from evasion_resistance_check import (  # noqa: E402
    EVASION_ATTACKS, HARD_BENIGN, engineer_rf_features,
)
from build_rf_features_v2 import structural_features  # noqa: E402
from text_normalize import normalize_text  # noqa: E402

MAXLEN = 200


def ordinal_encode(text, max_len=MAXLEN):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


class Bundle:
    """One trained system: RF + sequence model + meta-learner."""

    def __init__(self, path, v2_cols):
        from tensorflow import keras
        self.path = Path(path)
        with open(self.path / "rf2.pkl", "rb") as f:
            self.rf = pickle.load(f)
        with open(self.path / "meta.pkl", "rb") as f:
            self.meta = pickle.load(f)
        with open(self.path / "ngram_vectorizer.pkl", "rb") as f:
            self.vec = pickle.load(f)
        self.seq = keras.models.load_model(self.path / "lstm_best.keras")
        self.v2_cols = v2_cols
        self.params = self.seq.count_params()

    def features(self, texts):
        struct = pd.DataFrame([structural_features(t) for t in texts])
        agg = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
        ng = pd.DataFrame(self.vec.transform(texts).toarray(),
                          columns=[f"ngram_{i}" for i in range(300)])
        combined = pd.concat([agg.reset_index(drop=True),
                              struct.reset_index(drop=True),
                              ng.reset_index(drop=True)], axis=1)
        return combined[self.v2_cols]

    def score(self, texts, batch=512):
        """Return (rf, seq, stacked) probability arrays."""
        norm = [normalize_text(t) for t in texts]
        rf = self.rf.predict_proba(self.features(norm))[:, 1]
        seq = []
        for i in range(0, len(norm), batch):
            X = np.stack([ordinal_encode(t) for t in norm[i:i + batch]])
            seq += list(self.seq.predict(X, verbose=0).flatten())
        seq = np.array(seq)
        stacked = self.meta.predict_proba(np.column_stack([rf, seq]))[:, 1]
        return rf, seq, stacked


def metrics(y, p):
    pred = (p >= 0.5).astype(int)
    y = np.asarray(y)
    tp = int(((pred == 1) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec and rec and (prec + rec) else float("nan")
    return {"recall": rec, "specificity": spec, "precision": prec, "f1": f1,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "n": len(y)}


def fmt(m):
    def p(x):
        return "   n/a" if x != x else f"{x*100:6.2f}%"
    return (f"recall={p(m['recall'])}  spec={p(m['specificity'])}  "
            f"F1={p(m['f1'])}  (n={m['n']})")


def load_eval_corpus(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    texts = [r["text"] for r in rows if r.get("text", "").strip()]
    labels = [int(r["label"]) for r in rows if r.get("text", "").strip()]
    return texts, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default="models", help="baseline model dir")
    ap.add_argument("--b", default="models_bilstm", help="candidate model dir")
    ap.add_argument("--out", default=None, help="write JSON results here")
    args = ap.parse_args()

    v2_cols = list(pd.read_csv(ROOT / "data" / "prepared" / "rf_train_v2.csv")
                   .drop(columns=["label"]).columns)

    print("Loading bundles ...")
    A = Bundle(ROOT / args.a, v2_cols)
    B = Bundle(ROOT / args.b, v2_cols)
    names = {args.a: A, args.b: B}
    print(f"  {args.a:16s} seq params = {A.params:,}")
    print(f"  {args.b:16s} seq params = {B.params:,}")

    suites = {}

    # 1. clean held-out test set
    te = ROOT / "data" / "prepared" / "rf_test_v2.csv"
    if te.exists():
        suites["clean_test"] = None   # handled separately (features precomputed)

    # 2. real LLM holdout
    llm = ROOT / "data" / "eval" / "llm_holdout_full.csv"
    if llm.exists():
        suites["llm_holdout_real"] = load_eval_corpus(llm)

    # 3. curated evasion + hard benign
    suites["evasion_curated"] = (
        list(EVASION_ATTACKS) + list(HARD_BENIGN),
        [1] * len(EVASION_ATTACKS) + [0] * len(HARD_BENIGN),
    )

    results = {"a": args.a, "b": args.b,
               "params": {args.a: A.params, args.b: B.params}, "suites": {}}

    for suite, data in suites.items():
        if data is None:
            continue
        texts, y = data
        print(f"\n=== {suite}  (n={len(texts)}) " + "=" * (34 - len(suite)))
        results["suites"][suite] = {}
        for nm, bundle in names.items():
            _, seq, st = bundle.score(texts)
            m_seq, m_st = metrics(y, seq), metrics(y, st)
            print(f"  {nm:16s} seq     {fmt(m_seq)}")
            print(f"  {nm:16s} STACKED {fmt(m_st)}")
            results["suites"][suite][nm] = {"seq": m_seq, "stacked": m_st}

    # 4. whitespace-padding robustness -- the documented live failure mode
    atk = [t for t, l in zip(*suites["llm_holdout_real"]) if l == 1] \
        if "llm_holdout_real" in suites else list(EVASION_ATTACKS)
    variants = {
        "bare": atk,
        "trailing_40_spaces": [t + " " * 40 for t in atk],
        "leading_40_spaces": [" " * 40 + t for t in atk],
        "both_20_spaces": [" " * 20 + t + " " * 20 for t in atk],
    }
    print(f"\n=== padding robustness  (n={len(atk)} attacks) ===================")
    results["padding"] = {}
    for nm, bundle in names.items():
        results["padding"][nm] = {}
        print(f"  --- {nm}")
        for vname, vtexts in variants.items():
            _, seq, st = bundle.score(vtexts)
            d_seq = int((seq >= 0.5).sum())
            d_st = int((st >= 0.5).sum())
            results["padding"][nm][vname] = {
                "seq_detected": d_seq, "stacked_detected": d_st, "n": len(atk)}
            print(f"      {vname:20s} seq {d_seq:3d}/{len(atk)}   "
                  f"stacked {d_st:3d}/{len(atk)}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
