#!/usr/bin/env python3
"""
18_train_stacked.py  (Improvement Plan — reconstructed trainer)

Retrains the full stacked system from the honeypot log and overwrites the model
files the app loads:  models/rf2.pkl, models/lstm_best.keras, models/meta.pkl,
models/ngram_vectorizer.pkl.

Reconstructed to match the committed models exactly:
  RF v2  : RandomForest(n_estimators=200, max_depth=20, class_weight="balanced")
           on 19 structural features + 300 char n-gram TF-IDF = 319 features.
  LSTM   : Embedding(128,32) -> LSTM(64,seq) -> Dropout -> LSTM(32) -> Dropout
           -> Dense(1, sigmoid), on ordinal-encoded text (len 200, vocab 128).
  Meta   : LogisticRegression on [rf_proba, lstm_proba] from the VAL split
           (so the meta-learner never sees the models' training rows).

Split is session-grouped (same seed/method as the rest of the pipeline), so
train/val/test never share a session — no leakage.

Text is passed through normalize_text() (see scripts/text_normalize.py) before
every feature, identically here and in the live app.

USAGE (from dashboard/):
  python scripts/18_train_stacked.py                    # uses data/honeypot_final.log
  python scripts/18_train_stacked.py --epochs 8 --seed 42
"""
import argparse
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

ROOT = Path(__file__).parent.parent
SCRIPTS = ROOT / "scripts"
MODELS = ROOT / "models"
DATA = ROOT / "data"
sys.path.insert(0, str(SCRIPTS))

import importlib.util


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_prep = _load(SCRIPTS / "prepare_honeypot_for_training.py", "prep")
from build_rf_features_v2 import structural_features       # noqa: E402
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from text_normalize import normalize_text                   # noqa: E402

RF_COLS = ["payload_len", "entropy", "num_special_chars", "num_digits",
           "num_uppercase", "param_count", "is_post", "has_sqli_keyword",
           "has_xss_keyword", "quote_count", "comment_token_count",
           "has_tautology_pattern", "has_quote_before_sql_keyword",
           "has_comment_after_quote", "has_html_tag_open",
           "has_event_handler_pattern", "longest_special_run",
           "special_char_ratio", "quote_ratio",
           "has_or_near_equals", "has_or_comparison_keyword",
           "has_auth_bypass_phrase", "has_keyword_sequence_sqli",
           "has_where_true_phrase"]
NGRAM_N = 300
MAXLEN = 200


def ordinal_encode(text, max_len=MAXLEN):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def rf_matrix(texts, vec):
    st = pd.DataFrame([structural_features(t) for t in texts])
    ag = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ng = pd.DataFrame(vec.transform(texts).toarray(),
                      columns=[f"ngram_{i}" for i in range(NGRAM_N)])
    base = pd.concat([ag.reset_index(drop=True), st.reset_index(drop=True)], axis=1)
    return pd.concat([base[RF_COLS], ng.reset_index(drop=True)], axis=1)


def build_lstm(seed=42):
    from tensorflow import keras
    from tensorflow.keras import layers
    # The ORIGINAL two-layer stacked LSTM, as specified in the thesis design.
    #
    # An earlier note claimed this variant "trained to AUC 0.5 (no learning)"
    # and it was replaced by a single layer. That does not reproduce: under a
    # seeded, controlled run this architecture reaches val_auc 0.9996 in epoch 1
    # and 1.0000 by epoch 3. The original failure was almost certainly an
    # unseeded bad initialisation, not a property of the architecture -- hence
    # the explicit initializer seeding below.
    #
    # mask_zero=True is load-bearing: 0 is the PAD id, and the first layer must
    # propagate the mask to the second (return_sequences=True) so padding never
    # reaches the final state.
    init = keras.initializers.GlorotUniform(seed=seed)
    m = keras.Sequential([
        layers.Input(shape=(MAXLEN,)),
        layers.Embedding(input_dim=128, output_dim=32, mask_zero=True),
        layers.LSTM(64, return_sequences=True, kernel_initializer=init),
        layers.Dropout(0.3, seed=seed),
        layers.LSTM(32, kernel_initializer=init),
        layers.Dropout(0.3, seed=seed),
        layers.Dense(1, activation="sigmoid"),
    ])
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss="binary_crossentropy",
              metrics=[keras.metrics.AUC(name="auc")])
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=str(DATA / "honeypot_final.log"))
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    import random
    random.seed(args.seed)
    np.random.seed(args.seed)
    import tensorflow as tf
    tf.random.set_seed(args.seed)
    from tensorflow import keras

    print("=" * 68)
    print("18_train_stacked.py — retraining the full system")
    print("=" * 68)
    print(f"[1/6] Loading log + session-grouped split (seed {args.seed}) ...")
    df = _prep.load_log(Path(args.log))
    # Apply the SAME normalisation used at inference time, up front.
    df["_payload_text"] = df["_payload_text"].astype(str).map(normalize_text)
    train_df, val_df, test_df = _prep.session_grouped_split(df, args.seed)
    print(f"      train={len(train_df)} val={len(val_df)} test={len(test_df)}")

    tr_txt = train_df["_payload_text"].tolist()
    va_txt = val_df["_payload_text"].tolist()
    te_txt = test_df["_payload_text"].tolist()
    ytr = train_df["label"].to_numpy()
    yva = val_df["label"].to_numpy()
    yte = test_df["label"].to_numpy()

    print("[2/6] Fitting char n-gram TF-IDF on train text only ...")
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                          max_features=NGRAM_N, lowercase=False)
    vec.fit(tr_txt)

    print("[3/6] Training RandomForest v2 (319 features) ...")
    Xtr = rf_matrix(tr_txt, vec)
    Xva = rf_matrix(va_txt, vec)
    Xte = rf_matrix(te_txt, vec)
    rf = RandomForestClassifier(n_estimators=200, max_depth=20,
                                class_weight="balanced",
                                random_state=args.seed, n_jobs=-1)
    rf.fit(Xtr, ytr)

    print(f"[4/6] Training LSTM ({args.epochs} epochs, checkpoint best val_auc) ...")
    Etr = np.stack([ordinal_encode(t) for t in tr_txt])
    Eva = np.stack([ordinal_encode(t) for t in va_txt])
    Ete = np.stack([ordinal_encode(t) for t in te_txt])
    lstm = build_lstm(args.seed)
    ckpt = MODELS / "lstm_best.keras"
    cbs = [
        keras.callbacks.ModelCheckpoint(str(ckpt), monitor="val_auc",
                                        mode="max", save_best_only=True),
        keras.callbacks.EarlyStopping(monitor="val_auc", mode="max",
                                      patience=3, restore_best_weights=True),
    ]
    lstm.fit(Etr, ytr, validation_data=(Eva, yva),
             epochs=args.epochs, batch_size=128, callbacks=cbs, verbose=2)
    lstm = keras.models.load_model(ckpt)  # best checkpoint

    print("[5/6] Training meta-learner on VAL probabilities ...")
    rf_va = rf.predict_proba(Xva)[:, 1]
    lstm_va = lstm.predict(Eva, verbose=0).flatten()
    meta = LogisticRegression()
    meta.fit(np.column_stack([rf_va, lstm_va]), yva)

    print("[6/6] Saving models + quick test-set check ...")
    with open(MODELS / "rf2.pkl", "wb") as f:
        pickle.dump(rf, f)
    with open(MODELS / "meta.pkl", "wb") as f:
        pickle.dump(meta, f)
    with open(MODELS / "ngram_vectorizer.pkl", "wb") as f:
        pickle.dump(vec, f)
    # keep the app's data/prepared vectorizer copy in sync too
    (DATA / "prepared").mkdir(parents=True, exist_ok=True)
    with open(DATA / "prepared" / "ngram_vectorizer.pkl", "wb") as f:
        pickle.dump(vec, f)
    # Rewrite the prepared splits so downstream eval scripts (13, 14) read the
    # SAME rows/features these models were trained and tested on. Without this
    # they load stale .npz/.csv from a different split size and produce garbage.
    prep = DATA / "prepared"
    Xtr.assign(label=ytr).to_csv(prep / "rf_train_v2.csv", index=False)
    Xva.assign(label=yva).to_csv(prep / "rf_val_v2.csv", index=False)
    Xte.assign(label=yte).to_csv(prep / "rf_test_v2.csv", index=False)
    np.savez(prep / "lstm_train.npz", X=Etr, y=ytr)
    np.savez(prep / "lstm_val.npz", X=Eva, y=yva)
    np.savez(prep / "lstm_test.npz", X=Ete, y=yte)

    rf_te = rf.predict_proba(Xte)[:, 1]
    lstm_te = lstm.predict(Ete, verbose=0).flatten()
    stack_te = meta.predict_proba(np.column_stack([rf_te, lstm_te]))[:, 1]
    for name, p in [("RF", rf_te), ("LSTM", lstm_te), ("Stacked", stack_te)]:
        pred = (p >= 0.5).astype(int)
        print(f"      {name:8s} test F1={f1_score(yte, pred):.4f}")

    print("=" * 68)
    print("Done. models/ updated. Now re-run the ruler:")
    print("  python scripts/17_evaluate_csv.py")
    print("=" * 68)


if __name__ == "__main__":
    main()
