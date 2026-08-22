#!/usr/bin/env python3
"""
prepare_honeypot_for_training.py

Turns a honeypot JSONL log (the schema produced by
webids23_to_honeypot_log_v4.py, or your real post_audit.log -- same
fields) into the two input formats your confirmed architecture needs
(Chapter 3, Table 13):

  1. LSTM branch: character-sequence input, shape (max_payload_len, ),
     ordinal-encoded, ready for an Embedding layer -> LSTM(64) ->
     Dropout(0.3) -> LSTM(32) -> Dropout(0.3) -> Dense(sigmoid).

  2. RF branch: engineered numeric features (length, entropy, keyword
     flags, etc.) as a flat table.

Both branches are split from the SAME underlying rows so the two base
learners see identical train/val/test membership -- required for the
meta-learner (logistic regression) to be trained on matched held-out
predictions from both.

LEAKAGE PREVENTION:
- Split is done by session_id (GroupShuffleSplit), not by row. Multiple
  requests from the same synthetic/real session never end up split
  across train/val/test -- otherwise the model could learn session-level
  artifacts (e.g. a specific source_ip or session_id hash) instead of
  payload structure, and evasion-resistance numbers would be inflated.
- SMOTE (if --smote is passed) is fit and applied to the TRAIN split
  only, after the split is finalized, exactly as documented in your
  Chapter 3 methodology.

USAGE:
  python3 prepare_honeypot_for_training.py \
      --input webids23_honeypot_v4_balanced.log \
      --outdir prepared_data \
      --max-payload-len 200 \
      --smote

OUTPUT (written to --outdir):
  lstm_train.npz / lstm_val.npz / lstm_test.npz   -> X (int32 [N, max_len]), y (int8 [N])
  rf_train.csv   / rf_val.csv   / rf_test.csv      -> engineered features + label
  split_manifest.json                              -> row counts, session counts, class balance per split
"""

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

SQLI_KEYWORDS = ["select", "union", "drop", "sleep", "waitfor", "exec",
                  "or 1=1", "or '1'='1", "xp_cmdshell", "convert", "extractvalue"]
XSS_KEYWORDS = ["script", "onerror", "onload", "onfocus", "onmouseover",
                 "onstart", "ontoggle", "alert(", "javascript:", "<svg", "<img"]

PAD_IDX = 0
MAX_ORDINAL = 127  # printable ASCII range; anything above maps to UNK


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def payload_text(row: dict) -> str:
    """Reconstruct the attacker-controlled text: query string + body."""
    uri = row.get("uri", "")
    body = row.get("request_body", "") or ""
    query = uri.split("?", 1)[1] if "?" in uri else ""
    return f"{query} {body}".strip()


def engineer_rf_features(row: dict, text: str) -> dict:
    lower = text.lower()
    return {
        "payload_len": len(text),
        "entropy": round(shannon_entropy(text), 4),
        "num_special_chars": sum(1 for c in text if not c.isalnum() and not c.isspace()),
        "num_digits": sum(c.isdigit() for c in text),
        "num_uppercase": sum(c.isupper() for c in text),
        "param_count": row.get("uri", "").count("&") + (1 if "?" in row.get("uri", "") else 0),
        "is_post": int(row.get("method", "").upper() == "POST"),
        "has_sqli_keyword": int(any(k in lower for k in SQLI_KEYWORDS)),
        "has_xss_keyword": int(any(k in lower for k in XSS_KEYWORDS)),
        "quote_count": text.count("'") + text.count('"'),
        "comment_token_count": text.count("--") + text.count("/*") + text.count("#"),
    }


def ordinal_encode(text: str, max_len: int) -> np.ndarray:
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= MAX_ORDINAL else 1  # 1 = UNK, 0 reserved for PAD
    return arr


def load_log(path: Path) -> pd.DataFrame:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                print(f"[warn] skipping malformed line {line_no}", file=sys.stderr)
                continue
            text = payload_text(row)
            feats = engineer_rf_features(row, text)
            feats["_payload_text"] = text
            feats["_session_id"] = row.get("session_id", row.get("source_uid", f"row{line_no}"))
            feats["label"] = int(row["label"])
            feats["attack_family"] = row.get("attack_family", "unknown")
            records.append(feats)
    return pd.DataFrame.from_records(records)


def session_grouped_split(df: pd.DataFrame, seed: int):
    """70/15/15 split by session_id, stratified as best-effort via group split."""
    groups = df["_session_id"].values
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    train_idx, temp_idx = next(gss1.split(df, groups=groups))

    temp_df = df.iloc[temp_idx]
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
    val_idx_rel, test_idx_rel = next(gss2.split(temp_df, groups=temp_df["_session_id"].values))
    val_idx = temp_df.index[val_idx_rel]
    test_idx = temp_df.index[test_idx_rel]

    return df.loc[train_idx].copy(), df.loc[val_idx].copy(), df.loc[test_idx].copy()


def apply_smote_train_only(train_df: pd.DataFrame, feature_cols, seed: int):
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        print("[warn] imbalanced-learn not installed (pip install imbalanced-learn --break-system-packages); "
              "skipping SMOTE", file=sys.stderr)
        return train_df

    X = train_df[feature_cols].values
    y = train_df["label"].values
    if len(set(y)) < 2 or min(Counter(y).values()) < 2:
        print("[warn] not enough minority samples for SMOTE; skipping", file=sys.stderr)
        return train_df

    sm = SMOTE(random_state=seed)
    X_res, y_res = sm.fit_resample(X, y)
    resampled = pd.DataFrame(X_res, columns=feature_cols)
    resampled["label"] = y_res
    # synthetic rows have no real payload text / session id -- mark them explicitly
    resampled["_payload_text"] = ""
    resampled["_session_id"] = "SMOTE_SYNTHETIC"
    resampled["attack_family"] = "smote_synthetic"
    return resampled


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--outdir", type=Path, default=Path("prepared_data"))
    ap.add_argument("--max-payload-len", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--smote", action="store_true", help="apply SMOTE to the RF train split only")
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.input} ...")
    df = load_log(args.input)
    print(f"Loaded {len(df)} rows, {df['_session_id'].nunique()} sessions, "
          f"label balance: {df['label'].value_counts().to_dict()}")

    print("Splitting by session_id (70/15/15, no session crosses a split boundary)...")
    train_df, val_df, test_df = session_grouped_split(df, args.seed)

    rf_feature_cols = ["payload_len", "entropy", "num_special_chars", "num_digits",
                        "num_uppercase", "param_count", "is_post", "has_sqli_keyword",
                        "has_xss_keyword", "quote_count", "comment_token_count"]

    manifest = {}
    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        manifest[name] = {
            "rows": len(split_df),
            "sessions": int(split_df["_session_id"].nunique()),
            "distinct_payload_texts": int(split_df["_payload_text"].nunique()),
            "label_balance": {str(k): int(v) for k, v in split_df["label"].value_counts().items()},
            "attack_family_counts": {str(k): int(v) for k, v in split_df["attack_family"].value_counts().items()},
        }

    # Cross-split payload-content leakage check. Session-grouping only
    # guarantees the same SESSION never crosses a split boundary -- it
    # does NOT guarantee the same PAYLOAD TEXT doesn't appear in two
    # different sessions that land in different splits. If the source
    # log has low payload diversity in any class, identical content can
    # leak across train/val/test even with a perfectly session-grouped
    # split. Check explicitly rather than assume session-grouping covers it.
    train_texts = set(train_df["_payload_text"])
    val_texts = set(val_df["_payload_text"])
    test_texts = set(test_df["_payload_text"])
    overlap = {
        "train_val": len(train_texts & val_texts),
        "train_test": len(train_texts & test_texts),
        "val_test": len(val_texts & test_texts),
    }
    manifest["payload_content_leakage_check"] = overlap
    if any(overlap.values()):
        print(f"[WARN] Payload text overlaps across splits: {overlap} -- "
              f"identical request content appears in multiple splits. This "
              f"will inflate metrics for whichever class it affects. Check "
              f"payload diversity in the source log for that class.",
              file=sys.stderr)
    else:
        print("[ok] No payload-content overlap across train/val/test splits.")

    if args.smote:
        print("Applying SMOTE to RF train split only...")
        before = len(train_df)
        train_rf_df = apply_smote_train_only(train_df, rf_feature_cols, args.seed)
        print(f"  RF train rows: {before} -> {len(train_rf_df)}")
        manifest["train"]["rf_rows_after_smote"] = len(train_rf_df)
    else:
        train_rf_df = train_df

    # --- LSTM branch: char-sequence tensors (SMOTE not applied to sequences --
    #     LSTM train split uses the original, non-oversampled rows) ---
    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        X = np.stack([ordinal_encode(t, args.max_payload_len) for t in split_df["_payload_text"]])
        y = split_df["label"].values.astype(np.int8)
        np.savez_compressed(args.outdir / f"lstm_{name}.npz", X=X, y=y)
        print(f"  lstm_{name}.npz: X{X.shape} y{y.shape}")

    # --- RF branch: engineered feature tables ---
    for name, split_df in [("train", train_rf_df), ("val", val_df), ("test", test_df)]:
        out_cols = rf_feature_cols + ["label"]
        split_df[out_cols].to_csv(args.outdir / f"rf_{name}.csv", index=False)
        print(f"  rf_{name}.csv: {len(split_df)} rows")

    manifest["config"] = {
        "max_payload_len": args.max_payload_len,
        "seed": args.seed,
        "smote_applied_to_rf_train": args.smote,
        "vocab": "ordinal ASCII 0-127, 0=PAD, 1=UNK",
        "rf_feature_cols": rf_feature_cols,
    }
    with open(args.outdir / "split_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nDone. Outputs in {args.outdir}/")
    print("Manifest written to split_manifest.json -- check label_balance per split before training.")


if __name__ == "__main__":
    main()
