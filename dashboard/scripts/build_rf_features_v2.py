#!/usr/bin/env python3
"""
build_rf_features_v2.py

The RF's weak point (measured directly: 80% false positives on ordinary
text) came from feeding it only raw counts (payload_len, quote_count,
num_special_chars...). Counts can't distinguish "this text has a
semicolon because it's a sentence" from "this text has a semicolon
because it's `1; DROP TABLE users`" -- that distinction needs structure,
which counts throw away by design.

This script adds two genuinely different kinds of signal on top of the
original 11 aggregate features:

1. STRUCTURAL PATTERN FEATURES (hand-designed, targeted at the exact
   failure cases measured in evasion_resistance_check.py):
   - has_tautology_pattern: X=X (1=1, a=a) -- the actual SQLi tautology
     shape, not just "contains a special character"
   - has_quote_before_sql_keyword: a quote followed within a few chars by
     OR/AND/UNION/SELECT -- catches the injection *shape*, not just quote
     presence (ordinary text has quotes; ordinary text does NOT have
     quotes immediately preceding SQL keywords)
   - has_comment_after_quote: quote followed by --/#//* within ~20 chars
   - has_html_tag_open: an actual "<word" tag opening, distinct from
     stray '<' used in prose ("Q3 <-> Q4")
   - has_event_handler_pattern: on\\w+= (onerror=, onload=, ANY onXXX=,
     not just the fixed list the original has_xss_keyword used)
   - longest_special_run: longest consecutive run of punctuation --
     attacks cluster punctuation ('--,  ');--), prose doesn't
   - special_char_ratio / quote_ratio: RATIOS instead of raw counts, so
     a long sentence with one apostrophe isn't scored the same as a
     15-character payload that's mostly symbols

2. CHARACTER N-GRAM TF-IDF (char_wb, 2-4 grams, top 300 by TF-IDF
   weight, fit on TRAIN TEXT ONLY to avoid leakage): lets the model pick
   up structural sub-patterns (e.g. "1=1", "OR '", "ipt>") that hand-
   designed regexes don't explicitly cover, without hard-coding every
   possible variant.

CRITICAL: uses the exact same load_log()/session_grouped_split() as
prepare_honeypot_for_training.py (same seed), so rows line up 1:1 with
the already-generated lstm_{train,val,test}.npz -- the meta-learner
still needs matched RF/LSTM predictions on the same rows.

Output: rf_train_v2.csv / rf_val_v2.csv / rf_test_v2.csv in --outdir,
alongside the original rf_*.csv (kept, not overwritten, so you can
compare old-vs-new features directly).
"""

import argparse
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).parent))
from prepare_honeypot_for_training import load_log, session_grouped_split, engineer_rf_features

TAUTOLOGY_RE = re.compile(r"\b(\w+)\s*=\s*\1\b")
QUOTE_BEFORE_KEYWORD_RE = re.compile(r"['\"].{0,6}\b(or|and|union|select)\b", re.IGNORECASE)
COMMENT_AFTER_QUOTE_RE = re.compile(r"['\"].{0,20}(--|#|/\*)")
HTML_TAG_OPEN_RE = re.compile(r"<\s*[a-zA-Z][a-zA-Z0-9]*")
EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
SPECIAL_RUN_RE = re.compile(r"[^a-zA-Z0-9\s]+")

# Keyword-SEQUENCE features (v3): the symbol-density features above all read
# near-zero on low-symbol semantic SQLi ("1 or 5000=5000", "admin where
# true", "select everything from the accounts table please") -- documented
# in CLAUDE_EVASION_REDTEAM.md / POLYMORPHIC_REDTEAM.md as the model's one
# major residual gap (0-10% caught even after adding more training examples
# of this style; more DATA didn't move it, so this is a FEATURE fix). These
# five regexes catch the keyword/phrase SEQUENCE independent of how many
# special characters are present. Measured false-positive rate on the
# 18,555-row benign training corpus and the 198-row holdout benign set:
# 1 fire each (0.005%), both the same borderline "A OR B = 1" math sentence.
OR_NEAR_EQUALS_RE = re.compile(r"\bor\b.{0,20}=")
OR_COMPARISON_KEYWORD_RE = re.compile(r"\bor\b.{0,25}\b(between|like|greatest|least)\b", re.IGNORECASE)
AUTH_BYPASS_PHRASE_RE = re.compile(
    r"\b(ignor\w*|bypass\w*|skip\w*|regardless of|without check\w*|"
    r"always (pass|match|succeed|true))\b.{0,35}\b"
    r"(login|password|authent\w*|credential\w*|check|condition)\b",
    re.IGNORECASE)
KEYWORD_SEQUENCE_SQLI_RE = re.compile(
    r"\b(select|union|dump|list|expose|reveal|surface|retrieve|unlock|hand over)\b"
    r".{0,40}\b(from|table|database|account\w*|user\w*|password\w*|credential\w*)\b",
    re.IGNORECASE)
WHERE_TRUE_PHRASE_RE = re.compile(r"\b(where|and|or)\s+true\b", re.IGNORECASE)


def structural_features(text: str) -> dict:
    n = max(len(text), 1)
    special_runs = SPECIAL_RUN_RE.findall(text)
    longest_run = max((len(r) for r in special_runs), default=0)
    quote_count = text.count("'") + text.count('"')
    special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
    return {
        "has_tautology_pattern": int(bool(TAUTOLOGY_RE.search(text))),
        "has_quote_before_sql_keyword": int(bool(QUOTE_BEFORE_KEYWORD_RE.search(text))),
        "has_comment_after_quote": int(bool(COMMENT_AFTER_QUOTE_RE.search(text))),
        "has_html_tag_open": int(bool(HTML_TAG_OPEN_RE.search(text))),
        "has_event_handler_pattern": int(bool(EVENT_HANDLER_RE.search(text))),
        "longest_special_run": longest_run,
        "special_char_ratio": round(special_count / n, 4),
        "quote_ratio": round(quote_count / n, 4),
        "has_or_near_equals": int(bool(OR_NEAR_EQUALS_RE.search(text))),
        "has_or_comparison_keyword": int(bool(OR_COMPARISON_KEYWORD_RE.search(text))),
        "has_auth_bypass_phrase": int(bool(AUTH_BYPASS_PHRASE_RE.search(text))),
        "has_keyword_sequence_sqli": int(bool(KEYWORD_SEQUENCE_SQLI_RE.search(text))),
        "has_where_true_phrase": int(bool(WHERE_TRUE_PHRASE_RE.search(text))),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, required=True, help="honeypot JSONL log")
    ap.add_argument("--outdir", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--ngram-features", type=int, default=300)
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.input} ...")
    df = load_log(args.input)
    print(f"Loaded {len(df)} rows. Splitting (same method/seed as prepare_honeypot_for_training.py)...")
    train_df, val_df, test_df = session_grouped_split(df, args.seed)
    print(f"  train={len(train_df)} val={len(val_df)} test={len(test_df)}")

    # --- structural features, all three splits ---
    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        struct = split_df["_payload_text"].apply(structural_features).apply(pd.Series)
        split_df[struct.columns] = struct.values

    # --- char n-gram TF-IDF, fit on TRAIN TEXT ONLY ---
    print(f"Fitting char n-gram TF-IDF (top {args.ngram_features} features) on train text only...")
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                                  max_features=args.ngram_features, lowercase=False)
    vectorizer.fit(train_df["_payload_text"])
    ngram_cols = [f"ngram_{i}" for i in range(len(vectorizer.get_feature_names_out()))]

    rf_feature_cols = ["payload_len", "entropy", "num_special_chars", "num_digits",
                        "num_uppercase", "param_count", "is_post", "has_sqli_keyword",
                        "has_xss_keyword", "quote_count", "comment_token_count",
                        "has_tautology_pattern", "has_quote_before_sql_keyword",
                        "has_comment_after_quote", "has_html_tag_open",
                        "has_event_handler_pattern", "longest_special_run",
                        "special_char_ratio", "quote_ratio"]

    for name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        ngram_matrix = vectorizer.transform(split_df["_payload_text"]).toarray()
        ngram_df = pd.DataFrame(ngram_matrix, columns=ngram_cols, index=split_df.index)
        out = pd.concat([split_df[rf_feature_cols].reset_index(drop=True),
                          ngram_df.reset_index(drop=True)], axis=1)
        out["label"] = split_df["label"].values
        out.to_csv(args.outdir / f"rf_{name}_v2.csv", index=False)
        print(f"  rf_{name}_v2.csv: {out.shape[0]} rows x {out.shape[1]-1} features "
              f"({len(rf_feature_cols)} structural + {len(ngram_cols)} n-gram)")

    import pickle
    with open(args.outdir / "ngram_vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"\nSaved n-gram vectorizer to {args.outdir / 'ngram_vectorizer.pkl'} "
          f"(needed to transform new text consistently at inference time).")


if __name__ == "__main__":
    main()
