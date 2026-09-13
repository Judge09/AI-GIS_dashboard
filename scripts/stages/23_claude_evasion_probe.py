#!/usr/bin/env python3
"""
23_claude_evasion_probe.py

An ADVERSARIAL red-team of AI-GIS by an LLM (Claude) actively trying to defeat
it, rather than replaying a fixed corpus. Every payload below was hand-authored
to target a specific, named weakness in the model's design:

  - The RF keys on symbol density (see README 5.4), so LOW-SYMBOL attacks and
    HIGH-SYMBOL benign text are the natural blind spots.
  - The LSTM sees only the first 200 characters, so PADDING attacks with benign
    prose then injecting late should evade it.
  - Everything is NFKC-normalised, so novel Unicode tricks NFKC does NOT fold
    (zero-width joiners, tag characters, RTL overrides) may survive.
  - The n-gram vectoriser is fitted on the training vocabulary, so payloads
    built from character sequences absent from the corpus should score low.

Each case carries the evasion THEORY it tests, so a miss is diagnosable rather
than mysterious. Scored through the identical path app.py uses.

USAGE (from dashboard/):  python scripts/23_claude_evasion_probe.py
Writes reports/claude_evasion_probe.json.
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from build_rf_features_v2 import structural_features        # noqa: E402
from text_normalize import normalize_text                   # noqa: E402


# ── payloads: (text, true_label, category, evasion_theory) ──────────────────
# true_label 1 = this IS an attack and SHOULD be caught (a miss = evasion win)
# true_label 0 = this is BENIGN and should NOT be flagged (a flag = false alarm)
CASES = [
    # ---- A. Low-symbol / semantic SQLi (targets the symbol-density shortcut) ----
    ("1 OR 1 BETWEEN 1 AND 1", 1, "sqli/low-symbol",
     "BETWEEN tautology: no quotes, no comment tokens, minimal special chars"),
    ("1 or 5000=5000", 1, "sqli/low-symbol",
     "numeric tautology with large equal numbers, no quotes"),
    ("admin where true", 1, "sqli/low-symbol",
     "natural WHERE TRUE, reads almost like English"),
    ("1 || pg_sleep ( 10 )", 1, "sqli/low-symbol",
     "Postgres sleep with spaces breaking the SLEEP( token n-gram"),
    ("1 union all select null null null", 1, "sqli/low-symbol",
     "UNION with word 'null' spelled out, no commas"),

    # ---- B. Late-injection / padding (targets the 200-char LSTM window) ----
    (("Thank you for your interest in our premium subscription service. "
      "We are delighted to confirm your recent order and appreciate your "
      "continued trust in our platform over the past several years of loyal "
      "membership with us here. " + "' OR '1'='1"), 1, "sqli/late-inject",
     "classic tautology pushed past character 200 to escape the LSTM window"),
    (("Our records indicate a pending update to your account preferences. "
      "Please review the attached summary at your earliest convenience and "
      "reply to confirm the changes you would like us to apply to the profile. "
      + "<script>alert(1)</script>"), 1, "xss/late-inject",
     "script tag pushed past character 200"),

    # ---- C. Unicode NFKC does NOT fold (targets the normalisation assumption) ----
    ("1‍' OR '1'='1", 1, "sqli/unicode-zwj",
     "zero-width joiner inside the payload; NFKC keeps ZWJ, may split n-grams"),
    ("<script​>alert(1)</script>", 1, "xss/unicode-zwsp",
     "zero-width space inside the tag name"),
    ("<\U000e0073cript>alert(1)</script>", 1, "xss/unicode-tag",
     "Unicode TAG small-s (U+E0073) in place of 's' — invisible, NFKC-stable"),

    # ---- D. Encoding the vectoriser has not seen (targets the n-gram vocab) ----
    ("&#x27;&#x20;OR&#x20;&#x27;1&#x27;&#x3d;&#x27;1", 1, "sqli/html-entity",
     "HTML numeric entity encoding of ' OR '1'='1 — decodes in a browser"),
    ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", 1, "xss/hex-escape",
     "backslash-x hex escapes for angle brackets"),
    ("String['fromCharCode'](60,115,99,114,105,112,116,62)", 1, "xss/charcode-bracket",
     "bracket-notation property access, novel token shape"),

    # ---- E. Case / whitespace novelty ----
    ("1'\tOoRr\t1=1", 1, "sqli/doubled-letters",
     "doubled letters 'OoRr' defeat a literal 'or' n-gram after casefold fails"),
    ("1'%0d%0aOR%0d%0a1=1", 1, "sqli/crlf-split",
     "CRLF url-encoded between tokens"),

    # ---- F. Hard benign that SHOULD NOT flag (targets false-positive surface) ----
    ("SELECT the option that best describes your role, then click Continue.", 0,
     "benign/sql-word", "'SELECT' as an English verb in UI copy"),
    ("Drop the file here, or click to browse your computer for an image.", 0,
     "benign/drop-word", "'Drop' as a UI instruction"),
    ("Union members receive a 15% discount on all orders over $50.", 0,
     "benign/union-word", "'Union' as a noun"),
    ("Use --verbose or -v to print each step; add --dry-run to preview.", 0,
     "benign/cli-flags", "CLI documentation with -- comment-like tokens"),
    ("The array is a[i] = b[i] * 2; for i in 0..n where n > 0 and i < n.", 0,
     "benign/code-dense", "dense code with =, <, > and a tautology-like i<n"),
    ("Email o'brien@example.com or reply 'yes' to confirm; ref #A-1=B-2.", 0,
     "benign/quote-dense", "apostrophes, quotes, equals, hash in one line"),
    ("<div class=\"card\"><span>Welcome back, user!</span></div>", 0,
     "benign/safe-html", "legitimate HTML markup, no script or handler"),
    ("Regex to validate: ^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d]{8,}$ for passwords.", 0,
     "benign/regex", "password-policy regex, very high symbol density"),
]


def load_models():
    with open(ROOT / "models/rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(ROOT / "models/meta.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(ROOT / "models/ngram_vectorizer.pkl", "rb") as f:
        vec = pickle.load(f)
    from tensorflow import keras
    lstm = keras.models.load_model(ROOT / "models/lstm_best.keras")
    v2 = list(pd.read_csv(ROOT / "data/prepared/rf_train_v2.csv")
              .drop(columns=["label"]).columns)
    return rf, meta, vec, lstm, v2


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def score(text, rf, meta, vec, lstm, v2):
    t = normalize_text(text)   # identical to app.py predict_one
    st = pd.DataFrame([structural_features(t)])
    ag = pd.DataFrame([engineer_rf_features(t, "GET")])
    ng = pd.DataFrame(vec.transform([t]).toarray(),
                      columns=[f"ngram_{i}" for i in range(300)])
    X = pd.concat([ag.reset_index(drop=True), st.reset_index(drop=True),
                   ng.reset_index(drop=True)], axis=1)[v2]
    rf_p = float(rf.predict_proba(X)[:, 1][0])
    ls_p = float(lstm.predict(np.stack([ordinal_encode(t)]), verbose=0).flatten()[0])
    st_p = float(meta.predict_proba(np.array([[rf_p, ls_p]]))[:, 1][0])
    return rf_p, ls_p, st_p


def main():
    print("=" * 74)
    print("23_claude_evasion_probe.py  —  adversarial red-team of AI-GIS")
    print("=" * 74)
    rf, meta, vec, lstm, v2 = load_models()

    rows = []
    for text, label, cat, theory in CASES:
        rf_p, ls_p, st_p = score(text, rf, meta, vec, lstm, v2)
        pred = 1 if st_p >= 0.5 else 0
        if label == 1:
            evaded = pred == 0          # attack slipped through
            outcome = "EVADED" if evaded else "caught"
        else:
            evaded = pred == 1          # benign wrongly flagged
            outcome = "FALSE-ALARM" if evaded else "ok"
        rows.append({"category": cat, "true_label": label, "predicted": pred,
                     "rf": round(rf_p, 4), "lstm": round(ls_p, 4),
                     "stacked": round(st_p, 4), "outcome": outcome,
                     "text": text, "theory": theory})

    attacks = [r for r in rows if r["true_label"] == 1]
    benign = [r for r in rows if r["true_label"] == 0]
    evaded = [r for r in attacks if r["outcome"] == "EVADED"]
    fa = [r for r in benign if r["outcome"] == "FALSE-ALARM"]

    print(f"\nAttacks   : {len(attacks) - len(evaded)}/{len(attacks)} caught "
          f"({len(evaded)} evaded)")
    print(f"Benign    : {len(benign) - len(fa)}/{len(benign)} clean "
          f"({len(fa)} false alarms)\n")

    print("ATTACKS THAT EVADED (stacked < 0.5):")
    print("-" * 74)
    for r in evaded:
        print(f"  [{r['category']:22s}] stacked={r['stacked']:.4f} "
              f"(rf={r['rf']:.3f} lstm={r['lstm']:.3f})")
        print(f"      {r['text'][:66]!r}")
        print(f"      why: {r['theory']}")
    if not evaded:
        print("  (none)")

    print("\nBENIGN FALSE ALARMS (stacked >= 0.5):")
    print("-" * 74)
    for r in fa:
        print(f"  [{r['category']:22s}] stacked={r['stacked']:.4f} "
              f"(rf={r['rf']:.3f} lstm={r['lstm']:.3f})")
        print(f"      {r['text'][:66]!r}")
    if not fa:
        print("  (none)")

    summary = {
        "attacks_total": len(attacks),
        "attacks_caught": len(attacks) - len(evaded),
        "attacks_evaded": len(evaded),
        "benign_total": len(benign),
        "benign_clean": len(benign) - len(fa),
        "false_alarms": len(fa),
        "cases": rows,
    }
    out = ROOT / "reports" / "claude_evasion_probe.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nJSON written to: {out}")
    print("=" * 74)


if __name__ == "__main__":
    main()
