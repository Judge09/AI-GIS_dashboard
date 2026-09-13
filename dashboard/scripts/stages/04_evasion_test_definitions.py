#!/usr/bin/env python3
"""
04_evasion_test_definitions.py

Defines the two held-out stress-test sets used by every evaluation script:

  EVASION_ATTACKS: 23 hand-crafted SQLi/XSS payloads built with techniques
    NOT present in the training generators -- different encoding schemes,
    keyword-free blind patterns, JS obfuscation, whitespace tricks.
    These are a proxy sanity-check for LLM-generated evasion payloads.

  HARD_BENIGN: 15 legitimate-looking sentences that a naive classifier
    keyed on special characters might false-positive on.

Also exports:
  engineer_rf_features(text, method) -> dict   (11-dim base RF features)
  shannon_entropy(s) -> float

This module is safe to import from any script in scripts/ -- no absolute
paths, no side effects at import time. Running it directly prints a quick
sanity-check using a freshly fitted RF on data/prepared/rf_train_v2.csv.

USAGE (from project root):
  python scripts/04_evasion_test_definitions.py
"""

import math
import sys
from collections import Counter
from pathlib import Path

# ── Module-level constants (no side effects, safe to import) ─────────────────

SQLI_KEYWORDS = ["select", "union", "drop", "sleep", "waitfor", "exec",
                  "or 1=1", "or '1'='1", "xp_cmdshell", "convert", "extractvalue"]
XSS_KEYWORDS  = ["script", "onerror", "onload", "onfocus", "onmouseover",
                  "onstart", "ontoggle", "alert(", "javascript:", "<svg", "<img"]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def engineer_rf_features(text: str, method: str) -> dict:
    """11-dimensional base RF feature vector (Chapter 3, Table 11)."""
    lower = text.lower()
    return {
        "payload_len":         len(text),
        "entropy":             round(shannon_entropy(text), 4),
        "num_special_chars":   sum(1 for c in text if not c.isalnum() and not c.isspace()),
        "num_digits":          sum(c.isdigit() for c in text),
        "num_uppercase":       sum(c.isupper() for c in text),
        "param_count":         1,
        "is_post":             int(method.upper() == "POST"),
        "has_sqli_keyword":    int(any(k in lower for k in SQLI_KEYWORDS)),
        "has_xss_keyword":     int(any(k in lower for k in XSS_KEYWORDS)),
        "quote_count":         text.count("'") + text.count('"'),
        "comment_token_count": text.count("--") + text.count("/*") + text.count("#"),
    }


# ── Held-out evasion-style attacks ───────────────────────────────────────────
# Techniques NOT in training generators (tabs/newlines, backticks, hex literals,
# pure blind arithmetic, comment-fragmented keywords, JS obfuscation).
EVASION_ATTACKS = [
    # Whitespace-trick SQLi
    "1'%09OR%091=1%09--%09-", "1'%0aAND%0a1=1%0a#", "'%0d%0aOR%0d%0a'a'='a",
    # Backtick / MySQL-specific identifier quoting
    "1`;DROP TABLE `users`;--", "` OR `1`=`1",
    # Hex-encoded string literals
    "1 UNION SELECT 0x61646d696e,0x70617373776f7264--",
    "' OR 0x31=0x31--",
    # Pure boolean/arithmetic blind (no SQL keyword)
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT version()))x FROM information_schema.tables GROUP BY x)a)",
    "1)) OR (('1')=('1",
    # Comment-fragmented keywords
    "'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3--",
    "'+UN'+'ION+SEL'+'ECT+1--",
    # Nested / second-order style
    "1;SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END--",
    # XSS: JS obfuscation
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>",
    "<img src=x oNeRRor=/**/(alert)(1)>",
    '<a href="jav&#97;script:alert(1)">x</a>',
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<template><script>alert(1)</script></template>",
    "<x contenteditable onfocus=alert(1) autofocus>",
    "<script>/*comment*/alert`1`</script>",
    "'\"<img src=x id=dmFyIGE9YWxlcnQoMSk=onerror=eval(atob(this.id))>",
    '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
]

# ── Hard-benign examples ─────────────────────────────────────────────────────
HARD_BENIGN = [
    "123 O'Connell St, Dublin", "Smith & Sons Law Firm LLC",
    "Please review section 3.2(a) of the contract, re: pricing.",
    "SELECT is a reserved keyword in most SQL dialects.",
    'My favorite quote: "to be or not to be" -- Shakespeare',
    "Error code: 500 (Internal Server Error) -- see logs for details.",
    "cost = qty * unit_price; if (cost > budget) { flag(); }",
    "Contact us at support@company.com or call (555) 123-4567.",
    "Meeting notes 10/25: discussed Q3 <-> Q4 transition plan.",
    "Product SKU# ABC-123; Category: Electronics & Gadgets",
    "Recipe: mix 2 cups flour w/ 1 tsp salt; bake @ 350F for 20 min.",
    'git commit -m "fix: resolve null pointer in auth module"',
    'Rated 4.5/5 stars -- "great product, fast shipping!"',
    "Address: 42 O'Malley Ave, Apt #7, (near the park)",
    "Discount code SAVE20% applies to orders over $50.",
]


# ── Standalone sanity-check (only runs when executed directly) ───────────────
def main():
    import pickle
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score

    PROJECT_ROOT = Path(__file__).parent.parent.parent
    DATA_DIR     = PROJECT_ROOT / "data" / "prepared"

    for p in (DATA_DIR / "rf_train_v2.csv",):
        if not p.exists():
            print(f"[ERROR] File not found: {p}. "
                  f"Run scripts/03_build_rf_features_v2.py first.", file=sys.stderr)
            sys.exit(1)

    print("Loading v2 training data and fitting RF (sanity check) ...")
    train = pd.read_csv(DATA_DIR / "rf_train_v2.csv")
    Xtr, ytr = train.drop(columns=["label"]), train["label"]
    rf = RandomForestClassifier(random_state=42, n_estimators=100)
    rf.fit(Xtr, ytr)

    test = pd.read_csv(DATA_DIR / "rf_test_v2.csv")
    Xtest, ytest = test.drop(columns=["label"]), test["label"]
    clean_auc = roc_auc_score(ytest, rf.predict_proba(Xtest)[:, 1])
    print(f"Clean held-out test AUC-ROC: {clean_auc:.4f}\n")

    feature_cols = list(Xtr.columns)

    # Evasion check (base 11 features only — quick, no vectorizer needed)
    rows_e = [engineer_rf_features(p, "GET") for p in EVASION_ATTACKS]
    Xe = pd.DataFrame(rows_e)[[c for c in feature_cols if c in rows_e[0]]]
    # Fill missing v2 columns with 0 for this quick check
    for col in feature_cols:
        if col not in Xe.columns:
            Xe[col] = 0
    Xe = Xe[feature_cols]
    preds_e = rf.predict(Xe)
    caught = sum(preds_e)
    print(f"Evasion sanity (base-11 features only): {caught}/{len(EVASION_ATTACKS)} caught")

    rows_b = [engineer_rf_features(p, "GET") for p in HARD_BENIGN]
    Xb = pd.DataFrame(rows_b)
    for col in feature_cols:
        if col not in Xb.columns:
            Xb[col] = 0
    Xb = Xb[feature_cols]
    preds_b = rf.predict(Xb)
    fp = sum(preds_b)
    print(f"Hard-benign sanity (base-11 features only): {fp}/{len(HARD_BENIGN)} false positives")

    print("\n" + "=" * 60)
    print("STEP 04 — EVASION DEFINITIONS SANITY CHECK COMPLETE")
    print("=" * 60)
    print(f"  Clean test AUC-ROC : {clean_auc:.4f}")
    print(f"  Evasion caught     : {caught}/{len(EVASION_ATTACKS)}")
    print(f"  Hard-benign FP     : {fp}/{len(HARD_BENIGN)}")
    print("  (v2 features not shown here — use 10_final_evaluation.py for full results)")
    print("=" * 60)


if __name__ == "__main__":
    main()
