#!/usr/bin/env python3
"""
evasion_resistance_check.py

Trains the RF on the v8 training data (as reported: 1.000 AUC-ROC on the
clean held-out test set), then checks whether that holds up against
payloads built with GENUINELY DIFFERENT construction techniques than any
training generator used -- a rough proxy for "how does this perform
against LLM-generated evasion payloads it has never seen the pattern of."

This is NOT a substitute for the real evasion test (your held-out
Ollama-generated SQLi/XSS set) -- it's a sanity check I can actually run
right now without Ollama available in this environment. Treat the
numbers as directional, not as a thesis result.

Two held-out sets, neither seen during training:
  1. EVASION_ATTACKS: SQLi/XSS built with techniques NOT in the training
     generators -- different encoding schemes, keyword-free blind
     patterns, alternative syntax (backticks, hex literals, nested
     subqueries), JS obfuscation (String.fromCharCode, atob, template
     literals), whitespace tricks (%09/%0a instead of space), and
     payloads with few or no "sqli/xss keyword" hits so the has_*_keyword
     features can't just fire.
  2. HARD_BENIGN: legitimate-looking text that a naive classifier keyed
     on "any special character" might false-positive on -- addresses,
     business names, technical documentation snippets, code samples in
     a support ticket, SQL mentioned in prose ("SELECT is a SQL
     keyword").
"""

import sys
sys.path.insert(0, "/home/claude")
import math
from collections import Counter

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

SQLI_KEYWORDS = ["select", "union", "drop", "sleep", "waitfor", "exec",
                  "or 1=1", "or '1'='1", "xp_cmdshell", "convert", "extractvalue"]
XSS_KEYWORDS = ["script", "onerror", "onload", "onfocus", "onmouseover",
                 "onstart", "ontoggle", "alert(", "javascript:", "<svg", "<img"]


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def engineer_rf_features(text, method):
    lower = text.lower()
    return {
        "payload_len": len(text),
        "entropy": round(shannon_entropy(text), 4),
        "num_special_chars": sum(1 for c in text if not c.isalnum() and not c.isspace()),
        "num_digits": sum(c.isdigit() for c in text),
        "num_uppercase": sum(c.isupper() for c in text),
        "param_count": 1,
        "is_post": int(method.upper() == "POST"),
        "has_sqli_keyword": int(any(k in lower for k in SQLI_KEYWORDS)),
        "has_xss_keyword": int(any(k in lower for k in XSS_KEYWORDS)),
        "quote_count": text.count("'") + text.count('"'),
        "comment_token_count": text.count("--") + text.count("/*") + text.count("#"),
    }


# --------------------------------------------------------------------------
# Held-out evasion-style attacks -- techniques NOT present in any training
# generator (webids23_to_honeypot_log_v8.py's SQLI_GENERATORS/XSS_GENERATORS)
# --------------------------------------------------------------------------
EVASION_ATTACKS = [
    # Whitespace-trick SQLi (tabs/newlines instead of spaces -- CRS-bypass classic)
    "1'%09OR%091=1%09--%09-", "1'%0aAND%0a1=1%0a#", "'%0d%0aOR%0d%0a'a'='a",
    # Backtick / MySQL-specific identifier quoting (not in training generators)
    "1`;DROP TABLE `users`;--", "` OR `1`=`1",
    # Hex-encoded string literals (bypasses naive quote/keyword scanning)
    "1 UNION SELECT 0x61646d696e,0x70617373776f7264--",
    "' OR 0x31=0x31--",
    # No SQL keyword at all -- pure boolean/arithmetic blind
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT version()))x FROM information_schema.tables GROUP BY x)a)",
    "1)) OR (('1')=('1",
    # Comment-fragmented keywords (splits the literal keyword substring)
    "'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3--",
    "'+UN'+'ION+SEL'+'ECT+1--",
    # Nested/second-order style
    "1;SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END--",
    # XSS: JS obfuscation not in training generators
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>",
    "<img src=x oNeRRor=/**/(alert)(1)>",
    "<a href=\"jav&#97;script:alert(1)\">x</a>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<template><script>alert(1)</script></template>",
    "<x contenteditable onfocus=alert(1) autofocus>",
    "<script>/*comment*/alert`1`</script>",  # template-literal call syntax
    "'\"><img src=x id=dmFyIGE9YWxlcnQoMSk=onerror=eval(atob(this.id))>",
    "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # full hex-entity encoding
]

# --------------------------------------------------------------------------
# Hard benign -- legitimate text that could trip a shallow classifier
# --------------------------------------------------------------------------
HARD_BENIGN = [
    "123 O'Connell St, Dublin", "Smith & Sons Law Firm LLC",
    "Please review section 3.2(a) of the contract, re: pricing.",
    "SELECT is a reserved keyword in most SQL dialects.",
    "My favorite quote: \"to be or not to be\" -- Shakespeare",
    "Error code: 500 (Internal Server Error) -- see logs for details.",
    "cost = qty * unit_price; if (cost > budget) { flag(); }",
    "Contact us at support@company.com or call (555) 123-4567.",
    "Meeting notes 10/25: discussed Q3 <-> Q4 transition plan.",
    "Product SKU# ABC-123; Category: Electronics & Gadgets",
    "Recipe: mix 2 cups flour w/ 1 tsp salt; bake @ 350F for 20 min.",
    "git commit -m \"fix: resolve null pointer in auth module\"",
    "Rated 4.5/5 stars -- \"great product, fast shipping!\"",
    "Address: 42 O'Malley Ave, Apt #7, (near the park)",
    "Discount code SAVE20% applies to orders over $50.",
]


def main():
    print("Loading v8 training data and fitting RF...")
    train = pd.read_csv("/mnt/user-data/outputs/final_prepared_data_v8/rf_train.csv")
    Xtr, ytr = train.drop(columns=["label"]), train["label"]
    rf = RandomForestClassifier(random_state=42, n_estimators=100)
    rf.fit(Xtr, ytr)

    # Sanity: confirm clean test performance matches what was reported earlier
    test = pd.read_csv("/mnt/user-data/outputs/final_prepared_data_v8/rf_test.csv")
    Xtest, ytest = test.drop(columns=["label"]), test["label"]
    clean_auc = roc_auc_score(ytest, rf.predict_proba(Xtest)[:, 1])
    print(f"Clean held-out test AUC-ROC (sanity check): {clean_auc:.4f}\n")

    feature_cols = list(Xtr.columns)

    print("=" * 70)
    print("EVASION-STYLE ATTACKS (never-before-seen construction techniques)")
    print("=" * 70)
    rows = [engineer_rf_features(p, "GET") for p in EVASION_ATTACKS]
    Xe = pd.DataFrame(rows)[feature_cols]
    preds = rf.predict(Xe)
    proba = rf.predict_proba(Xe)[:, 1]
    caught = sum(preds)
    print(f"Caught: {caught}/{len(EVASION_ATTACKS)} ({caught/len(EVASION_ATTACKS)*100:.1f}%)\n")
    for p, pred, prob in zip(EVASION_ATTACKS, preds, proba):
        marker = "MISSED" if pred == 0 else "caught"
        print(f"  [{marker}] p={prob:.2f}  {p[:70]}")

    print()
    print("=" * 70)
    print("HARD BENIGN (legitimate text that could trigger false positives)")
    print("=" * 70)
    rows_b = [engineer_rf_features(p, "GET") for p in HARD_BENIGN]
    Xb = pd.DataFrame(rows_b)[feature_cols]
    preds_b = rf.predict(Xb)
    proba_b = rf.predict_proba(Xb)[:, 1]
    false_pos = sum(preds_b)
    print(f"False positives: {false_pos}/{len(HARD_BENIGN)} ({false_pos/len(HARD_BENIGN)*100:.1f}%)\n")
    for p, pred, prob in zip(HARD_BENIGN, preds_b, proba_b):
        marker = "FALSE POSITIVE" if pred == 1 else "correct"
        print(f"  [{marker}] p={prob:.2f}  {p[:70]}")

    print()
    print("=" * 70)
    print("Feature importances (for interpreting the failures above)")
    print("=" * 70)
    for f, imp in sorted(zip(feature_cols, rf.feature_importances_), key=lambda x: -x[1]):
        print(f"  {f}: {imp:.3f}")


if __name__ == "__main__":
    main()
