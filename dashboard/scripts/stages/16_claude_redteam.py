#!/usr/bin/env python3
"""Red-team the stacked ensemble with a Claude-authored evasion set.

Cases live in scripts/redteam_cases.json ([label, tag, text]; label 1=attack, 0=benign).
Each is scored through RF v2 + LSTM + meta-learner exactly as the live app does.
Read-only w.r.t. models. Writes reports/claude_redteam_results.json.

USAGE (from dashboard/):  python scripts/16_claude_redteam.py
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "lib"))
from evasion_resistance_check import engineer_rf_features  # noqa: E402
from build_rf_features_v2 import structural_features       # noqa: E402
from text_normalize import normalize_text                   # noqa: E402

with open(ROOT / "models/rf2.pkl", "rb") as f:
    RF = pickle.load(f)
with open(ROOT / "models/meta.pkl", "rb") as f:
    META = pickle.load(f)
with open(ROOT / "models/ngram_vectorizer.pkl", "rb") as f:
    VEC = pickle.load(f)
from tensorflow import keras  # noqa: E402
LSTM = keras.models.load_model(ROOT / "models/lstm_best.keras")
V2 = list(pd.read_csv(ROOT / "data/prepared/rf_train_v2.csv").drop(columns=["label"]).columns)

CASES = json.load(open(ROOT / "scripts/redteam_cases.json", encoding="utf-8"))


def enc(t, n=200):
    a = np.zeros(n, dtype=np.int32)
    for i, c in enumerate(t[:n]):
        o = ord(c)
        a[i] = o if o <= 127 else 1
    return a


def score(t):
    t = normalize_text(t)
    st = pd.DataFrame([structural_features(t)])
    ag = pd.DataFrame([engineer_rf_features(t, "GET")])
    ng = pd.DataFrame(VEC.transform([t]).toarray(),
                      columns=[f"ngram_{i}" for i in range(300)])
    X = pd.concat([ag, st, ng], axis=1)[V2]
    rf = float(RF.predict_proba(X)[:, 1][0])
    ls = float(LSTM.predict(np.stack([enc(t)]), verbose=0).flatten()[0])
    sk = float(META.predict_proba(np.array([[rf, ls]]))[:, 1][0])
    return rf, ls, sk


rows = []
for lbl, tag, t in CASES:
    rf, ls, sk = score(t)
    rows.append({"label": lbl, "tag": tag, "text": t,
                 "rf": round(rf, 4), "lstm": round(ls, 4),
                 "stacked": round(sk, 4), "flagged": sk >= 0.5})

atk = [r for r in rows if r["label"] == 1]
ben = [r for r in rows if r["label"] == 0]
caught = sum(r["flagged"] for r in atk)
fp = sum(r["flagged"] for r in ben)
summary = {
    "attacks_total": len(atk), "attacks_caught": caught,
    "attacks_missed": len(atk) - caught,
    "benign_total": len(ben), "false_positives": fp,
    "detection_rate": round(caught / len(atk), 4),
    "fpr": round(fp / len(ben), 4),
}
(ROOT / "reports/claude_redteam_results.json").write_text(
    json.dumps({"summary": summary, "cases": rows}, indent=2, ensure_ascii=False),
    encoding="utf-8")

print("=" * 72)
print("CLAUDE RED-TEAM RESULTS")
print("=" * 72)
print(f"  Attacks caught : {caught}/{len(atk)}   ({caught/len(atk)*100:.0f}%)")
print(f"  False positives: {fp}/{len(ben)}   ({fp/len(ben)*100:.0f}%)")
print("-" * 72)
print("  MISSED ATTACKS (evaded detection):")
missed = [r for r in atk if not r["flagged"]]
for r in missed:
    print(f"    [{r['tag']:16s}] stacked={r['stacked']:.4f}  {r['text'][:56]}")
if not missed:
    print("    (none)")
print("  FALSE ALARMS (benign flagged as attack):")
fa = [r for r in ben if r["flagged"]]
for r in fa:
    print(f"    [{r['tag']:16s}] stacked={r['stacked']:.4f}  {r['text'][:56]}")
if not fa:
    print("    (none)")
print("=" * 72)
