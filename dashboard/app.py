#!/usr/bin/env python3
"""
AI-GIS Dashboard — one local interface for the detection pipeline.

Run: python3 app.py
Then open http://127.0.0.1:5050 in a browser.

Routes:
  /            dashboard: dataset stats + model performance charts
  /tester      paste any text, get live RF v2 / LSTM / Stacked predictions
  /predict     POST endpoint used by the tester (JSON in, JSON out)
  /evasion     browse the real (23+15) and mock (150+150) evasion results
  /dataset     browse sample rows from the honeypot log
  /baseline    ModSecurity + OWASP CRS baseline vs AI-GIS
  /statistics  bootstrap 95% CIs + McNemar's test (Chapter 3 rigour)
  /ablation    6-condition ablation study
  /llm         results against the LLM-generated evasion corpus
"""

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE / "scripts"))

from evasion_resistance_check import (  # noqa: E402
    EVASION_ATTACKS, HARD_BENIGN, engineer_rf_features,
)
from build_rf_features_v2 import structural_features  # noqa: E402

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Load everything once at startup
# ---------------------------------------------------------------------------
print("Loading models...")
with open(BASE / "models" / "rf2.pkl", "rb") as f:
    RF = pickle.load(f)
with open(BASE / "models" / "meta.pkl", "rb") as f:
    META = pickle.load(f)
with open(BASE / "models" / "ngram_vectorizer.pkl", "rb") as f:
    VECTORIZER = pickle.load(f)

from tensorflow import keras  # noqa: E402
LSTM = keras.models.load_model(BASE / "models" / "lstm_best.keras")

V2_COLS = list(pd.read_csv(BASE / "data" / "prepared" / "rf_train_v2.csv")
               .drop(columns=["label"]).columns)

with open(BASE / "data" / "results.json") as f:
    RESULTS = json.load(f)
with open(BASE / "data" / "mock_attacker_results.json") as f:
    MOCK_RESULTS = json.load(f)

# ---------------------------------------------------------------------------
# Evaluation artifacts produced by scripts/11-14.
# These are optional: each page renders a "not generated yet" state instead of
# crashing, so the app still runs on a fresh clone before the pipeline is run.
# ---------------------------------------------------------------------------
REPORTS = BASE / "reports"


def load_report(name):
    """Return parsed JSON from reports/<name>, or None if it hasn't been generated."""
    path = REPORTS / name
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            # NaN appears in the ModSec report (AUC is undefined for binary output).
            return json.loads(f.read().replace("NaN", "null"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] could not read {path.name}: {exc}")
        return None


print("Models loaded. Ready.")


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def build_v2_features(texts):
    struct_df = pd.DataFrame([structural_features(t) for t in texts])
    agg_df = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ngram_df = pd.DataFrame(VECTORIZER.transform(texts).toarray(),
                             columns=[f"ngram_{i}" for i in range(300)])
    combined = pd.concat([agg_df.reset_index(drop=True), struct_df.reset_index(drop=True),
                           ngram_df.reset_index(drop=True)], axis=1)
    return combined[V2_COLS]


def predict_one(text: str):
    Xv2 = build_v2_features([text])
    Xlstm = np.stack([ordinal_encode(text)])
    rf_proba = float(RF.predict_proba(Xv2)[:, 1][0])
    lstm_proba = float(LSTM.predict(Xlstm, verbose=0).flatten()[0])
    stacked_proba = float(META.predict_proba(np.array([[rf_proba, lstm_proba]]))[:, 1][0])
    return {
        "rf_proba": round(rf_proba, 4),
        "lstm_proba": round(lstm_proba, 4),
        "stacked_proba": round(stacked_proba, 4),
        "verdict": "MALICIOUS" if stacked_proba >= 0.5 else "benign",
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    dataset_stats = {
        "total": 36364, "malicious": 18182, "benign": 18182,
        "sqli": 9091, "xss": 9091,
        "train": 24819, "val": 5562, "test": 5983,
    }
    clean_test = RESULTS["clean_test"]
    stress_test = RESULTS["stress_test"]
    return render_template("dashboard.html", stats=dataset_stats,
                            clean_test=clean_test, stress_test=stress_test, active="dashboard")


@app.route("/tester")
def tester():
    examples = [
        "' OR 1=1--",
        "<script>alert(document.cookie)</script>",
        "Smith & Sons Law Firm LLC",
        "Error code: 500 (Internal Server Error)",
    ]
    return render_template("tester.html", examples=examples, active="tester")


@app.route("/predict", methods=["POST"])
def predict():
    text = request.json.get("text", "")
    if not text.strip():
        return jsonify({"error": "empty input"}), 400
    return jsonify(predict_one(text))


@app.route("/evasion")
def evasion():
    real_evasion = [{"text": t, **{}} for t in EVASION_ATTACKS]
    real_benign = [{"text": t} for t in HARD_BENIGN]
    return render_template(
        "evasion.html",
        mock_normal=MOCK_RESULTS["normal"],
        mock_poly=MOCK_RESULTS["polymorphic"],
        real_evasion_count=len(EVASION_ATTACKS),
        real_benign_count=len(HARD_BENIGN),
        active="evasion",
    )


@app.route("/dataset")
def dataset():
    log_path = BASE / "data" / "honeypot_final.log"
    samples = {"malicious": [], "benign": []}
    seen_families = set()
    with open(log_path) as f:
        for line in f:
            row = json.loads(line)
            bucket = "malicious" if row["label"] == 1 else "benign"
            key = row.get("attack_family", "benign")
            if len(samples[bucket]) < 40:
                samples[bucket].append(row)
            if len(samples["malicious"]) >= 40 and len(samples["benign"]) >= 40:
                break
    return render_template("dataset.html", samples=samples, active="dataset")


@app.route("/baseline")
def baseline():
    """ModSecurity + OWASP CRS baseline vs the AI-GIS stacked ensemble."""
    modsec = load_report("modsec_baseline_results.json")
    return render_template(
        "baseline.html",
        modsec=modsec,
        ai_clean=RESULTS["clean_test"]["Stacked"],
        ai_stress=RESULTS["stress_test"]["Stacked"],
        active="baseline",
    )


@app.route("/statistics")
def statistics():
    """Bootstrap 95% confidence intervals and McNemar's test."""
    return render_template(
        "statistics.html",
        stats=load_report("statistical_significance.json"),
        active="statistics",
    )


@app.route("/ablation")
def ablation():
    """6-condition ablation study: what each component actually contributes."""
    raw = load_report("ablation_study_results.json")
    conditions = None
    if raw:
        # Keys look like "Cond_3_LR_11_Base_Feats" -> "LR 11 Base Feats"
        conditions = [
            {"key": k,
             "label": " ".join(k.split("_")[2:]),
             "metrics": v.get("Combined", {})}
            for k, v in raw.items()
        ]
    return render_template("ablation.html", conditions=conditions, active="ablation")


@app.route("/llm")
def llm():
    """Detection results against the LLM-generated evasion corpus."""
    modsec = load_report("modsec_baseline_results.json")
    return render_template(
        "llm.html",
        report=load_report("llm_corpus_results.json"),
        modsec_llm=(modsec or {}).get("llm_corpus"),
        active="llm",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
