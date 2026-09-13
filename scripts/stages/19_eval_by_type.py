#!/usr/bin/env python3
"""
19_eval_by_type.py  (Adviser item 3: SOP4 / RO2)

Breaks every evaluation out by ATTACK TYPE (SQLi vs XSS) instead of the
undifferentiated attack-vs-benign view, and produces the ROC curves SOP4
commits to.

Type is assigned by structural rule (see classify_attack): XSS if the payload
carries HTML-tag / event-handler / javascript: structure, SQLi if it carries
SQL syntax, "nl_intent" for the plain-language rows, "other" otherwise. The
rule is applied to the NORMALISED text -- the same text the models see.

Also reports the obfuscated vs non-obfuscated breakdown (adviser item 10) for
the training-log families, and writes ROC curves.

Outputs:
  reports/eval_by_type.json      per-type detection, FPR, AUC, PR-AUC
  reports/roc_by_type.png        ROC curves (overall + per type)

USAGE (from dashboard/):  python scripts/19_eval_by_type.py
"""
import argparse
import json
import pickle
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT, DATA_CORPUS  # noqa: E402
ROOT = _ROOT
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from build_rf_features_v2 import structural_features        # noqa: E402
from text_normalize import normalize_text                   # noqa: E402

from sklearn.metrics import roc_auc_score, roc_curve, average_precision_score

# --- type classification ----------------------------------------------------
XSS_RE = re.compile(
    r"(<\s*/?\s*(script|img|svg|body|iframe|input|a|audio|video|details|marquee)\b"
    r"|\bon[a-z]+\s*="
    r"|javascript\s*:"
    r"|<\s*[a-zA-Z][a-zA-Z0-9]*[^>]*>)",
    re.IGNORECASE)

SQLI_RE = re.compile(
    r"(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b"
    r"|\bsleep\s*\(|\bwaitfor\b|\bxp_cmdshell\b|\bconvert\s*\(|\bextractvalue\b"
    r"|--|/\*|\bor\b\s+\d+\s*=\s*\d+|\bor\b\s*'[^']*'\s*=\s*'|\border\s+by\b"
    r"|\binformation_schema\b|;\s*\w)",
    re.IGNORECASE)

NL_RE = re.compile(
    r"\b(drop|delete|select|union|bypass|steal|read|run|insert|execute|dump|"
    r"return|show|give|fetch|list|sleep|close|comment)\b", re.IGNORECASE)


def classify_attack(text: str) -> str:
    """SQLi / XSS / nl_intent / other, on the normalised text."""
    t = normalize_text(text)
    is_xss = bool(XSS_RE.search(t))
    is_sql = bool(SQLI_RE.search(t))
    if is_xss and not is_sql:
        return "XSS"
    if is_sql and not is_xss:
        return "SQLi"
    if is_xss and is_sql:
        # tag structure dominates, e.g. <img src=x onerror=...select...>
        return "XSS"
    special = sum(1 for c in t if not c.isalnum() and not c.isspace())
    if NL_RE.search(t) and special <= max(2, len(t) * 0.05):
        return "nl_intent"
    return "other"


def load_models():
    with open(ROOT / "models/rf2.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(ROOT / "models/meta.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(ROOT / "models/ngram_vectorizer.pkl", "rb") as f:
        vec = pickle.load(f)
    from tensorflow import keras
    lstm = keras.models.load_model(ROOT / "models/lstm_best.keras")
    v2_cols = list(pd.read_csv(ROOT / "data/prepared/rf_train_v2.csv")
                   .drop(columns=["label"]).columns)
    return rf, meta, vec, lstm, v2_cols


def ordinal_encode(text, max_len=200):
    arr = np.zeros(max_len, dtype=np.int32)
    for i, c in enumerate(text[:max_len]):
        code = ord(c)
        arr[i] = code if code <= 127 else 1
    return arr


def score_all(texts, rf, meta, vec, lstm, v2_cols):
    texts = [normalize_text(t) for t in texts]
    struct = pd.DataFrame([structural_features(t) for t in texts])
    agg = pd.DataFrame([engineer_rf_features(t, "GET") for t in texts])
    ng = pd.DataFrame(
        vec.transform(texts).toarray(),
        columns=[f"ngram_{i}" for i in range(len(vec.get_feature_names_out()))])
    X = pd.concat([agg.reset_index(drop=True), struct.reset_index(drop=True),
                   ng.reset_index(drop=True)], axis=1)
    X = X.reindex(columns=v2_cols, fill_value=0)
    rf_p = rf.predict_proba(X)[:, 1]
    E = np.stack([ordinal_encode(t) for t in texts])
    lstm_p = lstm.predict(E, verbose=0).flatten()
    st_p = meta.predict_proba(np.column_stack([rf_p, lstm_p]))[:, 1]
    return rf_p, lstm_p, st_p


def metrics_for(y, p, thr=0.5):
    y = np.asarray(y)
    p = np.asarray(p)
    pred = (p >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    out = {"n": int(len(y)), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
           "detection_rate": round(tp / (tp + fn), 4) if (tp + fn) else None,
           "fpr": round(fp / (fp + tn), 4) if (fp + tn) else None}
    if len(set(y.tolist())) == 2:
        out["auc"] = round(float(roc_auc_score(y, p)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, p)), 4)
    return out


def main():
    ap = argparse.ArgumentParser(description="Per-attack-type evaluation.")
    ap.add_argument("--csv", default=str(ROOT / "data/eval/holdout_eval.csv"),
                    help="Labelled CSV with text,label columns "
                         "(e.g. data/eval/llm_holdout_full.csv from 27_*).")
    args = ap.parse_args()

    print("=" * 70)
    print("19_eval_by_type.py  -  results broken out by attack type")
    print("=" * 70)

    df = pd.read_csv(args.csv)
    df["label"] = df["label"].astype(int)
    df["type"] = [classify_attack(t) if lab == 1 else "benign"
                  for t, lab in zip(df["text"], df["label"])]

    print("\nHold-out composition by type:")
    for k, v in df["type"].value_counts().items():
        print(f"   {k:12s} {v}")

    print("\nLoading models + scoring ...")
    rf, meta, vec, lstm, v2_cols = load_models()
    rf_p, lstm_p, st_p = score_all(df["text"].tolist(), rf, meta, vec, lstm, v2_cols)
    df["rf"], df["lstm"], df["stacked"] = rf_p, lstm_p, st_p

    benign = df[df["label"] == 0]
    results = {"holdout_composition": {k: int(v) for k, v
                                       in df["type"].value_counts().items()}}

    for model in ["rf", "lstm", "stacked"]:
        results[model] = {"overall": metrics_for(df["label"], df[model])}
        # per attack type: that type's attacks vs ALL benign (shared negatives)
        for atype in ["SQLi", "XSS", "nl_intent", "other"]:
            sub = df[(df["label"] == 1) & (df["type"] == atype)]
            if len(sub) == 0:
                continue
            y = np.concatenate([np.ones(len(sub)), np.zeros(len(benign))])
            p = np.concatenate([sub[model].values, benign[model].values])
            results[model][atype] = metrics_for(y, p)

    for model in ["rf", "lstm", "stacked"]:
        print(f"\n{'=' * 70}\n{model.upper()}\n{'=' * 70}")
        print(f"  {'segment':12s} {'n':>5s} {'detection':>10s} "
              f"{'FPR':>8s} {'AUC':>8s} {'PR-AUC':>8s}")
        print("  " + "-" * 62)
        for seg in ["overall", "SQLi", "XSS", "nl_intent", "other"]:
            if seg not in results[model]:
                continue
            m = results[model][seg]
            det = f"{m['detection_rate'] * 100:.1f}%" if m["detection_rate"] is not None else "-"
            fpr = f"{m['fpr'] * 100:.1f}%" if m["fpr"] is not None else "-"
            auc = f"{m.get('auc', float('nan')):.4f}"
            pra = f"{m.get('pr_auc', float('nan')):.4f}"
            n = m["n"] if seg == "overall" else m["tp"] + m["fn"]
            print(f"  {seg:12s} {n:5d} {det:>10s} {fpr:>8s} {auc:>8s} {pra:>8s}")

    # ---- obfuscated vs clean, from the training log (adviser item 10) -------
    print(f"\n{'=' * 70}\nOBFUSCATED vs NON-OBFUSCATED (training-log test split)\n{'=' * 70}")
    try:
        import prepare_honeypot_for_training as _prep
        log = _prep.load_log(DATA_CORPUS / "honeypot_final.log")
        log["_payload_text"] = log["_payload_text"].astype(str).map(normalize_text)
        _, _, te = _prep.session_grouped_split(log, 42)
        raw = {}
        with open(DATA_CORPUS / "honeypot_final.log", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                raw[r.get("session_id", "")] = bool(r.get("obfuscated"))
        te = te.copy()
        te["obf"] = [raw.get(s, False) for s in te["_session_id"]]
        rfp, lsp, stp = score_all(te["_payload_text"].tolist(),
                                  rf, meta, vec, lstm, v2_cols)
        te["stacked"] = stp
        ben = te[te["label"] == 0]
        obf_res = {}
        for flag, name in [(True, "obfuscated"), (False, "clean")]:
            sub = te[(te["label"] == 1) & (te["obf"] == flag)]
            if len(sub) == 0:
                continue
            y = np.concatenate([np.ones(len(sub)), np.zeros(len(ben))])
            p = np.concatenate([sub["stacked"].values, ben["stacked"].values])
            obf_res[name] = metrics_for(y, p)
            m = obf_res[name]
            print(f"  {name:12s} n={m['tp'] + m['fn']:5d}  "
                  f"detection={m['detection_rate'] * 100:.2f}%  AUC={m.get('auc')}")
        results["obfuscation_split"] = obf_res
    except Exception as e:  # noqa: BLE001
        print(f"  [warn] obfuscation split skipped: {e}")

    # ---- ROC curves --------------------------------------------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))

        ax = axes[0]
        for model, c in [("rf", "#2563eb"), ("lstm", "#d97706"), ("stacked", "#059669")]:
            fpr_c, tpr_c, _ = roc_curve(df["label"], df[model])
            ax.plot(fpr_c, tpr_c, color=c,
                    label=f"{model} (AUC={results[model]['overall']['auc']:.4f})")
        ax.plot([0, 1], [0, 1], "k--", lw=0.8, alpha=0.5)
        ax.set_title("ROC - overall (396-row hold-out)")
        ax.set_xlabel("False-positive rate")
        ax.set_ylabel("True-positive rate")
        ax.legend(loc="lower right", fontsize=9)
        ax.grid(alpha=0.3)

        ax = axes[1]
        for atype, c in [("SQLi", "#2563eb"), ("XSS", "#d97706"),
                         ("nl_intent", "#dc2626")]:
            if atype not in results["stacked"]:
                continue
            sub = df[(df["label"] == 1) & (df["type"] == atype)]
            y = np.concatenate([np.ones(len(sub)), np.zeros(len(benign))])
            p = np.concatenate([sub["stacked"].values, benign["stacked"].values])
            fpr_c, tpr_c, _ = roc_curve(y, p)
            ax.plot(fpr_c, tpr_c, color=c,
                    label=f"{atype} n={len(sub)} (AUC={results['stacked'][atype]['auc']:.4f})")
        ax.plot([0, 1], [0, 1], "k--", lw=0.8, alpha=0.5)
        ax.set_title("ROC - stacked ensemble, by attack type")
        ax.set_xlabel("False-positive rate")
        ax.set_ylabel("True-positive rate")
        ax.legend(loc="lower right", fontsize=9)
        ax.grid(alpha=0.3)

        fig.tight_layout()
        out_png = ROOT / "reports" / "roc_by_type.png"
        fig.savefig(out_png, dpi=150)
        print(f"\n  ROC curves written to: {out_png}")
        results["roc_png"] = out_png.name
    except ImportError:
        print("\n  [warn] matplotlib not installed; skipping ROC plot")

    out = ROOT / "reports" / "eval_by_type.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"  JSON written to      : {out}")
    print("=" * 70)


if __name__ == "__main__":
    main()
