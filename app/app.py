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
  /session     live attack-session simulator with per-session dynamic charts
"""

import json
import os
import pickle
import random
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify

# Project paths come from scripts/lib/paths.py so the app and the pipeline
# scripts agree on where models, data and reports live.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "lib"))

from paths import (  # noqa: E402
    DATA_EVAL, DATA_PREPARED, DATA_CORPUS, MODELS_CURRENT, REPORTS as REPORTS_DIR, ROOT,
)

from evasion_resistance_check import (  # noqa: E402
    EVASION_ATTACKS, HARD_BENIGN, engineer_rf_features,
)
from build_rf_features_v2 import structural_features  # noqa: E402
from text_normalize import normalize_text  # noqa: E402

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Load everything once at startup
# ---------------------------------------------------------------------------
print("Loading models...")
with open(MODELS_CURRENT / "rf2.pkl", "rb") as f:
    RF = pickle.load(f)
with open(MODELS_CURRENT / "meta.pkl", "rb") as f:
    META = pickle.load(f)
with open(MODELS_CURRENT / "ngram_vectorizer.pkl", "rb") as f:
    VECTORIZER = pickle.load(f)

from tensorflow import keras  # noqa: E402
LSTM = keras.models.load_model(MODELS_CURRENT / "lstm_best.keras")

V2_COLS = list(pd.read_csv(DATA_PREPARED / "rf_train_v2.csv")
               .drop(columns=["label"]).columns)

with open(DATA_CORPUS / "results.json") as f:
    RESULTS = json.load(f)
with open(DATA_CORPUS / "mock_attacker_results.json") as f:
    MOCK_RESULTS = json.load(f)

# ---------------------------------------------------------------------------
# Evaluation artifacts produced by scripts/11-14.
# These are optional: each page renders a "not generated yet" state instead of
# crashing, so the app still runs on a fresh clone before the pipeline is run.
# ---------------------------------------------------------------------------
REPORTS = REPORTS_DIR


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
    # Same Unicode/homoglyph folding the models were trained with. MUST match
    # scripts/18_train_stacked.py — both call normalize_text() before features.
    text = normalize_text(text)
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


def predict_many(texts):
    """Vectorized predict_one() for a whole batch.

    Identical math to predict_one(), but one Keras/sklearn call for the batch
    instead of one per payload. The per-call overhead dominates at ~4 req/s
    single-stepped, which makes a 1,800-row ALL run take ~9 minutes; batching
    it is what keeps that page usable.
    """
    if not texts:
        return []
    norm = [normalize_text(t) for t in texts]
    Xv2 = build_v2_features(norm)
    Xlstm = np.stack([ordinal_encode(t) for t in norm])

    rf = RF.predict_proba(Xv2)[:, 1]
    lstm = LSTM.predict(Xlstm, verbose=0).flatten()
    stacked = META.predict_proba(np.column_stack([rf, lstm]))[:, 1]

    return [
        {
            "rf_proba": round(float(r), 4),
            "lstm_proba": round(float(l), 4),
            "stacked_proba": round(float(st), 4),
            "verdict": "MALICIOUS" if st >= 0.5 else "benign",
        }
        for r, l, st in zip(rf, lstm, stacked)
    ]


# ---------------------------------------------------------------------------
# ModSecurity + OWASP CRS side-by-side
#
# The WAF runs as a Docker container (docker-compose.yml -> PL2, port 8080).
# Probe semantics are copied from scripts/12_evaluate_modsec_baseline.py so a
# number produced here means the same thing as one in the batch report:
# payload goes out as GET ?q=<urlencoded>, HTTP 403 = blocked, anything else
# = passed. A dropped connection counts as "passed", not as an error, because
# that is what the batch script does.
#
# If the container is not running the session simply proceeds without it --
# ModSec is an optional comparator, never a hard dependency of the page.
# ---------------------------------------------------------------------------

MODSEC_BASE = os.environ.get("MODSEC_URL", "http://127.0.0.1:8080/")
_MODSEC_STATE = {"checked": False, "alive": False}


def modsec_alive(force=False):
    """True if the WAF answers at all. Cached: a dead container should not cost
    a 3s timeout on every single request of an 1,800-row run."""
    if _MODSEC_STATE["checked"] and not force:
        return _MODSEC_STATE["alive"]
    alive = True
    try:
        req = urllib.request.Request(MODSEC_BASE, method="GET")
        for k, v in MODSEC_HEADERS.items():
            req.add_header(k, v)
        urllib.request.urlopen(req, timeout=3)
    except urllib.error.HTTPError:
        alive = True          # 403/404 still means the server is up
    except Exception:
        alive = False
    _MODSEC_STATE.update(checked=True, alive=alive)
    return alive


# Browser-like headers. WITHOUT THESE THE COMPARISON IS MEANINGLESS: CRS rule
# 920300 ("Request Missing an Accept Header") scores every header-less request,
# and at PARANOIA=2 / ANOMALY_INBOUND=5 that alone is enough to push ordinary
# benign text over the blocking threshold -- ModSecurity then appears to block
# 100% of traffic and score 0% specificity, which is an artifact of the probe,
# not of the WAF. scripts/12_evaluate_modsec_baseline.py sends only a
# User-Agent and so has this same flaw; see the note in the session page.
MODSEC_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def modsec_probe(payload, timeout=5):
    """Return 1 if ModSecurity blocked the payload, 0 if it passed, None on error."""
    import http.client
    encoded = urllib.parse.quote(payload, safe="")
    req = urllib.request.Request(f"{MODSEC_BASE}?q={encoded}", method="GET")
    for k, v in MODSEC_HEADERS.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 1 if resp.status == 403 else 0
    except urllib.error.HTTPError as e:
        return 1 if e.code == 403 else 0
    except (http.client.RemoteDisconnected, http.client.BadStatusLine,
            ConnectionResetError, ConnectionAbortedError):
        return 0              # dropped connection = not a block (matches script 12)
    except Exception:
        return None


def modsec_probe_many(texts, workers=12):
    """Probe a batch concurrently. One HTTP round-trip per payload is the cost
    here, so serial probing would make ModSec far slower than the models it is
    being compared against."""
    if not texts or not modsec_alive():
        return [None] * len(texts)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(modsec_probe, texts))


@app.route("/session/modsec_status")
def session_modsec_status():
    """Let the page tell the user whether the WAF comparator is available."""
    alive = modsec_alive(force=True)
    return jsonify({"alive": alive, "url": MODSEC_BASE})


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


# ---------------------------------------------------------------------------
# Dataset browser — pick a dataset, filter/search, page through it, and score
# each row live with AI-GIS and (optionally) ModSecurity.
# ---------------------------------------------------------------------------

# Registry of browsable datasets. Each loader returns a list of uniform row
# dicts: {text, label, attack_type, family, generator}.
DATASETS = {
    "honeypot": {
        "label": "Honeypot training corpus (WEB-IDS23-seeded)",
        "kind": "log", "file": "data/corpus/honeypot_final.log",
        "note": "The labelled corpus the models were trained on. 10 attack families + benign.",
    },
    "paper": {
        "label": "LLM Deepseek & Code Llama with Benign (1700)",
        "kind": "csv", "file": "data/eval/paper_benchmark.csv",
        "note": "Generated for held out test via Google Collab",
    },
    "holdout": {
        "label": "Held-out eval set (real)",
        "kind": "csv", "file": "data/eval/holdout_eval.csv",
        "note": "Real held-out evaluation records.",
    },
    "llm_real": {
        "label": "LLM holdout (real, 276)",
        "kind": "csv", "file": "data/eval/llm_holdout_full.csv",
        "note": "Genuine generator output kept entirely out of training.",
    },
    "claude": {
        "label": "Claude red-team (adversarial, 1,949)",
        "kind": "csv", "file": "data/eval/claude_redteam.csv",
        "note": "Assistant-authored polymorphic attacks, incl. natural-language "
                "intent injection — the hardest set, designed to probe evasion.",
    },
}

_DATASET_CACHE = {}


def _uniform_row(text, label, attack_type="", family="", generator=""):
    return {"text": str(text), "label": int(label),
            "attack_type": str(attack_type or ("benign" if not label else "unknown")),
            "family": str(family or ("benign" if not label else "unknown")),
            "generator": str(generator or "held_out")}


def load_dataset(key):
    """Load one browsable dataset as a list of uniform row dicts (cached)."""
    if key in _DATASET_CACHE:
        return _DATASET_CACHE[key]
    spec = DATASETS.get(key)
    if not spec:
        return []
    path = ROOT / spec["file"]
    rows = []
    if not path.exists():
        _DATASET_CACHE[key] = []
        return []
    def _hp_text(r):
        # attacker-controlled text = URI query + body (matches training prep)
        uri = r.get("uri", "")
        body = r.get("request_body", "") or ""
        query = uri.split("?", 1)[1] if "?" in uri else ""
        return f"{query} {body}".strip()

    if spec["kind"] == "log":
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fam = r.get("attack_family", "benign")
                atype = "sqli" if fam in {"tautology", "union_based", "boolean_blind",
                                          "time_based_blind", "error_based",
                                          "stacked_query", "auth_bypass"} else \
                        ("xss" if fam in {"reflected", "stored", "dom_based"} else "benign")
                rows.append(_uniform_row(_hp_text(r), r.get("label", 0),
                                         atype, fam, "honeypot"))
    else:  # csv
        df = pd.read_csv(path)
        for rec in df.to_dict("records"):
            text = str(rec.get("text", "")).strip()
            if not text or text == "nan":
                continue
            rows.append(_uniform_row(
                text, rec.get("label", 0),
                rec.get("attack_type") or rec.get("category") or "",
                rec.get("category") or rec.get("attack_type") or "",
                rec.get("generator") or ""))
    _DATASET_CACHE[key] = rows
    return rows


def dataset_summary(rows):
    """Class / family counts for the summary strip."""
    from collections import Counter
    total = len(rows)
    atk = sum(1 for r in rows if r["label"] == 1)
    fams = Counter(r["family"] for r in rows if r["label"] == 1)
    types = Counter(r["attack_type"] for r in rows if r["label"] == 1)
    return {"total": total, "attacks": atk, "benign": total - atk,
            "families": dict(fams.most_common()),
            "types": dict(types.most_common())}


@app.route("/dataset")
def dataset():
    default_key = "honeypot"
    rows = load_dataset(default_key)
    catalog = [{"key": k, "label": v["label"], "note": v["note"]}
               for k, v in DATASETS.items() if (ROOT / v["file"]).exists()]
    return render_template("dataset.html", active="dataset",
                           catalog=catalog, default_key=default_key,
                           summary=dataset_summary(rows))


@app.route("/dataset/rows", methods=["POST"])
def dataset_rows():
    """Filtered + paginated rows for the browser, optionally scored live."""
    body = request.json or {}
    key = body.get("dataset", "honeypot")
    q = (body.get("q") or "").strip().lower()
    cls = body.get("cls", "all")          # all | attack | benign
    fam = body.get("family", "all")
    page = max(0, int(body.get("page", 0)))
    size = min(50, max(5, int(body.get("size", 20))))
    score = bool(body.get("score"))       # run AI-GIS on the page
    use_modsec = bool(body.get("modsec"))

    rows = load_dataset(key)

    # filter
    def keep(r):
        if cls == "attack" and r["label"] != 1: return False
        if cls == "benign" and r["label"] != 0: return False
        if fam != "all" and r["family"] != fam: return False
        if q and q not in r["text"].lower(): return False
        return True
    filtered = [r for r in rows if keep(r)]

    total = len(filtered)
    window = filtered[page * size:(page + 1) * size]

    # optional live scoring of just this page
    if score and window:
        preds = predict_many([r["text"] for r in window])
        ms = modsec_probe_many([r["text"] for r in window]) if use_modsec else [None] * len(window)
        for r, p, m in zip(window, preds, ms):
            r = r  # window rows are dict refs from the cache list; copy fields out
        window = [{**r, **p, "modsec": m,
                   "ai_verdict": 1 if p["stacked_proba"] >= 0.5 else 0}
                  for r, p, m in zip(window, preds, ms)]

    fam_options = sorted({r["family"] for r in rows if r["label"] == 1})
    return jsonify({
        "rows": window, "total": total, "page": page, "size": size,
        "pages": (total + size - 1) // size,
        "family_options": fam_options,
        "scored": score, "modsec_used": use_modsec and modsec_alive(),
        "summary": dataset_summary(rows),
    })


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


# ---------------------------------------------------------------------------
# Attack session simulator
#
# The other pages report *aggregate* numbers from finished experiments. This
# one runs the live models one payload at a time, so a reader can watch the
# ensemble make decisions and see where it fails, in sequence.
#
# Payload pools are the real held-out sets already used elsewhere in the app:
#   evasion  -> EVASION_ATTACKS   (techniques absent from the training generators)
#   benign   -> HARD_BENIGN       (legitimate text with attack-like characters)
#   classic  -> textbook payloads the training generators do cover
# ---------------------------------------------------------------------------

CLASSIC_ATTACKS = [
    "' OR 1=1--",
    "admin'--",
    "1' UNION SELECT username, password FROM users--",
    "'; DROP TABLE users;--",
    "1 AND (SELECT SLEEP(5))",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.domain)",
    "<body onload=alert('xss')>",
]


# CSV corpora under data/eval/. Each entry is (filename, source label). These
# are loaded lazily and cached, because the ALL pool is ~1.8k rows and reading
# it on every batch request would dominate the response time.
#
# NOTE ON PROVENANCE: the *_TEMP files are synthetic template payloads from a
# pipeline dry-run, NOT real Code Llama / DeepSeek output -- their own manifest
# says so (data/eval/llm_holdout_manifest_TEMP.json: "TEMP_PLACEHOLDER": true).
# They are included here because they are the only corpus at full Section 3.5
# scale, and the ALL page labels them as synthetic so no one mistakes a number
# taken off this screen for a thesis result.
EVAL_DIR = DATA_EVAL

CORPUS_FILES = {
    "llm_temp":      ("llm_holdout_full_TEMP.csv",           "synthetic"),
    "llm_temp_hard": ("llm_holdout_attacks_TEMP_1600_HARD.csv", "synthetic"),
    "llm_real":      ("llm_holdout_full.csv",                 "real"),
    "benign_hard":   ("benign_hard_expanded_TEMP.csv",        "synthetic"),
    "holdout":       ("holdout_eval.csv",                     "real"),
    # The exact 1,700-record held-out benchmark behind the reported
    # 97.9% detection / 19.6% FPR / F1 0.925 figures.
    "paper":         ("paper_benchmark.csv",                  "benchmark"),
    # Assistant-authored polymorphic red-team (attacks only, the hardest set).
    "claude":        ("claude_redteam.csv",                   "redteam"),
}

_CORPUS_CACHE = {}


def load_corpus(key):
    """Load one eval CSV as a list of row dicts. Missing file -> empty list.

    Returns dicts rather than tuples so the UI can group results by generator
    (codellama / deepseek-r1) and attack_type (sqli / xss); columns beyond
    text+label are optional and default to "unknown".
    """
    if key in _CORPUS_CACHE:
        return _CORPUS_CACHE[key]

    fname, provenance = CORPUS_FILES[key]
    path = EVAL_DIR / fname
    if not path.exists():
        print(f"[warn] eval corpus missing: {fname}")
        _CORPUS_CACHE[key] = []
        return []

    df = pd.read_csv(path)
    rows = []
    for rec in df.to_dict("records"):
        text = str(rec.get("text", ""))
        if not text.strip() or text == "nan":
            continue
        rows.append({
            "text": text,
            "label": int(rec.get("label", 0)),
            "attack_type": str(rec.get("attack_type")
                                or rec.get("category") or "benign"),
            "generator": str(rec.get("generator") or "held_out"),
            "source": fname,
            "provenance": provenance,
        })
    _CORPUS_CACHE[key] = rows
    print(f"[eval] {fname}: {len(rows)} rows")
    return rows


def _wrap(texts, label, attack_type, generator):
    """Turn a hardcoded python list into corpus-shaped row dicts."""
    return [{"text": t, "label": label, "attack_type": attack_type,
             "generator": generator, "source": "builtin",
             "provenance": "curated"} for t in texts]


def session_pool(mode):
    """Return a list of row dicts for the requested session mode."""
    if mode == "classic":
        return _wrap(CLASSIC_ATTACKS, 1, "mixed", "curated")
    if mode == "evasion":
        return _wrap(EVASION_ATTACKS, 1, "mixed", "curated")
    if mode == "benign":
        return _wrap(HARD_BENIGN, 0, "benign", "curated")

    if mode == "all":
        # Everything we have: the full-scale LLM holdout plus every curated set.
        return (load_corpus("llm_temp")
                + _wrap(CLASSIC_ATTACKS, 1, "mixed", "curated")
                + _wrap(EVASION_ATTACKS, 1, "mixed", "curated")
                + _wrap(HARD_BENIGN, 0, "benign", "curated"))

    if mode == "all_hard":
        # The obfuscated variant of the 1600 attacks, plus held-out benign so
        # the run still has a false-positive axis.
        return (load_corpus("llm_temp_hard")
                + [r for r in load_corpus("llm_temp") if r["label"] == 0]
                + _wrap(HARD_BENIGN, 0, "benign", "curated"))

    if mode == "paper":
        # The exact held-out benchmark used for the reported results:
        # 1,000 obfuscated attacks + 700 unseen benign. Running this profile
        # reproduces the paper's 97.9% detection / 19.6% FPR live.
        return load_corpus("paper")

    if mode == "claude":
        # Claude-authored adversarial attacks (attacks only) + held-out benign
        # so the run still has a false-positive axis.
        return (load_corpus("claude")
                + _wrap(HARD_BENIGN, 0, "benign", "curated"))

    if mode == "llm_real":
        return load_corpus("llm_real")

    # mixed: attacks and benign interleaved, which is what a real log looks like
    return (_wrap(CLASSIC_ATTACKS, 1, "mixed", "curated")
            + _wrap(EVASION_ATTACKS, 1, "mixed", "curated")
            + _wrap(HARD_BENIGN, 0, "benign", "curated"))


@app.route("/session")
def session():
    """Live attack-session simulator."""
    return render_template("session.html", active="session")


@app.route("/session/batch", methods=["POST"])
def session_batch():
    """Score one slice of a session.

    The browser asks for payloads `offset..offset+size` of a shuffled pool so
    the charts can animate in as results arrive, instead of freezing for the
    whole run. `seed` keeps the shuffle stable across requests in one session.
    """
    body = request.json or {}
    mode = body.get("mode", "mixed")
    offset = int(body.get("offset", 0))
    size = min(int(body.get("size", 5)), 200)
    seed = int(body.get("seed", 0))

    # Copy before shuffling: cached-corpus modes (e.g. paper, llm_real) return
    # the cached list by reference, so an in-place shuffle would re-shuffle the
    # same list on every batch request and corrupt the offset windows.
    pool = list(session_pool(mode))
    random.Random(seed).shuffle(pool)

    window = pool[offset:offset + size]
    texts = [r["text"] for r in window]
    preds = predict_many(texts)

    # Optional WAF comparator, run only when the page asks for it.
    want_modsec = bool(body.get("modsec"))
    modsec = modsec_probe_many(texts) if want_modsec else [None] * len(texts)

    events = []
    for row, pred, ms in zip(window, preds, modsec):
        true_label = row["label"]
        predicted = 1 if pred["stacked_proba"] >= 0.5 else 0
        if predicted == true_label:
            outcome = "detected" if true_label == 1 else "allowed"
        else:
            outcome = "evaded" if true_label == 1 else "false_alarm"

        ms_outcome = None
        if ms is not None:
            if ms == true_label:
                ms_outcome = "detected" if true_label == 1 else "allowed"
            else:
                ms_outcome = "evaded" if true_label == 1 else "false_alarm"

        events.append({
            "text": row["text"],
            "true_label": true_label,
            "predicted": predicted,
            "outcome": outcome,
            "attack_type": row["attack_type"],
            "generator": row["generator"],
            "provenance": row["provenance"],
            "modsec": ms,
            "modsec_outcome": ms_outcome,
            **pred,
        })

    return jsonify({
        "events": events,
        "total": len(pool),
        "done": offset + size >= len(pool),
        "synthetic": any(r["provenance"] == "synthetic" for r in pool),
        "modsec_alive": modsec_alive() if want_modsec else None,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
