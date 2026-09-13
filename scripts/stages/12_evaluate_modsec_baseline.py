#!/usr/bin/env python3
"""
12_evaluate_modsec_baseline.py

Evaluates ModSecurity + OWASP CRS (Paranoia Level 2) against the identical
test sets used in 10_final_evaluation.py, producing a directly comparable
5-metric report for the thesis.

ModSecurity produces binary decisions only (200 OK vs 403 Forbidden).
This script fires each payload as an HTTP GET request and records the
response code as the WAF's prediction.

NOTE on AUC-ROC: Because ModSecurity has no probability score (only a
binary block decision), the AUC-ROC here is effectively accuracy. This
is reported transparently in the output JSON.

Evaluates four test sets:
  1. Internal clean test set  (data/prepared/rf_test_v2.csv)
  2. Hand-crafted evasion set (EVASION_ATTACKS, 23 payloads)
  3. Hard-benign set          (HARD_BENIGN, 15 payloads)
  4. LLM corpus               (data/corpus/llm_evasion_corpus.csv) — optional

Outputs:
  reports/modsec_baseline_results.json
  reports/modsec_reproducibility_env.json  (WAF version fingerprint)

USAGE (from project root):
  python scripts/12_evaluate_modsec_baseline.py
  python scripts/12_evaluate_modsec_baseline.py --host localhost --port 8080
"""

import argparse
import importlib.util
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, confusion_matrix,
)

# ── Seed (Rule 2) ────────────────────────────────────────────────────────────
import random
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ── Paths (Rule 6) ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT, DATA_CORPUS  # noqa: E402
PROJECT_ROOT = _ROOT
DATA_DIR     = PROJECT_ROOT / "data" / "prepared"
REPORTS_DIR  = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MODSEC_OUTPUT  = REPORTS_DIR / "modsec_baseline_results.json"
REPRO_OUTPUT   = REPORTS_DIR / "modsec_reproducibility_env.json"
CORPUS_PATH    = DATA_CORPUS / "llm_evasion_corpus.csv"

# ── Load sibling modules ──────────────────────────────────────────────────────
def _load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_m04 = _load_mod("evasion_test_definitions",
                 Path(__file__).parent / "04_evasion_test_definitions.py")
EVASION_ATTACKS = _m04.EVASION_ATTACKS
HARD_BENIGN     = _m04.HARD_BENIGN


# ── HTTP helper ───────────────────────────────────────────────────────────────
def probe(payload: str, base_url: str, timeout: int = 10) -> int:
    """
    Fire the payload as a GET ?q= parameter.
    Returns the HTTP status code (403 = blocked, 200 = passed).
    Returns -1 on connection error.
    """
    import http.client
    encoded = urllib.parse.quote(payload, safe="")
    url = f"{base_url}?q={encoded}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "AI-GIS-Thesis-Eval/1.0")
    # KNOWN ISSUE (verified 2026-08-26 against owasp/modsecurity-crs:nginx,
    # PARANOIA=2, ANOMALY_INBOUND=5): sending no Accept header triggers CRS rule
    # 920300 "Request Missing an Accept Header", which on its own scores enough
    # to block ordinary benign text. Measured effect on data/eval benign rows:
    # specificity 0% with UA only, 29% once Accept/Accept-Language are sent.
    # Any specificity/false-positive figure produced by this script WITHOUT the
    # headers below is an artifact of the probe, not of ModSecurity.
    # app.py:MODSEC_HEADERS sends the browser-like set; align this before
    # re-running the baseline for Chapter 4.
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code          # 403 comes through here
    except (http.client.RemoteDisconnected, http.client.BadStatusLine,
            ConnectionResetError, ConnectionAbortedError, OSError):
        return 200             # Connection aborted/reset = no block = treat as passed
    except urllib.error.URLError as e:
        print(f"\n  [WARN] Connection error for payload: {payload[:60]}...\n"
              f"         {e}", file=sys.stderr)
        return -1



def check_modsec_alive(base_url: str) -> None:
    """Verify ModSecurity container is up. Raises RuntimeError if not."""
    import http.client
    try:
        req = urllib.request.Request(base_url, method="GET")
        req.add_header("User-Agent", "AI-GIS-Thesis-Eval/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            pass  # Any 2xx/3xx is fine
    except urllib.error.HTTPError:
        pass  # 403/404 means server is up
    except (http.client.RemoteDisconnected, http.client.BadStatusLine,
            ConnectionResetError):
        pass  # Nginx may drop bare root — server is still up
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"[ERROR] Cannot reach ModSecurity at {base_url}.\n"
            f"  Make sure the Docker container is running:\n"
            f"  docker run -d --name modsec-baseline -p 8080:80 "
            f"-e PARANOIA=2 -e ANOMALY_INBOUND=5 owasp/modsecurity-crs:nginx\n"
            f"  Details: {e}"
        )



def fingerprint_waf(base_url: str) -> dict:
    """Probe ModSecurity server header for version fingerprint."""
    info = {"url": base_url, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        req = urllib.request.Request(base_url, method="GET")
        req.add_header("User-Agent", "AI-GIS-Thesis-Eval/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            info["server"] = resp.headers.get("Server", "unknown")
            info["x_powered_by"] = resp.headers.get("X-Powered-By", "unknown")
    except urllib.error.HTTPError as e:
        info["server"] = e.headers.get("Server", "unknown")
    except Exception:
        info["server"] = "unknown"
    return info


def compute_metrics(y_true: list, y_pred: list, label: str) -> dict:
    """Compute all 5 required Chapter 3 metrics (binary predictions)."""
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    if len(np.unique(y_true)) < 2:
        auc = float("nan")
    else:
        auc = round(float(roc_auc_score(y_true, y_pred)), 4)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "label":      label,
        "f1":         round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "fpr":        round(float(fpr), 4),
        "auc_roc":    auc,
        "precision":  round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":     round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "note_auc": "ModSec is binary (no score). AUC-ROC = accuracy here.",
    }


def evaluate_list(payloads: list, labels: list, base_url: str,
                  tag: str, timeout: int) -> tuple[dict, list, list]:
    """
    Fire each payload at ModSec, collect predictions.
    Returns (metrics_dict, y_true, y_pred).
    """
    y_pred = []
    errors = 0
    for payload in payloads:
        code = probe(payload, base_url, timeout)
        if code == -1:
            errors += 1
            y_pred.append(0)   # Treat connection error as 'passed' (conservative)
        else:
            y_pred.append(1 if code == 403 else 0)

    if errors > 0:
        print(f"  [WARN] {errors} connection error(s) in '{tag}' — treated as benign.",
              file=sys.stderr)

    metrics = compute_metrics(labels, y_pred, tag)
    return metrics, labels, y_pred


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate ModSecurity WAF baseline (Chapter 3 compliant)."
    )
    parser.add_argument("--host", default="localhost",
                        help="ModSecurity container hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=8080,
                        help="ModSecurity container port (default: 8080)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}/"

    print("=" * 64)
    print("AI-GIS  |  12_evaluate_modsec_baseline.py")
    print("=" * 64)
    print(f"  WAF target : {base_url}")
    print(f"  Timeout    : {args.timeout}s per request")

    # ── Pre-flight ────────────────────────────────────────────────────────────
    print("\n[1/5] Checking ModSecurity availability ...")
    check_modsec_alive(base_url)
    print("  [OK] ModSecurity is reachable.")

    # ── Fingerprint WAF version ───────────────────────────────────────────────
    print("[2/5] Fingerprinting WAF environment ...")
    waf_info = fingerprint_waf(base_url)
    waf_info["image"]    = "owasp/modsecurity-crs:nginx"
    waf_info["paranoia"] = 2
    waf_info["anomaly_inbound_threshold"] = 5
    with open(REPRO_OUTPUT, "w") as f:
        json.dump(waf_info, f, indent=2)
    print(f"  Server header : {waf_info.get('server', 'unknown')}")
    print(f"  Repro env     : {REPRO_OUTPUT}")

    # ── Load internal test set payloads from honeypot log ────────────────────
    print("[3/5] Loading internal test set (from honeypot log) ...")

    # Load script 02 to access load_log and session_grouped_split
    _m02 = _load_mod("prepare_training_data",
                     Path(__file__).parent / "02_prepare_training_data.py")

    log_path = PROJECT_ROOT / "data" / "final_honeypot_dataset_v10.log"
    if not log_path.exists():
        # Fallback: search data/ for any .log file
        candidates = list((PROJECT_ROOT / "data").glob("*.log"))
        if not candidates:
            raise RuntimeError(
                f"[ERROR] Honeypot log not found at {log_path}.\n"
                f"  No .log files found in data/. Cannot reconstruct test set."
            )
        log_path = candidates[0]
        print(f"  [WARN] Using fallback log: {log_path.name}")

    print(f"  Loading {log_path.name} ...")
    full_df = _m02.load_log(log_path)
    _, _, test_df = _m02.session_grouped_split(full_df, seed=SEED)

    test_payloads = test_df["_payload_text"].tolist()
    test_labels   = test_df["label"].astype(int).tolist()
    print(f"  Rows: {len(test_payloads):,}  "
          f"(malicious={sum(test_labels):,}, benign={test_labels.count(0):,})")
    print(f"  Firing {len(test_payloads):,} HTTP requests — this may take a while ...")


    # ── Evaluate test set ─────────────────────────────────────────────────────
    t0 = time.time()
    test_metrics, _, _ = evaluate_list(
        test_payloads, test_labels, base_url, "clean_test_set", args.timeout
    )
    print(f"  Done in {time.time() - t0:.1f}s")

    # ── Evaluate evasion stress-test sets ─────────────────────────────────────
    print("[4/5] Evaluating evasion and hard-benign sets ...")
    evasion_labels   = [1] * len(EVASION_ATTACKS)
    hardbenign_labels = [0] * len(HARD_BENIGN)

    evasion_metrics, _, ev_pred = evaluate_list(
        EVASION_ATTACKS, evasion_labels, base_url, "evasion_attacks", args.timeout
    )
    hardbenign_metrics, _, hb_pred = evaluate_list(
        HARD_BENIGN, hardbenign_labels, base_url, "hard_benign", args.timeout
    )

    evasion_caught  = sum(ev_pred)
    hard_benign_fp  = sum(hb_pred)

    # ── LLM corpus (optional) ────────────────────────────────────────────────
    print("[5/5] LLM evasion corpus evaluation ...")
    llm_results = None
    if not CORPUS_PATH.exists():
        print(f"  [SKIP] LLM corpus not found at {CORPUS_PATH}")
        print("         Run 11_generate_evasion_corpus.py first.")
    else:
        llm_df = pd.read_csv(CORPUS_PATH)
        llm_payloads = llm_df["generated_payload"].fillna("").astype(str).tolist()
        llm_labels   = llm_df["label"].astype(int).tolist()
        llm_metrics, _, llm_pred = evaluate_list(
            llm_payloads, llm_labels, base_url, "llm_corpus", args.timeout
        )
        by_model = {}
        if "model" in llm_df.columns:
            for model_name, group in llm_df.groupby("model"):
                idxs = group.index.tolist()
                preds = [llm_pred[i] for i in idxs]
                by_model[model_name] = {
                    "caught": sum(preds),
                    "total":  len(preds),
                }
        llm_results = {
            "metrics":   llm_metrics,
            "caught":    int(sum(llm_pred)),
            "total":     int(len(llm_payloads)),
            "by_model":  by_model,
        }
        print(f"  LLM corpus: {llm_results['caught']}/{llm_results['total']} caught")

    # ── Assemble and export JSON ───────────────────────────────────────────────
    output = {
        "description": "ModSecurity + OWASP CRS baseline — Chapter 3 compliant",
        "waf": {
            "image":    waf_info["image"],
            "paranoia": waf_info["paranoia"],
            "anomaly_inbound_threshold": waf_info["anomaly_inbound_threshold"],
            "server_header": waf_info.get("server", "unknown"),
            "timestamp": waf_info["timestamp"],
        },
        "note": (
            "ModSecurity produces binary decisions only (HTTP 403 = block). "
            "AUC-ROC is computed on binary 0/1 predictions and equals accuracy."
        ),
        "clean_test_set":     test_metrics,
        "evasion_stress_test": {
            "total":   len(EVASION_ATTACKS),
            "caught":  int(evasion_caught),
            "metrics": evasion_metrics,
        },
        "hard_benign": {
            "total":  len(HARD_BENIGN),
            "fp":     int(hard_benign_fp),
            "metrics": hardbenign_metrics,
        },
        "llm_corpus": llm_results,
    }
    with open(MODSEC_OUTPUT, "w") as f:
        json.dump(output, f, indent=2)

    # ── Terminal summary (Rule 4) ─────────────────────────────────────────────
    m = test_metrics
    print("\n" + "=" * 64)
    print("STEP 12 — MODSEC BASELINE EVALUATION COMPLETE")
    print("=" * 64)
    print(f"  WAF              : ModSecurity + OWASP CRS v4 (PL2)")
    print(f"  Clean test F1    : {m['f1']:.4f}  |  FPR     : {m['fpr']:.4f}")
    print(f"  Clean test AUC*  : {m['auc_roc']:.4f}  |  Prec    : {m['precision']:.4f}")
    print(f"  Clean test Rec   : {m['recall']:.4f}")
    print(f"  Evasion caught   : {evasion_caught}/{len(EVASION_ATTACKS)}")
    print(f"  Hard-benign FP   : {hard_benign_fp}/{len(HARD_BENIGN)}")
    if llm_results:
        print(f"  LLM corpus       : {llm_results['caught']}/{llm_results['total']} caught")
    print(f"  * AUC = accuracy for binary WAF (no probability score)")
    print(f"  Report           : {MODSEC_OUTPUT}")
    print(f"  Repro env        : {REPRO_OUTPUT}")
    print("=" * 64)


if __name__ == "__main__":
    main()
