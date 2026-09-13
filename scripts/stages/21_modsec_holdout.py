#!/usr/bin/env python3
"""
21_modsec_holdout.py  (Adviser item 4: SOP1 / RQ3 / RO3)

LIKE-FOR-LIKE ModSecurity comparison.

The earlier baseline fired ~2,733 clean requests through ModSecurity and
compared its FPR against the ensemble's FPR on a DIFFERENT 198-row benign set.
That is an order-of-magnitude comparison, not a controlled one.

This script fires the EXACT SAME 396-row hold-out set (198 attack / 198 benign)
through ModSecurity + OWASP CRS that the ensemble is scored on, so every number
in the comparison comes from identical inputs.

ModSecurity returns a binary decision (200 OK vs 403 Forbidden), so it has no
probability score: AUC is undefined and is reported as null rather than faked.

Each payload is sent BOTH as a query-string GET and as a POST body, and the
request counts as "blocked" if either is rejected -- CRS inspects both
locations, and the hold-out text is location-agnostic.

PREREQUISITES:
  docker network create modsec-net && docker compose up -d
  (Docker Desktop must be running; its bin must be on PATH.)

USAGE (from dashboard/):
  python scripts/21_modsec_holdout.py --host localhost --port 8080
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
# CRS at PL2 scores the CLIENT, not just the payload. Python-urllib's default
# User-Agent trips rule 913101 (scripting client, +5) and the absent Accept
# header trips 920300 (+2) -> anomaly 7 >= 5 -> every request is blocked before
# the payload is ever evaluated. Sending ordinary browser headers isolates the
# WAF's judgement of the PAYLOAD, which is what the comparison is about.
BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
}


def _open(req, timeout):
    for k, v in BROWSER_HEADERS.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:        # noqa: BLE001
        return -1


def probe(url_base: str, timeout: float = 10.0) -> bool:
    try:
        urllib.request.urlopen(url_base, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True          # any HTTP response means the WAF is up
    except Exception:        # noqa: BLE001
        return False


def send_get(base: str, payload: str, timeout: float = 10.0) -> int:
    url = f"{base}/?q={urllib.parse.quote(payload, safe='')}"
    return _open(urllib.request.Request(url, method="GET"), timeout)


def send_post(base: str, payload: str, timeout: float = 10.0) -> int:
    data = urllib.parse.urlencode({"q": payload}).encode()
    req = urllib.request.Request(base + "/", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    return _open(req, timeout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--csv", default=str(ROOT / "data/eval/holdout_eval.csv"))
    ap.add_argument("--out", default=str(ROOT / "reports/modsec_holdout.json"))
    args = ap.parse_args()

    base = f"http://{args.host}:{args.port}"
    print("=" * 70)
    print("21_modsec_holdout.py  -  like-for-like ModSecurity comparison")
    print("=" * 70)
    print(f"  target : {base}")

    # sanity: a plainly benign string must NOT be blocked, or the harness
    # itself is being scored rather than the payloads.
    if not probe(base):
        print(f"\n  ERROR: no HTTP response from {base}")
        print("  Start the WAF first:")
        print("    docker network create modsec-net")
        print("    docker compose up -d")
        sys.exit(2)
    print("  WAF is reachable.\n")

    df = pd.read_csv(args.csv)
    df["label"] = df["label"].astype(int)
    print(f"  hold-out: {len(df)} rows "
          f"({int((df['label'] == 1).sum())} attack / "
          f"{int((df['label'] == 0).sum())} benign)\n")

    blocked = []
    for i, (text, label) in enumerate(zip(df["text"], df["label"]), 1):
        g = send_get(base, str(text))
        p = send_post(base, str(text))
        is_blocked = (g == 403) or (p == 403)
        blocked.append(is_blocked)
        if i % 50 == 0:
            print(f"    {i}/{len(df)} sent ...", flush=True)

    df["blocked"] = blocked

    atk = df[df["label"] == 1]
    ben = df[df["label"] == 0]
    tp = int(atk["blocked"].sum())
    fn = int(len(atk) - tp)
    fp = int(ben["blocked"].sum())
    tn = int(len(ben) - fp)

    det = tp / len(atk) if len(atk) else None
    fpr = fp / len(ben) if len(ben) else None
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = det or 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

    res = {
        "dataset": "holdout_eval.csv (SAME 396 rows the ensemble is scored on)",
        "n": int(len(df)),
        "attacks": int(len(atk)), "benign": int(len(ben)),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_rate": round(det, 4) if det is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
        "precision": round(prec, 4), "f1": round(f1, 4),
        "auc": None,
        "auc_note": ("ModSecurity emits a binary block decision, not a score; "
                     "AUC is undefined and deliberately not fabricated."),
        "missed_attacks": atk[~atk["blocked"]]["text"].head(25).tolist(),
        "false_alarms": ben[ben["blocked"]]["text"].head(25).tolist(),
    }

    print(f"\n{'=' * 70}\nMODSECURITY + OWASP CRS on the 396-row hold-out\n{'=' * 70}")
    print(f"  detection rate : {det * 100:.1f}%  ({tp}/{len(atk)})")
    print(f"  false-pos rate : {fpr * 100:.1f}%  ({fp}/{len(ben)})")
    print(f"  precision      : {prec:.4f}")
    print(f"  F1             : {f1:.4f}")

    Path(args.out).write_text(json.dumps(res, indent=2))
    print(f"\n  JSON written to: {args.out}")
    print("=" * 70)


if __name__ == "__main__":
    main()
