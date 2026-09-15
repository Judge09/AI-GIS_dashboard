#!/usr/bin/env python3
"""build_lstm_coverage.py -- training coverage for two attack families the LSTM
currently abstains on (scores ~0.00 while RF catches them ~0.9).

Diagnosis (2026-09-15): on paper_benchmark the stacked model's 21 false
negatives are attacks where RF fires but LSTM abstains. They cluster in two
families ABSENT from the training corpus (0 of each):
  1. data:text/html,<tag onEVENT=...>   XSS  (onbegin/onstart/ontoggle/onfocus/...)
  2. hex-literal + tab / inline-comment  SQLi (0x61...  '\tOr\t...  /*!*/)

This appends provenance-tagged TRAINING attacks (label=1) in those families so
the LSTM can learn the character sequences. NO LLM output. Idempotent: rows
carry provenance="lstm-coverage", stripped on re-run. v9 honeypot schema
(payload in request_body).

Revert: delete rows where provenance=="lstm-coverage" (re-run strips them), or
restore the corpus from git / a backup.
"""
import argparse
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LOG = ROOT / "data" / "corpus" / "honeypot_final.log"

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "python-requests/2.31.0",
]

# --- Family 1: data:text/html XSS with varied tags + event handlers ---------
DATA_TAGS = ["body", "svg", "img", "audio", "video", "details", "marquee",
             "math", "iframe", "object", "input", "select", "textarea", "style"]
DATA_EVENTS = ["onbegin", "onstart", "ontoggle", "onfocus", "onload", "onmouseover",
               "onerror", "onanimationstart", "onpointerenter", "onwheel", "oncanplay"]
XSS_ACTIONS = ["alert(1)", "alert(document.cookie)", "alert(document.domain)",
               "print()", "confirm(1)", "(alert)(1)", "window['ale'+'rt']`1`",
               "eval('ale'+'rt(1)')", "alert(String.fromCharCode(88,83,83))"]


def gen_data_xss(rng):
    tag = rng.choice(DATA_TAGS)
    ev = rng.choice(DATA_EVENTS)
    act = rng.choice(XSS_ACTIONS)
    autofocus = " autofocus" if ev == "onfocus" else ""
    return "data:text/html,<%s %s=%s%s>" % (tag, ev, act, autofocus)


# --- Family 2: hex-literal + tab / inline-comment SQLi ----------------------
SQL_COLS = ["role", "token", "id", "user", "pass", "session", "name"]
HEX_VALUES = ["0x61646d696e", "0x756e696f6e", "0x726f6f74", "0x31", "0x73656c656374"]
SEPS = ["\t", "/**/", "/*!*/", " ", "%09", "%0a"]
COMMENTS = ["--", "#", "-- ", "/*"]


def gen_hextab_sqli(rng):
    sep = rng.choice(SEPS)
    col = rng.choice(SQL_COLS)
    hexv = rng.choice(HEX_VALUES)
    cmt = rng.choice(COMMENTS)
    op = rng.choice(["Or", "OR", "oR", "and", "AND", "union select"])
    prefix = rng.choice(["1", "'", "`", "1'", "admin'", ")"])
    return "%s%s%s%s%s=%s%s" % (prefix, sep, op, sep, col, hexv, cmt)


def make_row(text, kind, idx):
    return {
        "time": "2023-07-05T00:00:00Z",
        "source_ip": "10.2.%d.%d" % ((idx // 254) % 254, idx % 254 + 1),
        "host": "app.local:443",
        "method": "POST",
        "uri": "/submit",
        "user_agent": random.choice(UA_POOL),
        "request_body": text,
        "referer": "",
        "flow_uid": "lcov_%d" % idx,
        "dup_index": 0,
        "session_id": "lcov_sess_%d" % idx,
        "session_seq": 0,
        "label": 1,
        "attack_family": "xss_data_uri" if kind == "data_xss" else "sqli_hex_ws",
        "obfuscated": True,
        "synthetic_duplicate": False,
        "forced_unique_nonce": "lcov%d" % idx,
        "aug": True,
        "provenance": "lstm-coverage",
        "coverage_kind": kind,
    }


def norm(s):
    return re.sub(r"\s+", "", s.lower())


def load_eval_keys():
    """Normalised payloads of every eval set -- generated rows matching ANY of
    these are dropped, so training never sees a test payload (leakage guard)."""
    import pandas as pd
    keys = set()
    eval_dir = ROOT / "data" / "eval"
    for csv in eval_dir.glob("*.csv"):
        try:
            d = pd.read_csv(csv)
            col = "text" if "text" in d.columns else d.columns[0]
            keys.update(norm(str(t)) for t in d[col])
        except Exception:
            pass
    return keys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-data-xss", type=int, default=500)
    ap.add_argument("--n-hextab-sqli", type=int, default=500)
    args = ap.parse_args()
    random.seed(args.seed)
    rng = random.Random(args.seed)

    lines = LOG.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip()
            and json.loads(ln).get("provenance") != "lstm-coverage"]
    removed = len(lines) - len(kept)

    eval_keys = load_eval_keys()  # leakage guard
    plan = [(args.n_data_xss, "data_xss", gen_data_xss),
            (args.n_hextab_sqli, "hextab_sqli", gen_hextab_sqli)]
    seen, new_rows, idx, dropped_leak = set(), [], 0, 0
    for target, kind, gen in plan:
        made, tries = 0, 0
        while made < target and tries < target * 60:
            tries += 1
            text = gen(rng)
            k = norm(text)
            if k in seen:
                continue
            if k in eval_keys:      # never train on an eval payload
                dropped_leak += 1
                continue
            seen.add(k)
            new_rows.append(make_row(text, kind, idx))
            idx += 1
            made += 1
        if made < target:
            print("[warn] %s: only %d/%d unique" % (kind, made, target))

    with open(LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("=" * 60)
    print("Removed prior lstm-coverage rows : %d" % removed)
    print("Dropped (would leak into eval)   : %d" % dropped_leak)
    print("New data:text/html XSS rows      : %d" % sum(1 for r in new_rows if r["coverage_kind"] == "data_xss"))
    print("New hex/tab SQLi rows            : %d" % sum(1 for r in new_rows if r["coverage_kind"] == "hextab_sqli"))
    print("Log total now                    : %d" % (len(kept) + len(new_rows)))
    print("=" * 60)


if __name__ == "__main__":
    main()
