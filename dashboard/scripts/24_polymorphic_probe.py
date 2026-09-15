#!/usr/bin/env python3
"""
24_polymorphic_probe.py

Polymorphic red-team: take a small set of base attacks and generate many
semantically-equivalent MUTATIONS of each, then measure how consistently the
detector catches every variant of the same underlying attack.

Polymorphism is the realistic threat: an attacker who is blocked does not give
up, they mutate. A detector can score 96% on a fixed set yet collapse when the
SAME attack is presented in 40 different skins. The metric that matters here is
not overall detection but PER-FAMILY consistency: if a family is caught 12/40
times, an attacker simply retries until a variant lands.

Mutation operators (all preserve the attack's function):
  - case randomisation (SeLeCt)
  - inline comment insertion (/**/ between tokens)
  - whitespace substitution (tab, newline, url-encoded)
  - equivalent-syntax swaps (OR->||, quotes ' <-> ")
  - numeric obfuscation (1=1 -> 5=5, 0x31=0x31)
  - encoding (url-encode individual chars)

Scored through the identical path app.py uses. Deterministic (seeded).
USAGE (from dashboard/):  python scripts/24_polymorphic_probe.py
Writes reports/polymorphic_probe.json.
"""
import json
import pickle
import random
import sys
import urllib.parse
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from evasion_resistance_check import engineer_rf_features   # noqa: E402
from build_rf_features_v2 import structural_features, SEMANTIC_META_COLS  # noqa: E402
from text_normalize import normalize_text                   # noqa: E402

SEED = 4242
random.seed(SEED)
N_VARIANTS = 40   # mutations generated per base attack


# ── base attacks: (name, template, type) ───────────────────────────────────
BASE_ATTACKS = [
    ("tautology",       "1' OR '1'='1",                       "sqli"),
    ("union_select",    "1' UNION SELECT username,password FROM users--", "sqli"),
    ("auth_bypass",     "admin'--",                           "sqli"),
    ("time_blind",      "1' AND SLEEP(5)--",                  "sqli"),
    ("stacked_query",   "1'; DROP TABLE users--",             "sqli"),
    ("script_tag",      "<script>alert(1)</script>",          "xss"),
    ("img_onerror",     "<img src=x onerror=alert(1)>",       "xss"),
    ("svg_onload",      "<svg onload=alert(1)>",              "xss"),
    ("javascript_uri",  "<a href=javascript:alert(1)>x</a>",  "xss"),
    ("body_onload",     "<body onload=alert(document.cookie)>", "xss"),
]


# ── mutation operators (function-preserving) ────────────────────────────────
def mut_case(s):
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)

def mut_comment(s):
    # insert /**/ at some spaces
    return s.replace(" ", "/**/", random.randint(1, s.count(" ") or 1)) if " " in s else s

def mut_whitespace(s):
    ws = random.choice(["\t", "\n", "%09", "%0a", "  ", "/**/"])
    return s.replace(" ", ws) if " " in s else s

def mut_quote_swap(s):
    return s.replace("'", '"') if random.random() < 0.5 else s

def mut_or_syntax(s):
    return s.replace(" OR ", " || ").replace(" or ", " || ")

def mut_numeric(s):
    n = random.choice(["2", "7", "99", "0x31", "5000"])
    return s.replace("1'='1", f"{n}'='{n}").replace("1=1", f"{n}={n}")

def mut_urlencode_some(s):
    out = []
    for c in s:
        if c in "<>'\"();= " and random.random() < 0.4:
            out.append(urllib.parse.quote(c))
        else:
            out.append(c)
    return "".join(out)

def mut_double_letters(s):
    # OR -> OoR style noise a WAF-bypass might use; here simple char doubling on keywords
    for kw in ["OR", "or", "AND", "and"]:
        if kw in s and random.random() < 0.5:
            s = s.replace(kw, kw[0] + kw[0].lower() + kw[1:], 1)
    return s

OPS = [mut_case, mut_comment, mut_whitespace, mut_quote_swap, mut_or_syntax,
       mut_numeric, mut_urlencode_some, mut_double_letters]


def mutate(base):
    """Apply a random subset of operators, in random order."""
    s = base
    k = random.randint(1, 4)
    for op in random.sample(OPS, k):
        s = op(s)
    return s


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


def score_batch(texts, rf, meta, vec, lstm, v2):
    norm = [normalize_text(t) for t in texts]
    st = pd.DataFrame([structural_features(t) for t in norm])
    ag = pd.DataFrame([engineer_rf_features(t, "GET") for t in norm])
    ng = pd.DataFrame(vec.transform(norm).toarray(),
                      columns=[f"ngram_{i}" for i in range(300)])
    X = pd.concat([ag.reset_index(drop=True), st.reset_index(drop=True),
                   ng.reset_index(drop=True)], axis=1)[v2]
    rf_p = rf.predict_proba(X)[:, 1]
    E = np.stack([ordinal_encode(t) for t in norm])
    ls_p = lstm.predict(E, verbose=0).flatten()
    sem_p = X[SEMANTIC_META_COLS].to_numpy()
    st_p = meta.predict_proba(np.column_stack([rf_p, ls_p, sem_p]))[:, 1]
    return rf_p, ls_p, st_p


def main():
    print("=" * 74)
    print(f"24_polymorphic_probe.py  —  {N_VARIANTS} mutations x {len(BASE_ATTACKS)} attacks")
    print("=" * 74)
    rf, meta, vec, lstm, v2 = load_models()

    families = []
    all_texts, index = [], []
    for name, tmpl, atype in BASE_ATTACKS:
        variants = {tmpl}                      # include the pristine base
        tries = 0
        while len(variants) < N_VARIANTS and tries < N_VARIANTS * 20:
            variants.add(mutate(tmpl)); tries += 1
        variants = list(variants)[:N_VARIANTS]
        for v in variants:
            all_texts.append(v); index.append(len(families))
        families.append({"name": name, "type": atype, "base": tmpl,
                         "variants": variants})

    rf_p, ls_p, st_p = score_batch(all_texts, rf, meta, vec, lstm, v2)

    # attach scores back to families
    ptr = 0
    for fam in families:
        n = len(fam["variants"])
        fam_rf = rf_p[ptr:ptr+n]; fam_ls = ls_p[ptr:ptr+n]; fam_st = st_p[ptr:ptr+n]
        ptr += n
        caught = int((fam_st >= 0.5).sum())
        fam["n"] = n
        fam["caught"] = caught
        fam["catch_rate"] = round(caught / n, 4)
        fam["mean_stacked"] = round(float(fam_st.mean()), 4)
        fam["min_stacked"] = round(float(fam_st.min()), 4)
        # keep the 5 lowest-scoring (best-evading) variants for the report
        order = np.argsort(fam_st)[:5]
        fam["worst_variants"] = [{"text": fam["variants"][i],
                                  "stacked": round(float(fam_st[i]), 4),
                                  "rf": round(float(fam_rf[i]), 4),
                                  "lstm": round(float(fam_ls[i]), 4)} for i in order]
        del fam["variants"]

    total = sum(f["n"] for f in families)
    caught = sum(f["caught"] for f in families)
    print(f"\nOverall: {caught}/{total} variants caught "
          f"({caught/total*100:.1f}%)\n")

    print(f"{'family':16s} {'type':5s} {'caught':>10s} {'rate':>7s} "
          f"{'mean':>7s} {'min':>7s}")
    print("-" * 60)
    for f in sorted(families, key=lambda x: x["catch_rate"]):
        print(f"{f['name']:16s} {f['type']:5s} {f['caught']:>6d}/{f['n']:<3d} "
              f"{f['catch_rate']*100:>6.1f}% {f['mean_stacked']:>7.3f} {f['min_stacked']:>7.3f}")

    # families where an attacker could reliably get through
    leaky = [f for f in families if f["catch_rate"] < 1.0]
    print(f"\n{len(leaky)}/{len(families)} attack families have at least one "
          f"evading variant.")
    print("\nMost-evadable families (lowest catch rate):")
    for f in sorted(families, key=lambda x: x["catch_rate"])[:5]:
        if f["catch_rate"] >= 1.0:
            continue
        w = f["worst_variants"][0]
        print(f"  {f['name']:16s} caught {f['caught']}/{f['n']}  "
              f"— e.g. stacked={w['stacked']:.3f}  {w['text'][:44]!r}")

    out = ROOT / "reports" / "polymorphic_probe.json"
    out.write_text(json.dumps({"n_variants": N_VARIANTS,
                               "total": total, "caught": caught,
                               "overall_catch_rate": round(caught/total, 4),
                               "families": families}, indent=2))
    print(f"\nJSON written to: {out}")
    print("=" * 74)


if __name__ == "__main__":
    main()


# ── AGGRESSIVE tier — mutation CLASSES the model is known to be weak against ──
# The syntactic operators above stay inside the training distribution and the
# model catches them all. These operators leave it: semantic rewrites (low
# symbol density) and pipeline attacks (past the 200-char window). This is the
# honest polymorphic test -- an attacker uses THESE, not just case-flipping.
def run_aggressive():
    import numpy as np, pandas as pd, pickle, json
    from tensorflow import keras
    rf, meta, vec, lstm, v2 = load_models()

    AGGRESSIVE = {
        "semantic_sqli": [
            "1 or 1 between 1 and 1", "1 or 2 like 2", "1 or 'a' greatest 'a'",
            "give me all rows where the password is never checked",
            "return every account ignoring the login condition",
            "1 or 5000=5000", "1 or 0x41=0x41", "admin where true",
            "1 union all select null null from users",
            "select everything from the accounts table please",
        ],
        "semantic_xss": [
            "run a script that reads the cookie and sends it away",
            "make an image tag whose error handler pops an alert",
            "load javascript from an external site when the page opens",
            "String['fromCharCode'](60,115,99,114,105,112,116,62)",
            "top['ale'+'rt'](1)",
            "window['ev'+'al']('alert(1)')",
            "set an onmouseover handler that steals the session",
            "embed an iframe pointing at a javascript url",
        ],
        "past_window": [
            "Thank you for contacting support regarding your recent order. "
            "Our team has reviewed the details you provided and we appreciate "
            "your patience while we processed this request for you today. "
            + inj for inj in ["' OR '1'='1", "<script>alert(1)</script>",
                              "'; DROP TABLE users--", "<img src=x onerror=alert(1)>"]
        ],
    }

    print("\n" + "=" * 74)
    print("AGGRESSIVE TIER — mutation classes outside the training distribution")
    print("=" * 74)
    out = {}
    for fam, payloads in AGGRESSIVE.items():
        norm = [normalize_text(t) for t in payloads]
        st = pd.DataFrame([structural_features(t) for t in norm])
        ag = pd.DataFrame([engineer_rf_features(t, "GET") for t in norm])
        ng = pd.DataFrame(vec.transform(norm).toarray(),
                          columns=[f"ngram_{i}" for i in range(300)])
        X = pd.concat([ag.reset_index(drop=True), st.reset_index(drop=True),
                       ng.reset_index(drop=True)], axis=1)[v2]
        rf_p = rf.predict_proba(X)[:, 1]
        E = np.stack([ordinal_encode(t) for t in norm])
        ls_p = lstm.predict(E, verbose=0).flatten()
        sem_p = X[SEMANTIC_META_COLS].to_numpy()
        st_p = meta.predict_proba(np.column_stack([rf_p, ls_p, sem_p]))[:, 1]
        caught = int((st_p >= 0.5).sum())
        out[fam] = {"n": len(payloads), "caught": caught,
                    "catch_rate": round(caught/len(payloads), 4),
                    "evaded": [{"text": payloads[i], "stacked": round(float(st_p[i]), 4)}
                               for i in range(len(payloads)) if st_p[i] < 0.5]}
        print(f"\n{fam}: {caught}/{len(payloads)} caught "
              f"({caught/len(payloads)*100:.0f}%)")
        for e in out[fam]["evaded"]:
            print(f"    EVADED stacked={e['stacked']:.3f}  {e['text'][:56]!r}")

    tot = sum(v["n"] for v in out.values())
    cau = sum(v["caught"] for v in out.values())
    print(f"\nAggressive tier overall: {cau}/{tot} caught ({cau/tot*100:.0f}%)")
    p = ROOT / "reports" / "polymorphic_aggressive.json"
    p.write_text(json.dumps({"total": tot, "caught": cau,
                             "catch_rate": round(cau/tot, 4), "families": out}, indent=2))
    print(f"JSON written to: {p}")


if __name__ == "__main__" and "--aggressive" in sys.argv:
    run_aggressive()
