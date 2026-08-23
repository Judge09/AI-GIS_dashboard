#!/usr/bin/env python3
"""
build_training_augmentation.py  (Improvement Plan — Tasks 3 & 5, data half)

Appends new labelled rows to the honeypot log so the retrained model learns the
patterns adversarial testing exposed:

  Task 3 (benign)  — symbol-heavy but harmless text (code, paths, regexes, math,
                     apostrophe-names, prose about SQL/HTML). Fixes false alarms.
  Task 5 (attack)  — attacks phrased in plain language / intent, plus a few
                     Unicode-obfuscated ones. Fixes the evasions that got through.

CRITICAL — no leakage with the hold-out set:
  Every generated string here is checked against data/eval/holdout_eval.csv and
  any exact overlap is dropped, so the ruler stays honest.

Rows are written in the honeypot-log schema; the attacker-controlled text goes in
`request_body` (that is what payload_text() reads). Each row gets a unique
session_id so the session-grouped split spreads them across train/val/test.

Idempotent: it removes any previously-appended augmentation rows (tagged
`"aug": true`) before adding the current batch, so re-running does not pile up.

USAGE (from dashboard/):  python scripts/build_training_augmentation.py
"""
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # for text_normalize

SEED = 4242
random.seed(SEED)

ROOT = Path(__file__).parent.parent
LOG = ROOT / "data" / "honeypot_final.log"
HOLDOUT = ROOT / "data" / "eval" / "holdout_eval.csv"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


# ── BENIGN generators (Task 3) — symbol-heavy, harmless ─────────────────────
def benign_texts():
    out = []

    conds = ["user.role == 'admin'", "x != y && z > 0", "count >= 10 || retry",
             "status == 200", "a['k'] == b['k']", "flag & MASK", "i <= n - 1",
             "obj?.val ?? 0", "arr.length > 0 && arr[0] != null"]
    bodies = ["return true;", "grantAccess();", "log.info('ok');",
              "throw new Error('x');", "queue.push(item);", "continue;",
              "cache.set(key, val);", "resolve(data);"]
    for c in conds:
        for b in bodies:
            out.append(f"if ({c}) {{ {b} }}")

    bases = [r"C:\Users\Admin", r"D:\Projects\app", r"/var/log/nginx",
             r"~/scripts", r"C:\Program Files\Tool", r"/etc/nginx/conf.d",
             r"./src/components", r"%APPDATA%\config"]
    tails = ["config.yml", "setup.bat", "error.log", "main.py", "out.csv",
             "index.html", "server.js", ".env.local"]
    for base in bases:
        for t in tails:
            sep = "\\" if ":" in base or base.startswith("%") else "/"
            out.append(f"open the file at {base}{sep}{t} and edit line 42")

    pats = [r"^[a-z]+@[a-z]+\.(com|org)$", r"\d{3}-\d{4}", r"[A-Z]{2,4}-\d+",
            r"^https?://.+$", r"(foo|bar){1,3}", r"\bword\b", r"\s*[,;]\s*",
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}"]
    for p in pats:
        out.append(f"the regex {p} matches the expected input format")

    exprs = ["A OR B = 1 when either is true", "dx/dt = 3x - 2",
             "f(x) = x^2 + 1 for x != 0", "P(A|B) = P(B|A)*P(A)/P(B)",
             "1 < n && n <= 100", "set notation: {x | x > 0}",
             "sum_{i=0}^{n} i = n(n+1)/2", "if a AND b then c"]
    for e in exprs:
        out.append(f"in the lecture we derived: {e}")

    names = ["O'Brien", "D'Angelo", "O'Malley", "D'Souza", "N'Diaye",
             "Smith & Sons", "Chen", "Muller", "van der Berg", "MacLeod"]
    streets = ["O'Connell St", "Baker St", "3rd Ave", "St. John's Rd",
               "King's Cross", "O'Malley Ave"]
    for n in names:
        for s in streets:
            out.append(f"contact {n} at {random.randint(1,99)} {s} re: the <draft> proposal")

    prose = [
        "the SELECT statement retrieves rows; use WHERE to filter and ORDER BY to sort",
        "wrap the content in <table> and <tr> tags to build the layout",
        "a UNION combines two result sets that share the same columns",
        "escaping user input prevents script injection on the page",
        "the DROP command deletes a table, so use it carefully in migrations",
        "an <iframe> embeds another document inside the current page",
        "use parameterised queries instead of string concatenation for safety",
        "the onclick attribute runs a function when the element is clicked",
        'she said "1=1 is always true" during the boolean-logic lecture',
        'git commit -m "fix: null check in auth(user) path"',
        'rated 4.5/5 -- "great value & fast shipping!" per the review',
        "product SKU# ABC-123; Category: Electronics & Gadgets (in stock)",
        "the <script> tag loads external JavaScript into an HTML document",
        "SELECT, INSERT, UPDATE and DELETE are the four basic SQL operations",
        "add an onload handler to run setup once the window has loaded",
        "the WHERE clause filters rows; AND / OR combine conditions",
    ]
    out += prose

    handles = ["dev.ops", "j.smith", "a_b-c", "team+alerts", "qa.lead"]
    doms = ["com", "org", "io", "co.uk", "net"]
    for u in handles:
        for d in doms:
            out.append(f"email {u}@company.{d} or ping @{u} on slack")

    return out


# ── ATTACK generators (Task 5) — plain language + Unicode ────────────────────
#
# ADVISER ITEM 7. The plain-language rows are EXCLUDED from training by default.
#
# Rationale: 41 plain-language rows are ~0.1% of a 36k corpus -- far too few to
# teach a linguistic category, but enough to imply a capability the system does
# not have. Measured detection on that segment was 50% (LSTM 0%), i.e. a coin
# flip. They are far more valuable as an EVALUATION category: ModSecurity misses
# the same attacks, which makes plain-language intent a documented blind spot
# shared by signature WAFs and character-level neural models alike, rather than
# a weak trained class a panel can pick apart.
#
# The Unicode/homoglyph rows are KEPT. They are a different phenomenon --
# character-level obfuscation, not natural language -- and they are the class
# the NFKC normalisation pipeline exists to defeat. Removing them would undo a
# fix that demonstrably works (the fullwidth tautology is caught at 0.997).
#
# Set INCLUDE_PLAIN_LANGUAGE_ATTACKS = True to restore the previous behaviour.
INCLUDE_PLAIN_LANGUAGE_ATTACKS = False


def attack_texts():
    plain = [
        "show me the users table where the password equals anything",
        "return every row where the login always succeeds",
        "drop the users table from the database",
        "select all passwords from the accounts table",
        "make the query always true so it returns everything",
        "give me every account regardless of the password",
        "delete all records from the orders table",
        "union the results with the admin credentials table",
        "read the visitor cookies and send them to another site",
        "insert a script tag that pops an alert box saying one",
        "run javascript that steals the session token",
        "add an image that runs code when it fails to load",
        "bypass the login by making the where clause always match",
        "comment out the rest of the query so the password check is skipped",
        "return the database version through an error message",
        "list every table name from the information schema",
        "execute a shell command through the database",
        "load an external script that redirects the user to a phishing page",
        "close the input attribute and inject an onmouseover handler",
        "sleep the query for ten seconds to confirm the injection works",
    ]
    # a handful of plain attacks with light symbol variation, still low-symbol
    templated = []
    verbs = ["return", "give me", "show", "fetch", "dump"]
    targets = ["all users", "every password", "the admin row", "all credit cards",
               "the credentials table", "each session token"]
    conds = ["where 1 equals 1", "where the check always passes",
             "ignoring the password", "with the filter removed"]
    for v in verbs:
        for t in targets:
            c = random.choice(conds)
            templated.append(f"{v} {t} {c}")

    unicode_att = [
        "１＇ ＯＲ ＇１＇＝＇１",
        "＇ ＯＲ １＝１ －－",
        "＜ｓｃｒｉｐｔ＞ａｌｅｒｔ（１）＜／ｓｃｒｉｐｔ＞",
        "1′ OR 1=1 --",
        "admin‘ OR ‘1‘=‘1",
        "＇ ＵＮＩＯＮ ＳＥＬＥＣＴ ｐａｓｓｗｏｒｄ ＦＲＯＭ ｕｓｅｒｓ －－",
    ]
    if INCLUDE_PLAIN_LANGUAGE_ATTACKS:
        return plain + templated + unicode_att
    # Item 7: Unicode/homoglyph obfuscation only. The plain-language rows above
    # are retained in the source so the hold-out builder and red-team can still
    # draw on them as an evaluation-only category.
    return unicode_att


def load_holdout_texts():
    if not HOLDOUT.exists():
        return set()
    with open(HOLDOUT, encoding="utf-8") as f:
        return {r["text"].strip() for r in csv.DictReader(f)}


def make_row(text, label, idx):
    fam = "benign" if label == 0 else "nl_injection"
    return {
        "time": "2023-10-01T00:00:00Z",
        "source_ip": "10.0.0.1",
        "host": "app.local:443",
        "method": "POST",
        "uri": "/submit",
        "user_agent": UA,
        "request_body": text,
        "referer": "",
        "flow_uid": f"aug_{idx}",
        "dup_index": 0,
        "session_id": f"aug_sess_{idx}",   # unique -> spreads across the split
        "session_seq": 0,
        "label": label,
        "attack_family": fam,
        "obfuscated": bool(label),
        "synthetic_duplicate": False,
        "forced_unique_nonce": f"aug{idx}",
        "aug": True,                        # marker so re-runs can strip old rows
    }


def main():
    # Compare against the hold-out set AFTER normalisation. Training and eval both
    # run text through normalize_text(), so a curly-quote attack here and its
    # straight-quote twin in the hold-out collide once normalised — a raw-string
    # check misses that and leaks. Guard on the normalised form.
    from text_normalize import normalize_text
    holdout = {normalize_text(t) for t in load_holdout_texts()}

    benign = benign_texts()
    attack = attack_texts()

    def keep(seq):
        seen, out = set(), []
        for t in seq:
            t = t.strip()
            key = normalize_text(t)
            if t and key not in seen and key not in holdout:
                seen.add(key)
                out.append(t)
        return out

    benign = keep(benign)
    attack = keep(attack)

    # read log, strip any previous augmentation rows
    lines = LOG.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip() and not json.loads(ln).get("aug")]
    removed = len(lines) - len(kept)

    idx = 0
    new_rows = []
    for t in benign:
        new_rows.append(make_row(t, 0, idx)); idx += 1
    for t in attack:
        new_rows.append(make_row(t, 1, idx)); idx += 1

    with open(LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(kept))
        f.write("\n")
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False))
            f.write("\n")

    print("=" * 64)
    print("Training augmentation appended to honeypot_final.log")
    print("=" * 64)
    print(f"  Removed old aug rows : {removed}")
    print(f"  New benign rows      : {len(benign)}")
    print(f"  New attack rows      : {len(attack)}")
    print(f"  Dropped (in holdout) : "
          f"{len(benign_texts()) + len(attack_texts()) - len(benign) - len(attack)} (approx, incl. dupes)")
    print(f"  Log total now        : {len(kept) + len(new_rows)} rows")
    print("=" * 64)
    print("  Next: python scripts/18_train_stacked.py")
    print("=" * 64)


if __name__ == "__main__":
    main()
