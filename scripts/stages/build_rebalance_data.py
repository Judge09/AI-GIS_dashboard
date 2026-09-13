#!/usr/bin/env python3
"""build_rebalance_data.py -- targeted training rows for two measured gaps.

Status audit (2026-09-13) found the training corpus had:
  * benign rows containing SQL vocabulary: 5 / 18,410 (0.03%)  -> FPR regression
  * low-symbol attacks (no quote/tag/comment): 1 / 18,184 (0.005%)

This appends two provenance-tagged buckets to honeypot_final.log so the model
can learn (a) SQL vocabulary is not itself an attack, and (b) word-shaped SQLi.

TRAINING DATA ONLY. No LLM output. No test-set attacks. Idempotent: rows carry
aug=True + provenance="rebalance", so re-running strips prior rebalance rows
first (same contract as build_training_augmentation.py).

Schema matches webids23_to_honeypot_log_v9.py: the payload goes in
request_body, so prepare_honeypot_for_training.payload_text() reads it verbatim.
"""
import argparse
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LOG = ROOT / "data" / "corpus" / "honeypot_final.log"

# Deliberately NO scanner UAs (sqlmap/nmap): those were a documented leak.
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "python-requests/2.31.0",
]

TABLES = ["users", "orders", "products", "customers", "invoices", "sessions",
          "transactions", "payments", "reviews", "categories", "inventory", "contacts"]
COLUMNS = ["id", "name", "email", "status", "created_at", "total", "price", "quantity",
           "title", "description", "rating", "sku", "amount", "role"]
DIRS = ["ASC", "DESC"]
STATES = ["active", "pending", "closed"]


def benign_param_query(rng):
    """Parameterized queries -- the exact shape that scored 0.995 as a false alarm."""
    t, c, c2 = rng.choice(TABLES), rng.choice(COLUMNS), rng.choice(COLUMNS)
    d = rng.choice(DIRS)
    state = rng.choice(STATES)
    c3 = rng.choice(COLUMNS)
    forms = [
        '{"query": "SELECT %s FROM %s WHERE %s = ?", "params": [%d], "safe": true}' % (c, t, c2, rng.randint(1, 9999)),
        '{"query": "SELECT * FROM %s ORDER BY %s %s LIMIT ?", "params": [%d]}' % (t, c, d, rng.randint(10, 100)),
        '{"sql": "UPDATE %s SET %s = ? WHERE id = ?", "bindings": ["%s", %d]}' % (t, c, state, rng.randint(1, 999)),
        "SELECT %s, %s FROM %s WHERE %s = $1 AND status = $2  -- prepared statement, bound params" % (c, c2, t, c2),
        '{"stmt": "INSERT INTO %s (%s, %s) VALUES (?, ?)", "params": ["%s", %d]}' % (t, c, c2, c3, rng.randint(1, 500)),
    ]
    return rng.choice(forms)


def benign_orm_log(rng):
    """ORM / framework log output: SQL-shaped, obviously machine-generated, harmless."""
    t, c = rng.choice(TABLES), rng.choice(COLUMNS)
    d = rng.choice(["asc", "desc"])
    forms = [
        '[2024-06-12 10:%02d:%02d] SELECT "%s".* FROM "%s" WHERE "%s"."id" = %d LIMIT 1' % (rng.randint(10, 59), rng.randint(10, 59), t, t, t, rng.randint(1, 999)),
        "Hibernate: select %s from %s where %s=? order by %s %s" % (c, t, c, c, d),
        'DEBUG django.db.backends: (0.001) SELECT COUNT(*) FROM "%s" WHERE "status" = %%s; args=(active,)' % t,
        "Query OK: SELECT %s FROM %s JOIN categories ON %s.category_id = categories.id" % (c, t, t),
        'ActiveRecord: %s Load (0.3ms)  SELECT "%s".* FROM "%s" ORDER BY created_at DESC' % (t.capitalize(), t, t),
    ]
    return rng.choice(forms)


def benign_sql_word_prose(rng):
    """UI text / English where SQL words appear as ordinary vocabulary."""
    forms = [
        "How do I select multiple items from the cart?",
        "Please select your country from the dropdown and click continue.",
        "Union Station departures: platform %d, %d:%02d service." % (rng.randint(1, 20), rng.randint(1, 12), rng.randint(10, 59)),
        "Order by phone or online; delivery in 3-5 business days.",
        "Drop off your package at any %s location before 5pm." % rng.choice(["UPS", "FedEx", "USPS"]),
        "The workshop covers how to select the right materials for your project.",
        "Sort by price, rating, or newest and the table view updates instantly.",
        "Where can I update my delivery address and payment details?",
        "Insert the card, select your language, and follow the on-screen steps.",
        "Members union meeting agenda includes budget and the %s review." % rng.choice(["Q3", "Q4"]),
    ]
    return rng.choice(forms)


def attack_lowsym(rng):
    """Word-shaped SQLi with no punctuation -- the class the detector misses (label=1)."""
    n1, n2 = rng.randint(1, 9999), rng.randint(1, 9999)
    col, tbl = rng.choice(COLUMNS), rng.choice(TABLES)
    forms = [
        "1 or %d = %d" % (n1, n1),
        "1 or %d like %d" % (n1, n1),
        "%d or %d between %d and %d" % (n1, n2, n2, n2),
        "admin where true",
        "%d or true" % n1,
        "1 union all select %s from %s" % (rng.choice(["null", "user", "version"]), tbl),
        "select all %s from %s" % (col, tbl),
        "%d or %s is not null" % (n1, col),
        "%d or length %s gt 0" % (n1, col),
        "drop table %s where %d" % (tbl, n1),
        "1 union select current user",
        "%d or ascii %s gt %d" % (n1, col, rng.randint(1, 127)),
        "select %s from %s where %d or %d = %d" % (col, tbl, n1, n2, n2),
        "%d and %s in select %s from %s" % (n1, col, col, tbl),
        "1 or exists select %s from %s" % (col, tbl),
        "%d or sleep %d" % (n1, rng.randint(1, 9)),
    ]
    return rng.choice(forms)


def make_row(text, label, kind, idx):
    return {
        "time": "2023-07-05T00:00:00Z",
        "source_ip": "10.1.%d.%d" % ((idx // 254) % 254, idx % 254 + 1),
        "host": "app.local:443",
        "method": "POST",
        "uri": "/submit",
        "user_agent": random.choice(UA_POOL),
        "request_body": text,
        "referer": "",
        "flow_uid": "rebal_%d" % idx,
        "dup_index": 0,
        "session_id": "rebal_sess_%d" % idx,
        "session_seq": 0,
        "label": int(label),
        "attack_family": "benign" if label == 0 else "lowsym_sqli",
        "obfuscated": False,
        "synthetic_duplicate": False,
        "forced_unique_nonce": "rebal%d" % idx,
        "aug": True,
        "provenance": "rebalance",
        "rebalance_kind": kind,
    }


def norm(s):
    return re.sub(r"\s+", "", s.lower())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-benign-sql", type=int, default=1000)
    ap.add_argument("--n-benign-orm", type=int, default=350)
    ap.add_argument("--n-benign-prose", type=int, default=250)
    ap.add_argument("--n-lowsym-attack", type=int, default=400)
    args = ap.parse_args()

    random.seed(args.seed)
    rng = random.Random(args.seed)

    lines = LOG.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip()
            and json.loads(ln).get("provenance") != "rebalance"]
    removed = len(lines) - len(kept)

    plan = [
        (args.n_benign_sql,    0, "param_sql",      benign_param_query),
        (args.n_benign_orm,    0, "orm_log",        benign_orm_log),
        (args.n_benign_prose,  0, "sql_word_prose", benign_sql_word_prose),
        (args.n_lowsym_attack, 1, "lowsym_attack",  attack_lowsym),
    ]
    seen, new_rows, idx = set(), [], 0
    for target, label, kind, gen in plan:
        made, tries = 0, 0
        while made < target and tries < target * 40:
            tries += 1
            text = gen(rng)
            k = norm(text)
            if k in seen:
                continue
            seen.add(k)
            new_rows.append(make_row(text, label, kind, idx))
            idx += 1
            made += 1
        if made < target:
            print("[warn] %s: only %d/%d unique (generator exhausted)" % (kind, made, target))

    with open(LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    nb = sum(1 for r in new_rows if r["label"] == 0)
    na = sum(1 for r in new_rows if r["label"] == 1)
    print("=" * 60)
    print("Removed prior rebalance rows : %d" % removed)
    print("New benign rows              : %d" % nb)
    print("New attack rows (low-symbol) : %d" % na)
    print("Log total now                : %d" % (len(kept) + len(new_rows)))
    print("=" * 60)


if __name__ == "__main__":
    main()
