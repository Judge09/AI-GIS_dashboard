# Honeypot Corpus — Generation Scripts and Data

This bundle contains the honeypot dataset generator, the scripts that turn its
output into model-ready features, and the resulting CSV files, so the dataset
can be independently inspected and regenerated.

Every script has a **PLAIN-ENGLISH SUMMARY** comment block at the top
explaining, in non-specialist terms, what it is for and how to run it.

---

## 1. What the dataset is (and what is real vs. synthetic)

The corpus is built from **WEB-IDS23**, a public network-capture dataset.

- **Real** — the flow metadata: timestamps, source IPs, http/https service,
  and the recorded ground-truth label of which flows were attacks.
- **Synthetic** — the payload text itself (the actual SQL-injection or XSS
  string in the request).

This split is deliberate and is stated as a limitation of the work. WEB-IDS23
records *that* a flow was an SQL injection but does not include the attack text
a payload-inspecting model needs to read. The generator therefore keeps each
real flow and synthesises a payload matching that flow's recorded attack type.

---

## 2. The pipeline

```
WEB-IDS23 source CSVs  (public dataset, 5 files, ~284 MB — not in this bundle)
        |
        |  scripts/webids23_to_honeypot_log_v9.py      <-- THE GENERATOR
        v
honeypot_final.log     (JSON-lines: one HTTP request per line, labelled)
        |
        +--> scripts/prepare_honeypot_for_training.py  (train/val/test splits)
        |
        +--> scripts/build_rf_features_v2.py           <-- produced the rf_*_v2.csv here
                 v
        data/rf_train_v2.csv, rf_val_v2.csv, rf_test_v2.csv
```

`scripts/run_honeypot.py` is a wrapper that runs the generator with an audit
trail (hashes, row counts, timings). Run it with **no arguments** to audit the
existing corpus read-only; `--generate` rebuilds and overwrites it.

---

## 3. Files in this bundle

### `scripts/`
| File | Purpose |
|---|---|
| `webids23_to_honeypot_log_v9.py` | **The honeypot generator.** WEB-IDS23 CSVs → labelled honeypot log. |
| `run_honeypot.py` | Audited runner around the generator (read-only by default). |
| `prepare_honeypot_for_training.py` | Log → train/validation/test splits, in both LSTM and Random-Forest formats. |
| `build_rf_features_v2.py` | Improved Random-Forest features; produced the `rf_*_v2.csv` files here. |
| `text_normalize.py` | Shared Unicode-normalisation helper (closes the look-alike-character evasion). |

### `data/`
| File | Rows | Description |
|---|---|---|
| `honeypot_corpus.csv` | 36,792 | **Start here.** The generated corpus in plain readable CSV — the same records as `honeypot_final.log`, converted from JSON-lines for easy viewing in Excel. |
| `rf_train_v2.csv` | 25,558 | Random-Forest training features + label. |
| `rf_val_v2.csv` | 5,621 | Validation split. |
| `rf_test_v2.csv` | 5,613 | Test split (used once, for the final reported figures). |

**Note on the `rf_*_v2.csv` files:** the first ~19 columns are readable
engineered features (`payload_len`, `entropy`, `quote_count`,
`has_tautology_pattern`, …). The `ngram_0` … `ngram_299` columns are learned
character n-gram values — machine input, not meant to be read by eye. To
inspect the actual data, use `honeypot_corpus.csv`.

### `MANIFEST.json`
SHA-256 hash and byte size of every file above, plus the corpus statistics
below — so the contents can be checked for tampering or accidental change.

---

## 4. Corpus composition (verified, not claimed)

**36,792 rows total** — 18,182 attack (label 1), 18,610 benign (label 0).
Near-balanced by design, so accuracy is not inflated by class skew.

| Attack family | Rows | | Attack family | Rows |
|---|---|---|---|---|
| stored (XSS) | 3,773 | | union_based (SQLi) | 1,223 |
| reflected (XSS) | 2,772 | | time_based_blind | 1,261 |
| dom_based (XSS) | 2,546 | | auth_bypass | 1,169 |
| boolean_blind | 1,498 | | error_based | 1,113 |
| tautology | 1,484 | | **benign** | **18,610** |
| stacked_query | 1,343 | | | |

Other measured properties:

- **Unique `uri` + `request_body` pairs: 36,792 of 36,792 — zero duplicates.**
  This is the important one. An earlier version of the generator repeated the
  same payload up to 39 times, which lets a model score well by memorising
  rather than learning. v9 enforces uniqueness with a run-wide seen-set and
  retries on collision.
- **Obfuscated payloads: 12,906** (~35%) — deliberately disguised via
  URL-encoding, comment-splitting, case-mixing, so the model cannot rely on
  matching clean textbook attack strings.
- **`forced_unique_nonce`: 605** — rows where the uniqueness retry loop
  exhausted its attempts and appended a short random nonce as a guaranteed
  fallback. Flagged in the data so the frequency is auditable rather than
  hidden.
- **`synthetic_duplicate`: 0** — no WEB-IDS23 source row was oversampled.

---

## 5. Reproducing the corpus

The five WEB-IDS23 source CSVs are not included here (~284 MB). Place them in
`data/prepared/` as:

```
web-ids23_sql_injection_http (3).csv
web-ids23_sql_injection_https (2).csv
web-ids23_xss_http (1).csv
web-ids23_xss_https (1).csv
web-ids23_benign (1).csv
```

Then:

```bash
# 1. generate the corpus
python scripts/webids23_to_honeypot_log_v9.py \
    --sqli-http  "data/prepared/web-ids23_sql_injection_http (3).csv" \
    --sqli-https "data/prepared/web-ids23_sql_injection_https (2).csv" \
    --xss-http   "data/prepared/web-ids23_xss_http (1).csv" \
    --xss-https  "data/prepared/web-ids23_xss_https (1).csv" \
    --benign     "data/prepared/web-ids23_benign (1).csv" \
    --seed 42 -o data/honeypot_final.log

# 2. build the Random-Forest feature CSVs
python scripts/build_rf_features_v2.py \
    --input data/honeypot_final.log --outdir data/prepared --seed 42
```

`--seed 42` is what makes this reproducible: the same inputs and the same seed
produce the same corpus every time.

---

## 6. One caveat on row counts

The shipped `honeypot_corpus.csv` includes **428 rows** carrying a
`TEMP_benign_augmentation` flag. These were added by a separate benign-text
augmentation step *after* generation — they are not output of the generator
itself. They are flagged in the `TEMP_benign_augmentation` and `aug_category`
columns, so they can be filtered out if only the pure generator output is
wanted. Re-running section 5 from scratch yields the corpus without them.
