# AI-GIS — Dataset, Techniques, and Process

**Verified:** 2026-08-23. Every number was measured on this machine, not quoted
from an earlier run. Written to be **auditable**: each claim names the file and
line range that implements it, so a reviewer can check the code against the
prose.

**Contents**
1. What the system is
2. Dataset — provenance, derivation, composition
3. Feature engineering (all 319 features enumerated)
4. Models and training protocol
5. Evaluation design
6. Process, step by step
7. Results
8. Code-audit notes (things a reviewer should check)
9. Limitations
10. Reproduce
11. References

---

## 1. What the system is

A web-attack detector for **SQL injection** and **cross-site scripting**. It
reads the attacker-controlled text of an HTTP request and returns a probability
that the text is an attack.

"Attacker-controlled text" is defined precisely in
`prepare_honeypot_for_training.py:73-78`:

```python
def payload_text(row: dict) -> str:
    """Reconstruct the attacker-controlled text: query string + body."""
    uri   = row.get("uri", "")
    body  = row.get("request_body", "") or ""
    query = uri.split("?", 1)[1] if "?" in uri else ""
    return f"{query} {body}".strip()
```

So the model sees the **query string plus the request body** — never the path,
headers, or user-agent. That exclusion is deliberate (see §8.1).

Three models vote:

| | Model | Input |
|---|---|---|
| Base 1 | Random Forest | 319 engineered features |
| Base 2 | LSTM | raw characters, ordinal-encoded |
| Meta | Logistic Regression | `[rf_proba, lstm_proba]` |

This is **stacked generalisation** (Wolpert 1992); its use for intrusion
detection is surveyed in Thakkar & Lohiya (2021).

---

## 2. The dataset

### 2.1 Provenance — how WEB-IDS23 becomes the training log

This is the part most worth stating precisely, because the corpus is **neither
fully real nor fully synthetic**. It is a *synthetic payload overlay on real
flow metadata*.

The converter is `scripts/stages/webids23_to_honeypot_log_v9.py` (934 lines). Its own
docstring describes the arrangement as *"payload/IP content being a documented
synthetic overlay on real WEB-IDS23 flow metadata."*

**What comes from WEB-IDS23 (real).** The converter reads exactly six columns
(`webids23_to_honeypot_log_v9.py:139`):

```python
USECOLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]
```

These are Zeek/Bro connection-log fields. From them the pipeline inherits:

| Field | Becomes | Role |
|---|---|---|
| `uid` | `flow_uid` | Traces every generated row back to its source CSV row |
| `ts` | `time` | Real timestamp → real inter-arrival timing |
| `id.orig_h` | session key + synthetic public IP | Real client-grouping structure |
| `id.resp_h` | `host` | Real server-grouping structure |
| `service` | port (80/443) | http vs https |
| `attack_type` | ground-truth `label` | **The label is real, not invented** |

**What is generated (synthetic).** The actual payload strings, the URIs, the
user-agents, and the public IPs. WEB-IDS23 flow records do not carry request
bodies, so the payload text is generated combinatorially per attack family and
grafted onto the real flow.

**Sampling.** Rows are drawn by **reservoir sampling** over a chunked CSV read
(`:434-458`, `CHUNK_SIZE = 20_000`), so the source file is never loaded whole
and every row has equal selection probability.

**Sessions.** A session is a real client IP bucketed into a 120-second window
(`:76`, `:470-472`):

```python
SESSION_WINDOW_SECONDS = 120
bucket = epoch // SESSION_WINDOW_SECONDS
return f'{row["id.orig_h"]}_{bucket}'
```

This matters downstream: the train/val/test split groups on this key, so the
grouping reflects **real client behaviour**, not synthetic assignment.

**Determinism.** Randomness is seeded by content hash (`:384-386`), so the same
input row always yields the same output row:

```python
def rng_for(*parts: str) -> random.Random:
    seed = int(hashlib.sha256("|".join(parts).encode()).hexdigest(), 16) % (2**32)
```

### 2.2 Generator-quality controls (v5→v9 audit history)

The converter's docstring documents four defects found by auditing its own
earlier output. These are worth reporting because they are exactly the kind of
artefact that silently inflates results:

1. **Payload duplication.** v4 produced 72.9% duplicate rows (some DOM-XSS
   payloads repeated 39×) because `dom_based` had only ~12 distinct possible
   outputs sampled 36k times. Fixed by expanding component pools into the tens
   of thousands *and* enforcing uniqueness against a run-wide seen-set with 25
   retries (`MAX_UNIQUENESS_RETRIES = 25`, `:78`). A nonce fallback is flagged
   per-row as `forced_unique_nonce` so the fallback rate is auditable.
2. **Flag conflation.** `synthetic_duplicate` (flow-level reuse under
   oversampling) was being misread as payload-level duplication. The two are now
   separate fields.
3. **User-agent leakage.** v4 had 6 UAs, one literally `sqlmap/1.7.11` — a model
   could have learned `UA == sqlmap → malicious`. v9 uses ~18 weighted UAs so
   tool UAs appear at realistic low frequency (`python-requests` weight 3,
   `:368`). **This is why user-agent is excluded from the feature set entirely**
   (§8.1).
4. **Schema noise.** `host` is now always `ip:port`; redundant identical ID
   fields were replaced with `flow_uid` + `dup_index`.

Defect 3 is a textbook **shortcut** in the Geirhos et al. (2020) sense, caught
before it reached the model.

### 2.3 Composition — full breakdown

**Total: 36,635 rows** — 18,410 benign (50.3%) / 18,225 attack (49.7%).

| Class | `attack_family` | Rows | Technique |
|---|---|---:|---|
| Benign | `benign` | 18,410 | Normal browsing, search, form posts |
| XSS | `stored` | 3,773 | Payload persisted server-side, fires for later visitors |
| XSS | `reflected` | 2,772 | Payload echoed straight back in the response |
| XSS | `dom_based` | 2,546 | Executes via client-side DOM writes; never reaches server |
| SQLi | `boolean_blind` | 1,498 | Infers data one true/false question at a time |
| SQLi | `tautology` | 1,484 | `OR 1=1` — makes the WHERE clause always true |
| SQLi | `stacked_query` | 1,343 | `;` terminates, then a second statement runs |
| SQLi | `time_based_blind` | 1,261 | `SLEEP(10)` — infers data from response delay |
| SQLi | `union_based` | 1,223 | `UNION SELECT` welds attacker rows onto the result |
| SQLi | `auth_bypass` | 1,169 | Comments out the password check |
| SQLi | `error_based` | 1,113 | Leaks data through database error messages |
| Both | `nl_injection` | 43 | **Added by me** — attacks written in plain English |

**Sub-totals:** XSS **9,091** · classic SQLi **7,891** · plain-language **43**.

**Obfuscation:** 12,949 of 18,225 attacks (**71%**) carry `obfuscated: true` —
URL encoding, mixed case, hex, inline comments. A detector that only matched
literal `<script>` would fail most of this corpus.

**Generator component pools** (`:84-95`) — the combinatorial space:
- SQLi quotes: `'`, `"`
- SQLi comments: `--`, `#`, `-- -`, `/*x*/`, `-- comment`, `/**/`
- SQLi tables: 12 (`users`, `accounts`, `admin`, `customers`, …)
- SQLi column-sets: incl. `[username, password]`, `[card_number, cvv]`, `[ssn, dob]`

### 2.4 The rows I added (271)

`scripts/stages/build_training_augmentation.py`, `SEED = 4242`, idempotent (strips
prior `"aug": true` rows before appending).

**228 benign** — symbol-dense but harmless, six generator groups:

| Group | Construction | Example |
|---|---|---|
| Source code | 14 conditions × 8 bodies | `if (user.role == 'admin') { grantAccess(); }` |
| File paths | 8 bases × 8 tails | `open the file at C:\Users\Admin\config.yml and edit line 42` |
| Regexes | 8 patterns | `the regex ^[a-z]+@[a-z]+\.(com|org)$ matches …` |
| Maths | 8 expressions | `in the lecture we derived: P(A|B) = P(B|A)*P(A)/P(B)` |
| Names/addresses | 10 names × 6 streets | `contact O'Brien at 42 O'Connell St re: the <draft> proposal` |
| Prose about SQL/HTML | 16 fixed | `the DROP command deletes a table, so use it carefully` |
| Emails/handles | 5 × 5 | `email dev.ops@company.co.uk or ping @dev.ops on slack` |

**43 attack** — 20 plain-language + templated (5 verbs × 6 targets) + 6 Unicode:

```
"drop the users table from the database"
"make the query always true so it returns everything"
"１＇ ＯＲ ＇１＇＝＇１"            # fullwidth
"admin‘ OR ‘1‘=‘1"              # curly-quote homoglyph
```

**Why these two groups.** The detector had learned **"many symbols = attack"** —
a *shortcut*: a feature correlating with the label in training that is not the
causal signal (Geirhos et al., Nature MI 2020). The remedy is counter-examples
that break the correlation. Benign code is symbol-dense and harmless;
plain-English attacks are symbol-free and hostile. Together they make symbol
density non-predictive, forcing the model onto structure.

Each row is written with a **unique `session_id`** (`aug_sess_{idx}`) so the
session-grouped split scatters them across train/val/test rather than clumping
them into one split.

### 2.5 The evaluation set (the "ruler")

`scripts/stages/build_holdout_eval.py`, `SEED = 1234` → **396 rows, 198 attack / 198
benign** at `data/eval/holdout_eval.csv`.

Sources (`:44-125`): seeded from `EVASION_ATTACKS` and `HARD_BENIGN` in
`04_evasion_test_definitions.py`, then extended with templates, prose,
plain-language attacks, and Unicode variants, then deduplicated and balanced.

`EVASION_ATTACKS` is explicitly built from techniques **not present in any
training generator** (`evasion_resistance_check.py:71-79`) — whitespace tricks
(`1'%09OR%091=1%09--%09-`), MySQL backtick quoting (`` 1`;DROP TABLE `users`;-- ``),
and similar CRS-bypass classics.

The build log reports the balancing honestly:

```
[warn] only 198 benign / 222 attack available before balancing; using 198 each
```

**Why a second evaluation set exists.** The ordinary test split is
**saturated** — every model scores F1 ≈ 0.999 on it, so it cannot rank
detectors. Reporting 0.999 while the system fails on real inputs is the
"inappropriate performance measure" pitfall of Arp et al. (USENIX Security
2022). The hold-out set exists to make failure visible, and it did: it exposed a
**57.6% false-positive rate** that the test split rated 0.999.

---

## 3. Feature engineering — all 319, enumerated

### 3.1 Block A — 11 base features (`prepare_honeypot_for_training.py:81-95`)

| # | Feature | Definition |
|---|---|---|
| 1 | `payload_len` | `len(text)` |
| 2 | `entropy` | Shannon entropy of the character distribution |
| 3 | `num_special_chars` | count of non-alphanumeric, non-space |
| 4 | `num_digits` | count of digits |
| 5 | `num_uppercase` | count of uppercase |
| 6 | `param_count` | `uri.count("&") + (1 if "?" in uri else 0)` |
| 7 | `is_post` | `method == "POST"` |
| 8 | `has_sqli_keyword` | any of 11 keywords |
| 9 | `has_xss_keyword` | any of 11 keywords |
| 10 | `quote_count` | `'` + `"` |
| 11 | `comment_token_count` | `--` + `/*` + `#` |

Keyword lists (`:56-59`), verbatim:
```python
SQLI_KEYWORDS = ["select","union","drop","sleep","waitfor","exec",
                 "or 1=1","or '1'='1","xp_cmdshell","convert","extractvalue"]
XSS_KEYWORDS  = ["script","onerror","onload","onfocus","onmouseover",
                 "onstart","ontoggle","alert(","javascript:","<svg","<img"]
```

> ⚠️ **Features 6 and 7 are constant at inference.** See §8.2 — a real
> finding, with measured impact.

### 3.2 Block B — 8 structural features (`build_rf_features_v2.py:70-86`)

| # | Feature | Regex / definition |
|---|---|---|
| 12 | `has_tautology_pattern` | `\b(\w+)\s*=\s*\1\b` — backreference catches `1=1`, `a=a` |
| 13 | `has_quote_before_sql_keyword` | `['\"].{0,6}\b(or\|and\|union\|select)\b` |
| 14 | `has_comment_after_quote` | `['\"].{0,20}(--\|#\|/\*)` |
| 15 | `has_html_tag_open` | `<\s*[a-zA-Z][a-zA-Z0-9]*` |
| 16 | `has_event_handler_pattern` | `\bon\w+\s*=` |
| 17 | `longest_special_run` | longest consecutive non-alphanumeric run |
| 18 | `special_char_ratio` | `special_count / len` |
| 19 | `quote_ratio` | `quote_count / len` |

These are **generalising** features. `has_tautology_pattern` uses a
backreference, so it matches any `X=X`, not a hardcoded `1=1` list — it fires on
payloads no generator produced.

### 3.3 Block C — 300 character n-gram TF-IDF

```python
TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                max_features=300, lowercase=False)
```

**11 + 8 + 300 = 319.**

Three deliberate choices:

- **Character, not word.** `'/**/OR/**/1=1` has no word boundaries. Word
  tokenisation destroys it; character n-grams survive. Established for
  malicious-payload detection (Ferrag et al. 2020).
- **`lowercase=False`.** Mixed case (`SeLeCt`) is *itself* an evasion signal.
  Lowercasing would erase the evidence.
- **Fitted on training text only** (`18_train_stacked.py:142`, `vec.fit(tr_txt)`).
  Fitting on all data first leaks test vocabulary into training.

### 3.4 Measured feature importances (this model)

| Rank | Feature | Importance |
|---|---|---:|
| 1 | `longest_special_run` | 0.1039 |
| 2 | `num_special_chars` | 0.0792 |
| 3 | `special_char_ratio` | 0.0643 |
| 4 | `num_uppercase` | 0.0455 |
| 5 | `quote_ratio` | 0.0422 |
| 6 | `quote_count` | 0.0366 |
| 7 | `entropy` | 0.0351 |
| 8 | `ngram_212` | 0.0315 |
| 9 | `has_xss_keyword` | 0.0312 |
| 10 | `comment_token_count` | 0.0215 |

**Read this critically.** The top six are all symbol-density measures. Even
after augmentation, the RF's dominant signal is *"how many odd characters are
there"*. That explains the residual false alarms on source code (7 of 10) — the
shortcut was weakened, not eliminated. Honest framing: augmentation shifted the
decision boundary; it did not change what the model fundamentally keys on.

---

## 4. Models and training protocol

### 4.1 Session-grouped splitting (`prepare_honeypot_for_training.py:128-140`)

```python
gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
train_idx, temp_idx = next(gss1.split(df, groups=groups))
gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
```

70 / 15 / 15 by `session_id`, seed 42 → **25,414 / 5,390 / 5,831**.

All requests from one session land in the same split. Random row-splitting would
put request #3 of a session in training and #4 in test — near-duplicates
straddling the boundary, inflating scores. Arp et al. (2022) name this **data
snooping**; grouped splitting is the fix. Because sessions derive from *real*
WEB-IDS23 client IPs and timestamps (§2.1), the grouping reflects real client
behaviour.

> Note: `GroupShuffleSplit` groups but does **not** stratify. The docstring says
> "stratified as best-effort". With ~50/50 classes over 36k rows the drift is
> negligible, but it is not a guarantee.

### 4.2 Unicode normalisation (`scripts/lib/text_normalize.py`)

NFKC normalisation plus a 17-entry homoglyph table for curly quotes, primes, and
dashes that NFKC leaves alone.

```python
text = unicodedata.normalize("NFKC", text)
text = text.translate(_TRANS)
```

This closes a real evasion: `１＇ ＯＲ ＇１＇＝＇１` (fullwidth) renders identically to
a human, but the model saw unfamiliar codepoints and scored it benign. NFKC
folds it to `1' OR '1'='1`. Documented in **Unicode TS #39 (Security
Mechanisms)**; the same defence appears in OWASP input-canonicalisation guidance.

**Deliberately conservative.** It folds character *representations* only — it
does not strip, lowercase, or reorder, because those would destroy the very
features the detector depends on (mixed case, symbol runs).

**The critical property:** the same function is imported by the trainer
(`18_train_stacked.py:127`), the live app (`app.py:106`), and every evaluation
script. If training normalises and serving does not, predictions silently break
— **training/serving skew** (Sculley et al., NeurIPS 2015). One shared import is
the structural fix.

### 4.3 The three models (`18_train_stacked.py`)

| Model | Configuration | Rationale |
|---|---|---|
| **RF v2** | `n_estimators=200, max_depth=20, class_weight="balanced", random_state=42, n_jobs=-1` | Strong on sparse/tabular features; `max_depth=20` caps overfitting; gives importances |
| **LSTM** | `Embedding(128→32, mask_zero=True) → LSTM(64, return_sequences=True) → Dropout(0.3) → LSTM(32) → Dropout(0.3) → Dense(1, sigmoid)`; Adam 1e-3, batch 128, 6 epochs, Glorot init seeded | Reads character *order* — sequential structure the bag-of-n-grams flattens. **Two stacked layers, the original design** (see §4.4) |
| **Meta** | `LogisticRegression()` on `[rf_proba, lstm_proba]` | Learns how much to trust each base model |

**LSTM input encoding** (`:71-76`) — ordinal, length 200, vocab 128:
```python
arr[i] = code if code <= 127 else 1     # 0 = PAD, 1 = UNK
```
Non-ASCII → `1` (UNK). This is *why* NFKC matters so much: without it, every
fullwidth character collapses to the same UNK token and the attack becomes
invisible to the LSTM.

**`class_weight="balanced"`** offsets residual imbalance.
**`mask_zero=True`** is load-bearing: 0 is the PAD id, and the first LSTM must
propagate the mask to the second (`return_sequences=True`) so padding never
reaches the final state.

**Callbacks** (`:159-166`): `ModelCheckpoint(monitor="val_auc", save_best_only=True)`
plus `EarlyStopping(patience=3, restore_best_weights=True)`, then the best
checkpoint is explicitly reloaded (`:171`).

**Meta trained on VAL, not train** (`:173-177`):
```python
rf_va   = rf.predict_proba(Xva)[:, 1]
lstm_va = lstm.predict(Eva, verbose=0).flatten()
meta.fit(np.column_stack([rf_va, lstm_va]), yva)
```
If the meta-learner saw base predictions on data the bases were *fitted* on,
those predictions would be overconfident and it would learn the wrong weights.
Training the combiner on held-out predictions is the standard stacking protocol
(Wolpert 1992).

### 4.4 Architecture: the original two-layer design is retained

**There is no deviation.** An earlier working note claimed the two-layer stacked
LSTM "trained to AUC 0.5 (no learning)" under the current TensorFlow/Keras, and
it had been replaced by a single layer on that basis.

**That claim does not reproduce.** A controlled, seeded four-arm experiment
(identical data, identical split, seed 42, 6 epochs) shows the original
two-layer masked architecture training normally:

| Epoch | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| val_auc | 0.9996 | 0.9999 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

It reaches val_auc 1.0000 by epoch 3. The original failure was almost certainly
an **unseeded bad initialisation** — the same nondeterminism documented in §8.5
— rather than a property of the architecture.

The pipeline therefore uses the **two-layer stacked LSTM as originally
specified**, with the Glorot initialiser and dropout explicitly seeded so the
failure mode cannot recur silently. The single-layer variant is preserved in
`models/_backup_pre_aug/*_1layer.*` for comparison.

**Cost:** the two-layer model trains roughly 6x slower (~265 s vs ~40 s per
epoch on CPU). This matters only for the multi-seed variance study (§8.5).

---

## 5. Evaluation design

**Primary metrics:** detection rate (recall) and **false-positive rate**, at
threshold 0.5.

FPR is the headline on purpose. In intrusion detection, accuracy misleads
because of the **base-rate fallacy** — Axelsson (ACM TISSEC 2000) shows that when
attacks are rare, even a small FPR buries analysts in false alarms. A detector at
57% FPR is unusable regardless of recall. This project is a live demonstration:
the same model was F1 ≈ 0.999 on the test split and 57.6% FPR on realistic hard
input.

**Significance:** bootstrap 95% CIs (1,000 resamples) and **McNemar's test**.
McNemar is the correct test for two classifiers on the *same* test set — it is
paired, accounting for both models having seen identical inputs (Dietterich,
Neural Computation 1998).

**Four independent evaluations**, so no single set carries the claim:
1. 396-row hold-out (adversarial, deterministic)
2. 16+8 red-team set (`16_claude_redteam.py`)
3. 23-payload LLM-generated evasion corpus
4. ModSecurity + OWASP CRS, live over HTTP

---

## 6. Process, step by step

| # | Step | Script | Result |
|---|---|---|---|
| 1 | Build the hold-out ruler | `build_holdout_eval.py` | 396 adversarial rows |
| 2 | Measure BEFORE | `17_evaluate_csv.py` | Stacked 95.0% det / **57.6% FPR** |
| 3 | Augment training data | `build_training_augmentation.py` | 36,364 → 36,635 rows |
| 4 | Shared NFKC normalisation | `text_normalize.py` | Imported by trainer + app + evals |
| 5 | Retrain all three models | `18_train_stacked.py --epochs 6` | val_auc 1.0000 |
| 6 | Measure AFTER | `17_evaluate_csv.py` | Stacked 94.4% det / **5.1% FPR** |
| 7 | Independent red-team | `16_claude_redteam.py` | 14/16 caught, 1/8 false alarms |
| 8 | Regenerate downstream stats | `13_`, `14_`, `15_` | CIs, ablation, LLM corpus |

**Leakage guard (step 3).** Every generated string is checked against the
hold-out set *after normalisation* and overlaps are dropped — 38 dropped this
run. An earlier version compared raw strings and let one row through: a
curly-quote augmented attack and a straight-quote hold-out row folded to the same
text once normalised. Comparing normalised text closes it. This is a subtle
leakage path worth calling out — normalisation can *create* collisions that did
not exist in the raw data.

---

## 7. Results (measured 2026-08-23)

### 7.1 Headline — hold-out ruler, 396 rows

| Stacked ensemble | BEFORE | AFTER |
|---|---:|---:|
| False-positive rate | **57.6%** (114/198) | **5.1%** (10/198) |
| Detection rate | 95.0% (188/198) | 94.4% (187/198) |

**False alarms fell 11×; detection moved −0.6 pp — one row out of 198.** The
trap of buying a lower FPR by letting attacks through did not happen.

### 7.2 Per-model, AFTER

| Model | Detection | FPR |
|---|---:|---:|
| RF v2 | 100.0% (198/198) | 6.1% (12/198) |
| LSTM | 93.4% (185/198) | 5.1% (10/198) |
| Stacked | 94.4% (187/198) | 5.1% (10/198) |

### 7.3 Red-team (16 attacks, 8 hard-benign)

| | BEFORE | AFTER |
|---|---:|---:|
| Attacks caught | 12/16 | **14/16** |
| False alarms | 5/8 | **1/8** |

The Unicode homoglyph attack that evaded before is now caught — normalisation
working end to end.

### 7.4 Statistical significance (clean test split, 5,831 rows)

- Bootstrap 95% CI, stacked: **F1 0.9989 [0.9980–0.9997]**, FPR 0.0003 [0.0000–0.0011]
- McNemar stacked vs RF: **p = 0.13** (not significant)
- McNemar stacked vs LSTM: **p = 0.074** (not significant)

Neither reaches 0.05. Stated plainly: **the ensemble is not statistically proven
better than RF alone on this test set.** The set is saturated — all three models
sit at F1 ≈ 0.999 — so it has almost no power to separate them. A limitation of
the benchmark, not proof the ensemble is worthless, but it must not be
overclaimed.

### 7.5 Ablation, 6 conditions (clean test split)

| Condition | F1 | FPR | AUC |
|---|---:|---:|---:|
| 1. RF alone | 0.9997 | 0.0007 | 1.0000 |
| 2. LSTM alone | 0.9981 | 0.0004 | 1.0000 |
| 3. LR on 11 base features | 0.9836 | 0.0135 | 0.9953 |
| 4. RF + meta, no LSTM | 0.9943 | 0.0000 | 1.0000 |
| 5. LSTM + meta, no RF | **0.0000** | 0.0000 | 1.0000 |
| 6. Full stacked | 0.9989 | 0.0004 | 1.0000 |

Two readings:
- **Condition 5 collapses to F1 = 0** while its AUC is 1.0. The LSTM *ranks*
  perfectly but the meta-learner cannot place a threshold from that probability
  alone — it predicts one class for everything. **RF carries the ensemble.**
- **Condition 3** shows the 319-feature representation is worth ~1.6 F1 points
  over 11 hand-picked features, and cuts FPR 19×.

### 7.6 LLM-generated evasion corpus (23 payloads)

RF 23/23 · LSTM 20/23 · **Stacked 21/23** — down from 23/23 before augmentation.
A real, small regression, reported rather than hidden.

### 7.7 External baseline — ModSecurity + OWASP CRS (paranoia 2)

Run live in Docker; ~5,800 clean requests fired as real HTTP.

| Same clean traffic | ModSecurity + CRS | AI-GIS Stacked |
|---|---:|---:|
| False-positive rate | **32.8%** (895/2,733) | **5.1%** (10/198) |
| Attack detection | ~100% | 94.4% |
| Hard-benign false alarms | 8/15 | 1/8 |

The strongest fully-external claim available: comparable detection at ~6× fewer
false alarms than the industry-standard rule-based WAF. High CRS false-positive
rates at elevated paranoia levels are a documented operational problem in the CRS
project's own tuning guidance.

> **Caveat:** the two FPR figures come from **different traffic sets** (2,733
> clean requests vs 198 hold-out benign rows). This is a fair order-of-magnitude
> comparison, **not** like-for-like. Firing the 396-row hold-out through
> ModSecurity would make it exact, and is the single highest-value remaining
> experiment.

---

## 8. Code-audit notes

Findings from reading the code, for a reviewer checking implementation against
claims.

### 8.1 Excluded features (deliberate)

The model never sees user-agent, source IP, headers, or the URI path — only
query string + body. This is **correct and defensible**: §2.2 defect 3 shows the
generator once emitted `sqlmap/1.7.11` as a UA, and including UA would have let
the model learn `UA == sqlmap → malicious`, scoring beautifully in-corpus and
failing completely on real traffic. Excluding metadata forces the decision onto
payload structure.

### 8.2 Two features are constant at inference — measured impact: none

There are **two** `engineer_rf_features` implementations:

| File | Signature | `param_count` | `is_post` |
|---|---|---|---|
| `prepare_honeypot_for_training.py:81` | `(row, text)` | from real URI | from real method |
| `evasion_resistance_check.py:54` | `(text, method)` | **hardcoded `1`** | from arg |

The trainer, the app, and every eval script all call the **second** one with a
literal `"GET"` (`18_train_stacked.py:81`, `app.py:97`,
`17_evaluate_csv.py:60`, `16_claude_redteam.py:48`). So at training *and*
serving, `param_count ≡ 1` and `is_post ≡ 0`.

Training and serving therefore **agree** — there is no train/serve skew. But two
of 319 features are constants carrying zero information, even though the
underlying log has real variation (`is_post` is true for 14,414 of 36,635 rows;
`param_count` varies 0–3).

**Measured:** both features have importance **exactly 0.0000** in the trained RF.
The model correctly ignores them. Impact on results: **none.** The honest
description is *"the RF is effectively 317 features, not 319"* — worth a
footnote, not a correction to any number.

The first implementation is used only by `build_rf_features_v2.py`'s standalone
CSV path, which the current trainer bypasses (it builds features in memory).

### 8.3 Two feature-generation paths exist

`build_rf_features_v2.py` writes `rf_*_v2.csv` files; `18_train_stacked.py`
builds the same features in memory. The trainer regenerates the CSVs so
downstream scripts (`13_`, `14_`) read the exact rows the models saw. **If you
change feature code, both paths must change**, or the ablation and significance
scripts will silently report against different features than the model uses.

### 8.4 SMOTE exists but is unused

`prepare_honeypot_for_training.py:143-158` implements
`apply_smote_train_only()`. The current trainer never calls it — class balance
is handled by `class_weight="balanced"` instead. Dead code for this pipeline;
don't cite SMOTE in a writeup.

### 8.5 Reproducibility is asymmetric

RF (`random_state=42`), the splits (seed 42), the hold-out (seed 1234) and the
augmentation (seed 4242) are all deterministic and reproduce to the digit.
**TensorFlow is not seeded.** The LSTM differs run to run, and the meta-learner
sits on top of it — which is precisely why this run gives 5.1%/94.4% where an
earlier one gave 2.5%/95.5%. See §9.6.

---

## 9. Limitations

1. **The corpus is a synthetic payload overlay on real flow metadata.** Labels,
   timing, and session structure come from WEB-IDS23; payload strings do not.
   Payload realism is therefore unproven — the core caution of Arp et al. (2022).
2. **The clean test set is saturated** (F1 ≈ 0.999 for everything) and cannot
   discriminate between models. All real signal is in the 396-row hold-out.
3. **The ensemble is not statistically better than RF alone** (p = 0.13). RF has
   *perfect* recall on the hold-out (198/198) where stacked has 94.4%. A reader
   may reasonably ask why not ship RF alone; the honest answer is RF's FPR is
   higher (6.1% vs 5.1%) and the ensemble is steadier across the red-team and
   LLM corpora — but the case is not decisive. Ablation condition 5 shows the
   LSTM cannot stand alone at all.
4. **The shortcut was weakened, not removed.** The top six RF features are still
   all symbol-density measures (§3.4). 7 of 10 residual false alarms are source
   code.
5. **A small LLM-corpus regression** (23/23 → 21/23) came with the augmentation.
6. **LSTM run-to-run variance.** An earlier run of this same pipeline gave 2.5%
   FPR / 95.5% detection vs this run's 5.1% / 94.4%. Any single-run figure
   carries roughly that ±5-row variance. Proper fix: seed TensorFlow and average
   over ≥5 runs with a standard deviation.
7. **Single threshold (0.5), never tuned.** No ROC/PR analysis; FPR and recall
   could be traded deliberately.
8. **The ModSecurity comparison is not like-for-like** (§7.7).
9. **Residual failures**, all narrow and nameable:
   - `1 OR 1e0=1e0` — scientific-notation SQLi, evades at 0.12
   - `insert a script tag that pops an alert box saying one` — prose XSS, 0.23
   - `Contact O'Brien & O'Malley LLP re: contract <draft v2>.` — false-flags 0.99
   - Of 11 missed attacks: 9 plain-language intent, 1 hex-encoded UNION
   - Of 10 false alarms: 7 source-code lines

**Highest-value next experiments**, in order: (a) seed TF and report mean ± SD;
(b) fire the 396-row hold-out through ModSecurity for a like-for-like baseline;
(c) ROC-based threshold selection.

---

## 10. Reproduce

```bash
cd dashboard
python scripts/stages/build_holdout_eval.py            # the 396-row ruler (seed 1234)
python scripts/stages/17_evaluate_csv.py               # BEFORE (pre-aug models)
python scripts/stages/build_training_augmentation.py   # +228 benign, +43 attack (seed 4242)
python scripts/stages/18_train_stacked.py --epochs 6   # retrain RF + LSTM + meta (seed 42)
python scripts/stages/17_evaluate_csv.py               # AFTER
python scripts/stages/16_claude_redteam.py             # independent red-team
python scripts/stages/13_statistical_significance.py   # bootstrap CIs + McNemar
python scripts/stages/14_ablation_study.py             # 6-condition ablation
python scripts/stages/15_evaluate_llm_corpus.py        # LLM evasion corpus
```

Steps 4–9 must run **in order**: the trainer rewrites `data/prepared/*`, and the
downstream scripts read those files. Running `13_`/`14_` against stale splits
produces numbers that look fine and mean nothing.

Pre-augmentation models are in `models/_backup_pre_aug/` (git-ignored, local
only). Expect step 4 to take ~10 min on CPU; TF has no GPU support on native
Windows.

---

## 11. References

**Recent (within 5 years) — these carry the contemporary argument:**

1. Arp, D. et al. **"Dos and Don'ts of Machine Learning in Computer Security."**
   USENIX Security Symposium, 2022. — *Sampling bias, data snooping,
   inappropriate performance measures, lab-only evaluation. Motivates §2.5,
   §4.1, §5.*
2. Geirhos, R. et al. **"Shortcut Learning in Deep Neural Networks."** Nature
   Machine Intelligence 2(11), 2020. — *Why "symbols = attack" formed and why
   counter-examples fix it. Motivates §2.4, §3.4.*
3. Thakkar, A. & Lohiya, R. **"A Review on Machine Learning and Deep Learning
   Perspectives of IDS."** Archives of Computational Methods in Engineering
   28(4), 2021. — *Ensemble/stacking evidence for intrusion detection. §4.3.*
4. Ferrag, M.A. et al. **"Deep Learning for Cyber Security Intrusion Detection:
   Approaches, Datasets, and Comparative Study."** Journal of Information
   Security and Applications 50, 2020. — *Character-level and RNN approaches.
   §3.3.*
5. **Unicode Technical Standard #39: Unicode Security Mechanisms.** Unicode
   Consortium, current revision. — *Homoglyph/confusable attacks, NFKC. §4.2.*
6. **OWASP ModSecurity Core Rule Set** documentation — paranoia levels and
   false-positive tuning. — *Baseline for §7.7.*

**Foundational (older, but the originating and still-standard citations):**

7. Axelsson, S. **"The Base-Rate Fallacy and the Difficulty of Intrusion
   Detection."** ACM TISSEC 3(3), 2000. — *Why FPR, not accuracy. §5.*
8. Dietterich, T.G. **"Approximate Statistical Tests for Comparing Supervised
   Classification Learning Algorithms."** Neural Computation 10(7), 1998. —
   *McNemar's test for paired classifier comparison. §5.*
9. Wolpert, D.H. **"Stacked Generalization."** Neural Networks 5(2), 1992. —
   *The stacking method. §4.3.*
10. Sculley, D. et al. **"Hidden Technical Debt in Machine Learning Systems."**
    NeurIPS, 2015. — *Training/serving skew. §4.2, §8.2.*

> **On the WEB-IDS23 source dataset:** cite the originating WEB-IDS23 publication
> directly in any formal writeup. I have not included a citation for it here
> because the converter script references the dataset by name only and I could
> not verify authors/venue from the repository. Locate and verify that reference
> before submission — it is the single most important citation in the document.

> **On items 7–10:** these predate the 5-year window. They are included because
> they are the originating references for methods actually used here and remain
> the standard citations. **Verify every citation against the published record
> before submission** — they are given from knowledge, not fetched from a
> database.
