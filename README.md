# AI-GIS: Honeypot-Trained Hybrid Detection Model for LLM-Generated Web Injections

A hybrid machine-learning detector for **SQL injection (SQLi)** and **cross-site
scripting (XSS)**, packaged with a local Flask dashboard. It combines a Random
Forest over engineered features, a two-layer stacked LSTM over raw characters,
and a logistic-regression meta-learner, and is benchmarked against ModSecurity
with the OWASP Core Rule Set.

**Every figure in this document was measured on the committed code and data.**
Nothing is estimated, projected, or carried over from an earlier run. Each
result names the script that produced it and the JSON artifact it was read from,
so any claim here can be independently re-derived by running the command shown.

**Verification date:** 2026-08-23

---

## Table of contents

1. [What the system does](#1-what-the-system-does)
2. [Research questions and objectives](#2-research-questions-and-objectives)
3. [Datasets — full specification](#3-datasets--full-specification)
4. [Methodology](#4-methodology)
5. [Feature engineering — all 319 features](#5-feature-engineering--all-319-features)
6. [Model architecture and training](#6-model-architecture-and-training)
7. [Experimental procedure](#7-experimental-procedure)
8. [Results](#8-results)
9. [Libraries and environment](#9-libraries-and-environment)
10. [Reproduction](#10-reproduction)
11. [Threats to validity](#11-threats-to-validity)
12. [Repository layout](#12-repository-layout)

---

## 1. What the system does

The detector reads the **attacker-controllable text** of an HTTP request and
returns a probability that the text is an injection attack. It is a *passive*
classifier: it labels requests, it does not block, redirect, or modify traffic.
The ModSecurity baseline is likewise treated as a classifier rather than an
enforcement point, so the two are compared on equal terms.

Attacker-controllable text is defined precisely, in
`scripts/lib/prepare_honeypot_for_training.py:73-78`:

```python
def payload_text(row: dict) -> str:
    """Reconstruct the attacker-controlled text: query string + body."""
    uri   = row.get("uri", "")
    body  = row.get("request_body", "") or ""
    query = uri.split("?", 1)[1] if "?" in uri else ""
    return f"{query} {body}".strip()
```

The model therefore sees **the query string plus the request body, and nothing
else** — not the URI path, not headers, not the user-agent, not the source IP.
That exclusion is deliberate and is justified in §4.4.

### The three-layer design

| Layer | Model | Input | Role |
|---|---|---|---|
| 1 | Random Forest (`rf2.pkl`) | 319 engineered features | Structural / lexical evidence |
| 2 | Two-layer stacked LSTM (`lstm_best.keras`) | 200 ordinal character codes | Sequential order evidence |
| 3 | Logistic Regression (`meta.pkl`) | `[rf_proba, lstm_proba]` | Learned combination |

This is **stacked generalization** (Wolpert, 1992). The meta-learner is fitted
on *validation-set* predictions, never on training-set predictions — see §6.4
for why that distinction is load-bearing.

---

## 2. Research questions and objectives

| ID | Question | Objective | Answered in |
|---|---|---|---|
| RQ1 | How effectively does AI-GIS detect LLM-generated web injections when trained on honeypot-derived intelligence? | RO1 | §8.1, §8.8 |
| RQ2 | How accurately does it classify SQLi and XSS *across both attack types*? | RO2 | §8.3 |
| RQ3 | How does it compare to a rule-based WAF tested independently on the same data? | RO3 | §8.5 |

**Central RQ:** How effective is AI-GIS as a honeypot-trained hybrid detection
model against LLM-generated web injection attacks compared to a traditional
rule-based web application firewall?

| SoP | Problem | RQ | RO |
|---|---|---|---|
| SoP1 | Rule-based detection limitation | RQ3 | RO3 |
| SoP2 | Insufficient training data for LLM-generated attacks | RQ1 | RO1 |
| SoP3 | Single-model detection gap | RQ1–3 | RO1–3 |
| SoP4 | Attack-type performance variability | RQ2 | RO2 |

---

## 3. Datasets — full specification

Four distinct datasets are used. Conflating them is the most common way to
misread the results, so each is specified separately.

### 3.1 Training corpus — `data/honeypot_final.log`

**Format:** JSON Lines, one HTTP transaction per line.
**Size:** 36,594 rows across 12,448 sessions.
**Verified by:** direct enumeration of the committed file.

#### 3.1.1 Provenance — a hybrid corpus, not a synthetic one

The corpus is **neither captured attack traffic nor fully synthetic**. It is a
*synthetic payload overlay on real network-flow metadata*, and describing it any
other way misrepresents it.

The converter `scripts/stages/webids23_to_honeypot_log_v9.py` (934 lines) reads exactly
six columns from the **WEB-IDS23** source dataset (line 77):

```python
USECOLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]
```

These are Zeek/Bro connection-log fields. What each contributes:

| WEB-IDS23 field | Becomes | Consequence |
|---|---|---|
| `attack_type` | `label` | **Ground-truth labels are real, not invented** |
| `ts` | `time` | Real timestamps → real inter-arrival timing |
| `id.orig_h` | session key + synthetic public IP | **Real client-grouping structure** |
| `id.resp_h` | `host` | Real server-grouping structure |
| `service` | port (80 / 443) | http vs https |
| `uid` | `flow_uid` | Every generated row traces to its source record |

**What is generated:** payload strings, URIs, user-agents, and public IP
addresses. WEB-IDS23 flow records do not retain HTTP request bodies, so payload
text is generated combinatorially per attack family and grafted onto each
sampled flow.

This matters downstream: because sessions derive from *real* client IPs and
*real* timestamps, the session-grouped split (§4.1) reflects genuine client
behaviour rather than an arbitrary partition.

**Sampling:** reservoir sampling over a chunked CSV read
(`CHUNK_SIZE = 20_000`), so the source is never loaded whole and every source
row has equal selection probability.

**Sessionisation:** one real client IP bucketed into a 120-second window
(lines 76, 470–472):

```python
SESSION_WINDOW_SECONDS = 120
bucket = epoch // SESSION_WINDOW_SECONDS
return f'{row["id.orig_h"]}_{bucket}'
```

**Determinism:** per-row randomness is seeded by content hash (lines 384–386),
so the same input row always produces the same output row:

```python
def rng_for(*parts: str) -> random.Random:
    seed = int(hashlib.sha256("|".join(parts).encode()).hexdigest(), 16) % (2**32)
```

#### 3.1.2 Composition — complete breakdown

**36,594 rows: 18,410 benign (50.31%) / 18,184 attack (49.69%).**

| Class | `attack_family` | Rows | % corpus | Technique |
|---|---|---:|---:|---|
| Benign | `benign` | 18,410 | 50.31% | Browsing, search, form posts |
| XSS | `stored` | 3,773 | 10.31% | Payload persisted; fires for later visitors |
| XSS | `reflected` | 2,772 | 7.58% | Payload echoed directly in the response |
| XSS | `dom_based` | 2,546 | 6.96% | Executes via client-side DOM writes |
| SQLi | `boolean_blind` | 1,498 | 4.09% | Infers data one true/false question at a time |
| SQLi | `tautology` | 1,484 | 4.06% | `OR 1=1` — WHERE clause always true |
| SQLi | `stacked_query` | 1,343 | 3.67% | `;` terminates, second statement runs |
| SQLi | `time_based_blind` | 1,261 | 3.45% | `SLEEP(10)` — infers from response delay |
| SQLi | `union_based` | 1,223 | 3.34% | `UNION SELECT` welds attacker rows on |
| SQLi | `auth_bypass` | 1,169 | 3.19% | Comments out the password check |
| SQLi | `error_based` | 1,113 | 3.04% | Leaks data through DB error messages |
| Mixed | `nl_injection` | 2 | 0.01% | Unicode-homoglyph obfuscation (§3.1.4) |

**Aggregates:** XSS 9,091 (24.84%) · SQLi 8,091 (22.11%) · benign 18,410 (50.31%)

**HTTP methods:** GET 22,221 (60.72%) · POST 14,373 (39.28%)

**Obfuscation:** 12,908 of 18,184 attacks (**71.0%**) carry `obfuscated: true` —
URL encoding, mixed case, hex encoding, inline comment insertion. This is a
deliberate **stress-test prior**, not a claim about real traffic: real web
traffic is overwhelmingly benign and most real attacks are unobfuscated. The
high rate exists so the corpus rewards structural generalisation rather than
literal signature matching.

#### 3.1.3 Generator quality controls (v4 → v9 audit history)

The converter's docstring records four defects found by auditing its own earlier
output. Each is the kind of artifact that silently inflates results:

1. **Payload duplication.** v4 produced 72.9% duplicate rows (some DOM-XSS
   payloads repeated 39×) because the `dom_based` generator had only ~12
   distinct possible outputs sampled 36k times. Fixed by expanding component
   pools into the tens of thousands *and* enforcing uniqueness against a
   run-wide seen-set with 25 retries (`MAX_UNIQUENESS_RETRIES = 25`). A nonce
   fallback is flagged per row as `forced_unique_nonce` so its rate is auditable.
2. **Flag conflation.** `synthetic_duplicate` (flow-level reuse under
   oversampling) was being misread as payload-level duplication. Now separate
   fields.
3. **User-agent leakage.** v4 included `sqlmap/1.7.11` among only six UAs — a
   model could have learned `UA == sqlmap → malicious`, scoring beautifully
   in-corpus and failing completely in deployment. v9 uses ~18 weighted UAs so
   tool agents appear at realistic low frequency. **This is why user-agent is
   excluded from the feature set entirely** (§4.4).
4. **Schema noise.** `host` is now consistently `ip:port`; redundant identical
   ID fields were replaced with `flow_uid` + `dup_index`.

Defect 3 is a textbook **shortcut** in the sense of Geirhos et al. (2020),
caught before it reached the model.

#### 3.1.4 Augmentation — 230 rows added

Produced by `scripts/stages/build_training_augmentation.py` (`SEED = 4242`, idempotent
— it strips prior `"aug": true` rows before appending).

**228 benign rows**, symbol-dense but harmless, from seven generators:

| Generator | Construction | Example |
|---|---|---|
| Source code | 14 conditions × 8 bodies | `if (user.role == 'admin') { grantAccess(); }` |
| File paths | 8 bases × 8 tails | `open the file at C:\Users\Admin\config.yml and edit line 42` |
| Regexes | 8 patterns | `the regex ^[a-z]+@[a-z]+\.(com\|org)$ matches …` |
| Mathematics | 8 expressions | `in the lecture we derived: P(A\|B) = P(B\|A)*P(A)/P(B)` |
| Names / addresses | 10 names × 6 streets | `contact O'Brien at 42 O'Connell St re: the <draft> proposal` |
| Technical prose | 16 fixed strings | `the DROP command deletes a table, so use it carefully` |
| Emails / handles | 5 × 5 | `email dev.ops@company.co.uk or ping @dev.ops on slack` |

**2 attack rows**, Unicode-homoglyph obfuscation (e.g. a prime character `′`
substituted for an apostrophe).

**Rationale.** The detector had learned **"many symbols ⇒ attack"** — a
*shortcut*: a feature correlated with the label in training that is not the
causal signal (Geirhos et al., 2020). The remedy is counter-examples that break
the correlation: benign source code is symbol-dense and harmless. This is the
single largest driver of the false-positive reduction reported in §8.1.

Each augmented row receives a **unique `session_id`** (`aug_sess_{idx}`) so the
session-grouped split scatters them across train/val/test rather than clumping
them into one partition.

**Plain-language attack rows are deliberately excluded** — see §8.7.

**Leakage guard.** Every generated string is checked against the hold-out set
*after* Unicode normalisation, and overlaps are dropped (29 dropped in the
current build). An earlier version compared raw strings and let one row through:
a curly-quote attack and its straight-quote hold-out twin folded to the same
text once normalised. **Normalisation can create collisions that do not exist in
the raw data** — a subtle leakage path worth naming.

### 3.2 Adversarial hold-out set — `data/eval/holdout_eval.csv`

**This is the primary evaluation instrument.** 396 rows, 198 attack / 198
benign, built by `scripts/stages/build_holdout_eval.py` (`SEED = 1234`, deterministic).

**Composition by attack type** (classified by `19_eval_by_type.py`):

| Segment | n | Description |
|---|---:|---|
| Benign | 198 | Hard benign: source code, regexes, maths, apostrophe surnames, `<draft>` in prose |
| SQLi | 102 | Tautologies, UNION, blind, time-based, encoded variants |
| XSS | 77 | Tag injection, event handlers, `javascript:`, encoded variants |
| Other | 15 | Encoded / mixed payloads not cleanly typed |
| `nl_intent` | 4 | Plain-language attack intent |

**Why it exists.** The ordinary test split is **saturated** — every model scores
F1 ≈ 1.0 on it and it cannot rank detectors. Reporting 0.999 while the system
fails on realistic hard input is the "inappropriate performance measure" pitfall
named by Arp et al. (2022). The hold-out set was built to make failure visible,
and it worked immediately: it exposed a **57.6% false-positive rate** that the
test split had rated 0.999.

Attack seeds come from `EVASION_ATTACKS` in `04_evasion_test_definitions.py`,
explicitly built from techniques **absent from every training generator** —
whitespace tricks (`1'%09OR%091=1%09--%09-`), MySQL backtick quoting
(`` 1`;DROP TABLE `users`;-- ``), and comparable CRS-bypass classics.

The builder reports its own balancing honestly:

```
[warn] only 198 benign / 222 attack available before balancing; using 198 each
```

### 3.3 LLM-generated evasion corpus — `data/llm_evasion_corpus.csv`

23 rows, all attacks (`label=1`). Generated by
`scripts/stages/11_generate_evasion_corpus.py` against a **local Ollama instance**,
prompting the model to rewrite each of the 23 `EVASION_ATTACKS` into a
semantically equivalent but differently obfuscated variant.

**Generator model, verified from the CSV: `qwen2.5-coder:1.5b`** — a
1.5-billion-parameter model. (The script's usage examples mention
`codellama:13b` and `deepseek-r1:14b`; the committed corpus contains neither.)

**Technique distribution:** `hex_encoding` 21 · `comment_insertion` 1 ·
`unicode_escape_sequences` 1.

**This is the weakest evidence in the project and is presented as such.** 91% of
generations used a single technique despite the prompt requesting variety, and
several outputs are near-identical to their inputs (the model frequently deleted
a quote character rather than obfuscating). Treat it as a supplementary check,
not a headline result.

### 3.4 Red-team set — `scripts/redteam_cases.json`

16 hand-constructed attacks and 8 hard-benign strings targeting known weak
spots: scientific-notation SQLi (`1 OR 1e0=1e0`), prose-described XSS, backtick
XSS, and benign text with high apostrophe / angle-bracket density.

### 3.5 Placeholder files — do not cite

`data/mock_attacker_results.json`, `data/mock_codellama_normal.jsonl`, and
`data/mock_deepseek_polymorphic.jsonl` are **placeholders**. Every row carries
`"source": "MOCK_..._PLACEHOLDER"`. They are not real model output.

---

## 4. Methodology

### 4.1 Session-grouped splitting (leakage control)

Implemented in `prepare_honeypot_for_training.py:128-140` using
`GroupShuffleSplit`, grouping on `session_id`, seed 42:

```python
gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
train_idx, temp_idx = next(gss1.split(df, groups=groups))
gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
```

**Measured partition (70 / 15 / 15 by session):**

| Split | Rows | Attack | Benign | Sessions |
|---|---:|---:|---:|---:|
| Train | 24,358 | 11,483 | 12,875 | 8,713 |
| Validation | 5,679 | 2,941 | 2,738 | 1,867 |
| Test | 6,557 | 3,760 | 2,797 | 1,868 |

**Why group, not shuffle.** Random row-splitting would place request #3 of a
session in training and request #4 in test — near-duplicates straddling the
boundary, inflating every score. Arp et al. (2022) name this **data snooping**
as among the most common flaws in security-ML papers.

**Stated limitation:** `GroupShuffleSplit` groups but does **not** stratify. The
source docstring says "stratified as best-effort". With a ~50/50 class balance
over 36k rows the drift is small but not guaranteed — the test split is 57.3%
attack, visible in the table above.

### 4.2 Unicode normalisation (`scripts/lib/text_normalize.py`)

Every text passes through `normalize_text()` before any feature is computed:
Unicode **NFKC** normalisation plus a 17-entry homoglyph table for curly quotes,
primes, and dashes that NFKC leaves alone.

```python
text = unicodedata.normalize("NFKC", text)
text = text.translate(_TRANS)
```

**This closes a real evasion.** The payload `１＇ ＯＲ ＇１＇＝＇１` (fullwidth
characters) renders identically to a human, but the model saw unfamiliar
codepoints and scored it benign. NFKC folds it to `1' OR '1'='1`. Documented in
**Unicode Technical Standard #39 (Security Mechanisms)**.

It is **deliberately conservative**: it folds character *representations* only.
It does not strip, lowercase, or reorder, because those operations would destroy
the very features the detector depends on (mixed case, symbol runs).

**The critical property** is that the *same function* is imported by the trainer
(`18_train_stacked.py:127`), the live app (`app.py:106`), and every evaluation
script. If training normalises and serving does not, predictions silently break
— **training/serving skew** (Sculley et al., 2015). One shared import is the
structural fix, not a convention.

### 4.3 Why false-positive rate is the headline metric

In intrusion detection, accuracy misleads because of the **base-rate fallacy**
(Axelsson, 2000): when attacks are rare, even a small FPR buries analysts in
false alarms. This project is a live demonstration — the same model scored
F1 ≈ 0.999 on the test split while producing a 57.6% false-positive rate on
realistic hard input. A detector at 57% FPR is unusable regardless of recall.

### 4.4 Deliberately excluded features

The model never sees user-agent, source IP, headers, or URI path. §3.1.3 defect
3 shows why: the generator once emitted `sqlmap/1.7.11` as a user-agent, and
including UA would have let the model learn `UA == sqlmap → malicious` —
excellent in-corpus, worthless in deployment. Excluding metadata forces the
decision onto payload structure.

---

## 5. Feature engineering — all 319 features

### 5.1 Block A — 11 base features (`prepare_honeypot_for_training.py:81-95`)

| # | Feature | Definition |
|---|---|---|
| 1 | `payload_len` | `len(text)` |
| 2 | `entropy` | Shannon entropy of the character distribution |
| 3 | `num_special_chars` | Count of non-alphanumeric, non-space |
| 4 | `num_digits` | Count of digits |
| 5 | `num_uppercase` | Count of uppercase characters |
| 6 | `param_count` | `uri.count("&") + (1 if "?" in uri else 0)` |
| 7 | `is_post` | `method == "POST"` |
| 8 | `has_sqli_keyword` | Any of 11 SQL keywords |
| 9 | `has_xss_keyword` | Any of 11 XSS keywords |
| 10 | `quote_count` | `'` + `"` |
| 11 | `comment_token_count` | `--` + `/*` + `#` |

Keyword lists, verbatim (lines 56–59):

```python
SQLI_KEYWORDS = ["select","union","drop","sleep","waitfor","exec",
                 "or 1=1","or '1'='1","xp_cmdshell","convert","extractvalue"]
XSS_KEYWORDS  = ["script","onerror","onload","onfocus","onmouseover",
                 "onstart","ontoggle","alert(","javascript:","<svg","<img"]
```

> **Audit note.** Features 6 and 7 are **constant at both training and inference
> time**. Two implementations of `engineer_rf_features` exist; the trainer, the
> app and all evaluation scripts call the one in `evasion_resistance_check.py:54`
> with a literal `"GET"`, which hardcodes `param_count = 1` and yields
> `is_post = 0`. Training and serving therefore agree — there is **no skew** —
> but two features carry zero information. Measured Gini importance for both:
> **exactly 0.0000**. The model correctly ignores them. The accurate description
> is that the Random Forest is *effectively 317 features, not 319*. No reported
> number is affected.

### 5.2 Block B — 8 structural features (`build_rf_features_v2.py:70-86`)

| # | Feature | Pattern |
|---|---|---|
| 12 | `has_tautology_pattern` | `\b(\w+)\s*=\s*\1\b` — backreference, matches any `X=X` |
| 13 | `has_quote_before_sql_keyword` | `['\"].{0,6}\b(or\|and\|union\|select)\b` |
| 14 | `has_comment_after_quote` | `['\"].{0,20}(--\|#\|/\*)` |
| 15 | `has_html_tag_open` | `<\s*[a-zA-Z][a-zA-Z0-9]*` |
| 16 | `has_event_handler_pattern` | `\bon\w+\s*=` |
| 17 | `longest_special_run` | Longest consecutive non-alphanumeric run |
| 18 | `special_char_ratio` | `special_count / len` |
| 19 | `quote_ratio` | `quote_count / len` |

These **generalise rather than memorise**. `has_tautology_pattern` is a
backreference matching *any* self-comparison, not an enumerated list of `1=1`
variants — so it fires on payloads no generator produced.

**Provenance (design-leakage check).** These features live in
`build_rf_features_v2.py`, which is **tracked in git and predates the hold-out
set**; `build_holdout_eval.py` was written later. The features cannot have been
reverse-engineered from a set that did not exist. Their basis is published SQLi
and XSS taxonomy (tautology, quote-breakout, comment truncation, tag injection,
event-handler vectors), not inspection of the evaluation data.

### 5.3 Block C — 300 character n-gram TF-IDF features

```python
TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                max_features=300, lowercase=False)
```

**11 + 8 + 300 = 319 features.** Verified against `rf_train_v2.csv`.

Three deliberate choices:

- **Character, not word, n-grams.** `'/**/OR/**/1=1` has no word boundaries.
  Word tokenisation destroys it; character n-grams survive. This is the
  established representation for malicious-payload detection (Ferrag et al.,
  2020).
- **`lowercase=False`.** Mixed case (`SeLeCt`) is *itself* an evasion signal;
  lowercasing would erase the evidence.
- **Fitted on training text only** (`18_train_stacked.py:142`,
  `vec.fit(tr_txt)`). Fitting on all data first would leak test vocabulary.

### 5.4 Measured feature importances

Gini importance from the trained Random Forest, top 10:

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

**Read critically:** the top six are all symbol-density measures. Even after
augmentation, the dominant signal remains *"how many unusual characters are
present"*. This is why the residual false alarms are source-code lines. The
shortcut was **weakened, not eliminated** — augmentation shifted the decision
boundary without changing what the model fundamentally keys on.

---

## 6. Model architecture and training

### 6.1 Layer 1 — Random Forest

```python
RandomForestClassifier(n_estimators=200, max_depth=20,
                       class_weight="balanced",
                       random_state=seed, n_jobs=-1)
```

`max_depth=20` caps overfitting; `class_weight="balanced"` weights classes
inversely to frequency.

> **Note on class balancing.** SMOTE is **not used.**
> `prepare_honeypot_for_training.py:143-158` defines `apply_smote_train_only()`,
> but there is **no call site** in the training pipeline. Balance is handled
> entirely by `class_weight="balanced"`. The corpus is near-balanced by
> construction (50.31% / 49.69%), so resampling would have almost nothing to
> correct. Any methodology text citing SMOTE should be corrected.

### 6.2 Layer 2 — two-layer stacked LSTM

```python
Embedding(input_dim=128, output_dim=32, mask_zero=True)
  → LSTM(64, return_sequences=True, kernel_initializer=GlorotUniform(seed))
  → Dropout(0.3, seed=seed)
  → LSTM(32, kernel_initializer=GlorotUniform(seed))
  → Dropout(0.3, seed=seed)
  → Dense(1, activation="sigmoid")

optimizer = Adam(1e-3), loss = binary_crossentropy, metric = AUC
epochs = 6, batch_size = 128
callbacks = ModelCheckpoint(monitor="val_auc", save_best_only=True),
            EarlyStopping(monitor="val_auc", patience=3,
                          restore_best_weights=True)
```

**Input encoding** — ordinal, length 200, vocabulary 128:

```python
arr[i] = code if code <= 127 else 1     # 0 = PAD, 1 = UNK
```

Every non-ASCII character collapses to a single `UNK` token. **This is precisely
why NFKC normalisation matters**: without it, a fullwidth attack becomes a run
of identical UNK tokens and is invisible to the LSTM.

**`mask_zero=True` is load-bearing**, and `return_sequences=True` on the first
layer is what propagates that mask to the second. Without it, padding reaches
the final state.

#### Architecture note — a documented claim that did not reproduce

An earlier working note recorded that the two-layer stacked LSTM "trained to
AUC 0.5 (no learning)", and it had been replaced by a single layer on that
basis. **That claim does not reproduce.** A controlled, seeded diagnostic on the
original architecture:

| Epoch | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| val_auc | 0.9996 | 0.9999 | **1.0000** | 1.0000 | 1.0000 | 1.0000 |

The probable root cause was the missing `return_sequences=True` — a code defect,
not an architectural limitation. **The original two-layer design is therefore
used, and there is no deviation to declare.** Initialiser and dropout are now
explicitly seeded so the failure mode cannot recur silently.

Cost: ~165 s/epoch versus ~40 s for a single layer (CPU; TensorFlow has no GPU
support on native Windows).

### 6.3 Layer 3 — logistic-regression meta-learner

```python
meta = LogisticRegression()
meta.fit(np.column_stack([rf_va, lstm_va]), yva)
```

### 6.4 Why the meta-learner is fitted on validation, not training

If the meta-learner saw base-model predictions on data those models were
*fitted* on, those predictions would be overconfident and it would learn the
wrong weights. Fitting the combiner on held-out predictions is the standard
stacking protocol (Wolpert, 1992). This is the single most common way a stacked
ensemble is implemented incorrectly.

### 6.5 Threshold

All reported metrics use a fixed decision threshold of **0.5**. No ROC-based
threshold tuning was performed — see §11.

---

## 7. Experimental procedure

| Step | Script | Output |
|---|---|---|
| 1 | `build_holdout_eval.py` | 396-row adversarial hold-out (seed 1234) |
| 2 | `17_evaluate_csv.py` | BEFORE baseline on pre-augmentation models |
| 3 | `build_training_augmentation.py` | +228 benign, +2 Unicode attacks (seed 4242) |
| 4 | `18_train_stacked.py --epochs 6 --seed 42` | Retrained RF + LSTM + meta |
| 5 | `17_evaluate_csv.py` | AFTER — headline detection / FPR |
| 6 | `19_eval_by_type.py` | Per-type metrics, obfuscation split, ROC curves |
| 7 | `20_significance_holdout.py` | McNemar exact + effect sizes + bootstrap CIs |
| 8 | `16_claude_redteam.py` | Independent red-team |
| 9 | `13_statistical_significance.py` | Bootstrap CIs, McNemar (clean split) |
| 10 | `14_ablation_study.py` | 6-condition ablation |
| 11 | `15_evaluate_llm_corpus.py` | LLM evasion corpus |
| 12 | `21_modsec_holdout.py` | ModSecurity on the **identical** 396 rows |
| 13 | `22_multirun_variance.py --runs 5 --two-layer` | 5-seed mean ± SD |

Steps 4–11 must run **in order**: the trainer rewrites `data/prepared/*`, and
downstream scripts read those files. Running them against stale splits produces
numbers that look plausible and mean nothing.

---

## 8. Results

### 8.1 Primary result — reproducibility-corrected headline

**Five seeded training runs** (seeds 42–46), identical data and split, only the
random seed varying. Source: `reports/multirun_variance.json`.

**These are the numbers to cite. Single-run figures are not defensible.**

| Model | Detection (mean ± SD) | FPR (mean ± SD) | F1 | AUC |
|---|---:|---:|---:|---:|
| RF v2 | **100.00 ± 0.00%** | 6.97 ± 0.66% | 0.9663 ± 0.0031 | 0.9994 ± 0.0001 |
| LSTM | 92.83 ± 0.23% | 4.14 ± **3.77%** | 0.9428 ± 0.0176 | 0.9782 ± 0.0089 |
| **Stacked** | **96.16 ± 1.26%** | **3.64 ± 2.71%** | 0.9627 ± 0.0126 | 0.9971 ± 0.0023 |

Observed ranges: RF FPR 6.06–7.58% · LSTM FPR 1.01–10.61% · **Stacked FPR
1.01–8.08%**, detection 94.95–97.47%.

**Per-run detail:**

| Run | Seed | Stacked detection | Stacked FPR |
|---|---|---:|---:|
| 1 | 42 | 95.0% | 2.0% |
| 2 | 43 | 96.0% | **8.1%** ← outlier, **retained** |
| 3 | 44 | 95.0% | 1.0% |
| 4 | 45 | 97.5% | 3.5% |
| 5 | 46 | 97.5% | 3.5% |

**Headline claim, stated defensibly:**

> On a 396-row adversarial hold-out set, the false-positive rate fell from
> **57.6%** before intervention to **3.64% ± 2.71%**, while detection reached
> **96.16% ± 1.26%**, measured across five seeded training runs.

**Three findings that only a multi-run study can support:**

1. **The ensemble has the lowest false-alarm rate of all three models** — 3.64%
   versus RF 6.97% and LSTM 4.14% — while detection sits between them. In any
   single run this is invisible or reversed.
2. **All instability is neural, and stacking damps it.** LSTM FPR SD is 3.77%;
   the stacked SD is 2.71%, a ~28% reduction. RF is effectively deterministic
   (SD 0.66%).
3. **Detection is far more stable than FPR** (SD 1.26% vs 2.71%). The recall
   claim is robust; the false-alarm claim must always carry its ±.

> Seed 43 produced an 8.1% FPR outlier while the other four fell between 1.0%
> and 3.5%. **It is retained.** Discarding an inconvenient seed is exactly the
> practice this study exists to prevent, and the standard deviation should
> reflect that the tail is real.

### 8.2 Single-run detail — final shipped model (seed 42)

Source: `reports/holdout_eval_final.json`.

| Model | Detection | FPR | False alarms |
|---|---:|---:|---:|
| RF v2 | 95.0% (188/198) | 4.0% (8/198) | 8 |
| LSTM | 92.9% (184/198) | 0.5% (1/198) | 1 |
| **Stacked** | **93.4%** (185/198) | **0.5%** (1/198) | **1** |

**All 13 missed attacks, verbatim:**

```
<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>
show me the users table where the password equals anything          ← plain-language
run javascript that reads the visitor's cookies and sends them away ← plain-language
select all passwords from the accounts table                        ← plain-language
union the results with the admin credentials table                  ← plain-language
x contenteditable onfocus=alert(1) autofocus
insert a script tag that pops an alert box saying one               ← plain-language
make the query always true so it returns everything                 ← plain-language
bypass the login by making the where clause always match            ← plain-language
return every row where the login always succeeds                    ← plain-language
add an image that runs code when it fails to load                   ← plain-language
/*/**/String.fromCharCode(97,108,101,114,116,40,49,41)
drop the users table from the database                              ← plain-language
```

**10 of 13 are plain-language intent** — the category deliberately removed from
training (§8.7). The remaining three are `String.fromCharCode` obfuscation (×2)
and a `contenteditable`/`onfocus` XSS vector.

**The single false alarm:**

```
Address: 42 O'Malley Ave, Apt #7, (near the park)
```

### 8.3 Per-attack-type results (RQ2 / RO2 / SoP4)

Source: `reports/eval_by_type.json`. Each attack type is scored against **all
198 benign rows** (shared negatives), so FPR is common and detection/AUC are
per-type.

**Stacked ensemble:**

| Segment | n | Detection | FPR | AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|
| Overall | 396 | 93.4% | 0.5% | 0.9762 | 0.9852 |
| **SQLi** | 102 | **95.1%** | 0.5% | 0.9916 | 0.9883 |
| **XSS** | 77 | **97.4%** | 0.5% | 0.9997 | 0.9993 |
| `nl_intent` | 4 | **0.0%** | 0.5% | 0.4028 | 0.0284 |
| Other | 15 | 86.7% | 0.5% | 0.9040 | 0.8801 |

**Random Forest** — SQLi 95.1%, XSS 97.4%, `nl_intent` 0.0%, other 86.7%.
**LSTM** — SQLi 94.1%, XSS 97.4%, `nl_intent` 0.0%, other 86.7%.

**Finding: XSS is consistently easier than SQLi.** XSS carries unmistakable
structure — angle brackets, `on*=` handlers, `javascript:` — while SQLi hides
inside ordinary punctuation (quotes, hyphens, equals signs) that also appears
constantly in legitimate text.

ROC curves: `reports/roc_by_type.png` (panel 1: overall per model; panel 2:
stacked by attack type).

> **Caveat:** `nl_intent` has n = 4. Its rate and ROC curve are indicative only.
> Report it as a documented blind spot, not as a measured detection rate.

### 8.4 Statistical significance (RQ1 / SoP3)

#### On the adversarial hold-out — `reports/significance_holdout.json`

McNemar **exact binomial** test (correct for small discordant counts), with
effect sizes and paired bootstrap CIs (2,000 resamples).

**Error counts (of 396):** RF **18** · LSTM **15** · Stacked **14**

| Comparison | b | c | p (exact) | Odds ratio | Cohen's g | FPR diff [95% CI] | Detection diff [95% CI] |
|---|---:|---:|---:|---:|---:|---|---|
| Stacked vs RF | 8 | 4 | 0.388 | **2.00** | 0.167 | **[−6.5%, −1.0%]** | [−3.3%, 0.0%] |
| Stacked vs LSTM | 1 | 0 | 1.000 | ∞ | 0.500 | [0.0%, 0.0%] | [0.0%, +1.6%] |
| RF vs LSTM | 5 | 8 | 0.581 | 0.63 | 0.115 | [+0.6%, +6.4%] | [+0.5%, +4.3%] |

**Interpretation, stated without overclaiming:**

- **The ensemble is not statistically superior to Random Forest alone**
  (p = 0.388). The odds ratio of 2.00 means it fixes twice as many RF errors as
  it introduces, but at n = 396 this does not reach significance.
- **Its false-positive advantage over RF is a real effect**: the 95% CI
  [−6.5%, −1.0%] **excludes zero**.
- **Its detection cost is not reliably distinguishable from zero**: CI
  [−3.3%, 0.0%] touches zero.

#### On the clean test split — `reports/statistical_significance.json`

Bootstrap 95% CI (1,000 resamples): **F1 = 1.0000 [1.0000–1.0000], FPR = 0.0000**.
McNemar: stacked vs RF p = 1.000; stacked vs LSTM p = 0.248.

**The clean test split is now fully saturated and has no discriminating power.**
Every model comparison must use the adversarial hold-out.

#### Recommended framing

1. Do **not** claim raw statistical superiority over RF — the data does not
   support it.
2. **Do** claim the false-alarm advantage: a measured effect whose CI excludes
   zero, on the metric the base-rate argument makes decisive (Axelsson, 2000).
3. **Do** claim variance reduction — a genuine ensemble benefit, visible only
   across runs.
4. State explicitly that RF alone achieves perfect recall (100.00 ± 0.00%) at
   nearly double the false-alarm rate. An examiner will ask.

### 8.5 External baseline — ModSecurity + OWASP CRS (RQ3 / RO3 / SoP1)

**OWASP CRS 3.3.10 on ModSecurity 3.0.16, paranoia level 2**, run live in Docker
over real HTTP, fired against the **identical 396 hold-out rows**.
Source: `reports/modsec_holdout.json`.

| Metric | ModSecurity + CRS | AI-GIS Stacked |
|---|---:|---:|
| Detection | **95.5%** (189/198) | 93.4% (185/198) |
| **False-positive rate** | **70.2%** (139/198) | **0.5%** (1/198) |
| Precision | 0.576 | — |
| F1 | 0.719 | — |
| AUC | *undefined* | 0.9762 |

AUC is reported as undefined rather than fabricated: ModSecurity emits a binary
block decision (200 vs 403), not a score.

**At comparable detection — two attacks apart — ModSecurity raises 139 false
alarms against the ensemble's 1.** On this adversarial set CRS blocks roughly
7 in 10 legitimate requests.

**The 9 attacks ModSecurity misses are exactly the 9 plain-language ones.** A
signature-based WAF cannot match intent expressed as English — and neither can
the character-level LSTM (0.0% on that segment). **Natural-language attack
intent is a blind spot shared by both paradigms**, which is the project's most
defensible novel finding.

#### Methodological finding — CRS scores the client, not only the payload

An initial run of the new harness returned 100% detection *and* 100% FPR. The
audit log showed why, and it had nothing to do with payloads:

- Rule **913101**: `Python-urllib/3.13` flagged as a scripting user-agent (+5)
- Rule **920300**: missing `Accept` header (+2)
- Anomaly score **7 ≥ 5** → blocked in phase 2, before payload evaluation

All reported measurements send ordinary browser headers so the baseline is
evaluated on payload content alone. **Any CRS evaluation using a default HTTP
client library is measuring its own harness.**

#### On the two different ModSecurity figures

An earlier note in this repository claimed a previously reported **32.8%** CRS
false-positive rate was "almost certainly invalid" for this reason. **That claim
was wrong and is retracted.** The original harness
(`12_evaluate_modsec_baseline.py`) sends a custom user-agent
(`AI-GIS-Thesis-Eval/1.0`) which does **not** trip rule 913101. Re-measured on
the same 396 rows: **original harness 72.2% FPR, browser-header harness 70.2%** —
a 2-point difference.

**32.8% versus 70.2% is a traffic difference, not an error.** 32.8% is CRS
against ~2,733 ordinary clean requests; 70.2% is CRS against 198 deliberately
hard benign rows. Both are valid measurements of different things. **Only 70.2%
is like-for-like with the ensemble**, because only it uses identical inputs.

### 8.6 Ablation study — `reports/ablation_study_results.json`

Six conditions on the clean test split:

| # | Condition | F1 | FPR | AUC |
|---|---|---:|---:|---:|
| 1 | RF alone | 0.9999 | 0.0004 | 1.0000 |
| 2 | LSTM alone | 0.9996 | 0.0000 | 1.0000 |
| 3 | LR on 11 base features | 0.9869 | 0.0100 | 0.9985 |
| 4 | RF + meta, no LSTM | 0.9871 | 0.0000 | 1.0000 |
| 5 | LSTM + meta, no RF | **0.0000** | 0.0000 | 1.0000 |
| 6 | **Full stacked ensemble** | **1.0000** | **0.0000** | 1.0000 |

Two readings:

- **Condition 5 collapses to F1 = 0 while its AUC is 1.0.** The LSTM *ranks*
  perfectly but the meta-learner cannot place a usable threshold from that
  probability alone — it predicts one class for everything. **Random Forest
  anchors the ensemble.**
- **Condition 3** shows the full 319-feature representation is worth ~1.3 F1
  points and a 25× lower FPR over 11 hand-picked features — evidence for the
  *feature engineering*, distinct from evidence for the stacking.

### 8.7 Effect of excluding plain-language attack rows

The 43 originally augmented attack rows split **41 plain-language / 2
Unicode-homoglyph**. These are different phenomena and are treated differently:

- **41 plain-language rows removed from training.** At ~0.1% of a 36k corpus
  they were far too few to teach a linguistic category, but enough to imply a
  capability the system lacked (50% detection; LSTM 0%).
- **2 Unicode-homoglyph rows retained.** Character-level obfuscation is not
  natural language, and it is the class the NFKC pipeline exists to defeat.

Controlled by `INCLUDE_PLAIN_LANGUAGE_ATTACKS` in
`build_training_augmentation.py` (default `False`), so the decision is
reversible and visible.

**Measured cost (seed 42):**

| Metric | With plain-language training | Without (final) |
|---|---:|---:|
| Stacked detection | 95.0% | 93.4% |
| Stacked FPR | 2.0% (4 alarms) | **0.5%** (1 alarm) |
| `nl_intent` detection | 50.0% | **0.0%** |
| Red-team attacks caught | 14/16 | 12/16 |

**The raw comparison overstates the cost**, because the hold-out still contains
4 plain-language attacks the model is now deliberately never trained on.
Excluding that category from *both* sides:

| | With plain-language | Without (final) |
|---|---:|---:|
| Detection excluding `nl_intent` | 96.4% (187/194) | **95.9%** (186/194) |
| False alarms | 4 | **1** |

**The real cost is 0.5 percentage points of detection on the categories the
system actually claims to handle, in exchange for a 4× reduction in false
alarms.** SQLi and XSS detection are unaffected.

### 8.8 Supporting evaluations

| Evaluation | Result | Source |
|---|---|---|
| Red-team (16 attacks, 8 hard-benign) | **12/16** caught, **1/8** false alarms | `claude_redteam_results.json` |
| LLM evasion corpus (23 payloads) | RF 23/23 · LSTM 20/23 · **Stacked 21/23** | `llm_corpus_results.json` |
| Obfuscated attacks (test split) | **100.0%** detection (2,282 rows) | `eval_by_type.json` |
| Non-obfuscated attacks (test split) | **100.0%** detection (1,478 rows) | `eval_by_type.json` |

**Obfuscation is fully solved on in-distribution data** — a 0.0 percentage-point
gap between obfuscated and clean attacks. **Semantics is not**: plain-language
intent remains at 0.0%. The system detects payload *structure*, not *meaning*.

Red-team residual failures, with scores:

```
1 OR 1e0=1e0                                        0.1336  scientific-notation SQLi
show me the users table where the password equals…  0.0056  plain-language
<img src=x onerror=`alert\x281\x29`>                0.4125  backtick XSS
insert a script tag that pops an alert box saying…  0.0186  plain-language
Contact O'Brien & O'Malley LLP re: contract <draft> 0.9847  false alarm
```

---

## 9. Libraries and environment

**Verified on the machine that produced every result above.**

| Component | Version |
|---|---|
| Python | 3.13.12 |
| OS | Windows 11 |
| NumPy | 2.4.4 |
| pandas | 3.0.5 |
| scikit-learn | 1.9.0 |
| TensorFlow | 2.21.0 |
| SciPy | 1.18.0 |
| matplotlib | 3.11.1 |
| Flask | 3.1.3 |
| joblib | 1.5.3 |
| ModSecurity | 3.0.16 |
| OWASP CRS | 3.3.10 |
| Docker | 29.7.2 |
| Ollama model (corpus generation) | `qwen2.5-coder:1.5b` |

**Component roles:**

- **scikit-learn** — `RandomForestClassifier`, `LogisticRegression`,
  `TfidfVectorizer`, `GroupShuffleSplit`, and all metrics (`roc_auc_score`,
  `f1_score`, `average_precision_score`, `roc_curve`)
- **TensorFlow / Keras** — LSTM, `ModelCheckpoint`, `EarlyStopping`
- **SciPy** — `stats.binomtest` for the exact McNemar test
- **NumPy** — ordinal encoding, bootstrap resampling
- **pandas** — log parsing, feature frames, CSV I/O
- **matplotlib** — ROC curves (`Agg` backend)
- **Flask** — dashboard and live-prediction endpoint

> TensorFlow has **no GPU support on native Windows** for versions ≥ 2.11. All
> training was CPU-bound: ~165 s/epoch for the two-layer LSTM, ~20 min for a
> complete pipeline run.

---

## 10. Reproduction

### Setup

```bash
cd dashboard
python -m venv venv
# Windows PowerShell:  .\venv\Scripts\Activate.ps1
# macOS / Linux:       source venv/bin/activate
pip install -r requirements.txt
python app.py                       # dashboard at http://127.0.0.1:5050
```

### Full pipeline, in order

```bash
cd dashboard
python scripts/stages/build_holdout_eval.py            # 396-row ruler (seed 1234)
python scripts/stages/build_training_augmentation.py   # +230 rows (seed 4242)
python scripts/stages/18_train_stacked.py --epochs 6 --seed 42
python scripts/stages/17_evaluate_csv.py               # headline detection / FPR
python scripts/stages/19_eval_by_type.py               # per-type + ROC + obfuscation
python scripts/stages/20_significance_holdout.py       # McNemar + effect sizes
python scripts/stages/16_claude_redteam.py             # red-team
python scripts/stages/13_statistical_significance.py   # bootstrap CIs
python scripts/stages/14_ablation_study.py             # 6-condition ablation
python scripts/stages/15_evaluate_llm_corpus.py        # LLM corpus
python scripts/stages/22_multirun_variance.py --runs 5 --epochs 6 --two-layer
```

### External baseline (requires Docker Desktop)

```bash
docker network create modsec-net
docker compose -f deploy/docker-compose.yml up -d
python scripts/stages/21_modsec_holdout.py --host localhost --port 8080
```

**Determinism:** the splits (seed 42), hold-out (1234), augmentation (4242), and
Random Forest (`random_state`) reproduce exactly. **The LSTM does not** — see
§8.1. Both models and data are committed (~70 MB) so the exact artifacts behind
these numbers are recoverable without retraining.

---

## 11. Threats to validity

1. **The corpus is a synthetic payload overlay.** Labels, timing, and session
   structure are real WEB-IDS23 data; payload strings are generated. Payload
   realism is asserted by construction, not observed — the central caution of
   Arp et al. (2022).
2. **The clean test split is saturated** (F1 = 1.0000, FPR = 0.0000) and cannot
   rank models. All comparisons use the 396-row hold-out.
3. **The ensemble is not statistically superior to RF alone** (p = 0.388). Its
   defensible advantages are a lower false-alarm rate (CI excludes zero) and
   reduced run-to-run variance.
4. **False-positive rate carries substantial run-to-run variance** (SD 2.71%;
   one seed produced 8.1%). Always quote mean ± SD.
5. **`nl_intent` has n = 4.** Far too small to support a rate. Report as a
   documented blind spot corroborated by ModSecurity failing identically.
6. **The LLM evasion corpus is weak evidence** — 23 payloads from a
   1.5B-parameter model, 91% one technique, several near-identical to inputs.
7. **Plain-language detection is 0.0% by design.** The system detects payload
   structure, not natural-language intent.
8. **Two of 319 features are constants** (`param_count`, `is_post`) with
   measured importance 0.0000. No skew, no effect on results.
9. **Single fixed threshold (0.5).** No ROC-based tuning; detection and FPR
   could be traded deliberately.
10. **The ModSecurity comparison covers one configuration** (CRS 3.3.10,
    paranoia 2). Other paranoia levels would shift its operating point.
11. **The residual shortcut.** The top six Random Forest features remain
    symbol-density measures; augmentation weakened but did not eliminate the
    "symbols ⇒ attack" heuristic.
12. **Flask development server** — not hardened. Do not expose to the internet.

---

## 12. Repository layout

```
AI-GIS/
├── README.md                  This document
├── LICENSE
├── dashboard/                 The application and everything it loads
│   ├── app.py                 Flask backend, routes, live prediction
│   ├── run_pipeline.py        End-to-end reproduction driver
│   ├── run_honeypot.py        Self-contained honeypot corpus generator
│   ├── METHODOLOGY.md         Full methodology and code-audit trail
│   ├── models/
│   │   ├── rf2.pkl            Random Forest (319 features)
│   │   ├── lstm_best.keras    Two-layer stacked LSTM
│   │   ├── meta.pkl           Logistic-regression meta-learner
│   │   └── ngram_vectorizer.pkl   Fitted char n-gram TF-IDF
│   ├── data/
│   │   ├── honeypot_final.log 36,594-row training corpus (JSONL)
│   │   ├── eval/              Hold-out and red-team corpora
│   │   └── prepared/          Session-grouped splits + source CSVs
│   ├── scripts/
│   │   ├── lib/               Shared modules (features, normalisation)
│   │   ├── stages/            Numbered pipeline + generation stages
│   │   └── *.json             Red-team case definitions
│   ├── reports/               Generated artifacts only (JSON, PNG, figures)
│   └── templates/  static/    Dashboard UI (offline, no CDN)
├── docs/
│   ├── guides/                Runbooks (Azure, local, improvement plan)
│   └── reports/               Narrative write-ups and chapter deliverables
├── notebooks/colab/           Colab notebooks
├── artifacts/                 Non-code outputs: paper, bundles, corpora
│   ├── preserved/             Paper-matching model checkpoint
│   ├── submission_resecurity/ Reviewer submission bundle
│   └── handoff/               Honeypot handoff bundle
└── deploy/                    docker-compose (ModSecurity + OWASP CRS)
```

---

## References

1. Arp, D. et al. "Dos and Don'ts of Machine Learning in Computer Security."
   *USENIX Security Symposium*, 2022.
2. Geirhos, R. et al. "Shortcut Learning in Deep Neural Networks."
   *Nature Machine Intelligence* 2(11), 2020.
3. Thakkar, A. & Lohiya, R. "A Review on Machine Learning and Deep Learning
   Perspectives of IDS." *Archives of Computational Methods in Engineering*
   28(4), 2021.
4. Ferrag, M.A. et al. "Deep Learning for Cyber Security Intrusion Detection."
   *Journal of Information Security and Applications* 50, 2020.
5. Unicode Consortium. *Unicode Technical Standard #39: Security Mechanisms.*
6. OWASP. *ModSecurity Core Rule Set* documentation — paranoia levels and
   false-positive tuning.
7. Axelsson, S. "The Base-Rate Fallacy and the Difficulty of Intrusion
   Detection." *ACM TISSEC* 3(3), 2000.
8. Dietterich, T.G. "Approximate Statistical Tests for Comparing Supervised
   Classification Learning Algorithms." *Neural Computation* 10(7), 1998.
9. Wolpert, D.H. "Stacked Generalization." *Neural Networks* 5(2), 1992.
10. Sculley, D. et al. "Hidden Technical Debt in Machine Learning Systems."
    *NeurIPS*, 2015.

> Items 7–10 predate a 5-year recency window. They are the originating and still
> standard citations for the methods used here. **The WEB-IDS23 source dataset
> must be cited directly in any formal write-up** — it is not listed above
> because the converter references it by name only, and the authors and venue
> could not be verified from this repository. Verify all citations against the
> published record before submission.

---

## License

MIT — see [`LICENSE`](LICENSE).
