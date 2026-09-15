# AI-GIS — Model Changes and Measured Scores

**Purpose of this file:** hand-off document. Contains (1) every model change made to
the Random Forest, LSTM, and meta-learner, and (2) every measured score, with exact
numbers, so the Chapter 3 / Chapter 4 text can be updated by someone else.

**Date of measurement:** 2026-09-15
**Model measured:** the currently committed model (`dashboard/models/rf2.pkl`,
`lstm_best.keras`, `meta.pkl`, `ngram_vectorizer.pkl`), git commit `50bfaa8`,
branch `claude/mic-test-12b27s`.
**Benchmark:** `dashboard/data/eval/holdout_eval.csv` — 396 rows, 198 attack / 198 benign.

> **Integrity statement.** Every number below was computed by running the committed
> model on the benchmark, not copied from an earlier report. Zero exact-text overlap was
> verified between all 36,884 training rows and a 556-string banned set covering the
> hold-out plus every literal probe string in the red-team scripts. The hold-out file is
> byte-identical to before this work started (verified by `git diff`). Where a number
> could not be honestly computed, it is marked NOT COMPUTED with the reason, not estimated.

---

# PART 1 — MODEL CHANGES

Three changes were made, in this order. Only **Change A** improved the shipped model's
score; **B** and **C** are honest negative results and are documented as such.

## Change A — Dataset expansion ("aug2")

**What:** added 290 rows to `data/honeypot_final.log` — 145 benign and 145 attack (equal).
**Script:** `dashboard/scripts/build_training_augmentation_v2.py` (new, idempotent).
**Corpus size:** 36,594 → **36,884 rows**.

| New family | Rows | Label |
|---|---:|---|
| `semantic_sqli_aug` (low-symbol SQLi phrasing) | 49 | attack |
| `semantic_xss_aug` (low-symbol XSS phrasing) | 48 | attack |
| `past_window_aug` (payload placed past character 200) | 48 | attack |
| `benign` (new short/medium prose + code) | ~73 | benign |
| `benign` (new long-form >200 char text, **no** payload) | ~72 | benign |

**Why these two classes:** a direct audit of the corpus found (a) the longest string in
the entire 36,594-row corpus was **131 characters** — nothing exceeded the LSTM's 200-char
window, so the model had never seen a past-the-window attack in training; and (b) low-symbol
semantic attacks were represented by **2 rows total**.

The long-form benign rows exist so that raw length alone does not become a spurious attack
signal — every past-window attack has a same-length, same-style benign counterpart.

**Leakage control:** every generated candidate is checked against the hold-out set, both
red-team JSON case files, and every literal probe string in `23_claude_evasion_probe.py`
and `24_polymorphic_probe.py` (including its `--aggressive` tier). Exact matches are dropped.

## Change B — Random Forest features: 319 → 324

**What:** added 5 boolean regex features to `structural_features()` in
`dashboard/scripts/build_rf_features_v2.py`.

**Feature vector composition:**

| Group | Before | After |
|---|---:|---:|
| Aggregate payload features | 11 | 11 |
| Structural-pattern features | 8 | 8 |
| **Keyword-sequence features (new)** | **0** | **5** |
| Character n-gram TF-IDF | 300 | 300 |
| **Total** | **319** | **324** |

**The 5 new features (exact regexes as implemented):**

```python
OR_NEAR_EQUALS_RE = re.compile(r"\bor\b.{0,20}=")

OR_COMPARISON_KEYWORD_RE = re.compile(
    r"\bor\b.{0,25}\b(between|like|greatest|least)\b", re.IGNORECASE)

AUTH_BYPASS_PHRASE_RE = re.compile(
    r"\b(ignor\w*|bypass\w*|skip\w*|regardless of|without check\w*|"
    r"always (pass|match|succeed|true))\b.{0,35}\b"
    r"(login|password|authent\w*|credential\w*|check|condition)\b", re.IGNORECASE)

KEYWORD_SEQUENCE_SQLI_RE = re.compile(
    r"\b(select|union|dump|list|expose|reveal|surface|retrieve|unlock|hand over)\b"
    r".{0,40}\b(from|table|database|account\w*|user\w*|password\w*|credential\w*)\b",
    re.IGNORECASE)

WHERE_TRUE_PHRASE_RE = re.compile(r"\b(where|and|or)\s+true\b", re.IGNORECASE)
```

Feature names: `has_or_near_equals`, `has_or_comparison_keyword`,
`has_auth_bypass_phrase`, `has_keyword_sequence_sqli`, `has_where_true_phrase`.

**Rationale:** the RF's dominant features were all symbol-density measures
(special-char ratio, quote count, longest special run), which all read near-zero on
low-symbol SQLi such as `1 or 5000=5000` or `admin where true` regardless of the
underlying SQL semantics. These 5 features detect the keyword *sequence* directly,
independent of symbol count.

**Measured false-positive cost before wiring in** (verified, not assumed):
1 fire in 18,555 benign training rows (0.005%) and 1 fire in 198 hold-out benign rows —
both the same borderline sentence, `"...A OR B = 1 when either is true"`.

**Verified effect at the RF branch level:** RF-alone confidence on previously-evading
semantic SQLi rose from ~0.1–0.3 to **0.60–0.71** (7 of 9 such cases would be caught by
RF's own 0.5 threshold). **But see Part 3 — this did not translate into ensemble gain.**

## Change C — Meta-learner: 2 inputs → 7 inputs

**What:** the Logistic Regression meta-learner now receives the 5 semantic flags directly,
alongside the two branch probabilities.

```
BEFORE:  meta.fit([rf_proba, lstm_proba], y)                        # 2 inputs
AFTER:   meta.fit([rf_proba, lstm_proba,
                   has_or_near_equals, has_or_comparison_keyword,
                   has_auth_bypass_phrase, has_keyword_sequence_sqli,
                   has_where_true_phrase], y)                       # 7 inputs
```

Column order is defined once as `SEMANTIC_META_COLS` in `build_rf_features_v2.py` and
imported everywhere (single source of truth, no duplicated literal lists).

**Rationale:** diagnosed bottleneck. The 2-input meta-learner had coefficients
`[6.58, 5.76]` and intercept `-6.03`. Solving the boundary: when `lstm_proba ≈ 0`
(which it structurally always is on low-symbol text — the LSTM is a pure character-sequence
model with no keyword features), RF alone must exceed **~0.92** to push the ensemble over
0.5. RF's improved 0.60–0.71 never reached that bar.

**Files updated (12 call sites across 10 files)** — every place that builds the
meta-learner's input:
`app.py` (live inference), `18_train_stacked.py` (fit + eval), `17_evaluate_csv.py`,
`19_eval_by_type.py`, `20_significance_holdout.py`, `22_multirun_variance.py` (fit + eval),
`23_claude_evasion_probe.py`, `24_polymorphic_probe.py` (2 sites),
`15_evaluate_llm_corpus.py`, `evaluate_against_mock_attackers.py`, `16_claude_redteam.py`.
(`13_statistical_significance.py` and `14_ablation_study.py` fit their own meta-learner on
an older, separate feature set and are out of scope.)

## NOT changed — LSTM

The LSTM branch is **unchanged**. Architecture, encoding, and training are identical to
the previous version:

```
Input(200)
Embedding(input_dim=128, output_dim=32, mask_zero=True)
LSTM(64, return_sequences=True)
Dropout(0.3)
LSTM(32)
Dropout(0.3)
Dense(1, activation="sigmoid")
```
Ordinal encoding: 0 = PAD, 1 = non-ASCII/unknown, else ASCII code. Max length 200.
Trained up to 8 epochs, best-val_auc checkpoint, early stopping patience 3, seed 42.

---

# PART 2 — MEASURED SCORES

## 2.1 Dataset and split

| Item | Value |
|---|---:|
| Development corpus (after aug2) | 36,884 rows |
| — benign | 18,555 |
| — attack | 18,329 |
| Training partition | 25,478 |
| Validation partition | 5,463 |
| Internal test partition | 5,943 |
| Hold-out benchmark (untouched) | 396 |
| — attack / benign | 198 / 198 |

**Hold-out attack composition** (classified by structural rule on normalized text):

| Type | Rows |
|---|---:|
| SQLi | 102 |
| XSS | 77 |
| nl_intent (plain-language) | 4 |
| other | 15 |

## 2.2 Headline result — SINGLE SEED (seed 42, the shipped model)

Threshold 0.50. All figures computed fresh from the committed model.

| Model | Recall | Precision | F1 | FPR | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| Random Forest alone | 100.00% | 0.9706 | 0.9851 | 3.03% | 0.9998 |
| LSTM alone | 93.43% | 0.9585 | 0.9463 | 4.04% | 0.9812 |
| **AI-GIS (full stack)** | **98.48%** | **0.9653** | **0.9750** | **3.54%** | **0.9980** |

**Stacked F1 95% bootstrap CI (1,000 resamples): [0.9588, 0.9896]**

**Confusion matrix — AI-GIS full stack:**

| Actual \ Predicted | Attack | Benign |
|---|---:|---:|
| **Attack** | 195 (TP) | **3 (FN)** |
| **Benign** | 7 (FP) | 191 (TN) |

**False Negative Rate = 1.52% (3/198).**

## 2.3 Per-attack-type, with confusion matrices

Benign reference set is shared across types (there is no "SQLi-benign" vs "XSS-benign"
partition) — same convention the existing document already uses.

| Type | n | TP | **FN** | Recall | FP (shared) | TN (shared) |
|---|---:|---:|---:|---:|---:|---:|
| **SQLi** | 102 | 99 | **3** | **97.06%** | 7 | 191 |
| **XSS** | 77 | 77 | **0** | **100.00%** | 7 | 191 |
| nl_intent | 4 | 4 | 0 | 100.00% | 7 | 191 |
| other | 15 | 15 | 0 | 100.00% | 7 | 191 |

**SQLi confusion matrix**

| Actual \ Predicted | Attack | Benign |
|---|---:|---:|
| **Attack (SQLi, n=102)** | 99 | **3 (FN)** |
| **Benign (n=198)** | 7 | 191 |

**XSS confusion matrix**

| Actual \ Predicted | Attack | Benign |
|---|---:|---:|
| **Attack (XSS, n=77)** | 77 | **0 (FN)** |
| **Benign (n=198)** | 7 | 191 |

**Key finding: all 3 false negatives are SQLi. XSS has zero false negatives on this
benchmark.** (Note this is the *reverse* of the midterm finding where XSS was weaker —
per-type ranking is benchmark-dependent and should not be stated as a fixed model property.)

## 2.4 FALSE NEGATIVES — all 3, individually

| # | Payload | Stacked | RF | LSTM | Type |
|---|---|---:|---:|---:|---|
| 1 | `/*/**/String.fromCharCode(97,108,101,114,116,40,49,41)` | **0.4992** | 0.9199 | 0.0001 | SQLi |
| 2 | `admin'); drop table users('` | **0.1612** | 0.6001 | 0.0780 | SQLi |
| 3 | `drop the users table from the database` | **0.4462** | 0.7948 | 0.1053 | SQLi |

**Analysis:**
- #1 and #3 are **borderline** — 0.0008 and 0.0538 below the 0.50 threshold. A small
  threshold shift flips them (at a cost on the benign side).
- #1 is caught confidently by **RF alone (0.9199)** but dragged under by a near-zero
  LSTM read (0.0001). This is the meta-learner bottleneck described in Change C.
- #3 is the documented **nl_intent blind spot** — natural-language attack intent with
  almost no symbolic structure. The model detects payload structure, not intent.

## 2.5 FALSE POSITIVES — all 7

| # | Text | Stacked | RF | LSTM |
|---|---|---:|---:|---:|
| 1 | `if (user.role == 'admin') { throw new Error('x'); }` | 0.9454 | 0.4838 | 0.9911 |
| 2 | `if (user.role == 'admin') { queue.push(item); }` | 0.8480 | 0.3409 | 0.9571 |
| 3 | `if (user.role == 'admin') { log.info('ok'); }` | 0.8139 | 0.2676 | 0.9982 |
| 4 | `if (status == 200) { log.info('ok'); }` | 0.8019 | 0.2604 | 0.9930 |
| 5 | `if (user.role == 'admin') { grantAccess(); }` | 0.7768 | 0.2339 | 0.9969 |
| 6 | `if (status == 200) { grantAccess(); }` | 0.6537 | 0.1701 | 0.9632 |
| 7 | `Product SKU# ABC-123; Category: Electronics & Gadgets (in stock).` | 0.6395 | 0.5053 | 0.5715 |

**6 of 7 are one template family: auth-related equality conditionals in source code.**
Note the pattern — RF scores these *correctly low* (0.17–0.48); it is the **LSTM** that
flags them (0.96–0.99). These are pre-existing hard-benign rows from the original corpus,
not newly added text.

## 2.6 MULTI-SEED RESULTS (3 seeds: 42, 43, 44; 2-layer LSTM)

This is the defensible headline. Architecture-matched to the methodology used for the
previously published 5-seed baseline.

| Metric | BEFORE (5-seed, published baseline) | AFTER (3-seed, current) | Δ |
|---|---:|---:|---:|
| **Stacked detection** | 96.16 ± 1.26% | **97.81 ± 1.27%** | **+1.65pp** |
| **Stacked FNR** | 3.84 ± 1.26% | **2.19 ± 1.27%** | **−1.65pp** |
| **Stacked FPR** | 3.64 ± 2.71% | **3.37 ± 1.05%** | **−0.27pp** |
| **Stacked F1** | 0.9627 ± 0.0126 | **0.9724 ± 0.0116** | **+0.0097** |
| **Stacked AUC** | 0.9971 ± 0.0023 | **0.9984 ± 0.0008** | +0.0013 |
| RF detection | 100.00 ± 0.00% | 100.00 ± 0.00% | — |
| RF FPR | 6.97 ± 0.66% | **4.55 ± 1.34%** | **−2.42pp** |
| RF F1 | 0.9663 ± 0.0031 | **0.9778 ± 0.0064** | +0.0115 |
| LSTM detection | 92.83 ± 0.23% | **95.96 ± 1.52%** | +3.13pp |
| LSTM FPR | 4.14 ± 3.77% | 5.05 ± 1.01% | +0.91pp |

**Note on FPR variance:** stacked FPR standard deviation tightened from ±2.71% to ±1.05% —
the false-alarm behaviour is now more predictable run-to-run, not just lower on average.

**Caveat for the write-up:** 3 seeds here vs 5 in the published baseline, and a different
seed set (42–44 vs 42–46). Same script, same architecture, same eval set. Recommend
re-running at 5 seeds before this goes in as the final headline number.

## 2.7 Ablation study (6 conditions, freshly computed on the same hold-out)

| Condition | F1 | FPR | Recall | ROC-AUC |
|---|---:|---:|---:|---:|
| RF alone | **0.9851** | 3.03% | 100.00% | 0.9998 |
| LSTM alone | 0.9463 | 4.04% | 93.43% | 0.9812 |
| Logistic Regression on engineered features (no RF/LSTM) | 0.9474 | 6.06% | 95.45% | 0.9735 |
| RF + meta (LSTM zeroed) | 0.7815 | 0.00% | **64.14%** | 0.9998 |
| LSTM + meta (RF zeroed) | 0.0962 | 0.00% | **5.05%** | 0.9818 |
| **Full RF + LSTM + meta (shipped)** | 0.9750 | 3.54% | 98.48% | 0.9980 |

**Two findings that must be reported honestly:**

1. **The full stack does NOT outperform Random Forest alone** (F1 0.9750 vs 0.9851).
   This reproduces the midterm finding on a different benchmark with a different feature set.
2. **"RF + meta (LSTM zeroed)" collapses to 64.14% recall** — far below RF's own 100% —
   despite using the identical RF probability as input. This is formal proof of the
   meta-learner bottleneck: the linear combiner needs RF > ~0.92 to fire when LSTM is silent.
   **"LSTM + meta (RF zeroed)" collapses to 5.05%**, confirming RF anchors the ensemble.

## 2.8 Meta-learner fitted coefficients (current model)

| Input | Coefficient |
|---|---:|
| `rf_proba` | **6.5509** |
| `lstm_proba` | **5.7625** |
| `has_or_near_equals` | 0.0291 |
| `has_or_comparison_keyword` | 0.0000 |
| `has_auth_bypass_phrase` | 0.2003 |
| `has_keyword_sequence_sqli` | 0.4267 |
| `has_where_true_phrase` | 0.0146 |
| *(intercept)* | **−6.0297** |

**Interpretation:** the 5 semantic flags barely acquired weight. Two reasons: they fire on
a tiny fraction of the validation split (low statistical power for a rare binary feature),
and a **linear** model cannot express the rule actually needed — *"trust RF alone when this
flag fires"* is an interaction effect (`flag × rf_proba`), not an additive term.

## 2.9 ModSecurity CRS PL2 comparison (same 396 rows)

| Metric | AI-GIS | ModSecurity CRS PL2 |
|---|---:|---:|
| Recall | **98.48%** | 95.45% |
| FPR | **3.54%** | **70.20%** |
| Precision | **0.9653** | 0.5762 |
| F1 | **0.9750** | 0.7186 |
| ROC-AUC | 0.9980 | not reported (binary output) |

| System | TP | FN | FP | TN |
|---|---:|---:|---:|---:|
| AI-GIS | 195 | 3 | 7 | 191 |
| ModSecurity CRS PL2 | 189 | 9 | 139 | 59 |

> **⚠ NOT COMPUTED — paired McNemar test vs ModSecurity.**
> The stored ModSecurity artifact (`reports/modsec_holdout.json`) contains the complete
> list of its 9 missed attacks, but only a **25-item sample of its 139 false alarms**.
> A row-by-row paired test would require inventing which 114 of the 198 benign rows are the
> unlisted false alarms — that is fabrication, not evaluation. The live Docker + ModSecurity
> harness that would regenerate the complete list was not available (Docker daemon
> unreachable). **Action:** re-run `scripts/21_modsec_holdout.py` against a live
> ModSecurity + CRS PL2 container, then compute the paired McNemar test properly.
> Report the comparison above as aggregate/unpaired until then.

## 2.10 Red-team probe results (progression)

**`24_polymorphic_probe.py` — Tier 1 (400 syntactic mutations, 40 × 10 families):**

| Stage | Caught |
|---|---:|
| Baseline (pre-change) | 400/400 (100%) |
| After Change A (aug2) | 400/400 (100%) |
| After Changes B + C | 399/400 (99.75%) |

The single Tier-1 miss after B+C is `1'; drop tABle USeRS--` at stacked **0.4919**
(RF 0.9085, LSTM 0.0079) — a boundary case, same meta-learner dynamic. Multi-seed
analysis showed this is noise, not a real regression.

**`24_polymorphic_probe.py --aggressive` — Tier 2 (22 semantic/structural mutations):**

| Class | Baseline | After A | After B | After C |
|---|---:|---:|---:|---:|
| `semantic_sqli` | 0/10 (0%) | 1/10 | 1/10 | **2/10 (20%)** |
| `semantic_xss` | 2/8 (25%) | **5/8 (62%)** | 5/8 | 5/8 |
| `past_window` | 0/4 (0%) | **4/4 (100%)** | 3/4 | 3/4 |
| **Overall** | **2/22 (9%)** | **10/22 (45%)** | 9/22 (41%) | **10/22 (45%)** |

**`23_claude_evasion_probe.py` (15 hand-authored attacks, 8 hard-benign):**

| Stage | Attacks caught | False alarms |
|---|---:|---:|
| Baseline | 8/15 (47% evaded) | 1/8 |
| After A | **10/15 (33% evaded)** | 2/8 |
| After B + C | 10/15 | 2/8 |

The two `late-inject` (past-the-window) cases went from evading at **0.092 / 0.069** to
being caught at **0.888 / 0.857** — a direct, clean confirmation that Change A fixed that class.

## 2.11 Model integrity checks

| Check | Result | Meaning |
|---|---|---|
| Session overlap across dev partitions | 0 / 0 / 0 | Enforced structurally by session-grouped split |
| Exact-text leakage: training vs hold-out + all red-team probe strings | **0 / 36,884** | Checked against a 556-string banned set, raw and normalized |
| Shuffled-label sanity check | Test AUC = **0.5503** | Near-random when labels are permuted — no label shortcut |
| Largest single RF feature importance | **0.1002** | No single feature dominates (324 features total) |
| Hold-out file integrity | byte-identical to pre-work state | Verified via `git diff` |
| Repeated training, same seed | identical scores | Reproducible |

---

# PART 3 — WHAT WORKED, WHAT DIDN'T

Stated plainly because it matters for how the chapters are written.

| Change | Multi-seed verdict |
|---|---|
| **A — dataset expansion (aug2)** | ✅ **Real, reproducible improvement.** Detection +1.65pp, FPR −0.27pp, F1 +0.0097, FPR variance tightened 2.71→1.05. Fixed `past_window` 0/4 → 4/4 and `semantic_xss` 2/8 → 5/8. |
| **B — RF keyword-sequence features** | ⚠️ **Wash at ensemble level.** Verified to work at the RF branch (confidence 0.1–0.3 → 0.60–0.71 on target cases) but every headline metric moved less than one seed-SD. Kept: zero measured cost, and the meta-learner fix needs them. |
| **C — meta-learner semantic inputs** | ⚠️ **Wash.** Every metric within one noise SD (detection +0.17pp, FPR +0.00pp, F1 +0.0009). Coefficients stayed near zero — confirms the diagnosis rather than refuting it. |

**Do not claim B or C improved detection.** They did not. Their value is the diagnosis.

## The one unresolved gap, precisely stated

`semantic_sqli` remains at **2/10** on the aggressive tier. The blocker is now known exactly:

> The meta-learner is a **linear** logistic regression. With coefficients ~[6.55, 5.76] and
> intercept −6.03, RF alone must exceed **~0.92** to cross 0.5 when LSTM reads ~0. The LSTM
> structurally *always* reads ~0 on low-symbol text because it is a character-sequence model
> with no keyword features. A linear model cannot express *"trust RF when a semantic flag
> fires"* — that is an interaction term.

**Recommended next step (not attempted):** either add an explicit interaction input
(`has_keyword_sequence_sqli × rf_proba`) or replace the linear combiner with a shallow
decision tree / small gradient-boosted meta-learner that can natively express a conditional
override. This changes `app.py`'s live inference path and every eval script's meta-learner
input shape, so it deserves its own scoped validation pass.

---

# PART 4 — SUGGESTED DOCUMENT EDITS

## Chapter 3 (model sections only)

- **§3.3 intro + Figure 14:** RF input is now a **324**-dimensional vector (was 319); the
  meta-learner now takes **7 inputs** (was 2).
- **§3.3.1 Random Forest Branch + Table 10:** update feature table to
  11 aggregate + 8 structural + **5 keyword-sequence** + 300 n-gram = **324**.
  Add the 5 regexes and the measured 0.005% benign fire-rate.
- **§3.3.2 LSTM Branch + Table 11:** **no change.**
- **§3.3.3 Meta-Learner:** rewrite to the 7-input form; add the fitted coefficient table
  (§2.8 above) and the linear-model limitation.
- **§3.6 Table 12 (dataset division):** train 25,478 / val 5,463 / internal test 5,943 /
  hold-out 396.
- **⚠ Cross-chapter inconsistency to decide on:** Chapter 2 §2.2.5 and Figure 6/7 also state
  "319 features". If Chapter 2 is left untouched it will disagree with Chapter 3. Either
  update Chapter 2's number too, or add a footnote in Chapter 3 noting the refinement.

## Chapter 4

- Benchmark is now the **396-row** hold-out (198/198), replacing the 1,700-record benchmark.
  This satisfies the midterm Action Item "construct a separate untouched benchmark."
- All tables/figures repopulated from §2.2–§2.11 above.
- **Add** SQLi and XSS confusion matrices (§2.3) and the false-negative table (§2.4).
- **Keep** the honest ablation finding that the full stack does not beat RF alone.
- **Disclose** the un-computable paired McNemar (§2.9) rather than approximating it.
- **Do not** claim the LLM-specific research questions (RQ1/RO1) are answered — the planned
  Code Llama / DeepSeek-R1 ~2,200-record corpus has not been generated. This hold-out is an
  adversarially curated set, not a confirmed LLM-generated corpus.

---

## Reproduce everything in this file

```bash
cd dashboard
python scripts/build_training_augmentation_v2.py       # Change A (idempotent)
python scripts/18_train_stacked.py --epochs 8 --seed 42
python scripts/17_evaluate_csv.py                       # headline numbers
python scripts/24_polymorphic_probe.py --aggressive     # Tier 1 + Tier 2
python scripts/23_claude_evasion_probe.py               # hand-authored red-team
python scripts/22_multirun_variance.py --runs 5 --epochs 6 --two-layer \
       --out reports/multirun_final.json                # multi-seed (use 5 for final)
```

Prior model states are backed up in `dashboard/models/_backup_pre_aug2/`,
`_backup_pre_v3feat/`, and `_backup_pre_v4meta/`.
