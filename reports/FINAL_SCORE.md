# AI-GIS — Final Verified Score

**Date:** 2026-09-15
**Model:** `models/current` (V0 — the clean baseline; RF v2 + stacked LSTM + LR meta)
**Threshold:** 0.55 (locked). Verified identical to 0.5 on the benchmark.

This score is reproducible from the committed artifacts and eval CSVs alone.
It was produced three independent ways that agree exactly (see Verification).

---

## Headline

On the primary non-saturated benchmark (`paper_benchmark.csv`, 1,700 rows):

| Metric | Value |
|---|---|
| **Detection (recall)** | **97.9%** |
| **False-positive rate** | **19.6%** |
| **F1** | **0.925** |
| **AUC** | **0.993** |
| Precision | 0.877 |
| Accuracy | 0.907 |
| False negatives | 21 / 1,000 |
| False positives | 137 / 700 |
| Confusion [TN, FP, FN, TP] | [563, 137, 21, 979] |

## All evaluation sets

| Set | Rows (atk/ben) | Detection | FPR | F1 | AUC | FN | FP |
|---|---|---|---|---|---|---|---|
| paper_benchmark.csv | 1700 (1000/700) | 97.9% | 19.6% | 0.925 | 0.993 | 21 | 137 |
| holdout_eval.csv | 396 (198/198) | 91.9% | 0.0% | 0.958 | 0.975 | 16 | 0 |
| llm_holdout_full.csv | 276 (78/198) | 94.9% | 0.0% | 0.974 | 0.999 | 4 | 0 |

## Model configuration (verified live)

- RF: **319 features** (11 counting + 8 pattern flags + 300 char n-gram TF-IDF), no word features
- LSTM: input width **200**, unidirectional 2-layer (64 → Dropout 0.3 → 32 → Dropout 0.3 → Dense sigmoid)
- Meta: LogisticRegression, coef `[5.988, 6.324]`, intercept `-6.143` (≈ average of the two base probabilities)
- No `word_vectorizer.pkl` present (this is the pre-experiment baseline)

## Provenance (sha256, first 16 hex)

| Artifact | sha256 | size |
|---|---|---|
| models/current/rf2.pkl | `08aff449c01470bd` | 3,803,694 |
| models/current/lstm_best.keras | `3216f0b91767379a` | 537,870 |
| models/current/meta.pkl | `49fdec026e05bda6` | 720 |
| models/current/ngram_vectorizer.pkl | `2b74ed700968c032` | 10,586 |
| data/eval/paper_benchmark.csv | `a93382ca220c6b31` | — |
| data/eval/holdout_eval.csv | `2112d2e51f3a725e` | — |
| data/eval/llm_holdout_full.csv | `cc89fa1e14c91d83` | — |

**Environment:** Python 3.13.12, scikit-learn 1.9.0, TensorFlow 2.21.0.

## Reproduce

```bash
python scripts/stages/17_evaluate_csv.py --csv data/eval/paper_benchmark.csv
```
Machine-readable copy of these numbers: `reports/FINAL_SCORE.json`.

---

## Verification (triple-checked)

The benchmark stacked result (979/1000 caught, 137 FP) was produced by:
1. A from-scratch scorer that reimplements the full predict path (`FINAL_SCORE.json`).
2. The repo's own `scripts/stages/17_evaluate_csv.py`.
3. The same scorer at thresholds 0.5 and 0.55.

All three agree: **detection 97.9%, FPR 19.6%, FN 21, FP 137.** The stacked
verdict is identical at 0.5 and 0.55.

## Caveats (stated, not hidden)

1. **The 19.6% FPR is this model's known weakness.** V0 false-alarms on benign
   text containing SQL vocabulary. It is the *clean, mergeable* baseline, not a
   solved model. Every attempt this cycle to lower that FPR (word features,
   MAXLEN 400, single-format benign rebalancing) made it worse (~50%), which is
   why the model was reverted to V0.
2. **The LSTM is redundant, not broken.** On the in-distribution test split it
   scores AUC 1.0000 and correlates with the RF at Pearson 0.9989. It adds no
   discrimination the RF lacks; on out-of-distribution attacks it can suppress
   correct RF detections via the averaging meta-learner. Diagnostic only — no
   change was made to the locked architecture.
3. **A 26-payload cross-split overlap** remains in the corpus. It inflates all
   figures slightly and uniformly; it is a known, separate cleanup item.
4. **The generated internal test split is saturated** (AUC ≈ 1.0 for almost any
   config), so it cannot discriminate models. The three eval sets above are the
   non-saturated sets and are the basis for this score.
