# Threshold-tuning attempt — honest result: no significant improvement found

**Date:** 2026-09-15
**Scope:** decision-threshold tuning only. No retraining, no new features, no
data changes, no code changes to `app.py` (still hardcoded to 0.5).

## What was tried

The stacked ensemble's live decision rule is `stacked_proba >= 0.5`
(`app.py:118`). That threshold was never tuned — it's the default midpoint.
The hypothesis: a different threshold might trade a small amount of FPR for
detection (or vice versa) and beat the current operating point.

## Attempt 1 — tune on the honeypot log's TEST split (FAILED, as expected)

Reconstructed the TEST split exactly as `18_train_stacked.py` does
(`prepare_honeypot_for_training.session_grouped_split`, seed 42) and swept
thresholds there. Result: TEST is **saturated** (100.00% detection, 0.00% FPR
at thr=0.5) — consistent with the "clean test split is saturated" finding
already documented in `FINAL_RESULTS.md` §6. A threshold picked on saturated
data is meaningless and, as a sanity check, applying the resulting threshold
(0.06) to the real 396-row adversarial hold-out **made things worse**:
FPR rose from 0.51% to 3.54% for a detection gain of only 1.5pp. Recorded in
`reports/threshold_tuning_results.json`. Discarded.

## Attempt 2 — 5-fold stratified CV directly on the adversarial hold-out

To avoid both leakage and the saturation problem, threshold selection was
done via 5-fold stratified cross-validation **on the 396-row adversarial
hold-out itself** (`data/eval/holdout_eval.csv`):

- In each fold, a threshold is chosen using only the other 4/5 of the
  hold-out (minimize FPR subject to detection not dropping >0.5pp below the
  fold's own thr=0.5 baseline).
- That threshold is applied only to the held-out 1/5 — no row is ever
  scored with a threshold fit on itself.
- Results are pooled across all 5 held-out folds for a leakage-free estimate
  on the full 396 rows.

Chosen thresholds landed around **0.11–0.13** in every fold (vs. the
current 0.5).

| | BEFORE (thr=0.5) | AFTER (CV-tuned, ~0.13) |
|---|---:|---:|
| Detection | 93.43% (185/198) | 94.44% (187/198) |
| FPR | 0.51% (1/198) | 1.01% (2/198) |
| F1 | 0.9635 | 0.9664 |

Two more attacks caught, one more false alarm, out of 396 rows total.

## Significance check

McNemar exact test, paired, before-vs-after on the same 396 rows:
- Discordant pairs: b=1 (before right / after wrong), c=2 (before wrong /
  after right) — **3 discordant rows out of 396**.
- p = 1.0000 — **not significant**.

## Conclusion — do not ship this

The numeric direction (lower threshold → +1pp detection, +0.5pp FPR) is
real and reproducible, but the entire effect is **3 rows** on a 396-row set.
That is indistinguishable from noise (p=1.0). The current committed model
is already operating in a regime where the adversarial hold-out is too
small to say whether 0.5 or 0.13 is the better threshold — claiming an
"improvement" here would not survive scrutiny.

**No changes were made to `app.py` or any committed model.** The two
threshold-sweep JSON files are kept for the record:
- `reports/threshold_tuning_results.json` (attempt 1, discarded direction)
- `reports/threshold_tuning_cv_results.json` (attempt 2, the CV result above)

## What would actually move the score

Threshold tuning has no more headroom at this hold-out size — the honest
next steps, in order of leverage, are:

1. **Grow the adversarial hold-out set.** 396 rows can't resolve a 3-row
   effect. This is the actual bottleneck, not the model or the threshold.
2. **The `nl_intent` blind spot (0% detection, n=4)** is the one segment
   with real, non-marginal headroom — but `FINAL_RESULTS.md` §2 already
   shows that training on it costs a 4× increase in false alarms. Any fix
   here needs a feature/architecture change (e.g. a semantic/embedding
   signal that doesn't rely on payload structure), not a threshold.
3. Re-run the existing 5-seed multirun study (`22_multirun_variance.py`)
   after any real change, per the project's own methodology — single-run
   numbers on this dataset size are not reliable evidence either way.
