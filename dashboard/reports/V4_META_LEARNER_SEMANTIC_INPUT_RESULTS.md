# Meta-learner semantic input (v4): the fix v3 diagnosed, implemented

**Date:** 2026-09-15
**Scope:** meta-learner input shape change (2 → 7 columns), no new data, same
RF/LSTM architecture. Touches `app.py`'s live inference path and every eval
script — the widest-reaching change in this series.

## What this fixes and why

`V3_KEYWORD_SEQUENCE_FEATURES_RESULTS.md` diagnosed precisely why the 5
keyword-sequence features (v3) didn't move the shipped ensemble despite
genuinely raising RF's own confidence on `semantic_sqli` cases (0.6–0.7, up
from ~0.1–0.3): the meta-learner is a logistic regression on
`[rf_proba, lstm_proba]` alone, with coefficients `[6.58, 5.76]` and
intercept `-6.03`. Solving the boundary: RF must exceed ~0.92 to override a
silent LSTM (which is structurally always silent on low-symbol text). RF's
new 0.6–0.7 never got there.

The fix implemented here: give the meta-learner the 5 semantic flags
directly, not just RF's scalar probability. New input:
`[rf_proba, lstm_proba, has_or_near_equals, has_or_comparison_keyword,
has_auth_bypass_phrase, has_keyword_sequence_sqli, has_where_true_phrase]`
(defined once as `SEMANTIC_META_COLS` in `build_rf_features_v2.py`, imported
everywhere else to avoid the duplication risk `RF_COLS` already had).

**Every call site that constructs the meta-learner's input was updated**,
verified by grep, not assumed: `app.py`, `18_train_stacked.py` (fit + eval),
`17_evaluate_csv.py`, `19_eval_by_type.py`, `20_significance_holdout.py`,
`22_multirun_variance.py` (fit + eval), `23_claude_evasion_probe.py`,
`24_polymorphic_probe.py` (both call sites), `15_evaluate_llm_corpus.py`,
`evaluate_against_mock_attackers.py`, `16_claude_redteam.py` — 12 call sites,
10 files. (`13_statistical_significance.py` and `14_ablation_study.py` fit
their own from-scratch meta-learner on a different, older feature set and
are out of scope.)

## What actually happened — and it's a smaller effect than hoped, honestly reported

**The meta-learner barely learned to use the new flags.** Fitted
coefficients:

| Input | Coefficient |
|---|---:|
| `rf_proba` | 6.551 |
| `lstm_proba` | 5.763 |
| `has_or_near_equals` | 0.029 |
| `has_or_comparison_keyword` | 0.000 |
| `has_auth_bypass_phrase` | 0.200 |
| `has_keyword_sequence_sqli` | 0.427 |
| `has_where_true_phrase` | 0.015 |

**Why so small:** these flags fire on a tiny fraction of the ~5,463-row VAL
split logistic regression fits on — plain L2-regularized logistic
regression has little power to learn a large coefficient for a rare binary
feature, and more importantly, **it cannot express the actual rule I
wanted** ("trust RF alone when a semantic flag fires, ignore LSTM's
silence") — that is an *interaction* effect (flag × rf_proba), and a linear
model without explicit interaction terms can only add a small independent
bump, not override another term conditionally.

## Measured result (single seed) — marginal gain, one new regression

- `semantic_sqli` (aggressive tier): 1/10 → **2/10**. One additional case
  (`select everything from the accounts table please`) crossed 0.5.
- `semantic_xss`, `past_window`, `claude_evasion_probe.py`: **unchanged**
  (5/8, 3/4, 10/15 respectively) — same as the v3-only state.
- **New regression found, not hidden:** Tier 1 (400 syntactic mutations),
  which held at a perfect 400/400 across every prior change in this series,
  dropped to **399/400**. The evading case: `"1'; drop tABle USeRS--"` —
  rf=0.9085 (confident), lstm=0.0079 (near-silent on this specific case
  mutation), stacked=**0.4919** — just under threshold. Refitting the
  meta-learner with 5 extra dimensions shifted `rf_proba`'s and
  `lstm_proba`'s own coefficients very slightly (6.58→6.55, 5.76→5.76,
  intercept -6.03 unchanged to 3 d.p.), enough to flip one boundary case
  that was previously just above 0.5.

This is the honest shape of the result: a small, traceable gain on the
targeted class, paid for by a small, traceable loss on a previously-perfect
one — both are boundary effects on individual cases, which is exactly what
a single seed cannot distinguish from noise.

## Multi-seed validation

See the follow-up in this same file / conversation for the 3-seed,
2-layer-LSTM result (`reports/multirun_variance_v4meta_2layer.json`),
compared against the v3-only 3-seed baseline
(detection 97.64 ± 1.54%, FPR 3.37 ± 1.05%, F1 0.9715 ± 0.0130), before
treating either the gain or the regression as real.
