# Evaluation artifacts

Every JSON in this folder was generated **on this machine, from the models
committed in `../models/`** — `rf2.pkl`, `lstm_best.keras`, `meta.pkl`.

This matters: the upstream `ElijahQuibin/AIGIS` repository ships result JSONs
produced from a *different* model set (`final_rf_v2.pkl`,
`lstm_best_checkpointed.keras`) that is not committed there. Those numbers do
not match these, so they were regenerated rather than imported.

| File | Produced by | External dependency |
|------|-------------|---------------------|
| `statistical_significance.json` | `scripts/13_statistical_significance.py` | none |
| `ablation_study_results.json` | `scripts/14_ablation_study.py` | none |
| `llm_corpus_results.json` | `scripts/15_evaluate_llm_corpus.py` | corpus from script 11 |
| `modsec_baseline_results.json` | `scripts/12_evaluate_modsec_baseline.py` | **Docker** (not yet run) |

## Environment

- scikit-learn **1.8.0** — pinned, because the committed models were trained
  with it. Unpickling under another minor version warns and may alter results.
- Seed 42 throughout.

## Divergences from the upstream numbers

Two are worth knowing before citing anything:

1. **McNemar, stacked vs LSTM.** Upstream reports p = 0.023 (significant).
   Regenerated here: p = 0.4795 (**not** significant), b = 2 rather than 7.
   The local LSTM disagrees with the ensemble on fewer rows.
2. **Ablation condition 5.** Reported as F1 = 0.0 alongside AUC-ROC = 1.0. That
   is a thresholding artifact — zeroing the RF input pushes all probabilities
   under 0.5. `Combined_at_best_threshold` records the corrected value
   (F1 ≈ 0.9998 at t = 0.01).

## Two bugs fixed in the ported scripts

- **`14_ablation_study.py` family masks** matched the literal strings `"sqli"`
  and `"xss"`, but this honeypot log labels attacks by sub-family
  (`union_based`, `stored`, `dom_based`, …). Both subsets were silently empty,
  which is why every `SQLi_Only` / `XSS_Only` block upstream reads 0.0. Now
  mapped to sub-families.
- **Fixed 0.5 threshold** in the same script, as described above; each
  condition now also reports metrics at its own best-F1 threshold.
