# 2-layer BiLSTM vs 2-layer LSTM — measured A/B

Trained 2026-08-26. Both bundles use identical data, split, seed (42),
preprocessing and meta-learner; the ONLY variable is directionality.

    models/         LSTM(64,seq) -> LSTM(32)                 41,377 params
    models_bilstm/  Bi(LSTM 64,seq) -> Bi(LSTM 32)           95,041 params  (2.30x)

BiLSTM training: EarlyStopping at epoch 5, best val_auc 1.0000 (epoch 1-2),
weights restored to best. ~76 min CPU.

## Clean validation: a tie, and uninformative

Both architectures sit at val_auc 0.9998-1.0000. The clean test set is
saturated and cannot discriminate between them. All signal is in the
held-out and robustness suites below.

## Held-out corpora (stacked ensemble)

| suite                       | LSTM                     | BiLSTM                   |
|-----------------------------|--------------------------|--------------------------|
| llm_holdout_real (n=276)    | rec 94.87% spec 100.00%  | rec 96.15% spec  99.49%  |
| evasion_curated  (n=38)     | rec 95.65% spec 100.00%  | rec 95.65% spec  93.33%  |

BiLSTM buys +1.28pp recall on the real LLM holdout and loses specificity on
both. F1 is effectively unchanged (97.37% vs 97.40% on the LLM holdout).

## Padding robustness (78 real holdout attacks, stacked)

| variant             | LSTM   | BiLSTM |
|---------------------|--------|--------|
| bare                | 74/78  | 75/78  |
| leading 40 spaces   |  8/78  | **66/78** |
| leading 100 spaces  |  6/78  | 62/78  |
| trailing 40 spaces  |  2/78  |  6/78  |
| trailing 100 spaces |  2/78  |  2/78  |
| 20 leading + 20 trailing | 1/78 | 5/78 |

**This is the one real difference.** The BiLSTM largely fixes LEADING padding
(8 -> 66) because its backward pass reads the payload before reaching the
padding. It does essentially nothing for TRAILING padding (2 -> 6), because
the forward pass is still terminated by the space run and the backward pass
starts inside it.

A prediction made before this ran -- that bidirectionality would not help
because the attack is symmetric -- was WRONG for the leading case and right
for the trailing case.

## False positives

BiLSTM introduces one on HARD_BENIGN that the baseline does not have:

    "Smith & Sons Law Firm LLC"    uni=0.015   bi=0.886

## Conclusion

**Not worth adopting as-is.** 2.3x the parameters and ~76 min of training buys
+1.28pp recall on one holdout, costs specificity on two, adds a false positive
on a 15-row benign set, and fixes only half of the padding evasion.

The trailing-space evasion -- the one that takes the ensemble from 74/78 to
2/78 -- is NOT solved by architecture. It is a preprocessing defect
(`normalize_text()` does not strip) and the one-line fix restores the full
score on BOTH architectures. Do that first; see
reports/FINDING_trailing_space_evasion.md.

Reproduce: `python scripts/28_compare_arch.py --a models --b models_bilstm`
Raw numbers: reports/arch_comparison.json
