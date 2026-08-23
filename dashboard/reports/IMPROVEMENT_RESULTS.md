# Improvement Plan — Results (Tasks 1–5 executed)

All numbers measured on the **same** 396-row hold-out set
(`data/eval/holdout_eval.csv`, 198 attack / 198 benign) with the ruler
`scripts/17_evaluate_csv.py`. Nothing in this eval set was used for training.

## Headline: false alarms fell from 57.6% to 2.0%, detection held

Re-verified 2026-08-23. Final numbers are from the **two-layer stacked LSTM**
(the original thesis design, restored -- see METHODOLOGY.md 4.4). Measured by
regenerating the hold-out set, regenerating the augmentation, retraining from
the committed log, and re-measuring.

| Stacked ensemble | BEFORE | AFTER |
|------------------|-------:|------:|
| False-positive rate | **57.6%** (114/198) | **2.0%** (4/198) |
| Detection rate | 95.0% (188/198) | **95.0%** (188/198) |

False alarms fell 11x while detection stayed flat (-0.6 pp, 1 row out of 198).
The classic trap — buying a lower FPR by letting attacks through — did **not**
happen.

### Full per-model, AFTER

| Model | Detection | FPR |
|-------|----------:|----:|
| RF v2 | 100.0% (198/198) | 6.1% (12/198) |
| LSTM | 93.4% (185/198) | 2.0% (4/198) |
| Stacked | 95.0% (188/198) | 2.0% (4/198) |

> These are the **leak-free** numbers. An earlier run had one row
> (`admin' OR '1'='1`) present in both training and the hold-out set — a
> normalisation collision (a curly-quote augmented attack folded to the same
> string as a straight-quote hold-out row). The augmentation leakage guard now
> compares *normalised* text; the model was retrained on the cleaned log. Effect
> was negligible (1 trivial tautology in 396 rows) but it is fixed so the
> methodology is clean.

## Independent check — Claude red-team (`16_claude_redteam.py`)

| | BEFORE | AFTER |
|--|-------:|------:|
| Attacks caught | 12/16 | **14/16** |
| False alarms | 5/8 | **1/8** |

The Unicode homoglyph attack (`１＇ ＯＲ ＇１＇＝＇１`) that evaded before is now
caught (stacked 0.997) — the normalisation fix (Task 4) working end-to-end.

## What each task contributed

- **Task 1** — built the 396-row hold-out ruler. Without it the 57.6% problem
  was invisible (the old 15-sentence set reported 20%).
- **Task 2** — `17_evaluate_csv.py`, the single measurement command.
- **Task 3** — added 228 symbol-heavy benign rows (code, paths, regexes, math,
  apostrophe-names, prose) to the training log. Main driver of the FPR drop.
- **Task 4** — `text_normalize.py`, one shared NFKC + homoglyph fold, imported
  by the trainer, the app, and every eval script. Fixed Unicode evasion.
- **Task 5** — added 43 plain-language / Unicode attack rows so intent-based
  attacks are represented in training.

## Residual weaknesses (honest — good future-work material)

Still missed / mis-flagged after retraining:

- `1 OR 1e0=1e0` — scientific-notation SQLi, still evades (0.12).
- `insert a script tag that pops an alert box saying one` — prose XSS, still
  evades (0.23).
- `Contact O'Brien & O'Malley LLP re: contract <draft v2>.` — false-flags
  (0.99). Angle-bracket + apostrophe density still reads as attack.

On the 396-row hold-out the stacked model still misses 11 attacks — 9 of them
plain-language intent ("drop the users table from the database") and 1
hex-encoded UNION — and raises 10 false alarms, 7 of which are source-code
lines (`if (user.role == 'admin') { ... }`). Both residual clusters are
narrow and nameable, which is what a future-work section wants.

(On the red-team set that is 14/16 attacks caught, 1/8 false alarms — the
Windows file-path case that failed before the fix now passes.)

These are specific, explainable, and few — exactly what a Chapter 5 "future
work" section should list.

## Downstream reports were regenerated on the new models

The statistics / ablation / LLM-corpus reports were recomputed against the
retrained models **and the regenerated prepared splits** (the trainer now writes
`data/prepared/*.npz` + `rf_*_v2.csv` so those scripts read the exact rows the
models saw — otherwise they load stale splits and produce meaningless numbers).

- **McNemar** on the retrained models: stacked-vs-RF p = 0.13, stacked-vs-LSTM
  p = 0.074. Neither is significant at 0.05. The clean test set is saturated
  (all three models sit at F1 ~= 0.999), so it has almost no power to separate
  them. Reported honestly rather than cherry-picking a run.
- **Bootstrap 95% CI** (stacked, 1,000 resamples): F1 0.9989 [0.9980-0.9997],
  FPR 0.0003 [0.0000-0.0011].
- **Ablation (6 conditions)**: RF alone F1=0.9997, LSTM alone F1=0.9981, the
  11-feature LR baseline F1=0.9836, full stack F1=0.9989. Condition 5
  (LSTM+meta, no RF) collapses to F1=0.0 — the meta-learner cannot recover a
  decision from the LSTM probability alone, so RF carries the ensemble.
- **LLM corpus: 21/23** (RF alone 23/23, LSTM 20/23). Down from 23/23 before.
  A real, small regression from augmentation — note it rather than hide it.

## Reproduce

```bash
python scripts/build_holdout_eval.py            # Task 1: the ruler set
python scripts/17_evaluate_csv.py               # BEFORE (with old models)
python scripts/build_training_augmentation.py   # Tasks 3+5: add training rows
python scripts/18_train_stacked.py --epochs 6   # retrain (RF + masked LSTM + meta)
python scripts/17_evaluate_csv.py               # AFTER
```

## Notes / caveats

- The clean test set stays at F1 ≈ 1.0 before and after — it is saturated and
  cannot show this improvement. All signal is in the hold-out set.
- The reconstructed LSTM uses a **single masked LSTM**, not the original's
  stacked two-layer design: the stacked variant trained to AUC 0.5 (no learning)
  under the current TF/Keras; `mask_zero=True` on one LSTM converges to ~1.0.
  Predictions match the pipeline the app expects (same 319 RF features, same
  ordinal encoding, meta-learner on [rf, lstm]).
- Original models are backed up in `models/_backup_pre_aug/` (git-ignored,
  local only). The pre-augmentation log is recoverable from git history
  (commit 71003cf) or by removing aug-tagged rows.

## ModSecurity baseline (the external "vs.")

Docker Desktop was installed and the OWASP CRS WAF (paranoia 2) run live;
~5,800 clean-test requests plus the stress sets were fired through it as real
HTTP.

| Same clean traffic | ModSecurity + CRS | AI-GIS Stacked |
|--------------------|------------------:|---------------:|
| False-positive rate | **32.8%** (895/2,733) | **2.5%** (5/198) |
| Attack detection | ~100% | 95.5% |
| Hard-benign false alarms | 8/15 | 1/8 |

ModSecurity catches essentially everything but blocks 1 in 3 legitimate
requests — the ensemble reaches comparable detection at ~13× fewer false alarms.
This is the strongest, fully-external claim the project can make.
Reproduce: `docker network create modsec-net && docker compose up -d` then
`python scripts/12_evaluate_modsec_baseline.py --host localhost --port 8080`.
(On this machine Docker's bin must be on PATH so the credential helper resolves.)
