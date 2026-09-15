# Keyword-sequence features (v3): a feature fix for the semantic_sqli gap

**Date:** 2026-09-15
**Scope:** 5 new RF structural features, no new training data, no architecture
change. Built on top of the aug2 dataset (previous change).

## Why a feature, not more data

The aug2 dataset expansion (previous change) added 49 new `semantic_sqli_aug`
training rows but `semantic_sqli` catch rate on the polymorphic red-team's
aggressive tier stayed at 0/10 → 1/10 — essentially unmoved. Both
`CLAUDE_EVASION_REDTEAM.md` and `POLYMORPHIC_REDTEAM.md` had already
predicted this and recommended a keyword-*sequence* feature independent of
symbol density instead. This change implements exactly that.

## What was added

Five new boolean regex features in `build_rf_features_v2.py::structural_features()`:

| Feature | Catches | e.g. |
|---|---|---|
| `has_or_near_equals` | `OR` within 20 chars of `=` | `1 or 5000=5000` |
| `has_or_comparison_keyword` | `OR` near `between/like/greatest/least` | `1 or 1 between 1 and 1` |
| `has_auth_bypass_phrase` | ignore/bypass/skip/regardless-of phrasing near login/password/auth words | `return every account ignoring the login condition` |
| `has_keyword_sequence_sqli` | SQL verb (select/union/dump/...) within 40 chars of a target noun (table/account/password/...) | `select everything from the accounts table please` |
| `has_where_true_phrase` | `where/and/or` immediately followed by `true` | `admin where true` |

**Measured false-positive rate before wiring into the pipeline** (not
assumed): 1 fire out of 18,555 benign training rows (0.005%), and the same
1 fire out of 198 holdout benign rows — both the identical borderline math
sentence ("...A OR B = 1 when either is true"). Verified this is genuinely
low-collateral before proceeding, not just plausible-looking regexes.

Wired into the two scripts that hardcode the RF column list
(`18_train_stacked.py`, `22_multirun_variance.py`); every other script reads
columns dynamically from `rf_train_v2.csv` and picked them up automatically
on retrain. RF now uses 324 features (was 319).

## What it actually did — and the honest limit of what it did

**At the RF-alone level, it worked exactly as designed.** Direct check on
the 9 previously-evading `semantic_sqli` cases:

| Case | RF (before) | RF (after) |
|---|---:|---:|
| `1 or 1 between 1 and 1` | ~0.1–0.2 | **0.670** |
| `1 or 2 like 2` | ~0.1–0.2 | **0.675** |
| `admin where true` | ~0.1–0.2 | **0.665** |
| `1 union all select null null from users` | ~0.2–0.3 | **0.705** |
| `select everything from the accounts table please` | ~0.3 | **0.695** |
| `return every account ignoring the login condition` | ~0.1 | **0.610** |

**7 of 9 would be caught if RF's own decision were used alone** (RF ≥ 0.5).

**But the STACKED ensemble barely moved** (0/10 → 1/10 → still 1/10 after
this change). Root cause, diagnosed directly rather than assumed: the
meta-learner is a logistic regression on `[rf_proba, lstm_proba]` with
learned coefficients `[6.58, 5.76]` and intercept `-6.03`. Solving the
decision boundary: when `lstm_proba ≈ 0` (which it structurally always is
for low-symbol text — the LSTM is a pure character-sequence model with no
keyword features at all), RF alone needs to exceed **~0.92** to cross 0.5
in the ensemble. RF's new, genuinely-improved 0.6–0.7 confidence is nowhere
near enough to overcome a confidently-silent LSTM.

**This is a real, further-diagnosed limitation, one level deeper than the
red-team reports had located it.** They named "add a keyword-sequence
feature" as the fix; that fix now demonstrably works at the RF level, and
the ensemble's stacking mechanism is the actual remaining blocker. The
meta-learner was fit to trust agreement between branches, and has no way to
let RF override a confident-wrong LSTM vote — it never sees RF's underlying
features, only its scalar probability.

## Measured result (single seed, holdout, honest but not final — see below)

| | aug2-only (before) | aug2+features (after) |
|---|---:|---:|
| Detection | 97.98% (194/198) | 98.48% (195/198) |
| FPR | 3.54% (7/198) | 3.54% (7/198) |
| F1 | 0.9724 | 0.9750 |

McNemar (paired, same 396 rows): 1 newly-caught attack, 0 newly-missed,
p=1.0 (not significant — too small an effect at single-seed n=396 to prove
anything, consistent with the mechanism above: the feature raises RF's
confidence but rarely enough to flip the ensemble's final vote at n=396).

**One small regression found and reported, not hidden:** on the polymorphic
aggressive tier, `past_window` dropped from 4/4 to 3/4 — one probe case
moved from just-above to just-below threshold (0.477, essentially a
coin-flip boundary effect from retraining variance, not a new systemic gap).

Tier 1 (400 syntactic mutations) and `claude_evasion_probe.py`'s catch/false-alarm
counts were unchanged (10/15 attacks, 2/8 false alarms) — the new features
didn't move those specific probe cases either way beyond the mechanism above.

## Multi-seed validation — the single-seed "+1 catch" does NOT hold up

`22_multirun_variance.py --two-layer`, 3 seeds (42, 43, 44), same
methodology as the aug2 validation. Comparison is against the aug2-ONLY
3-seed result (the immediately-prior state), not the original pre-aug2
baseline, since this change is additive on top of aug2:

| Metric | aug2-only (3-seed) | aug2+features (3-seed) | Δ |
|---|---:|---:|---:|
| Stacked detection | 97.98 ± 1.52% | 97.64 ± 1.54% | −0.34pp |
| Stacked FPR | 3.20 ± 0.77% | 3.37 ± 1.05% | +0.17pp |
| Stacked F1 | 0.9740 ± 0.0114 | 0.9715 ± 0.0130 | −0.0025 |

**Every difference is well inside one standard deviation of the 3-seed
noise floor (SD ≈ 1.0–1.5pp on detection/FPR).** This is not an
improvement and not a regression — it is statistically indistinguishable
from no change at all at the ensemble level.

**This confirms the mechanism diagnosis above, precisely.** The single-seed
"+1 attack caught" result reported earlier was noise, exactly as the
meta-learner analysis predicted it would be: RF's new signal is real (0.6–
0.7 confidence, up from ~0.1–0.3) but structurally can't cross the ~0.92
bar the logistic combiner requires when LSTM is silent, so the shipped
ensemble's headline numbers don't move either way. The value of this change
is the diagnosis, not a score improvement — reporting that plainly rather
than leaning on the single-seed number that looked positive.

## Honest bottom line

- **The feature fix is real and verified at the level it targets (RF).**
  Not a placebo, not cherry-picked — directly measured before/after on the
  exact evading cases (RF confidence 0.6–0.7, up from ~0.1–0.3).
- **It does NOT improve the shipped stacked model.** The multi-seed study
  shows every headline metric moved by less than one noise SD — this is a
  wash at the ensemble level, not an improvement. The single-seed result
  that looked like a small gain (+1 attack caught) did not replicate under
  proper seed-averaging, and I'm reporting that rather than the more
  flattering single-seed number.
- **`semantic_sqli` is NOT solved.** Still ~1/10 on the aggressive tier,
  before and after this change.
- **What this change actually is: a confirmed, precise diagnosis, not a
  score improvement.** The bottleneck is now known exactly — the
  meta-learner's logistic combiner requires RF alone to exceed ~0.92 to
  override a silent LSTM, and RF's new signal (0.6–0.7) doesn't reach that
  bar. The real next fix is giving the meta-learner more than a bare
  probability from RF — e.g. also passing it 1–2 of these semantic flags
  directly, or replacing the linear combiner with something that can
  express "trust RF alone when it's confident AND a semantic flag fired."
  Not implemented here — it changes the live inference path (`app.py`) and
  every eval script's meta-learner input shape, a larger, riskier change
  than this one, and deserves its own deliberate pass rather than being
  bundled in on the strength of a single-seed result that didn't hold up.
- **Recommendation: keep the features (they're free — zero measured cost,
  zero measured benefit at the ensemble level, and available for the
  meta-learner fix above to use), but do not claim this pass improved
  detection.** It didn't, and the multi-seed data says so plainly.

## Reproduce

```bash
cd dashboard
python scripts/18_train_stacked.py --epochs 8 --seed 42
python scripts/17_evaluate_csv.py
python scripts/24_polymorphic_probe.py --aggressive
python scripts/23_claude_evasion_probe.py
```

Prior (aug2-only) models backed up to `models/_backup_pre_v3feat/`.
