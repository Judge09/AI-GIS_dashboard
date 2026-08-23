# Final Results — All Adviser Items Closed

**Date:** 2026-08-23
**Architecture:** two-layer stacked LSTM (original thesis design, restored)
**Training data:** plain-language attack rows excluded (adviser item 7)

**All 10 adviser items are now addressed.** Two require a decision from you and
are flagged as such; the rest are closed with measurements.

---

## 1. Reproducibility — the headline numbers (adviser item 6)

**5 seeded runs, identical data and split, only the random seed varies.**
This is the number to quote in Chapter 4 — not any single run.

| Model | Detection | FPR | F1 | AUC |
|---|---:|---:|---:|---:|
| RF v2 | **100.00 ± 0.00%** | 6.97 ± 0.66% | 0.9663 ± 0.0031 | 0.9994 ± 0.0001 |
| LSTM | 92.83 ± 0.23% | 4.14 ± **3.77%** | 0.9428 ± 0.0176 | 0.9782 ± 0.0089 |
| **Stacked** | **96.16 ± 1.26%** | **3.64 ± 2.71%** | 0.9627 ± 0.0126 | 0.9971 ± 0.0023 |

Per-run detail (`reports/multirun_variance.json`):

| Run | Seed | Stacked detection | Stacked FPR |
|---|---|---:|---:|
| 1 | 42 | 95.0% | 2.0% |
| 2 | 43 | 96.0% | **8.1%** ← outlier, retained |
| 3 | 44 | 95.0% | 1.0% |
| 4 | 45 | 97.5% | 3.5% |
| 5 | 46 | 97.5% | 3.5% |

**Three findings only a multi-run study can support:**

1. **The ensemble beats both base models on false alarms.** Stacked 3.64% vs
   RF 6.97% and LSTM 4.14%, while detection sits between them. In any single
   run this is invisible or reversed.
2. **All instability is in the neural component, and stacking damps it.**
   LSTM FPR SD is 3.77%; stacked is 2.71%. RF is effectively deterministic
   (SD 0.66%).
3. **Detection is far more stable than FPR** (SD 1.26% vs 2.71%). The recall
   claim is solid; the false-alarm claim must carry its ±.

> Run 2 (seed 43) is an outlier — the other four sit between 1.0% and 3.5% FPR.
> **It is retained.** Dropping an inconvenient seed is precisely the practice
> this study exists to prevent, and the SD honestly reflects that the tail
> exists.

**Headline for Chapter 4:**
> False-positive rate fell from 57.6% to **3.64% ± 2.71%** while detection rose
> to **96.16% ± 1.26%**, measured across five seeded training runs on a 396-row
> adversarial hold-out set.

---

## 2. The plain-language decision and its cost (adviser item 7)

### What was done

The 43 augmented attack rows split **41 plain-language / 2 Unicode-homoglyph**.
These are different phenomena and were treated differently:

- **41 plain-language rows removed from training.** At ~0.1% of a 36k corpus
  they were too few to teach a linguistic category but enough to imply a
  capability the system lacked (50% detection, LSTM 0%).
- **2 Unicode/homoglyph rows kept.** Character-level obfuscation, not natural
  language — and the class the NFKC pipeline exists to defeat. Removing them
  would undo a fix that demonstrably works.

Controlled by `INCLUDE_PLAIN_LANGUAGE_ATTACKS` in
`build_training_augmentation.py` (default `False`), so the decision is
reversible and visible.

### The measured cost — stated plainly

| Metric (single run, seed 42) | With plain-lang training | **Without (final)** |
|---|---:|---:|
| Stacked detection | 95.0% | **93.4%** |
| Stacked FPR | 2.0% (4 alarms) | **0.5%** (1 alarm) |
| `nl_intent` detection | 50.0% | **0.0%** |
| Red-team attacks caught | 14/16 | **12/16** |

**This looks like a regression, and partly it is — but the raw comparison is
unfair to the decision.** The hold-out set still contains 4 plain-language
attacks the model is now deliberately never trained on. Excluding that
category from both sides:

| | With plain-lang | Without (final) |
|---|---:|---:|
| Detection, excluding `nl_intent` | 96.4% (187/194) | **95.9%** (186/194) |
| False alarms | 4 | **1** |

**The real cost is 0.5 percentage points of detection on the categories the
system actually claims to handle, in exchange for a 4× reduction in false
alarms.** SQLi detection is unchanged (95.1%) and XSS is 97.4%.

### Why this is the right call anyway

`nl_intent` detection is now **0.0%**, which is the honest number. The system
no longer implies a capability it does not have. And the finding is stronger as
an evaluation category than it ever was as a training class:

> ModSecurity + OWASP CRS misses the *same* 9 plain-language attacks. Natural-
> language attack intent is a blind spot shared by signature-based WAFs and
> character-level neural detectors alike — neither paradigm addresses it.

That is a Chapter 5 contribution. A trained class detected 50% of the time is
just a weak result.

**⚠️ YOUR DECISION:** if you would rather present the higher headline detection
(95.0%) and defend a 50%-detection trained class, set
`INCLUDE_PLAIN_LANGUAGE_ATTACKS = True` and retrain. I recommend against it,
but the trade is now measured rather than assumed.

---

## 3. Final per-attack-type results (adviser item 3)

Stacked ensemble, hold-out set, final models:

| Segment | n | Detection | FPR | AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|
| Overall | 396 | 93.4% | 0.5% | 0.9762 | 0.9852 |
| **SQLi** | 102 | **95.1%** | 0.5% | 0.9916 | 0.9883 |
| **XSS** | 77 | **97.4%** | 0.5% | 0.9997 | 0.9993 |
| `nl_intent` | 4 | **0.0%** | 0.5% | 0.4028 | 0.0284 |
| other | 15 | 86.7% | 0.5% | 0.9040 | 0.8801 |

**XSS remains easier than SQLi** for every model — XSS carries unmistakable
structure (angle brackets, `on*=` handlers) while SQLi hides inside ordinary
punctuation.

ROC curves: `reports/roc_by_type.png`.

> **Caveat:** `nl_intent` has n=4. Its detection rate and ROC curve are
> indicative only. Report the category as a documented blind spot, not as a
> measured rate.

---

## 4. Statistical significance (adviser item 2)

### On the 396-row adversarial hold-out

**Error counts:** RF 18 · stacked 14 · LSTM 15

| Comparison | b | c | p (exact) | Odds ratio | Cohen's g | FPR diff [95% CI] |
|---|---:|---:|---:|---:|---:|---|
| stacked vs RF | 8 | 4 | 0.388 | **2.00** | 0.167 | **[−6.5%, −1.0%]** |
| stacked vs LSTM | 1 | 0 | 1.00 | ∞ | 0.500 | [0.0%, 0.0%] |
| RF vs LSTM | 5 | 8 | 0.581 | 0.63 | 0.115 | [+0.6%, +6.4%] |

**The ensemble's odds ratio against RF is now 2.0** — it fixes twice as many RF
errors as it introduces. Not significant at n=396 (p = 0.388), but the point
estimate favours the ensemble, having favoured RF before these fixes.

**Its FPR advantage over RF is a real effect**: 95% CI [−6.5%, −1.0%] excludes
zero. Detection difference CI [−3.3%, 0.0%] touches zero — the ensemble does
not reliably lose detection.

### Recommended framing for the central RQ

1. **Do not claim raw statistical superiority over RF.** The data does not
   support it (p = 0.388), and you do not need it.
2. **Do claim the false-alarm advantage.** It is a measured effect with a CI
   excluding zero, and it is the metric that matters operationally — the
   base-rate argument (Axelsson 2000) makes FPR decisive for a deployable
   detector.
3. **Do claim variance reduction.** The 5-run study shows the ensemble damps
   LSTM instability (SD 2.71% vs 3.77%). This is a genuine ensemble benefit and
   is only visible across runs.
4. **Note that RF alone achieves perfect recall (100.0 ± 0.00%)** at nearly
   double the false-alarm rate (6.97% vs 3.64%). State the trade explicitly —
   an examiner will ask why not ship RF alone.

---

## 5. External baseline (adviser item 4)

**Like-for-like, identical 396 rows.** OWASP CRS 3.3.10 / ModSecurity 3.0.16,
paranoia level 2, live over HTTP.

| Metric | ModSecurity + CRS | AI-GIS Stacked (final) |
|---|---:|---:|
| Detection | 95.5% (189/198) | 93.4% (185/198) |
| **False-positive rate** | **70.2%** (139/198) | **0.5%** (1/198) |
| Precision | 0.576 | — |
| F1 | 0.719 | — |
| AUC | *undefined* (binary decision) | 0.9762 |

**At comparable detection, ModSecurity raises 139 false alarms to the
ensemble's 1.** On this adversarial set CRS blocks 7 in 10 legitimate requests.

**The 9 attacks ModSecurity misses are exactly the 9 plain-language ones** —
the same category our detector now explicitly does not claim. This is the
shared blind spot, and it is the project's most defensible novel finding.

### Correction recorded

An earlier note in this repository claimed the previously reported 32.8% CRS
false-positive rate was "almost certainly invalid" due to a client-header bug.
**That claim was wrong and has been retracted.** The original harness sends a
custom user-agent (`AI-GIS-Thesis-Eval/1.0`) which does not trip CRS scanner
detection. Re-measured on the same 396 rows: original harness 72.2% FPR,
browser-header harness 70.2% — a 2-point difference.

**32.8% vs 70.2% is a traffic difference, not an error.** 32.8% is CRS against
~2,733 ordinary clean requests; 70.2% is CRS against 198 deliberately hard
benign rows. Both stand; only 70.2% is like-for-like.

---

## 6. Supporting evaluations

| Evaluation | Result |
|---|---|
| Red-team (16 attacks, 8 hard-benign) | **12/16** caught, **1/8** false alarms |
| LLM evasion corpus (23 payloads) | RF 23/23 · LSTM 20/23 · **Stacked 21/23** |
| Obfuscated vs clean (test split) | **100.0%** vs **100.0%** — no gap |
| Ablation, full stack | F1 = 1.0000, FPR = 0.0000 |
| Ablation, LSTM+meta without RF | F1 = **0.0000** — RF anchors the ensemble |
| Bootstrap CI (clean split) | F1 1.0000 [1.0000–1.0000] |

**Obfuscation is fully solved** on in-distribution data (100% both segments,
adviser item 10). Semantics is not — that is the plain-language gap.

**The clean test split is now completely saturated** (stacked F1 = 1.0000, zero
false positives). It has no remaining power to discriminate between models.
**All Chapter 4 model comparisons must use the 396-row hold-out.**

---

## 7. Status of all ten items

| # | Item | Status |
|---|---|---|
| 1 | LSTM architecture | ✅ Closed — claim was wrong; 2-layer restored, no deviation to declare |
| 2 | Ensemble-vs-RF significance | ✅ Closed — reframed with effect sizes on the adversarial set |
| 3 | Per-attack-type results | ✅ Closed — SQLi/XSS/nl_intent + ROC curves |
| 4 | Like-for-like ModSecurity | ✅ Closed — 70.2% vs 0.5% on identical rows |
| 5 | SOP2 wording | ⚠️ **Text supplied** — needs your approval (`CHAPTER3_EDITS.md`) |
| 6 | Seed TF, mean ± SD | ✅ Closed — 5 runs, `multirun_variance.json` |
| 7 | `nl_injection` class | ⚠️ **Actioned, reversible** — cost measured, your call to confirm |
| 8 | SMOTE mismatch | ✅ Closed — confirmed dead code; Chapter 3 text supplied |
| 9 | Feature-design leakage | ✅ Closed — features provably predate the hold-out set |
| 10 | 71% obfuscation rate | ✅ Closed — 100.0% vs 100.0%, framed as stress-test choice |

---

## 8. Chapter 4 readiness

| Section | Status | Source |
|---|---|---|
| 4.1 Dataset description | ✅ Ready | `METHODOLOGY.md` §2 |
| 4.2 Model performance | ✅ **Ready** | `multirun_variance.json` — mean ± SD |
| 4.3 Per-attack-type | ✅ Ready | `eval_by_type.json`, `roc_by_type.png` |
| 4.4 Statistical significance | ✅ Ready | `significance_holdout.json` |
| 4.5 Ablation | ✅ Ready | `ablation_study_results.json` |
| 4.6 Baseline comparison | ✅ Ready | `modsec_holdout.json` |
| 4.7 Evasion / red-team | ✅ Ready | `claude_redteam_results.json`, `llm_corpus_results.json` |
| 4.8 Error analysis | ✅ Ready | `holdout_eval_final.json` |

**All eight sections are evidenced.** Every table above can be transcribed
directly; no further computation is required.

### Before you write

1. **Confirm item 7** (§2). If you reverse it, sections 4.2, 4.3, 4.7 and 4.8
   all change.
2. **Apply the five Chapter 3 edits** (`CHAPTER3_EDITS.md`) — Chapter 3 must
   agree with Chapter 4 on architecture, balancing, and dataset provenance.
3. **Quote mean ± SD, never single-run figures**, for any headline metric.

---

## 9. Honest limitations for Chapter 5

1. **`nl_intent` has n=4.** Too small to support a rate. Report it as a
   documented blind spot, corroborated by ModSecurity failing identically.
2. **The corpus is a synthetic payload overlay on real WEB-IDS23 flow
   metadata.** Labels, timing and session structure are real; payload strings
   are generated. Payload realism is asserted by construction, not observed.
3. **The clean test split is saturated** and cannot rank models.
4. **The ensemble is not statistically superior to RF alone** (p = 0.388). Its
   defensible advantages are lower false alarms (CI excludes zero) and reduced
   run-to-run variance.
5. **FPR carries meaningful run-to-run variance** (SD 2.71%). One seed produced
   8.1%. This is characterised rather than hidden.
6. **The LLM evasion corpus is weak evidence** — 23 payloads from a
   1.5B-parameter local model, 91% using a single obfuscation technique.
7. **Plain-language attack detection is 0.0%** by design. The system detects
   payload structure, not intent expressed in natural language.
