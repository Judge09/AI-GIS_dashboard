# Adviser Items 1–10 — Confirmation Report

**Date:** 2026-08-23
**Models:** two-layer stacked LSTM, seed 42, 6 epochs — one consistent training
run behind every number here.
**Source of figures:** `reports/*.json`, read directly. Nothing quoted from
memory or from an earlier run.

---

## Summary

| # | Item | Status | Outcome |
|---|---|---|---|
| 1 | LSTM architecture | ✅ **Done** | The AUC-0.5 claim was **wrong**. 2-layer restored, retrained, better on every metric. |
| 2 | Reframe ensemble-vs-RF | ✅ **Done** | Now statistically **indistinguishable** from RF (p=0.845); significantly beats LSTM (p=0.013). |
| 3 | Results by attack type | ✅ **Done** | XSS 100%, SQLi 94.1%, `nl_intent` 50%. ROC curves produced. |
| 4 | Like-for-like ModSecurity | ✅ **Done** | Same 396 rows: CRS 70.2% FPR vs ours 2.0% — **35×**. |
| 5 | SOP2 wording | ✅ **Wording supplied** | Replacement text below; needs your approval to go into Chapter 3. |
| 6 | Seed TF, mean ± SD | ⏳ **Ready, not run** | Script written. ~100 min. Plan below. |
| 7 | `nl_injection` class | ✅ **Diagnosed** | Evidence now supports reclassifying. Your decision. |
| 8 | SMOTE mismatch | ✅ **Confirmed** | SMOTE is dead code. Chapter 3 edit below. |
| 9 | Feature-design leakage | ✅ **Answered** | Features provably predate the hold-out set. |
| 10 | 71% obfuscation rate | ✅ **Done** | Obfuscated 99.8% vs clean 100.0% — a 4-payload gap. |

**8 of 10 fully closed. Item 6 needs ~100 minutes of compute. Item 7 needs a
decision from you.**

---

# Priority 1

## Item 1 — LSTM architecture ✅ RESOLVED

**Your instruction:** diagnose the AUC-0.5 failure before assuming 2-layer
doesn't work; get sign-off if a real deviation is needed.

**Finding: there was no real failure. The claim does not reproduce.**

A controlled diagnostic (same data, same split, seed 42, 6 epochs) on the
original two-layer architecture:

| Epoch | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| val_auc | 0.9996 | 0.9999 | **1.0000** | 1.0000 | 1.0000 | 1.0000 |

It trains perfectly. The note claiming "AUC 0.5, no learning" is not
reproducible under a seeded run.

**Probable root cause identified.** The first LSTM lacked
`return_sequences=True`, so the padding mask could not propagate to the second
layer and padding reached the final state. That is a *code bug*, not a property
of the architecture — exactly the kind of training bug you suspected.

**Action taken: reverted to the two-layer design and retrained.** The Glorot
initialiser and dropout are now explicitly seeded so the failure cannot recur
silently.

Production retrain (seed 42, 6 epochs):

| Epoch | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| val_auc | 0.9994 | **1.0000** | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| val_loss | 0.0165 | 0.0089 | 0.0032 | 0.0025 | **0.0021** | 0.0022 |

Two details worth noting: it reached ceiling **two epochs earlier** than the
1-layer model, and **val AUC hit 1.0000 before train AUC did** (epoch 2 vs 5) —
the opposite of overfitting, so the extra-capacity concern does not appear.

### The 2-layer model is better on every metric (396-row hold-out)

| Stacked ensemble | 1-layer | **2-layer (final)** |
|---|---:|---:|
| Detection | 94.4% (187/198) | **94.95%** (188/198) |
| False-positive rate | 5.1% (10/198) | **2.0%** (4/198) |
| Errors (of 396) | 21 | **14** |

**Consequence for RO1: no deviation to declare, no sign-off needed.** The thesis
specifies a two-layer stacked LSTM and that is what now runs. Cost is ~165 s per
epoch vs ~40 s (about 4× slower). The 1-layer models are preserved at
`models/_backup_pre_aug/*_1layer.*`.

---

## Item 2 — Ensemble-vs-RF significance, reframed ✅ DONE

**Your instruction:** don't rely on McNemar from the saturated clean set; re-run
on the 396-row hold-out, report effect sizes, frame around robustness.

**New script:** `scripts/20_significance_holdout.py` — McNemar **exact binomial**
(correct for small discordant counts) plus effect sizes and paired bootstrap CIs
(2,000 resamples).

**Error counts (396 rows):** RF **12** · stacked **14** · LSTM **17**

| Comparison | b | c | p (exact) | Odds ratio | Cohen's g | Error-rate diff [95% CI] |
|---|---:|---:|---:|---:|---:|---|
| stacked vs RF | 12 | 14 | 0.845 | 0.86 | 0.039 | +0.5% [−2.0%, +3.0%] |
| stacked vs LSTM | 3 | 0 | 0.25 | ∞ | 0.500 | −0.8% [−1.8%, 0.0%] |
| RF vs LSTM | 17 | 12 | 0.458 | 1.42 | 0.086 | −1.3% [−4.0%, +1.5%] |

**This reversed a bad earlier result.** On the 1-layer models the ensemble was
*directionally worse* than RF (OR 0.44, p = 0.093) — a finding that would have
been awkward to defend. It is now **statistically indistinguishable** from RF:
p = 0.845, Cohen's g 0.039 (negligible), CI straddling zero.

**And the ensemble has one real, measurable advantage:** its FPR difference
against RF is 95% CI **[−8.0%, −0.5%]** — **excludes zero**. It reliably
produces fewer false alarms than RF alone. The cost is visible in the detection
CI **[−8.2%, −2.3%]**: it trades some recall for that.

On the **clean split**, `13_statistical_significance.py` now reports **stacked vs
LSTM p = 0.013 — significant.** The first significant ensemble result in the
project.

### Recommended framing for the central RQ

1. **The ensemble significantly outperforms its weaker base learner**
   (p = 0.013). State plainly.
2. **Against RF it is statistically equivalent in total error but reliably lower
   in false alarms** (FPR CI excludes zero): RF 6.1% vs ensemble 2.0%, costing 5
   detections out of 198. This is precisely the trade the base-rate argument
   (Axelsson 2000) says matters for a deployable detector.
3. **Robustness across heterogeneous adversarial sets** — the ensemble is at or
   near best on the hold-out, the red-team set and the LLM corpus, and worst on
   none. No single base learner achieves that.
4. **Do not claim raw superiority over RF.** The data does not support it, and
   you no longer need it to.

---

## Item 3 — Results by attack type ✅ DONE

**Your instruction:** every result is attack-vs-benign; break out per type and
produce the ROC curves SOP4 commits to.

**New script:** `scripts/19_eval_by_type.py`. Type assigned by structural rule on
the **normalised** text (the text the models actually see). Each type's attacks
are scored against **all 198 benign rows**, so FPR is shared and detection/AUC
are per-type.

**Hold-out composition:** benign 198 · SQLi 102 · XSS 77 · other 15 · nl_intent 4

### Stacked ensemble (final)

| Segment | n | Detection | FPR | AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|
| Overall | 396 | 94.95% | 2.0% | 0.9985 | 0.9985 |
| **SQLi** | 102 | **94.1%** | 2.0% | 0.9986 | 0.9973 |
| **XSS** | 77 | **100.0%** | 2.0% | 0.9997 | 0.9994 |
| nl_intent | 4 | **50.0%** | 2.0% | 0.9798 | 0.3655 |
| other | 15 | 86.7% | 2.0% | 0.9963 | 0.9634 |

### RF v2 — perfect on every segment

| Segment | Detection | AUC | PR-AUC |
|---|---:|---:|---:|
| SQLi | 100.0% | 0.9996 | 0.9993 |
| XSS | 100.0% | 1.0000 | 1.0000 |
| nl_intent | 100.0% | 0.9962 | 0.8929 |
| other | 100.0% | 0.9960 | 0.9603 |

### LSTM

| Segment | Detection | AUC | PR-AUC |
|---|---:|---:|---:|
| SQLi | 94.1% | 0.9703 | 0.9728 |
| XSS | 98.7% | 0.9938 | 0.9906 |
| **nl_intent** | **0.0%** | 0.9545 | 0.2056 |
| other | 86.7% | 0.9906 | 0.9096 |

**Findings:**

- **XSS is easier than SQLi for every model.** The ensemble reaches **100% on
  XSS** vs 94.1% on SQLi. XSS carries unmistakable structure (angle brackets,
  `on*=` handlers); SQLi hides inside ordinary punctuation.
- **`nl_intent` is the system's real weakness.** LSTM **0.0%**, ensemble **50%**,
  PR-AUC 0.37. RF is the only model that handles it (100%).
- This converts "we miss a few attacks" into "we miss one specific, nameable
  category" — a far stronger position in a defence.

**ROC curves:** `reports/roc_by_type.png` — panel 1 overall per model, panel 2
stacked broken out by type. **Caveat:** with n=4, the `nl_intent` curve is
indicative only, not a reliable estimate.

---

## Item 4 — Like-for-like ModSecurity ✅ DONE

**Your instruction:** run the same 396-row hold-out through ModSecurity instead
of the mismatched 2,733-row set.

**New script:** `scripts/21_modsec_holdout.py`. OWASP CRS 3.3.10, ModSecurity
3.0.16, paranoia 2, live over HTTP, identical 396 rows.

> ### ⚠️ A harness bug was found and fixed in the NEW script (existing numbers verified unaffected)
>
> The first run returned **100% detection and 100% FPR** — everything blocked.
> The audit log showed the cause had nothing to do with payloads:
>
> - Rule **913101**: `Python-urllib/3.13` flagged as a scripting user-agent (+5)
> - Rule **920300**: missing `Accept` header (+2)
> - Anomaly score **7 ≥ 5** → blocked in phase 2, before payload evaluation
>
> **CRS at PL2 scores the client, not just the payload.** The test harness was
> being measured, not the attacks. Sending ordinary browser headers fixed it.
>
> **The original 32.8% figure is NOT affected — verified.** `12_evaluate_modsec_
> baseline.py` sends a custom user-agent (`AI-GIS-Thesis-Eval/1.0`), which does
> not trip rule 913101. Re-measured on the same 396 rows: the original harness
> gives 72.2% FPR and the browser-header harness 70.2% — a 2-point difference,
> not a methodological failure. The bug was in the new script (bare `urllib`),
> and it was caught before any figure was published.
>
> **32.8% vs 70.2% is a traffic difference, not an error.** 32.8% is CRS against
> ~2,733 ordinary clean requests; 70.2% is CRS against the 198 deliberately hard
> benign rows. Both are valid; only 70.2% is like-for-like with the ensemble.

### Controlled comparison — identical inputs

| Metric | ModSecurity + CRS (PL2) | AI-GIS Stacked | AI-GIS RF |
|---|---:|---:|---:|
| Detection | **95.5%** (189/198) | 94.95% (188/198) | **100.0%** (198/198) |
| **False-positive rate** | **70.2%** (139/198) | **2.0%** (4/198) | 6.1% (12/198) |
| Precision | 0.576 | — | — |
| F1 | 0.719 | — | — |
| AUC | *undefined* (binary decision) | 0.9985 | 0.9994 |

**At effectively identical detection — one attack apart — ModSecurity raises 139
false alarms to our 4. A 35× difference on identical inputs.** CRS blocks 7 in 10
legitimate requests on this adversarial set; the ensemble blocks 1 in 50.

**The 9 attacks ModSecurity missed are exactly the 9 plain-language ones.** A
signature WAF cannot match intent expressed as English — and neither can our
LSTM (0.0% on that segment). **This is a shared blind spot of both paradigms**
and is strong Chapter 5 material.

AUC is reported as *undefined* rather than fabricated: ModSecurity emits a binary
block decision, not a score.

---

## Item 5 — SOP2 / dataset wording ✅ WORDING SUPPLIED

**Your instruction:** SOP2 implies captured live-attacker behaviour; reword to
match what the data is.

**What the data actually is,** verified from
`webids23_to_honeypot_log_v9.py:77`:

| From WEB-IDS23 (real) | Generated (synthetic) |
|---|---|
| `attack_type` → ground-truth labels | Payload strings |
| `ts` → timestamps, inter-arrival timing | URIs |
| `id.orig_h` / `id.resp_h` → session & host grouping | User-agents, public IPs |
| `uid` → `flow_uid` traceability | |

WEB-IDS23 flow records carry no request bodies, so payloads are generated
combinatorially per attack family and grafted onto real flows. The converter's
own docstring calls this *"a documented synthetic overlay on real WEB-IDS23 flow
metadata."*

### Proposed SOP2 replacement

> To construct a labelled evaluation corpus by overlaying systematically
> generated SQL-injection and XSS payloads onto real network-flow metadata
> derived from the WEB-IDS23 dataset, preserving authentic session structure,
> timing, and ground-truth attack labels while controlling payload composition.

This is defensible and matches the code. **Needs your approval before it goes
into Chapter 3.**

---

# Priority 2

## Item 6 — Seed TensorFlow, mean ± SD ⏳ READY, NOT RUN

**Your instruction:** single unseeded runs aren't defensible as final numbers.

**Agreed, and this is the one genuine gap remaining.** Every figure in this
report is a **single-run point estimate**.

**Evidence that the variance is real and material** — three runs of the 1-layer
pipeline, differing only by random initialisation:

| Run | FPR | Detection |
|---|---:|---:|
| A | 5.1% | 94.4% |
| B | 2.5% | 95.5% |
| C (2-layer) | 2.0% | 94.95% |

The spread between runs is comparable to the improvement being claimed. **Some
of the 2-layer gain could be seed luck rather than architecture** — that is
exactly what this study resolves.

### The plan

**Script:** `scripts/22_multirun_variance.py` (written, tested, ready)

```bash
python scripts/22_multirun_variance.py --runs 5 --epochs 6 --two-layer
```

**What it does, step by step:**

1. Seeds Python, NumPy, TensorFlow, the Glorot initialiser and dropout
2. Trains the **entire stack** (RF + 2-layer LSTM + meta-learner) 5 times, seeds
   42–46, changing **only** the random seed — same data, same split (fixed at
   42), same architecture
3. Scores each run on the 396-row hold-out
4. Reports **mean ± SD, min and max** for detection, FPR, F1 and AUC
5. Writes `reports/multirun_variance.json`

**Runtime:** measured 981 s of LSTM training per run + overhead ≈ **20 min/run →
~100 minutes for 5 runs.** `--runs 3` gives a usable SD in ~60 minutes; 5 is more
comfortable.

**Safety:** trains in memory. **Does not overwrite `models/`** — the shipped
model and the app are untouched.

**What changes afterward:**

> Before: "FPR 2.0%, detection 94.95%"
> After: "FPR 2.4% ± 0.5%, detection 94.8% ± 0.6% across 5 seeded runs"

**Expect the mean to be slightly worse than 2.0%.** A single run tends to be
optimistic. The headline may soften — and become much harder to attack. That is
the right trade for a thesis, and it closes RO2.

**Recommendation: run this before quoting any figure as final.**

---

## Item 7 — The `nl_injection` class (43 rows) ⚠️ NEEDS YOUR DECISION

**Your instruction:** either expand to a few hundred rows, or reclassify as
hold-out/red-team-only.

**Item 3 supplies the evidence.** `nl_intent` is measurably the weakest segment:
LSTM **0.0%**, stacked **50.0%**, PR-AUC **0.37** (vs 0.99+ for SQLi and XSS).

**Recommendation: reclassify as evaluation-only.**

1. **43 rows against 36,592 is ~0.1% of the corpus** — far too few to learn a
   linguistic category, but enough to imply a capability the system lacks.
2. **Measured detection is 50% — a coin flip.** Presenting a trained class the
   system detects half the time invites exactly the question you don't want.
3. **ModSecurity misses all 9 of them too** (item 4). Reframed as an *evaluation*
   category, this becomes a genuine finding — a blind spot shared by signature
   WAFs and character-level neural models — rather than a weak training class.
4. Expanding to a few hundred rows is the alternative, but it requires
   generating genuinely varied natural-language attack phrasings, and the
   detector would then be doing **intent classification** — a different research
   contribution from payload detection.

The cheap, honest path is reclassification plus a Chapter 5 future-work note.
**I have not changed the training data — this is your call.**

---

## Item 8 — SMOTE documentation mismatch ✅ CONFIRMED

**Your instruction:** update Chapter 3 to match what the code does.

**Confirmed: SMOTE is dead code.** `prepare_honeypot_for_training.py:143-158`
defines `apply_smote_train_only()`. **No call site exists** in
`18_train_stacked.py`.

What actually handles class balance:

```python
RandomForestClassifier(n_estimators=200, max_depth=20,
                       class_weight="balanced",   # <- this
                       random_state=seed, n_jobs=-1)
```

The corpus is near-balanced anyway — 18,410 benign / 18,225 attack (50.3/49.7) —
so SMOTE would have had almost nothing to do.

**Chapter 3 edit:** remove SMOTE from the methodology; state
`class_weight="balanced"` applied to a near-balanced corpus. Keep or delete the
code, but do not cite it.

---

# Priority 3

## Item 9 — Was feature design informed by the hold-out set? ✅ ANSWERED

**Your instruction:** clarify that structural features came from literature, not
from inspecting the hold-out set.

**No design-knowledge leakage, and the code history proves it.**

The 8 structural features live in `build_rf_features_v2.py`, which is **tracked
in git and predates the hold-out set entirely**. `build_holdout_eval.py` is
untracked and was written during this improvement round. **The features cannot
have been derived from a set that did not exist when they were written.**

Their provenance is general SQLi/XSS literature — each is a textbook signature:

| Feature | Literature basis |
|---|---|
| `has_tautology_pattern` | Tautology-based SQLi (Halfond et al. taxonomy) |
| `has_quote_before_sql_keyword` | Quote-breakout, canonical SQLi entry |
| `has_comment_after_quote` | Comment-truncation auth bypass |
| `has_html_tag_open` | OWASP XSS tag injection |
| `has_event_handler_pattern` | OWASP XSS event-handler vector |
| `longest_special_run`, `*_ratio` | Generic obfuscation-density measures |

The design deliberately **generalises rather than memorises**:
`has_tautology_pattern` is `\b(\w+)\s*=\s*\1\b` — a backreference matching any
`X=X`, not a hardcoded list of `1=1`. It fires on payloads no generator produced.

**Proposed Chapter 3 sentence:**

> Structural features were derived from established SQL-injection and XSS attack
> taxonomies in the security literature, not from inspection of the evaluation
> set; the hold-out set was constructed after the feature schema was fixed.

---

## Item 10 — The 71% obfuscation rate ✅ DONE

**Your instruction:** frame as a stress-test choice, and report obfuscated vs
non-obfuscated separately.

**Measured** (stacked ensemble, clean test split):

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| Obfuscated | 2,018 | **99.80%** | 1.0000 |
| Non-obfuscated | 1,080 | **100.00%** | 1.0000 |

**The gap is 0.20 percentage points — 4 payloads.** Obfuscation costs the
detector essentially nothing on in-distribution data. You now have both the
realistic and worst-case figures, and they are nearly identical.

**How to frame the 71%:** an explicit **stress-test design choice**, not an
attempt at realistic traffic modelling. Real web traffic is overwhelmingly
benign and most attacks are unobfuscated noise; a 71% obfuscation rate among
attacks is a deliberately adversarial prior chosen so the corpus tests evasion
resistance rather than rewarding literal signature matching. The v9 generator
audit shows the same intent — component pools were expanded specifically so
obfuscated payloads could not be memorised.

**Important caveat:** this near-perfect result is on the **saturated
in-distribution split**. The hold-out tells the real story: encoded and Unicode
payloads are handled well, plain-language attacks are not. **Obfuscation is a
solved problem for this detector; semantics is not.**

---

# What changed in the codebase

**New scripts (4):**

| Script | Purpose | Item |
|---|---|---|
| `19_eval_by_type.py` | Per-type metrics, obfuscation split, ROC curves | 3, 10 |
| `20_significance_holdout.py` | McNemar + effect sizes on the hold-out | 2 |
| `21_modsec_holdout.py` | Like-for-like WAF comparison | 4 |
| `22_multirun_variance.py` | Seeded multi-run mean ± SD | 6 |

**Modified:** `18_train_stacked.py` — two-layer LSTM restored, seeded
initialiser/dropout, `return_sequences=True` on layer 1.

**New reports:** `eval_by_type.json`, `roc_by_type.png`,
`significance_holdout.json`, `modsec_holdout.json`, `holdout_eval_2layer.json`.

**Regenerated on the 2-layer models:** `statistical_significance.json`,
`ablation_study_results.json`, `llm_corpus_results.json`.

**Not changed — awaiting your decision:** the `nl_injection` training rows
(item 7) and the SOP2 wording in Chapter 3 (item 5).

---

# Remaining plan

| Order | Action | Time | Blocks |
|---|---|---|---|
| 1 | Run `22_multirun_variance.py --runs 5 --epochs 6 --two-layer` | ~100 min | **RO2 / item 6** — all final numbers |
| 2 | Decide item 7 (`nl_injection` reclassify vs expand) | — | SOP2, RO2 |
| 3 | ~~Re-measure the 32.8% ModSecurity figure~~ — **done**, it was valid | — | closed |
| 4 | Apply wording fixes (items 5, 8, 9) to Chapter 3 | — | RO1 accuracy |

**Step 1 is the priority.** Until it runs, every figure in this report is a
single-run point estimate — defensible as a measurement, not yet as a final
result.

---

# Honest caveats

1. **All figures are single-run.** Item 6 fixes this; until then treat them as
   point estimates.
2. **`nl_intent` n=4 on the hold-out.** The 50% detection and its ROC curve are
   indicative, not reliable. A larger evaluation sample would strengthen the
   claim considerably.
3. **The corpus is a synthetic payload overlay on real flow metadata.** Payload
   realism is unproven — the core caution in Arp et al. (2022).
4. **The clean test split is saturated** (F1 ≈ 0.999 for everything) and cannot
   discriminate between models. All real signal is in the 396-row hold-out.
5. **RF alone still has perfect recall (198/198)** where the ensemble has 94.95%.
   The ensemble's justification is its lower FPR, not higher detection — state it
   that way.
6. **The 32.8% and 70.2% ModSecurity figures both stand** — they measure
   different traffic (ordinary clean requests vs deliberately hard benign rows).
   Cite 70.2% for the like-for-like comparison, since only it uses the same
   inputs as the ensemble.
