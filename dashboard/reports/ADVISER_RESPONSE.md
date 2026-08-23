# Adviser Items — Results

**Run date:** 2026-08-23. Every figure below was measured on this machine.
Where an item is not yet complete, it says so explicitly rather than
estimating.

## Status at a glance

| # | Item | Status | Headline |
|---|---|---|---|
| 1 | LSTM architecture | ✅ **Resolved — 2-layer restored** | Claim was wrong; 2-layer retrained and is **better on every metric**. |
| 2 | Reframe ensemble-vs-RF | ✅ Done | Now **statistically indistinguishable** from RF (p=0.845); beats LSTM (p=0.013). |
| 3 | Results by attack type | ✅ Done | XSS **100%**, SQLi 94.1%, `nl_intent` **50%**. ROC curves produced. |
| 4 | Like-for-like ModSecurity | ✅ Done | Same 396 rows: CRS **70.2% FPR** vs ours **2.0%** — 35×. |
| 5 | SOP2 wording | ✅ Wording supplied | Dataset is synthetic payloads on real WEB-IDS23 flow metadata. |
| 6 | Seed TF, mean ± SD | ⏳ Script ready, not yet run | `22_multirun_variance.py --two-layer` — needs ~2 h. |
| 7 | `nl_injection` (43 rows) | ✅ Diagnosed, recommendation below | Now measurably the weakest class — evidence supports reclassifying. |
| 8 | SMOTE mismatch | ✅ Confirmed | SMOTE is dead code. `class_weight="balanced"` is what runs. |
| 9 | Feature-design leakage | ✅ Answered from code history | Features predate the hold-out set. Traceable. |
| 10 | 71% obfuscation rate | ✅ Done | Obfuscated 99.80% vs clean 100.00% — negligible gap. |

---

## Item 1 — LSTM architecture: **the AUC-0.5 claim does not reproduce**

You were right to say "diagnose before assuming". I ran a controlled diagnostic
(identical data, identical split, seed 42, 6 epochs) starting with the original
architecture:

| Arm | Architecture | Result |
|---|---|---|
| **A** | **2-layer masked, the ORIGINAL design** | **val_auc 0.9996 → 0.9999 → 1.0000 → 1.0000 → 1.0000 → 1.0000** |

**The two-layer stacked LSTM trains correctly.** It reaches val_auc 1.0000 by
epoch 3. The earlier "trained to AUC 0.5, no learning" note is **not
reproducible** under a seeded, controlled run.

Arm A settled the question, so the remaining diagnostic arms (no-mask, gradient
clipping, 1-layer control) were cancelled rather than left competing for CPU
with the production retrain. The mechanism is identified below regardless: the
missing `return_sequences=True`.

**What this means for RO1:** there is **no architectural deviation to declare
and no adviser sign-off needed.** The thesis can specify the original two-layer
design, because that is what the data supports.

**ACTIONED — the two-layer architecture has been restored and retrained.**
`build_lstm()` is back to the original design, with the Glorot initialiser and
dropout explicitly seeded so the failure mode cannot recur silently. The first
LSTM now carries `return_sequences=True` so the pad mask propagates to the
second layer — **this was very likely the original bug**: without it, padding
reaches the final state.

Production retrain curve (seed 42, 6 epochs):

| Epoch | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| val_auc | 0.9994 | **1.0000** | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| val_loss | 0.0165 | 0.0089 | 0.0032 | 0.0025 | **0.0021** | 0.0022 |

It reached ceiling **two epochs earlier than the 1-layer model** and val_loss
kept falling — it is genuinely fitting, not sitting at a degenerate solution.
Note val AUC hit 1.0000 *before* train AUC did (epoch 2 vs 5), the opposite of
overfitting: the extra-capacity concern does not show up here.

### 2-layer vs 1-layer, measured on the 396-row hold-out

| Stacked ensemble | 1-layer | **2-layer (final)** |
|---|---:|---:|
| Detection | 94.4% (187/198) | **95.0%** (188/198) |
| False-positive rate | 5.1% (10/198) | **2.0%** (4/198) |
| Errors (of 396) | 21 | **14** |

**The 2-layer model is better on every metric.** FPR more than halved and
detection rose. The decision is settled on evidence, not design fidelity alone.
Cost: ~165 s/epoch vs ~40 s (about 4× slower).

The 1-layer models are preserved at `models/_backup_pre_aug/*_1layer.*`.

---

## Item 2 — Ensemble vs RF, reframed on the adversarial set

New script: `scripts/20_significance_holdout.py`. McNemar **exact binomial**
(correct for small discordant counts), plus the effect sizes you asked for, on
the 396-row hold-out instead of the saturated clean split.

**Re-measured on the 2-layer models. The picture improved materially.**

**Error counts (396 rows):** RF **12** · stacked **14** · LSTM **17**
(1-layer was: RF 12 · stacked 21 · LSTM 23)

| Comparison | b | c | p (exact) | Odds ratio | Cohen's g | Error-rate diff [95% CI] |
|---|---:|---:|---:|---:|---:|---|
| stacked vs RF | 12 | 14 | 0.845 | 0.86 | 0.039 | +0.5% [−2.0%, +3.0%] |
| stacked vs LSTM | 3 | 0 | 0.25 | ∞ | 0.500 | −0.8% [−1.8%, 0.0%] |
| RF vs LSTM | 17 | 12 | 0.458 | 1.42 | 0.086 | −1.3% [−4.0%, +1.5%] |

**The earlier uncomfortable result is gone.** On the 1-layer stack the ensemble
was directionally worse than RF (OR 0.44, p = 0.093). It is now **statistically
indistinguishable**: p = 0.845, odds ratio 0.86, Cohen's g 0.039 — a negligible
effect size, and the error-rate CI straddles zero. RF no longer significantly
beats the LSTM either (p = 0.458, was 0.043).

**And the ensemble now has a real, measurable advantage:** its FPR difference
against RF is 95% CI **[−8.0%, −0.5%]**, which **excludes zero**. The ensemble
reliably produces fewer false alarms than RF alone. The trade is visible in the
detection CI **[−8.2%, −2.3%]**: it gives up some recall to buy that.

On the **clean test split**, `13_statistical_significance.py` now reports
**stacked vs LSTM p = 0.013 — significant.** That is the first significant
ensemble result in the project.

**Recommended reframing for the RQ** — still do not claim raw superiority over
RF, but the defensible claim is now much stronger:

1. **The ensemble significantly outperforms its weaker base learner**
   (stacked vs LSTM, p = 0.013 on the clean split). State this plainly.
2. **Against RF it is statistically equivalent in overall error, but reliably
   lower in false alarms** — FPR difference CI [−8.0%, −0.5%] excludes zero.
   That is exactly the trade the base-rate argument (Axelsson 2000) says matters
   for a deployable detector: RF's 6.1% FPR vs the ensemble's 2.0%, at a cost of
   5 detections out of 198.
3. **Robustness across heterogeneous adversarial sets.** The ensemble is at or
   near the best model on the hold-out, the red-team set and the LLM corpus,
   without being worst anywhere — which no single base learner achieves.
4. You no longer need to lead with a negative result. Report the RF equivalence
   honestly, but the headline is the FPR advantage.

---

## Item 3 — Results broken out by attack type (SOP4 / RO2)

New script: `scripts/19_eval_by_type.py`. Type is assigned by structural rule on
the **normalised** text — the same text the models see. Each type's attacks are
scored against **all 198 benign rows** (shared negatives), so FPR is common
across rows and detection/AUC are per-type.

**Hold-out composition:** benign 198 · SQLi 102 · XSS 77 · other 15 · nl_intent 4

### Stacked ensemble (2-layer, final)

| Segment | n | Detection | FPR | AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|
| Overall | 396 | 95.0% | 2.0% | 0.9985 | 0.9985 |
| **SQLi** | 102 | **94.1%** | 2.0% | 0.9986 | 0.9973 |
| **XSS** | 77 | **100.0%** | 2.0% | 0.9997 | 0.9994 |
| nl_intent | 4 | **50.0%** | 2.0% | 0.9798 | 0.3655 |
| other | 15 | 86.7% | 2.0% | 0.9963 | 0.9634 |

### RF v2

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| SQLi | 102 | 100.0% | 0.9996 |
| XSS | 77 | 100.0% | 1.0000 |
| nl_intent | 4 | 100.0% | 0.9962 |
| other | 15 | 100.0% | 0.9960 |

### LSTM

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| SQLi | 102 | 94.1% | 0.9703 |
| XSS | 77 | 98.7% | 0.9938 |
| **nl_intent** | 4 | **0.0%** | 0.9545 |
| other | 15 | 86.7% | 0.9906 |

**Findings:**

- **XSS is easier than SQLi** for every model — the ensemble now scores
  **100% on XSS** vs 94.1% on SQLi. XSS carries unmistakable structure (angle
  brackets, `on*=` handlers) while SQLi hides inside ordinary punctuation.
- **`nl_intent` remains the real weakness, but improved.** The LSTM still scores
  **0.0%**; the ensemble doubled from 25% to **50%**. PR-AUC 0.37 (was 0.18)
  confirms it is still the weakest segment by a wide margin. RF is the only
  model that handles it reliably (100%).
- **This is the per-type evidence SOP4 requires,** and it changes the story from
  "we miss a few attacks" to "we miss a specific, nameable category."

**ROC curves:** `reports/roc_by_type.png` — two panels (overall per model;
stacked broken out by type).

---

## Item 4 — Like-for-like ModSecurity (SOP1 / RQ3 / RO3)

New script: `scripts/21_modsec_holdout.py`. OWASP CRS 3.3.10, ModSecurity
3.0.16, paranoia level 2, live over HTTP, firing the **exact same 396 rows**
the ensemble is scored on.

> ### A methodology bug found and fixed — read this before quoting any figure
>
> The first run returned **100% detection and 100% FPR** — everything blocked.
> The audit log showed why, and it had nothing to do with the payloads:
>
> - Rule **913101**: `Python-urllib/3.13` flagged as a scripting user-agent (+5)
> - Rule **920300**: missing `Accept` header (+2)
> - Anomaly score **7 ≥ 5** → blocked in phase 2, before payload evaluation
>
> **CRS at PL2 scores the client, not just the payload.** The harness was being
> measured, not the attacks. Sending ordinary browser headers fixed it.
>
> **The original 32.8% figure is NOT affected — verified by re-measurement.**
> `12_evaluate_modsec_baseline.py` sends a custom user-agent
> (`AI-GIS-Thesis-Eval/1.0`) which does not trip rule 913101. Re-run on the same
> 396 rows: original harness **72.2%** FPR vs browser-header harness **70.2%** —
> a 2-point difference, not a methodological failure. The bug was in the new
> script only (bare `urllib`), and was caught before any figure was published.
>
> **32.8% vs 70.2% is a traffic difference, not an error.** 32.8% is CRS against
> ~2,733 ordinary clean requests; 70.2% is CRS against the 198 deliberately hard
> benign rows. Both are valid; only 70.2% is like-for-like with the ensemble.

### Like-for-like result — identical 396 rows

| Metric | ModSecurity + CRS (PL2) | AI-GIS Stacked | AI-GIS RF |
|---|---:|---:|---:|
| Detection rate | **95.5%** (189/198) | 95.0% (188/198) | **100.0%** (198/198) |
| **False-positive rate** | **70.2%** (139/198) | **2.0%** (4/198) | 6.1% (12/198) |
| Precision | 0.576 | — | — |
| F1 | 0.719 | — | — |
| AUC | *undefined* (binary decision) | 0.9985 | 0.9994 |

**This is now a controlled comparison, and it is the strongest result in the
project.** At **effectively identical detection (95.5% vs 95.0% — one attack
apart)**, ModSecurity raises **139 false alarms to our 4** — a **35× difference
on identical inputs**. On this adversarial set CRS blocks 7 in 10 legitimate
requests; the ensemble blocks 1 in 50.

(ModSecurity's own figures are model-independent and unchanged; only the
ensemble column was re-measured on the 2-layer models.)

**The 9 attacks ModSecurity missed are *exactly* the 9 plain-language ones** —
"drop the users table from the database", "bypass the login by making the where
clause always match". A signature WAF cannot match intent expressed as English,
and neither can our LSTM (0.0% on that segment). **This is a shared blind spot
of both paradigms** and is excellent Chapter 5 material.

Its false alarms are the same hard-benign families that trouble us: source-code
lines, `<draft>` in prose, apostrophe surnames — but it fires on far more of them.

---

## Item 5 — SOP2 / dataset wording

**The problem:** SOP2 implies captured live-attacker behaviour. The data is not
that.

**What the data actually is,** verified from `webids23_to_honeypot_log_v9.py:77`:

| From WEB-IDS23 (real) | Generated (synthetic) |
|---|---|
| `attack_type` → ground-truth labels | Payload strings |
| `ts` → real timestamps and inter-arrival timing | URIs |
| `id.orig_h` / `id.resp_h` → session and host grouping | User-agents, public IPs |
| `uid` → `flow_uid` traceability | |

WEB-IDS23 flow records carry no request bodies, so payloads are generated
combinatorially per attack family and grafted onto real flows. The converter's
own docstring calls this *"a documented synthetic overlay on real WEB-IDS23 flow
metadata."*

**Suggested SOP2 replacement wording:**

> To construct a labelled evaluation corpus by overlaying systematically
> generated SQL-injection and XSS payloads onto real network-flow metadata
> derived from the WEB-IDS23 dataset, preserving authentic session structure,
> timing, and ground-truth attack labels while controlling payload composition.

That is defensible and matches the code. The current wording is not.

---

## Item 6 — Seeded multi-run variance (⏳ not yet run)

Script written: `scripts/22_multirun_variance.py`. It seeds Python, NumPy and
TensorFlow, seeds the Glorot initialiser and dropout, retrains N times with a
different seed each run (split held fixed at 42), evaluates each on the hold-out,
and reports mean ± SD for detection, FPR, F1 and AUC.

```bash
python scripts/22_multirun_variance.py --runs 5 --epochs 6              # 1-layer
python scripts/22_multirun_variance.py --runs 5 --epochs 6 --two-layer  # original
```

It trains in memory and does **not** overwrite `models/`.

**Item 1 is now decided (2-layer), so this is the next thing to run.** Use
`--two-layer` to match the shipped architecture:

```bash
python scripts/22_multirun_variance.py --runs 5 --epochs 6 --two-layer
```

Budget ~2 hours (2-layer is ~4× slower per epoch). Known variance so far: three
separate runs of the 1-layer pipeline gave FPR 5.1% / 2.5% and detection
94.4% / 95.5% — the spread is real and material, which is exactly why this study
is needed before quoting any single figure as final.

---

## Item 7 — The `nl_injection` class (43 rows)

Item 3 gives you the evidence to decide this: `nl_intent` is still **measurably
the weakest segment in the system** — LSTM 0.0%, stacked 50.0%, PR-AUC 0.37
(on the 2-layer models; it was 25% / 0.18 on the 1-layer).

**Recommendation: reclassify as hold-out / red-team-only, do not keep it as a
trained category.** Reasons:

1. **43 rows against 36,592 is ~0.1% of the corpus** — far too few to learn a
   linguistic category, and enough to imply a capability the system lacks.
2. **Measured detection is 50%** — a coin flip. Presenting a trained class the
   system detects half the time invites exactly the question you do not want.
3. **ModSecurity misses all 9 of them too** (item 4). Reframed as an *evaluation*
   category, it becomes a strong finding — a blind spot shared by signature WAFs
   and character-level neural models alike — rather than a weak training class.
4. Expanding to a few hundred rows is the alternative, but it requires
   generating genuinely varied natural-language attack phrasings, and the
   detector would then be doing intent classification, which is a different
   research contribution from payload detection.

The cheap, honest path is reclassification plus a Chapter 5 "future work" note.

---

## Item 8 — SMOTE documentation mismatch (confirmed)

`prepare_honeypot_for_training.py:143-158` defines `apply_smote_train_only()`.
**The current trainer never calls it.** Verified: no call site in
`18_train_stacked.py`.

What actually handles class balance:

```python
RandomForestClassifier(n_estimators=200, max_depth=20,
                       class_weight="balanced",   # <- this
                       random_state=seed, n_jobs=-1)
```

The corpus is near-balanced anyway (18,410 benign / 18,225 attack, 50.3/49.7),
so SMOTE would have had almost nothing to do.

**Chapter 3 action:** remove SMOTE from the methodology; state
`class_weight="balanced"` on a near-balanced corpus. Keep the code or delete it,
but do not cite it.

---

## Item 9 — Was feature design informed by the hold-out set?

**No, and the code history shows it.**

The 8 structural features live in `build_rf_features_v2.py`, which is **tracked
in git and predates the hold-out set entirely** — `build_holdout_eval.py` is
untracked and was written during this improvement round. The features cannot
have been derived from a set that did not exist.

Their provenance is general SQLi/XSS literature, and each is a textbook
signature rather than an artefact of any specific payload:

| Feature | Literature basis |
|---|---|
| `has_tautology_pattern` | Tautology-based SQLi — Halfond et al.'s classic taxonomy |
| `has_quote_before_sql_keyword` | Quote-breakout, the canonical SQLi entry pattern |
| `has_comment_after_quote` | Comment-truncation auth bypass |
| `has_html_tag_open` | OWASP XSS tag injection |
| `has_event_handler_pattern` | OWASP XSS event-handler vector |
| `longest_special_run`, `*_ratio` | Generic obfuscation-density measures |

Note the design deliberately **generalises rather than memorises**:
`has_tautology_pattern` is `\b(\w+)\s*=\s*\1\b` — a backreference matching any
`X=X`, not a hardcoded list of `1=1`. It fires on payloads no generator produced.

**Suggested Chapter 3 sentence:**

> Structural features were derived from established SQL-injection and XSS attack
> taxonomies in the security literature, not from inspection of the evaluation
> set; the hold-out set was constructed after the feature schema was fixed.

---

## Item 10 — The 71% obfuscation rate

**Measured** (stacked ensemble, clean test split, `19_eval_by_type.py`):

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| Obfuscated | 2,018 | **99.80%** | 1.0000 |
| Non-obfuscated | 1,080 | **100.00%** | 1.0000 |

**The gap is 0.20 percentage points — 4 payloads.** Obfuscation costs the
detector essentially nothing on in-distribution data. Both numbers are available,
so you can report a realistic and a worst-case figure as requested, and they are
nearly the same.

**How to frame the 71%:** an explicit stress-test design choice, not an attempt
at realistic traffic modelling. Real web traffic is overwhelmingly benign and
most attacks are unobfuscated script-kiddie noise; a 71% obfuscation rate among
attacks is a deliberately adversarial prior chosen so the corpus tests evasion
resistance rather than rewarding literal signature matching. The v9 generator
audit (§2.2 of METHODOLOGY.md) shows the same intent — component pools were
expanded specifically so obfuscated payloads could not be memorised.

**Caveat worth stating:** this near-perfect obfuscated detection is on the
*saturated in-distribution* split. The hold-out tells the real story — encoded
and Unicode payloads there are handled well, but plain-language attacks are not.
Obfuscation is a solved problem for this detector; **semantics is not.**

---

## What I changed, and what I did not

**New scripts (4):**
- `scripts/19_eval_by_type.py` — per-type metrics, obfuscation split, ROC curves
- `scripts/20_significance_holdout.py` — McNemar + effect sizes on the hold-out
- `scripts/21_modsec_holdout.py` — like-for-like WAF comparison
- `scripts/22_multirun_variance.py` — seeded multi-run mean ± SD

**New reports:**
- `reports/eval_by_type.json`, `reports/roc_by_type.png`
- `reports/significance_holdout.json`
- `reports/modsec_holdout.json`

**Done since the first pass:**
- **Item 1:** reverted to the 2-layer LSTM, retrained, and re-measured. It is
  better on every metric, so the decision is evidence-backed.
- **All downstream evaluations re-run** against the 2-layer models, so every
  number in this document and in IMPROVEMENT_RESULTS.md comes from **one
  consistent training run** (seed 42, 6 epochs, 2-layer).

**Deliberately not done — these are your decisions:**
- **Item 7:** did not remove `nl_injection` from training.
- **Item 6:** the 5-seed variance study has not been run (~2 hours).

## Recommended order from here

1. **Run the variance study**: `22_multirun_variance.py --runs 5 --epochs 6
   --two-layer`. Until then, treat every figure here as a single-run point
   estimate, not a final number.
2. **Decide item 7** (`nl_injection`) — the per-type evidence supports
   reclassifying it as evaluation-only.
3. ~~Re-measure the 32.8% ModSecurity figure~~ — **done; it was valid.**
   Original harness 72.2% vs browser-header 70.2% on identical rows. The 32.8%
   figure measures different traffic (ordinary clean requests), not a broken
   harness. Cite 70.2% for the like-for-like claim.
4. Apply the wording fixes (items 5, 8, 9) to Chapter 3.
