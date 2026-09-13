# Chapter 3 — Ready-to-Paste Edits

Chapter 3 lives in a `.docx` outside this repo, so these are supplied as text
for you to paste rather than applied automatically. Each edit closes a specific
adviser item and is backed by a verified finding.

**Apply all five.** Each one is a place where the current chapter says something
the code does not do.

---

## Edit 1 — SOP2 wording (adviser item 5)

**Problem:** SOP2 as written implies captured live-attacker behaviour. The
dataset is not that, and a panel that reads the converter will notice.

**What the data actually is** — verified from
`scripts/webids23_to_honeypot_log_v9.py:77`:

| From WEB-IDS23 (real) | Generated (synthetic) |
|---|---|
| `attack_type` → ground-truth labels | Payload strings |
| `ts` → timestamps, inter-arrival timing | URIs |
| `id.orig_h` / `id.resp_h` → session and host grouping | User-agents, public IPs |
| `uid` → `flow_uid` traceability | |

WEB-IDS23 flow records carry no request bodies, so payloads are generated
combinatorially per attack family and grafted onto real flows. The converter's
own docstring calls this *"a documented synthetic overlay on real WEB-IDS23 flow
metadata."*

### Replacement text

> To construct a labelled evaluation corpus by overlaying systematically
> generated SQL-injection and XSS payloads onto real network-flow metadata
> derived from the WEB-IDS23 dataset, preserving authentic session structure,
> timing, and ground-truth attack labels while controlling payload composition.

### Supporting paragraph for the dataset section

> The corpus is a hybrid construction rather than captured attack traffic. Flow
> metadata — connection timestamps, client and server addresses, service type,
> and ground-truth attack labels — is drawn directly from the WEB-IDS23 dataset
> via reservoir sampling over the source records. Because WEB-IDS23 flow records
> do not retain HTTP request bodies, the attacker-controlled payload text is
> generated combinatorially per attack family and grafted onto each sampled
> flow. This preserves realistic session grouping and inter-arrival timing while
> allowing controlled variation of payload structure and obfuscation. The
> limitation this imposes — that payload realism is asserted by construction
> rather than observed — is stated explicitly in the limitations section.

---

## Edit 2 — Remove SMOTE (adviser item 8)

**Problem:** Chapter 3 describes SMOTE. The code never calls it.

**Verified:** `prepare_honeypot_for_training.py:143-158` defines
`apply_smote_train_only()`. There is **no call site** in
`18_train_stacked.py`. Class balance is handled entirely by
`class_weight="balanced"` on the Random Forest.

### Replacement text

> Class balance is addressed through cost-sensitive learning rather than
> resampling. The Random Forest is fitted with `class_weight="balanced"`, which
> weights each class inversely to its frequency in the training split. Synthetic
> oversampling was not applied: the corpus is near-balanced by construction
> (18,410 benign to 18,225 attack, 50.3% / 49.7%), so resampling would offer no
> meaningful correction.

**Also:** delete any SMOTE citation from the reference list if it appears
nowhere else.

---

## Edit 3 — Feature-design provenance (adviser item 9)

**Problem:** an examiner may ask whether structural features were reverse-
engineered from the evaluation set — design-knowledge leakage, which is subtler
than text leakage and not caught by a train/test split.

**Verified:** `build_rf_features_v2.py` is tracked in git and **predates the
hold-out set**. `build_holdout_eval.py` was written later. The features cannot
have been derived from a set that did not exist when they were written.

### Replacement text

> Structural features were derived from established SQL-injection and XSS attack
> taxonomies in the security literature, not from inspection of the evaluation
> set. The feature schema was fixed before the adversarial hold-out set was
> constructed, and version-control history confirms this ordering. The features
> are deliberately general rather than payload-specific: the tautology detector,
> for example, is implemented as a backreference (`\b(\w+)\s*=\s*\1\b`) that
> matches any self-comparison, not an enumerated list of known strings such as
> `1=1`, and therefore fires on payload variants absent from every generator.

---

## Edit 4 — LSTM architecture (adviser item 1)

**Problem:** if the chapter records a deviation to a single-layer LSTM, remove
it. There is no deviation.

**Verified:** the claim that the two-layer stacked LSTM "trained to AUC 0.5 (no
learning)" does not reproduce. Under a seeded run it reaches val_auc 0.9994 in
epoch 1 and 1.0000 by epoch 2. Probable root cause: the first LSTM lacked
`return_sequences=True`, so the padding mask could not propagate to the second
layer — a code defect, not an architectural limitation.

### Replacement text

> The sequence model is a two-layer stacked LSTM over ordinally encoded
> characters (vocabulary 128, sequence length 200). An embedding layer
> (32 dimensions, `mask_zero=True`) feeds a 64-unit LSTM returning full
> sequences, followed by dropout (0.3), a 32-unit LSTM returning its final
> state, further dropout, and a sigmoid output. Mask propagation is explicit:
> the first recurrent layer returns sequences so that padding positions remain
> masked through the second, preventing padded timesteps from contributing to
> the final representation. Weight initialisation and dropout are seeded to make
> training reproducible.

---

## Edit 5 — ModSecurity baseline figures (adviser item 4)

**Problem:** the 32.8% figure and the ensemble's false-positive rate were
measured on **different traffic**, which is not a valid comparison.

**Verified:** both measurements are individually sound — the 32.8% figure was
re-checked and is not affected by the CRS client-scoring issue (the original
harness sends a custom user-agent that does not trip scanner detection;
re-measured, it gives 72.2% on the hold-out versus 70.2% with browser headers).
The problem was only that the two rates described different inputs.

### Replacement text

> The rule-based baseline is OWASP Core Rule Set 3.3.10 running on ModSecurity
> 3.0.16 at paranoia level 2, evaluated live over HTTP. Two measurements are
> reported. Against approximately 2,733 ordinary clean requests the WAF produced
> a 32.8% false-positive rate. Against the 396-row adversarial hold-out set —
> the identical inputs on which the ensemble is scored — it produced 95.5%
> detection at a 70.2% false-positive rate, compared with the ensemble's 95.0%
> detection at 2.0%. Only the second comparison is like-for-like, and it is the
> one used for the central claim; the first is reported to characterise the
> baseline's behaviour on ordinary traffic.
>
> Because ModSecurity emits a binary block decision rather than a score, AUC is
> undefined for the baseline and is not reported.

**Methodological note worth including** — it is a genuine finding:

> Core Rule Set evaluation at paranoia level 2 scores request metadata as well
> as payload content: a default Python HTTP client triggers scanner-detection
> (rule 913101) and missing-Accept-header (rule 920300) rules whose combined
> anomaly score exceeds the blocking threshold before payload inspection occurs.
> All measurements reported here send ordinary browser headers so that the
> baseline is evaluated on payload content alone.

---

## Cross-check before submitting

| Chapter 3 claim | Must say |
|---|---|
| Dataset origin | Synthetic payloads on real WEB-IDS23 flow metadata |
| Class balancing | `class_weight="balanced"`, **not** SMOTE |
| LSTM | Two-layer stacked, no deviation |
| Feature provenance | Literature-derived, predates the hold-out set |
| ModSecurity | Two figures, different traffic; 70.2% is the like-for-like one |
| Evaluation sets | Clean test split **and** the 396-row adversarial hold-out |

Any figure quoted in Chapter 4 should carry the mean ± SD from
`reports/multirun_variance.json`, not a single-run point estimate.
