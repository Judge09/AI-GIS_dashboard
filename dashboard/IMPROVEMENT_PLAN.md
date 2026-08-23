# AI-GIS — Improvement Plan (handoff instructions)

This is a step-by-step plan to fix the two real weaknesses found by adversarial
testing. It is written so you can hand each numbered task to a developer (or an
AI assistant) as-is. Do the tasks **in order** — later ones depend on earlier ones.

---

## The problem, in one paragraph

The model learned **what attacks look like (punctuation/symbols)**, not **what
they mean**. Two consequences, proven by `scripts/16_claude_redteam.py`:

1. **False alarms** — 5/8 innocent symbol-heavy sentences (code, file paths,
   the name `O'Brien`) were flagged as attacks.
2. **Missed attacks** — 4/16 evasions got through, all of them low on symbols:
   plain-English attacks (`show me the users table where the password equals
   anything` → 0.015) and Unicode look-alikes (`１＇ ＯＲ ＇１＇＝＇１`).

Fix #1 is a **dataset** job. Fix #2 is a **dataset + preprocessing** job. Both
end with **retraining the model**. Nothing here changes the architecture.

---

## GOLDEN RULE — check BOTH numbers every time

After **every** change, re-measure two things together:

- **Attacks caught** (detection rate) — must stay high.
- **False alarms** (FPR) — should go down.

Making one better while quietly breaking the other is the classic mistake.
The command to check is in Task 2.

---

## TASK 1 — Build a proper test set (do this FIRST)

**Why first:** the current benign test is only 15 sentences. That is too small
to trust any result. You cannot tell if a change helped until you can measure it
properly. **This task does not change the model — it changes how you measure it.**

**What to build:** a labelled evaluation set of **at least 300 benign + 300
attack** examples, saved as a CSV.

- **File to create:** `data/eval/holdout_eval.csv`
- **Columns:** `text,label` (label: `1` = attack, `0` = benign)
- **The benign half must cover the categories the model currently fails on:**
  - code snippets (`if (x == 1) { ... }`)
  - file paths (`C:\Users\Admin\scripts\`)
  - regexes (`^[a-z]+@[a-z]+\.(com|org)$`)
  - math / logic (`A OR B = 1`, `dx/dt`)
  - names & addresses with apostrophes (`O'Brien`, `42 O'Malley Ave`)
  - quotes, legal/contract text, git commit messages, SQL/HTML discussed in prose
- **The attack half** can reuse the 23 evasion payloads in
  `scripts/04_evasion_test_definitions.py` plus the LLM corpus in
  `data/llm_evasion_corpus.csv`, expanded with more variety.

> **CRITICAL — no leakage.** These test rows must **not** appear in training
> data (Task 3). Keep this file separate and never train on it. It is the ruler,
> not the clay.

---

## TASK 2 — Write a "score any CSV" evaluation script

**Why:** you need one command that takes a CSV and prints detection rate + FPR,
so every later step is measured the same way.

- **New script:** `scripts/17_evaluate_csv.py`
- **Base it on:** `scripts/15_evaluate_llm_corpus.py` (it already loads all four
  models and reproduces the exact feature pipeline — copy that loading code).
- **Input:** any CSV with `text,label` columns (e.g. `data/eval/holdout_eval.csv`).
- **Output:** print a table of **RF / LSTM / Stacked**, each with:
  attacks caught, false positives, detection rate, FPR — and save to
  `reports/holdout_eval_results.json`.
- Run it **once now** against the current models to record the "BEFORE" numbers.

This script is your ruler for Tasks 3–5. Do not skip it.

---

## TASK 3 — Fix false alarms: expand the BENIGN training data

**This is the highest-payoff, lowest-effort fix. Do it before Task 4.**

**The dataset part:**

- The training data is the honeypot log: `data/honeypot_final.log`
  (JSON-lines; each row has `label`, `attack_family`, and payload text).
- **Add several hundred new benign rows** covering the same hard categories as
  Task 1 (code, paths, regexes, names, math, prose). Label them `0`, give them
  `attack_family: "benign"`.
- **Do NOT reuse the exact Task-1 test sentences** — write fresh ones, or split a
  larger pool so train and test never overlap.

**The generator part (optional but recommended):**

- Reuse the Ollama setup from `scripts/11_generate_evasion_corpus.py`, but flip
  the prompt: ask the model to produce **realistic, harmless developer/office
  text that contains code, symbols, or technical jargon.** Save as benign rows.
- This is the mirror image of the attack generator you already have.

**The retrain part:**

- Re-run the pipeline that builds features and trains the models. The scripts
  are, in order:
  1. `scripts/prepare_honeypot_for_training.py` — rebuilds the RF/LSTM splits
     from the log (`load_log`, `session_grouped_split`).
  2. `scripts/build_rf_features_v2.py` — rebuilds the structural + n-gram
     features (`structural_features`).
  3. The trainer (see the upstream `05_train_stacked_ensemble.py` /
     `08_train_lstm_properly.py` referenced in `../docs/`) — retrains RF, LSTM,
     and the meta-learner.
- This overwrites `models/rf2.pkl`, `models/lstm_best.keras`, `models/meta.pkl`,
  and `models/ngram_vectorizer.pkl`.

**Then re-run Task 2.** Did false alarms drop? Did attacks-caught stay high?
Record the "AFTER" numbers next to the "BEFORE" ones.

---

## TASK 4 — Fix missed attacks, part A: normalise weird characters

**Why:** the Unicode attack `１＇ ＯＲ ＇１＇＝＇１` evaded detection because the
model saw unfamiliar look-alike characters. Normalising them to plain ASCII
**before** feature extraction catches this cheaply.

- **Where to change:** the text-cleaning step at the very start of feature
  building, so **both training and prediction** use it. The prediction path is
  in `app.py` (`build_v2_features` / `ordinal_encode`); the training path is in
  `scripts/prepare_honeypot_for_training.py` and `scripts/build_rf_features_v2.py`.
- **What to add:** a single `normalize_text()` function that applies Unicode
  NFKC normalisation (`unicodedata.normalize("NFKC", text)`) and maps common
  fullwidth/homoglyph characters to ASCII. Call it as the first line of every
  feature function so training and serving stay identical.

> **CRITICAL — same cleaning everywhere.** If training normalises text but the
> live app doesn't (or vice-versa), predictions silently break. Add
> `normalize_text()` in **one** place and import it in both.

**Then re-run Task 2** — the Unicode case should now be caught.

---

## TASK 5 — Fix missed attacks, part B: teach it plain-language attacks

**Why:** `show me the users table where the password equals anything` scored
0.015 — the model has never seen an attack written as a sentence.

- **The dataset part:** add attack rows to `data/honeypot_final.log` that
  describe or phrase attacks in **natural language**, labelled `1`. Examples:
  "drop the users table", "return every row where the login always succeeds",
  "inject a script that shows an alert". Keep them distinct from the Task-1
  test rows.
- **The generator part:** extend the attack generator
  (`scripts/11_generate_evasion_corpus.py`) with a prompt variant that asks for
  **intent-based / natural-language** attack phrasings, not just symbol
  obfuscation.
- **Retrain** (same pipeline as Task 3), then **re-run Task 2**.

> This is the hardest fix and may trade a little clean-set accuracy for
> robustness. Watch both numbers. If detection on the easy set drops below what
> you can accept, dial back how many prose-attacks you add.

---

## What NOT to do

- **Don't hyperparameter-tune the model to fix this.** The upstream repo already
  tried (`../docs/` mentions `06_rf_tuning_attempt_FAILED.py`) and it made false
  positives **worse**. Your bottleneck is **data coverage**, not architecture.
- **Don't trust the clean test set** (`rf_test_v2.csv`). It is synthetic and
  already scores 1.0 — it will keep scoring 1.0 whether you help or hurt. All
  the real signal is in the Task-1 hold-out set.
- **Don't chase 100%.** No detector reaches it on real text. The goal is a
  measured **before → after** improvement you can defend.

---

## Summary table — what each fix touches

| Fix | Weakness | Dataset | Generator | Preprocessing | Retrain? |
|-----|----------|---------|-----------|---------------|----------|
| Task 1 | (measurement) | new `holdout_eval.csv` | — | — | No |
| Task 2 | (measurement) | — | — | — | No |
| Task 3 | False alarms | +benign to log | benign prompt | — | **Yes** |
| Task 4 | Unicode evasion | — | — | `normalize_text()` | **Yes** |
| Task 5 | Prose attacks | +prose attacks to log | attack prompt | — | **Yes** |

**Order:** 1 → 2 → 3 → (re-measure) → 4 → 5 → (final re-measure).
Record BEFORE/AFTER numbers at each step — that trail is your Chapter 4.
