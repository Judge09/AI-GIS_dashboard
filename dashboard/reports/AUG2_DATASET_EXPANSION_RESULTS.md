# Dataset expansion (aug2): equal benign/attack batch targeting the two measured gaps

**Date:** 2026-09-15
**Scope:** new training data + retrain. No architecture change, no threshold change.

## What was added

Per direct analysis of `data/honeypot_final.log` (see chat record / prior audit),
the corpus had two concrete, measured gaps rather than a generic "needs more
data" problem:

1. **No training row exceeds 200 characters** (max = 131 chars) — the LSTM's
   200-char window is never exercised past its boundary, matching the
   documented "past-the-window" evasion (0/4 caught in the polymorphic
   red-team's aggressive tier, 2/2 evaded in the Claude red-team).
2. **Low-symbol / semantic-phrasing attacks are ~unrepresented** (2 rows) —
   matching 0/10 semantic SQLi and 2/8 semantic XSS caught in the same
   aggressive tier.

`scripts/build_training_augmentation_v2.py` adds **145 new benign rows and
145 new attack rows (equal, as requested)**:

| Family | Rows | Label |
|---|---:|---|
| `semantic_sqli_aug` (low-symbol SQLi, new wording) | 49 | attack |
| `semantic_xss_aug` (low-symbol XSS, new wording) | 48 | attack |
| `past_window_aug` (attack payload placed past char 200) | 48 | attack |
| `benign` — new short/medium prose & code | ~73 | benign |
| `benign` — new long-form (>200 char) benign, **no** attack payload | ~72 | benign |

The long-form *benign* rows exist specifically so raw length alone doesn't
become a spurious attack signal — every past-window attack has a same-length,
same-style benign counterpart with nothing injected.

**Leakage check (automated, not just claimed):** every generated candidate is
checked against (a) `data/eval/holdout_eval.csv`, (b) the literal probe
strings hard-coded in `23_claude_evasion_probe.py` and
`24_polymorphic_probe.py` (including its `--aggressive` tier), (c)
`redteam_cases.json` / `redteam_round2_cases.json`, and (d) the existing
`build_training_augmentation.py` batch. Verified zero exact-string overlap
against all of these before training — the model is trained on *new*
examples of the same evasion classes, not the eval probes themselves.

**Idempotent:** re-running the script reproduces the identical 145/145 batch
(tagged `"aug2": true`); found and fixed a bug where a naive re-run would
have silently deleted the batch instead.

## Retrain

`scripts/18_train_stacked.py --epochs 8 --seed 42` on the expanded log
(36,884 rows). Prior committed models backed up to
`models/_backup_pre_aug2/` before overwriting.

## Result on the untouched 396-row adversarial hold-out

| | OLD (pre-aug2) | NEW (post-aug2) |
|---|---:|---:|
| Detection | 93.43% (185/198) | **97.98%** (194/198) |
| FPR | 0.51% (1/198) | 3.54% (7/198) |
| F1 | 0.9635 | **0.9724** |

**Split by error type (this is the honest picture — the net McNemar on all
396 rows is NOT significant, p=0.648, because it nets two opposite effects):**

- **Attacks (n=198):** 10 newly caught, 1 newly missed. Exact binomial
  p = **0.0117** — the detection improvement is statistically significant.
- **Benign (n=198):** 7 newly false-alarmed, 1 newly cleared. Exact binomial
  p = 0.0703 — the FPR increase is real but does not quite reach
  significance at n=198.

**Root cause of the new false alarms, traced exactly (not guessed):** 6 of
the 7 new false alarms are all the same pre-existing benign template family —
auth-related equality conditionals (`if (user.role == 'admin') { ... }`,
`if (status == 200) { ... }`). These are among the ORIGINAL corpus's benign
rows, not new ones added here; retraining shifted the decision boundary
enough to flip them. The 7th is a new symbol-heavy product-SKU string.

## Result on the two dedicated red-team probes (the actual target of this change)

**`23_claude_evasion_probe.py` (15 hand-authored attacks, 8 hard-benign):**

| | Before | After |
|---|---:|---:|
| Attacks caught | 8/15 (53%) | **10/15 (67%)** |
| False alarms | 1/8 | 2/8 |

The two "past-the-window" cases (`sqli/late-inject`, `xss/late-inject`) that
evaded before at 0.09 / 0.07 are now **caught at 0.89 / 0.86** — a clean,
direct confirmation the targeted fix worked. The new false alarm is a regex
string (`benign/regex`, 0.978).

**`24_polymorphic_probe.py --aggressive` (the 22-case class-level test):**

| Class | Before | After |
|---|---:|---:|
| `past_window` | 0/4 (0%) | **4/4 (100%)** |
| `semantic_xss` | 2/8 (25%) | **5/8 (62%)** |
| `semantic_sqli` | 0/10 (0%) | 1/10 (10%) |
| **Overall aggressive tier** | **2/22 (9%)** | **10/22 (45%)** |

**Tier 1 (400 syntactic mutations) stays at 100/100% — no regression** in
the model's existing, documented strength.

## Honest conclusion

- **`past_window` is essentially solved** (0%→100% on the dedicated probe) —
  the training-data fix for a structural blind spot worked exactly as
  designed, at no measured cost to that specific class.
- **`semantic_xss` improved substantially** (25%→62%).
- **`semantic_sqli` barely moved** (0%→10%) — low-symbol numeric/tautology
  SQLi phrasing (`1 or 5000=5000`, `admin where true`) remains almost
  entirely unresolved by more training data alone. Scores rose across the
  board (many moved from ~0.02 to 0.1–0.4) but mostly didn't cross 0.5. This
  matches the earlier red-team's own recommendation: this class may need an
  explicit keyword-sequence feature, not just more examples.
- **Overall detection on the standard hold-out rose significantly** (p=0.012
  on the attack side), but **FPR rose from 0.51% to 3.54%**, traced to a
  specific, nameable regression in auth-related benign code snippets — a
  real cost, not free lunch, though it falls just short of significance at
  n=198.

**Models were overwritten in `models/` by the retrain.** Given the FPR
regression is real (even if not fully significant) and traced to a specific,
fixable template class, the honest recommendation is: either (a) ship this
as a genuine net improvement (higher F1, big red-team gains, one nameable
regression), or (b) add a small number of `if (x == 'y')`-style auth
conditionals to the benign side to patch the specific regression before
shipping. Not done automatically here — flagging for a decision rather than
silently picking one.

## Reproduce

```bash
cd dashboard
python scripts/build_training_augmentation_v2.py
python scripts/18_train_stacked.py --epochs 8 --seed 42
python scripts/17_evaluate_csv.py
python scripts/23_claude_evasion_probe.py
python scripts/24_polymorphic_probe.py --aggressive
```

Prior models: `models/_backup_pre_aug2/`. Raw comparison data:
`reports/aug2_before_after_holdout.json`,
`reports/holdout_eval_after_aug2.json`.
