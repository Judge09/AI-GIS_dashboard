# Adversarial Red-Team: Can an LLM Evade AI-GIS?

**Date:** 2026-08-23
**Attacker:** Claude (Opus), authoring novel payloads to defeat the detector
**Target:** the final shipped models, scored through the identical path
`app.py` uses (`scripts/23_claude_evasion_probe.py`)
**Result artifact:** `reports/claude_evasion_probe.json`

> **This is not the earlier `16_claude_redteam.py` corpus.** That set replays
> fixed cases. This one is an *active* red-team: 15 attacks and 8 benign strings
> hand-authored to target specific, named weaknesses in the model's design,
> each carrying the evasion theory it tests so a miss is diagnosable.

---

## Headline

| | Result |
|---|---:|
| Attacks caught | **8 / 15** |
| **Attacks that evaded** | **7 / 15 (47%)** |
| Benign kept clean | 7 / 8 |
| Benign false-alarmed | 1 / 8 |

**Nearly half of purpose-built attacks slipped through.** This does not
contradict the 93–96% detection reported elsewhere — those numbers are measured
against payloads drawn from the *same distribution* as training. This test
deliberately leaves that distribution, which is exactly what a motivated
attacker does. **The gap between the two is the real finding.**

---

## The seven evasions, and why each worked

Every evasion traces to one of three design facts already documented in the
README. None is a surprise; all are now demonstrated rather than hypothesised.

### Weakness 1 — the symbol-density shortcut (4 evasions)

The Random Forest's top six features are all symbol-density measures (README
§5.4). An attack with few special characters therefore reads as benign.

| Payload | Stacked | RF | LSTM |
|---|---:|---:|---:|
| `admin where true` | **0.010** | 0.225 | 0.010 |
| `1 union all select null null null` | **0.017** | 0.321 | 0.001 |
| `1 or 5000=5000` | **0.020** | 0.346 | 0.000 |
| `1 \|\| pg_sleep ( 10 )` | **0.171** | 0.714 | 0.002 |

All four are functional SQL injection. None uses a quote, and three use no
comment token. `admin where true` reads almost like English. The model scored
every one below 0.20 — well clear of the 0.5 threshold.

Note the split: RF is *suspicious* of the pg_sleep case (0.714) but the LSTM
(0.002) drags the ensemble back down to 0.171. Here the meta-learner's trust in
the LSTM actively *hurts*.

### Weakness 2 — the 200-character LSTM window (2 evasions)

The LSTM reads only the first 200 characters (README §6.2). Prefix an attack
with benign prose past that length and the LSTM never sees the payload.

| Payload | Stacked | RF | LSTM | Injection at char |
|---|---:|---:|---:|---:|
| 236-char note + `' OR '1'='1` | **0.092** | 0.600 | 0.001 | 234 |
| 232-char note + `<script>alert(1)</script>` | **0.069** | 0.550 | 0.001 | 223 |

Both inject *past character 200*. The LSTM scored each ~0.001 — completely blind,
exactly as the theory predicts. RF still catches a whiff (0.55–0.60) because
TF-IDF sees the whole string, but the LSTM's near-zero vote pulls the ensemble
under threshold. **This is a structural limit, not a tuning issue:** any attack
padded past 200 benign characters evades the sequence model by construction.

### Weakness 3 — token shapes absent from the training vocabulary (1 evasion)

| Payload | Stacked | RF | LSTM |
|---|---:|---:|---:|
| `String['fromCharCode'](60,115,99,...)` | **0.195** | 0.741 | 0.000 |

Bracket-notation property access (`String['fromCharCode']`) is a valid
JavaScript XSS primitive whose character sequence barely appears in the corpus.
RF is suspicious (0.741); the LSTM (0.000) has never seen the shape and vetoes.

---

## What the model DID resist (8 caught, worth stating)

The detector is not weak everywhere. It caught:

- **Every Unicode trick I tried** — zero-width joiner inside a tautology,
  zero-width space in a tag name, and a Unicode TAG character (U+E0073)
  substituted for `s`. All scored ≥ 0.5. The NFKC pipeline plus the
  non-ASCII → UNK encoding handled cases NFKC does not even fold.
- **HTML numeric-entity encoding** (`&#x27;&#x20;OR...`) — caught.
- **Backslash-hex escapes** (`\x3cscript\x3e`) — caught.
- **CRLF-split and doubled-letter tricks** (`OoRr`, `%0d%0a`) — caught.

So the classic "encode the payload" evasions that the training corpus was built
around are genuinely covered. The evasions that succeeded are the ones the
corpus does *not* represent: semantic low-symbol SQL, and structural attacks on
the input pipeline itself.

---

## The one false alarm

| Payload | Stacked | RF | LSTM |
|---|---:|---:|---:|
| `<div class="card"><span>Welcome back, user!</span></div>` | **0.992** | 0.771 | **1.000** |

Legitimate, harmless HTML markup — no script, no event handler — flagged as an
attack with 99% confidence. The LSTM is certain (1.000). The model has learned
that *angle-bracket tag structure* signals XSS, and cannot distinguish a `<div>`
from a `<script>`. Any application that legitimately accepts HTML (a comment
field, a CMS, a rich-text editor) would see constant false positives.

---

## Honest interpretation

**For the thesis, this strengthens rather than weakens the work** — *if framed
correctly.*

1. **It is real adversarial evidence.** An LLM given the model's design
   defeated it 47% of the time with novel payloads. That is a concrete answer to
   "how robust is it against an adaptive attacker?" — the question the LLM-corpus
   evaluation (23 weak payloads, README §3.3) was too thin to answer.

2. **Every evasion is explained by a documented limitation.** Nothing here is a
   mystery bug. The symbol-density shortcut (§5.4), the 200-char window (§6.2),
   and the fixed vocabulary are all already stated. This test *confirms* they
   have the consequences the README claims — which is exactly what a rigorous
   limitations section should do.

3. **It sharpens the central finding.** The system detects payload *structure
   drawn from its training distribution*. It does not detect (a) semantic intent
   with low symbol density, or (b) attacks that exploit the input pipeline's
   fixed geometry. Both gaps are shared with signature-based WAFs — a
   low-symbol tautology evades a regex WAF for the same reason it evades this
   model.

**What it is not:** evidence the detector is broken. Against in-distribution
attacks it performs as reported. The evasions require an attacker who knows the
architecture and crafts against it — a strictly harder threat model than the
one the thesis claims to address (LLM-*generated* payloads, which in practice
were the weak `qwen2.5-coder:1.5b` outputs).

---

## Concrete mitigations (for Chapter 5 future work)

| Evasion | Mitigation | Cost |
|---|---|---|
| Symbol-density shortcut | Add a semantic/keyword-sequence feature (`SELECT`+`FROM`, `OR`+`=`) independent of symbol count | Low — feature engineering |
| 200-char window | Sliding-window or max-pool the LSTM over the full string; or a separate "any suspicious substring" scan | Medium — architecture change |
| Fixed vocabulary | Retrain the n-gram vectoriser periodically on fresh evasion corpora | Low — retraining |
| `<div>` false alarm | Distinguish dangerous tags (`script`, `svg`, `iframe`, `on*=`) from inert markup, rather than any `<tag>` | Low — feature refinement |

The single highest-value change is a **semantic feature that does not depend on
symbol density**: it addresses four of the seven evasions at once and is pure
feature engineering, no retraining architecture required.

---

## Reproduce

```bash
cd dashboard
python scripts/23_claude_evasion_probe.py
```

All 23 cases, their scores, and their evasion theories are in
`reports/claude_evasion_probe.json`.

---

## Caveats on this red-team itself

- **n = 15 attacks, 8 benign.** These are illustrative probes, not a
  statistically powered benchmark. The 47% evasion rate characterises *these*
  hand-picked hard cases, not attacks in general.
- **The payloads were authored with knowledge of the architecture.** This is a
  white-box adversary. A black-box attacker would need more attempts.
- **Some evasions are edge-of-functional.** `admin where true` is a valid SQL
  fragment but its exploitability depends on the surrounding query; it is a
  detection failure regardless, but not every evaded string is a guaranteed
  working exploit.
- Scored offline through the exact `app.py` feature path; not fired as live
  HTTP.
