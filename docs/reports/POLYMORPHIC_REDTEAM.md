# Polymorphic Attack Red-Team

**Date:** 2026-08-23
**Method:** generate many function-preserving mutations of each base attack,
measure per-family catch consistency. Scored through the identical path
`app.py` uses (`scripts/24_polymorphic_probe.py`).
**Artifacts:** `reports/polymorphic_probe.json`, `reports/polymorphic_aggressive.json`

> **Why polymorphism is the right test.** An attacker who is blocked does not
> give up — they mutate the same attack until a variant lands. A detector can
> score 96% on a fixed set and still fail if it catches *one* form of an attack
> but misses its siblings. The metric that matters is **per-family
> consistency**: catch 39/40 variants and the attacker just uses the 40th.

The test runs in two tiers, and they give **opposite** answers. Both are true,
and the gap between them is the finding.

---

## Tier 1 — syntactic mutations: PERFECT

400 variants (40 mutations × 10 base attacks), using function-preserving
operators that stay inside the training distribution: random case, inline
`/**/` comments, tab/newline/URL-encoded whitespace, `'`↔`"` swaps, `OR`→`||`,
numeric obfuscation (`1=1`→`5000=5000`, `0x41=0x41`), partial URL-encoding, and
keyword letter-doubling.

| Attack family | Type | Caught | Rate | Min score |
|---|---|---:|---:|---:|
| tautology | sqli | 40/40 | 100% | 0.992 |
| union_select | sqli | 40/40 | 100% | 0.626 |
| auth_bypass | sqli | 40/40 | 100% | 0.997 |
| time_blind | sqli | 40/40 | 100% | 0.998 |
| stacked_query | sqli | 40/40 | 100% | 0.602 |
| script_tag | xss | 40/40 | 100% | 0.997 |
| img_onerror | xss | 40/40 | 100% | 0.732 |
| svg_onload | xss | 40/40 | 100% | 0.994 |
| javascript_uri | xss | 40/40 | 100% | 0.997 |
| body_onload | xss | 40/40 | 100% | 0.997 |

**Overall: 400/400 (100%). Zero families have an evading variant.**

Even the *weakest* mutation of every family scored ≥ 0.60 — comfortably over the
0.5 threshold. Examples the model still caught:

```
1"  uniOn  sELeCt  uSeRNAme,pAssWorD  fRoM  usERs--    → caught (0.63)
1'; drop tABle USeRS--                                 → caught (0.60)
1" || "7"="7                                           → caught (0.99)
```

**This is a genuine strength.** Classic polymorphism — the case-flipping,
comment-stuffing, encoding tricks that defeat naive signature matching — does
**not** work against AI-GIS. The character n-gram + structural feature design
generalises across these mutations exactly as intended. A regex WAF would leak
on several of these; this model does not.

---

## Tier 2 — semantic & structural mutations: COLLAPSE

The honest polymorphic test cannot stop at syntax, because a real attacker also
mutates *how the attack is expressed*, not just how it is spelled. This tier
uses the three mutation classes the earlier red-team
(`CLAUDE_EVASION_REDTEAM.md`) already identified as blind spots.

| Mutation class | Caught | Rate |
|---|---:|---:|
| Semantic SQLi (low symbol density) | **0/10** | **0%** |
| Semantic XSS (intent / novel token shapes) | 2/8 | 25% |
| Past-the-window (attack after 200 benign chars) | **0/4** | **0%** |
| **Aggressive tier overall** | **2/22** | **9%** |

Every semantic SQLi variant evaded:

```
1 or 1 between 1 and 1                                    0.004
1 or 2 like 2                                             0.004
1 or 5000=5000                                            0.020
1 or 0x41=0x41                                            0.020
admin where true                                         0.010
1 union all select null null from users                  0.016
give me all rows where the password is never checked     0.006
return every account ignoring the login condition        0.003
select everything from the accounts table please         0.010
```

Every past-the-window variant evaded (attack injected after character 200):

```
"Thank you for contacting support…" + ' OR '1'='1        0.087
"Thank you for contacting support…" + <script>alert(1)>  0.092
"Thank you for contacting support…" + '; DROP TABLE…     0.140
```

**These are the same underlying attacks as Tier 1** — a tautology, a UNION, a
script tag. Presented in syntactic skins, all 400 were caught. Presented as
low-symbol semantics or pushed past the LSTM window, nearly all evade.

---

## The finding, in one sentence

**AI-GIS is robust to polymorphism of *form* and fragile to polymorphism of
*expression*.** It caught 400/400 attacks that were mutated in how they are
*written*, and missed 20/22 of the same attacks mutated in how they are
*phrased* or *positioned*.

### Why this happens

- **Tier 1 stays in-distribution.** Case changes, comments, and encodings all
  preserve the symbol-density and n-gram fingerprints the model learned. The
  training corpus is 71% obfuscated precisely so these mutations are covered
  (README §3.1.2). This is the design working.
- **Tier 2 leaves the distribution.** Low-symbol semantics defeat the
  symbol-density features (README §5.4); past-the-window attacks defeat the
  200-character LSTM (README §6.2). These are documented limitations, now shown
  to be *systematically* exploitable, not just one-off.

---

## For the thesis

**Report both tiers. The contrast is the contribution.**

1. **Tier 1 is a positive result worth claiming.** "AI-GIS caught 100% of 400
   function-preserving polymorphic mutations across ten attack families,
   including case, comment-insertion, whitespace, encoding, and equivalent-
   syntax transforms." That is a real robustness claim a signature WAF cannot
   match.

2. **Tier 2 bounds the claim honestly.** "Robustness is limited to syntactic
   polymorphism; semantic rewriting and input-pipeline attacks evade at 91%."
   Stating this pre-empts the exact question an examiner asks after seeing the
   100%.

3. **It confirms the shared-blind-spot narrative.** The evading class —
   low-symbol semantic injection — is the same class ModSecurity misses (README
   §8.5). Neither structural ML nor signature matching addresses attack
   *meaning*. That is the project's defensible novel finding, now supported from
   a second angle.

---

## Mitigations (Chapter 5)

Same root causes as the earlier red-team, so the same fixes apply:

| Evading class | Fix | Effort |
|---|---|---|
| Low-symbol semantic SQLi | Keyword-*sequence* feature (`SELECT`…`FROM`, `OR`…`=`) independent of symbol count | Low |
| Past-the-window | Max-pool the LSTM over the full input, or scan all 200-char windows | Medium |
| Novel token shapes | Periodically refit the n-gram vocabulary on fresh evasion corpora | Low |

The single keyword-sequence feature would move Tier 2 semantic SQLi from 0/10
toward parity with Tier 1, and costs no architecture change.

---

## Reproduce

```bash
cd dashboard
python scripts/24_polymorphic_probe.py               # Tier 1 (400 syntactic)
python scripts/24_polymorphic_probe.py --aggressive  # Tier 2 (semantic/structural)
```

## Caveats

- Tier 1 is deterministic (seed 4242); the 40 variants per family are distinct
  after deduplication.
- Tier 2 is a small hand-authored set (22 cases) illustrating the classes, not a
  powered benchmark — the 9% characterises these specific hard cases.
- White-box adversary: mutations were designed with knowledge of the
  architecture.
- Scored offline through the exact `app.py` feature path, not fired as live HTTP.
