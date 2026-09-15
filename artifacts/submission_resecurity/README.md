# Honeypot Corpus Generator — Review Package

Self-contained package for external review: one script that turns WEB-IDS23
flow records into a labelled honeypot-style HTTP log, plus runnable sample
inputs and the corpus they produce.

Everything here is verifiable without trusting this document:

```bash
python verify.py                          # 46 checks: integrity + generator invariants
python verify.py --inputs /path/to/csvs   # also validate against your own WEB-IDS23 files
```

## Contents

```
README.md                          this file — what the package is, verified figures
USAGE.md                           how to run the generator; every flag explained
DATA_PROVENANCE.md                 what is real vs. synthetic, and known limitations
verify.py                          independent verification (46 checks, exits non-zero on failure)
webids23_to_honeypot_log_v9.py     the generator (1,010 lines, single file, stdlib + pandas)
sample_input/                      5 WEB-IDS23 slices, enough to run out of the box (4.7 MB)
output/sample_output.log           corpus generated from those slices, 16,000 rows (8.5 MB)
output/sample_generation_report.txt console output of that run
SHA256SUMS.txt                     SHA-256 for all 12 files; `sha256sum -c` verifies
```

### Where to start

| If you want to… | Do this |
|---|---|
| Confirm the package is intact and the figures hold | `python verify.py` |
| Run it against the full WEB-IDS23 dataset | [USAGE.md](USAGE.md), then `verify.py --inputs DIR` |
| Understand what the dataset is and its limits | [DATA_PROVENANCE.md](DATA_PROVENANCE.md) |

## A note on the sample inputs

`sample_input/` holds **truncated slices** of the five WEB-IDS23 CSVs — 2,000
rows per attack file and 9,000 benign — so the package stays at 14 MB instead
of 291 MB and runs immediately after unzipping.

They are for demonstrating and verifying the pipeline, **not** for producing a
corpus to train on. A full run uses the complete WEB-IDS23 export; see
[USAGE.md §2](USAGE.md). The generator is input-agnostic — any CSV carrying the
six required columns works, whatever its size, column order, or name — and
`verify.py --inputs DIR` runs the same invariant checks against your own copy.

## What the script does

WEB-IDS23 is a public network-capture dataset. It records that a given flow
*was* an SQL-injection or XSS attack, but it does **not** contain the attack
text itself — the payload. A payload-inspecting model needs that text.

So this script keeps the **real flow metadata** from WEB-IDS23 (timestamps,
source IPs, http/https, and the ground-truth attack labels) and **synthesises
a realistic payload** to match each flow's recorded attack type.

This is a deliberate, documented trade-off, and the most important thing to
know when reviewing the package:

> **Flow metadata is real. Payload text is synthetic.**

Six columns are read from the source CSVs
(`webids23_to_honeypot_log_v9.py:152`):

```python
USECOLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]
```

## Reproducing the sample corpus

```bash
python webids23_to_honeypot_log_v9.py \
    --sqli-http  sample_input/web-ids23_sql_injection_http_3.csv \
    --sqli-https sample_input/web-ids23_sql_injection_https_2.csv \
    --xss-http   sample_input/web-ids23_xss_http_1.csv \
    --xss-https  sample_input/web-ids23_xss_https_1.csv \
    --benign     sample_input/web-ids23_benign_1.csv \
    --seed 42 -o output/sample_output.log
```

Runs in ~45 s. Requires Python 3 and `pandas`; everything else is stdlib.

Expected output SHA-256:

```
a13c3d30fe7743eac72e0791d4e35f84b8ae30cb4d89eb23d784acdc8e48b451
```

Verified: repeated runs at the same seed produce byte-identical files.

## Verified properties of `output/sample_output.log`

| Property | Value |
|---|---|
| Rows | 16,000 |
| Unique `uri`+`request_body` pairs | 16,000 |
| Exact duplicates | **0** |
| Class balance | 8,000 attack / 8,000 benign (1.00:1) |
| Flow-level oversampled duplicates | 0 |
| Uniqueness-fallback rows | 1,535 (9.6%) |
| Distinct attack payloads | SQLi 4,000 / XSS 4,000 |

Attack families: `union_based`, `tautology`, `boolean_blind`, `error_based`,
`stacked_query`, `time_based_blind`, `auth_bypass` (SQLi); `reflected`,
`stored`, `dom_based` (XSS).

> The 9.6% uniqueness-fallback rate is an artefact of the small sample: 4,000
> payloads per class are drawn from template pools sized for a much larger
> corpus, so collisions are frequent. On the full dataset the same code yields
> **0.49%**. The rate is reported per-run and flagged per-row, so it is always
> auditable — see [DATA_PROVENANCE.md §4.4](DATA_PROVENANCE.md).

## The two things a reviewer usually checks

**1. No duplicate payloads.** An earlier version of this generator leaked the
same payload thousands of times, which inflates accuracy — the model just
memorises. This version enforces uniqueness: every payload is checked against
a set of everything already produced and retried on collision. If retries are
exhausted, a nonce is appended and the row is flagged
`forced_unique_nonce: true` so the fallback rate is auditable.

**2. No giveaway shortcuts.** User-agents are deliberately varied (~18,
weighted so ordinary browsers dominate and tool UAs like sqlmap appear at
realistic low frequency) so a model cannot cheat by learning
`user_agent == sqlmap → malicious` instead of reading payload structure.
`verify.py` asserts both — no UA exceeds 50% of rows, and the sqlmap UA does
not perfectly predict the label.

## Output schema

One JSON object per line:

| Field | Meaning |
|---|---|
| `time`, `source_ip`, `host`, `method`, `uri`, `user_agent`, `request_body`, `referer` | the HTTP request |
| `label` | ground truth: `1` = attack, `0` = benign |
| `attack_family` | e.g. `union_based`, `reflected`, `benign` |
| `obfuscated` | payload was deliberately disguised (URL-encoding, comment-splitting, case-mixing) |
| `flow_uid` | traces the row back to its source WEB-IDS23 CSV row |
| `dup_index` | `0` for original, `1+` for oversampled copies of a flow |
| `session_id`, `session_seq` | session clustering |
| `synthetic_duplicate` | flow-level reuse (same CSV row sampled twice under oversampling) |
| `forced_unique_nonce` | audit flag for the uniqueness fallback described above |

Note `synthetic_duplicate` and `forced_unique_nonce` track two *different*
mechanisms — flow-level reuse vs. payload-level collision — and are
deliberately kept as separate fields rather than conflated.

## Limitations

The corpus has real constraints that bear directly on how its results should be
read. Full treatment in [DATA_PROVENANCE.md §4](DATA_PROVENANCE.md); in short:

- **Payload text is synthetic.** A model scoring well here has learned to
  recognise *these generators' output*, which is not the same as detecting
  attacks in the wild.
- **Benign flows are not all HTTP.** The benign source is ~62% DNS and ~31%
  SSL; those flows receive synthetic HTTP requests, so benign traffic is less
  varied than production traffic.
- **1:1 class balance is artificial** and will understate false-positive rate
  for a real deployment.
- **SQLi is downsampled 19:1** on the full dataset (176,884 usable flows →
  9,091) to match the smaller XSS class.

## Changes made while preparing this package

Two defects were found and fixed. Both are disclosed because they affect how
this package compares against earlier artefacts.

**Reproducibility was broken.** The uniqueness fallback drew its nonce from
`secrets.token_hex()`, which reads OS entropy and ignores `--seed` entirely.
The script advertised "same inputs + same seed = byte-identical corpus", but
that was false for the rows where the fallback fired. Both nonce sites now draw
from the seeded RNG; determinism is asserted by `verify.py`.

Consequence: any corpus generated *before* this fix will not reproduce
byte-for-byte, because those rows carried OS-random nonces.

**Stale documentation.** The file was titled `v9` but its docstring still
described itself as `v5`; a header claimed a row count that did not match the
corpus. Both corrected against measured values.

**Input validation added.** Pointing the script at a CSV that was not a
WEB-IDS23 export produced a raw pandas traceback. Inputs are now checked before
any work starts, and a missing file, missing column, unreadable file, or
empty file is reported by name with what to do about it.

---

*Package verified with `python verify.py` — 46/46 checks passing. Validated
against the full WEB-IDS23 dataset with `verify.py --inputs DIR` — 63/63.*
