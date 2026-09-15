# How to Use `webids23_to_honeypot_log_v9.py`

Practical guide to running the honeypot corpus generator.

- For *what* the package is and its verified figures, see [README.md](README.md).
- For *what is real vs. synthetic* and the dataset's limitations, see
  [DATA_PROVENANCE.md](DATA_PROVENANCE.md).
- To check the package is intact, run `python verify.py`.

---

## 1. Requirements

| | |
|---|---|
| Python | 3.8+ (tested on 3.13) |
| Packages | `pandas` — everything else is standard library |
| Disk | ~20 MB output per 36k rows; inputs are 272 MB |
| RAM | Modest. Inputs are streamed in chunks, never loaded whole |
| Time | ~65 s for a full 36k-row run |

```bash
pip install pandas
```

Runs on Windows, macOS, and Linux. On Windows the peak-memory line of the
report prints `Peak RSS: nan MB` — the `resource` module is Unix-only and is
deliberately skipped. This is cosmetic and affects nothing else.

---

## 2. Quick start

### 2a. With the bundled samples (works immediately)

```bash
python webids23_to_honeypot_log_v9.py \
    --sqli-http  sample_input/web-ids23_sql_injection_http_3.csv \
    --sqli-https sample_input/web-ids23_sql_injection_https_2.csv \
    --xss-http   sample_input/web-ids23_xss_http_1.csv \
    --xss-https  sample_input/web-ids23_xss_https_1.csv \
    --benign     sample_input/web-ids23_benign_1.csv \
    --seed 42 -o output/sample_output.log
```

Produces 16,000 rows in ~45 s, SHA-256
`a13c3d30fe7743eac72e0791d4e35f84b8ae30cb4d89eb23d784acdc8e48b451`.

`sample_input/` holds truncated slices of the WEB-IDS23 CSVs so the package
runs out of the box. They demonstrate and verify the pipeline; they are **not**
a corpus to train on.

### 2b. With the full WEB-IDS23 dataset

Obtain the five WEB-IDS23 flow exports and point the same flags at them. File
names do not matter — only the six required columns do:

```bash
python webids23_to_honeypot_log_v9.py \
    --sqli-http  "/data/webids23/sql_injection_http.csv" \
    --sqli-https "/data/webids23/sql_injection_https.csv" \
    --xss-http   "/data/webids23/xss_http.csv" \
    --xss-https  "/data/webids23/xss_https.csv" \
    --benign     "/data/webids23/benign.csv" \
    --seed 42 -o honeypot_full.log
```

A full run takes ~65 s and yields roughly 36k rows at the default `match_min`
strategy. To confirm the generator behaves correctly on your copy:

```bash
python verify.py --inputs /data/webids23
```

That runs the full invariant suite — no duplicate payloads, correct labelling,
schema conformance, seed reproducibility, and flag behaviour — against *your*
files rather than the bundled sample. CSVs are matched to flags by filename
(`sqli`/`xss`/`benign`, `http` vs `https`).

### Input requirements

Any CSV works if it carries these six columns, in any order, alongside any
number of others:

| Column | Meaning |
|---|---|
| `uid` | unique flow id |
| `ts` | timestamp |
| `id.orig_h` | client IP |
| `id.resp_h` | server IP |
| `service` | `http` or `ssl` (sets port 80 vs 443) |
| `attack_type` | ground-truth class label |

Extra columns are ignored, and `.csv.gz` is read transparently. Missing files,
missing columns, unreadable files and empty files are each reported by name
before any work starts.

> **Windows note:** the `\` line-continuations above are for bash. In PowerShell
> use a backtick `` ` `` instead, or put the whole command on one line. Quote
> any path containing spaces or parentheses.

---

## 3. All options

| Flag | Default | What it does |
|---|---|---|
| `--sqli-http` | *none* | SQLi-over-HTTP source CSV |
| `--sqli-https` | *none* | SQLi-over-HTTPS source CSV |
| `--xss-http` | *none* | XSS-over-HTTP source CSV |
| `--xss-https` | *none* | XSS-over-HTTPS source CSV |
| `--benign` | *none* | Benign-traffic source CSV |
| `--strategy` | `match_min` | How attack-class targets are set — see §4 |
| `--custom-sqli-count` | natural count | Row target for SQLi (`--strategy custom` only) |
| `--custom-xss-count` | natural count | Row target for XSS (`--strategy custom` only) |
| `--benign-ratio` | `1.0` | Benign rows per attack row — see §5 |
| `--seed` | `42` | RNG seed. Same seed + same inputs = byte-identical output |
| `--obfuscate-prob` | `0.4` | Probability each payload is obfuscated — see §6 |
| `-o`, `--output` | `honeypot_from_webids23.log` | Output path |

All five input flags are optional and independent: pass only the ones you want.
Passing none exits with `No input CSVs given. See --help.`

---

## 4. `--strategy` — balancing SQLi against XSS

The source CSVs are wildly imbalanced. In the shipped data SQLi has 176,884
usable flows and XSS only 9,091. Left alone, a model would see a 19:1 skew and
learn to just guess SQLi. The strategy flag decides how to correct that.

| Strategy | Target for both classes | Effect |
|---|---|---|
| `match_min` *(default)* | `min(sqli, xss)` = 9,091 | **Downsamples the larger class.** Every row is a distinct real flow — no reuse. |
| `match_max` | `max(sqli, xss)` = 176,884 | **Oversamples the smaller class.** Needs ~19 reuses of each XSS flow. |
| `custom` | whatever you pass | Set each class explicitly. |

**`match_min` is the default for a reason** — it is the only one of the three
that guarantees every row comes from a distinct source flow. Prefer it unless
you specifically need volume.

If you only supply one attack class, `match_min` falls back to that class's
natural count rather than collapsing to zero.

```bash
# Explicit per-class counts
python webids23_to_honeypot_log_v9.py \
    --sqli-http "…sql_injection_http (3).csv" \
    --xss-http  "…xss_http (1).csv" \
    --benign    "…benign (1).csv" \
    --strategy custom --custom-sqli-count 2000 --custom-xss-count 2000 \
    -o small.log
```

### What oversampling actually reuses

Asking for more rows than a file has does **not** duplicate payloads. Requesting
8,000 rows from the 4,558-flow XSS file gives:

```
[ok] xss_http: 8000 entries (4558 unique flows + 3442 oversampled)
flow-level (oversampled) duplicates: 3442 (43.0% of total)
```

…yet all 8,000 `uri`+`request_body` pairs are still unique. The *flow metadata*
(timestamp, source IP) is reused; a fresh payload is generated each time, and
the copy is marked `dup_index: 1` and `synthetic_duplicate: true`.

This is why the log has two separate audit flags:

- `synthetic_duplicate` — this **flow** was sampled more than once
- `forced_unique_nonce` — this **payload** needed a nonce to stay unique

They measure different things and should not be conflated when auditing.

---

## 5. `--benign-ratio` — attack/benign balance

Benign target = `benign_ratio × (sqli_target + xss_target)`.

| Value | Result |
|---|---|
| `1.0` *(default)* | 1:1 balanced — 18,182 attack / 18,182 benign |
| `2.0` | Twice as much benign traffic as attack |
| `4.0`–`9.0` | Closer to realistic traffic, where attacks are rare |
| `0` | No benign rows at all (attack-only corpus) |

Balanced data is convenient for training but optimistic: a detector tuned at 1:1
will show a higher false-positive rate against real traffic, where benign
dominates. If you are measuring FPR for a realistic deployment, raise this.

---

## 6. `--obfuscate-prob` — WAF-evasion disguising

Fraction of attack payloads rewritten to evade naive signature matching —
URL-encoding, comment-splitting, case-mixing. Verified to behave linearly:
`0.0` gives 0/300 obfuscated, `1.0` gives 300/300.

- `0.0` — clean payloads only; useful as an easy-case baseline
- `0.4` *(default)* — mixed corpus
- `1.0` — every payload disguised; a stress test, not a realistic corpus

Only attack rows are affected; benign rows are never obfuscated.

---

## 7. Reproducibility

`--seed` controls every random draw. Same inputs + same seed = byte-identical
output, verified across repeated runs.

```bash
python webids23_to_honeypot_log_v9.py … --seed 42 -o a.log
python webids23_to_honeypot_log_v9.py … --seed 42 -o b.log
sha256sum a.log b.log     # identical
```

Change the seed to get an independent corpus from the same inputs — useful for
variance studies (train on several seeds, report the spread rather than one
lucky run).

> **Caveat for older outputs.** Before the fix documented in the script header,
> the uniqueness fallback drew its nonce from `secrets.token_hex()`, which reads
> OS entropy and ignores `--seed`. Any corpus generated by an earlier copy will
> **not** reproduce byte-for-byte — roughly 0.5% of its rows carried random
> nonces. Corpora generated by this version reproduce exactly.

---

## 8. Reading the output

JSON-lines: one JSON object per line, UTF-8.

```python
import json
rows = [json.loads(l) for l in open("output/honeypot_final.log", encoding="utf-8") if l.strip()]

attacks = [r for r in rows if r["label"] == 1]
texts   = [r["uri"] + " " + r["request_body"] for r in rows]   # what a model reads
labels  = [r["label"] for r in rows]
```

With pandas:

```python
import pandas as pd
df = pd.read_json("output/honeypot_final.log", lines=True)
print(df.groupby("attack_family").size())
```

Field-by-field schema is in [README.md](README.md#output-schema).

### Splitting without leaking

Do **not** split randomly by row. Rows sharing a `session_id` belong to one
simulated user session — in the shipped corpus 4,900 sessions span more than one
row, and the largest holds 409. A random row split scatters those across train
and test, and the model scores partly on sessions it has already seen.

Split on **groups**, not rows:

```python
from sklearn.model_selection import GroupShuffleSplit
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df["session_id"]))
```

`session_id` is the grouping key that matters here. Under `match_min` every
`flow_uid` is already unique (36,364 distinct across 36,364 rows), so grouping by
it changes nothing — but if you oversample with `match_max` or a large
`--custom-*-count`, flows *are* reused and you should group by `flow_uid` as
well.

---

## 9. Verifying a generated corpus

The three checks worth running on any output:

```python
import json, hashlib, pathlib
p = pathlib.Path("output/honeypot_final.log")
rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

seen = {(r["uri"], r["request_body"]) for r in rows}
print("rows:", len(rows), "unique:", len(seen), "dupes:", len(rows) - len(seen))
print("balance:", {0: sum(r["label"] == 0 for r in rows), 1: sum(r["label"] == 1 for r in rows)})
print("sha256:", hashlib.sha256(p.read_bytes()).hexdigest())
```

Expected for the shipped run: `36364 / 36364 / 0`, balance `18182 / 18182`.

To verify the whole package:

```bash
sha256sum -c SHA256SUMS.txt
```

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `No input CSVs given. See --help.` | No `--sqli-*` / `--xss-*` / `--benign` flag passed. |
| `FileNotFoundError` with a traceback | A path is wrong. Paths are not validated up front, so this surfaces as a raw traceback — check spelling, and quote names containing spaces or parentheses. |
| `ModuleNotFoundError: pandas` | `pip install pandas` |
| `Peak RSS: nan MB` | Expected on Windows. Cosmetic only. |
| Output not reproducing across runs | Confirm identical `--seed` *and* identical inputs. If it still differs, the copy predates the nonce fix — see §7. |
| Huge `flow-level duplicates` percentage | You asked for more rows than the source has. Lower the target or use `--strategy match_min`. |
| Nonzero `forced_unique_nonce` count | Normal at ~0.5%. A large value means the payload space is exhausted relative to the row count — reduce the target. |

---

## 11. Worked examples

**Small smoke test** (a few seconds, no large benign file):

```bash
python webids23_to_honeypot_log_v9.py \
    --xss-http "webids23_source/web-ids23_xss_http (1).csv" \
    --strategy custom --custom-xss-count 300 --benign-ratio 0 \
    -o smoke.log
```

**Realistic-imbalance evaluation set** (attacks rare, as in production):

```bash
python webids23_to_honeypot_log_v9.py \
    --sqli-http "…sql_injection_http (3).csv" --xss-http "…xss_http (1).csv" \
    --benign "…benign (1).csv" \
    --benign-ratio 9.0 --seed 99 -o eval_realistic.log
```

**Clean-payload baseline** (no obfuscation — establishes the easy-case ceiling):

```bash
python webids23_to_honeypot_log_v9.py … --obfuscate-prob 0.0 -o baseline_clean.log
```

**Five-seed variance study:**

```bash
for S in 1 2 3 4 5; do
  python webids23_to_honeypot_log_v9.py … --seed $S -o corpus_seed$S.log
done
```

---

## 12. Limitation to keep in view

*Full treatment in [DATA_PROVENANCE.md §4](DATA_PROVENANCE.md).*

Payload text is **synthetic**. The flow metadata — timestamps, source IPs,
http/https, and the ground-truth attack labels — is real WEB-IDS23 data, but the
attack strings themselves are generated by this script from templates, because
WEB-IDS23 records that a flow was an attack without preserving the payload.

A model scoring well here has learned to recognise *these generators' output*.
That is a real result, but it is not the same as detecting attacks in the wild,
and any reported figure should be paired with a held-out set the generators
never touched.
