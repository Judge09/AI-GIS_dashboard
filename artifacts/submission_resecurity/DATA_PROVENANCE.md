# Data Provenance & Methodology

What in this corpus is real recorded traffic, what is generated, and the
limitations that follow. Read this alongside [README.md](README.md) when
assessing whether results on this dataset support a given claim.

---

## 1. Source dataset

**WEB-IDS23** — a public intrusion-detection dataset of labelled network flows,
captured with Zeek/Bro and exported as per-flow feature CSVs.

The five files under `webids23_source/` are the exact inputs used. They are
redistributed here so the pipeline can be re-run and audited without hunting
for the originals; the licence and citation terms are those of the upstream
publication, and this package claims no ownership of them.

| File | Rows | Bytes | `attack_type` | Services present |
|---|---:|---:|---|---|
| `web-ids23_benign (1).csv` | 825,187 | 227,925,967 | `benign` | dns, ssl, http, ntp, ayiya |
| `web-ids23_sql_injection_http (3).csv` | 74,300 | 22,579,240 | `sql_injection_http` | http |
| `web-ids23_sql_injection_https (2).csv` | 102,584 | 31,415,203 | `sql_injection_https` | ssl, http |
| `web-ids23_xss_http (1).csv` | 4,558 | 1,361,758 | `xss_http` | http |
| `web-ids23_xss_https (1).csv` | 4,533 | 1,354,390 | `xss_https` | ssl |

Row counts are exact (full pass over each file). After dropping rows with a
missing endpoint address, the generator counts **176,884 usable SQLi flows**
and **9,091 usable XSS flows** (see `output/generation_report.txt`).

Capture window spanned by the generated corpus: **2023-07-05 to 2023-09-17**.

Per-file SHA-256 values are in [SHA256SUMS.txt](SHA256SUMS.txt).

---

## 2. What the generator reads

Each source CSV has **38 columns** of flow-level features. The generator reads
**six** (`webids23_to_honeypot_log_v9.py:152`):

```python
USECOLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]
```

| Column | Used for |
|---|---|
| `uid` | Zeek flow id → `flow_uid`, traceability back to the source row |
| `ts` | capture timestamp → `time`, preserving real inter-arrival timing |
| `id.orig_h` | client IP → session grouping key, and a synthetic public IP |
| `id.resp_h` | server IP → synthetic `host` |
| `service` | `http` vs `ssl` → port 80 vs 443 |
| `attack_type` | **ground-truth label** and attack class |

The other 32 columns — packet counts, TCP flag tallies, window sizes, flow
duration, throughput — are **not used**. They describe the shape of the
connection, not its content, and this project trains a payload-inspecting
model. They remain in the shipped CSVs so a reviewer can confirm what was left
on the table.

---

## 3. What is real and what is generated

> **Flow metadata is real. Payload text is synthetic.**

| Field | Origin |
|---|---|
| `time` | **Real** — WEB-IDS23 capture timestamp |
| `flow_uid` | **Real** — Zeek `uid` |
| `label`, `attack_family` | **Real** — derived from `attack_type` |
| `host` port (80/443) | **Real** — derived from `service` |
| `session_id`, `session_seq` | **Derived** — clustered from real `id.orig_h` |
| `source_ip`, `host` address | **Synthetic** — real IPs are RFC1918 private and are deterministically remapped to public-looking addresses |
| `uri`, `request_body` | **Synthetic** — generated from templates |
| `method`, `user_agent`, `referer` | **Synthetic** |

### Why payloads had to be generated

WEB-IDS23 records *that* a flow was an SQL injection or XSS attempt, but stores
only flow statistics — it does not retain the HTTP request text. A model that
inspects payloads needs that text, so the generator keeps each flow's real
metadata and label and synthesises a payload consistent with its recorded
attack type.

This is the central limitation of the dataset and is stated openly rather than
buried: **a model scoring well here has learned to recognise these generators'
output.** That is a genuine result about payload structure, but it is not
equivalent to detecting attacks in the wild. Any headline figure should be
paired with a held-out set the generators never produced.

---

## 4. Known caveats

These are the points a reviewer is most likely to raise. Each is real; none is
hidden.

**4.1 — Benign flows are not all HTTP.** The benign source is general network
capture: roughly 62% DNS, 31% SSL, only ~7% HTTP. The generator does not
filter by `service`, so a benign row may be built on a DNS or NTP flow and then
given a synthetic HTTP request. The *timing and client-grouping structure* of
those rows is real; the protocol framing is not. Consequence: benign HTTP
traffic here is less varied than real web traffic, which likely makes the
benign class easier to separate than it would be in production.

**4.2 — Class balance is artificial.** The default `--benign-ratio 1.0` yields
1:1. Real web traffic is overwhelmingly benign. A false-positive rate measured
at 1:1 will understate the operational rate; regenerate with `--benign-ratio 9.0`
or higher before quoting FPR for a deployment scenario.

**4.3 — SQLi is downsampled 19:1.** The default `match_min` strategy cuts SQLi
from 176,884 usable flows to 9,091 to match XSS. This is deliberate — it keeps
every row a distinct real flow and prevents the model from simply guessing the
majority class — but it discards most of the available SQLi data.

**4.4 — Payload diversity is bounded by the templates.** Attack strings are
assembled from finite component pools. Uniqueness is enforced at the string
level (verified: 36,364 unique of 36,364), but uniqueness is not diversity —
two payloads can differ by one token and still be near-identical to a model.
The 177 rows (0.49%) that required a uniqueness nonce indicate where the
template space was locally exhausted.

**4.5 — Source IPs are remapped.** WEB-IDS23 client addresses are RFC1918
private (`192.168.100.x`). They are deterministically mapped to public-looking
addresses so the log resembles internet-facing traffic. The mapping is stable,
so session structure survives, but the addresses are fictional and must not be
treated as attributable.

**4.6 — Timestamps are 2023 capture times.** They are real, but they span the
original capture window (2023-07-05 to 2023-09-17), not the generation date.
A time-based split is possible using `time`, but the range is fixed and cannot
be extended without new source capture.

---

## 5. Guarding against shortcut learning

Two specific leaks were designed out, because both would inflate scores without
the model learning anything about payloads:

**User agents.** An earlier version shipped six UAs, one literally
`sqlmap/1.7.11`. Had UA been used as a feature, a model could learn
`UA == sqlmap → malicious` and score well while being useless. The current
version samples ~18 UAs with weights so ordinary browsers dominate and tool UAs
appear at realistic low frequency.

**Payload duplication.** An earlier version emitted the same payload thousands
of times; a model could memorise rather than generalise. Uniqueness is now
enforced against a run-wide set with retry-on-collision, and the fallback is
flagged per row (`forced_unique_nonce`) so its rate is auditable rather than
invisible.

Both are verified by [verify.py](verify.py).

---

## 6. Correct evaluation practice

**Split on groups, not rows.** 4,900 sessions span multiple rows (largest: 409).
A random row split scatters a session across train and test and inflates
scores. Group by `session_id` — and by `flow_uid` too if you oversample. See
[USAGE.md §8](USAGE.md).

**Do not report a single seed.** Regenerate across several `--seed` values and
report the spread. A single run's figure carries sampling noise that a spread
makes visible.

**Pair with an out-of-distribution set.** The strongest evidence this dataset
can support is in-distribution. Attacks from a different generator, a public
payload corpus, or hand-written by a red team measure something this corpus
structurally cannot.

---

## 7. Reproducibility

Every random draw derives from `--seed`. Same inputs + same seed = byte-identical
output, verified by regenerating in a clean directory and comparing SHA-256:

```
2af6e8302c5109b153824bd96ed7411e319fa3ade88bf9292f6efb13d0f563fc
```

Run `python verify.py --regenerate` to confirm this independently.

> **Historical note.** Before the fix documented in the script header, the
> uniqueness fallback drew its nonce from `secrets.token_hex()`, which reads OS
> entropy and ignores `--seed`. The reproducibility claim was therefore false
> for ~0.5% of rows in any corpus produced by an earlier copy of the script.
> Both nonce sites now draw from the seeded RNG. This is disclosed because a
> corpus generated before the fix will not reproduce, and a reviewer comparing
> against an older artefact needs to know why.
