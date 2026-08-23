# AI-GIS Dashboard

A local Flask web app for an **AI-based web-attack detection system**. It trains
and serves an ensemble of models (Random Forest v2 + a two-layer stacked LSTM +
a logistic-regression meta-learner) on a labelled corpus of SQL-injection, XSS,
and benign traffic, and gives you an interactive dashboard to explore the data,
inspect model performance, run an evasion stress test, and get **live
predictions** on any text you paste in.

> **Methodology, dataset provenance, and the full audit trail live in
> [`dashboard/METHODOLOGY.md`](dashboard/METHODOLOGY.md).**
> **Setup, usage, and troubleshooting live in
> [`dashboard/README.md`](dashboard/README.md).**
> This top-level file is a project overview.

---

## Headline results

Measured on a 396-row adversarial hold-out set (198 attack / 198 benign),
disjoint from training. **Mean ± SD across 5 seeded training runs** — not a
single run.

| Stacked ensemble | Before improvement | **After (5 runs)** |
|---|---:|---:|
| False-positive rate | 57.6% | **3.64% ± 2.71%** |
| Detection rate | 95.0% | **96.16% ± 1.26%** |

**False alarms fell ~16× while detection rose.** Per-model, same 5 runs:

| Model | Detection | FPR | AUC |
|---|---:|---:|---:|
| RF v2 | 100.00 ± 0.00% | 6.97 ± 0.66% | 0.9994 |
| LSTM | 92.83 ± 0.23% | 4.14 ± 3.77% | 0.9782 |
| **Stacked** | 96.16 ± 1.26% | **3.64 ± 2.71%** | 0.9971 |

The ensemble has the lowest false-alarm rate of the three and roughly 30% less
run-to-run variance than the LSTM it contains — a benefit invisible in any
single run.

### Versus ModSecurity + OWASP CRS, on identical inputs

| | ModSecurity (CRS, PL2) | AI-GIS Stacked |
|---|---:|---:|
| Detection | 95.5% (189/198) | 93.4% (185/198) |
| **False-positive rate** | **70.2%** (139/198) | **0.5%** (1/198) |

At comparable detection the rule-based WAF raises **139 false alarms to the
ensemble's 1** — it blocks 7 in 10 legitimate requests on this adversarial set.

**Both systems miss the same 9 plain-language attacks.** Natural-language
attack intent is a blind spot shared by signature WAFs and character-level
neural detectors alike.

### By attack type

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| XSS | 77 | **97.4%** | 0.9997 |
| SQLi | 102 | **95.1%** | 0.9916 |
| Plain-language intent | 4 | **0.0%** | 0.4028 |

Plain-language attacks are **deliberately not trained on** — 41 such rows were
removed because ~0.1% of the corpus was too few to teach a linguistic category
but enough to imply a capability the system lacks. 0.0% is the honest number,
and it is corroborated by ModSecurity failing on the identical attacks.

Full results, per-run detail and the reasoning behind each decision:
[`dashboard/reports/FINAL_RESULTS.md`](dashboard/reports/FINAL_RESULTS.md).

---

## What it does

| Page | What it shows |
|------|---------------|
| **Dashboard** | Dataset stats, clean-test performance, evasion + false-positive stress charts |
| **Try a Payload** | Paste any text → live RF v2 / LSTM / Stacked verdict with confidence |
| **Evasion Results** | Real and mock evasion attempts by attack family |
| **Dataset Browser** | Sample rows straight from the honeypot log |
| **Baseline vs AI-GIS** | ModSecurity + OWASP CRS (paranoia 2) against the ensemble |
| **Statistics** | Bootstrap 95% CIs + McNemar's test |
| **Ablation** | 6-condition study of what each component contributes |
| **LLM Corpus** | Detection results on machine-generated evasion payloads |

## Quick start

```bash
cd dashboard
python -m venv venv
# Windows PowerShell:  .\venv\Scripts\Activate.ps1
# Windows cmd:         venv\Scripts\activate.bat
# macOS / Linux:       source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5050**.

`tensorflow-cpu` is a few hundred MB, so the first install takes a few minutes.
Python 3.10 or 3.11 is the safest choice. See
[`dashboard/README.md`](dashboard/README.md) for platform-specific notes
(PowerShell execution policy, the Windows VC++ redistributable for TensorFlow,
port conflicts).

## Repository layout

```
dashboard/
├── app.py              Flask backend (routes + live prediction)
├── METHODOLOGY.md      Dataset provenance, all 319 features, code audit
├── templates/          Jinja2 HTML pages
├── static/             CSS + locally-bundled Chart.js (offline, no CDN)
├── models/             Trained RF v2, 2-layer LSTM, meta-learner, vectorizer
├── scripts/            The ML pipeline (generation, features, training, evaluation)
├── reports/            Generated evaluation artifacts (JSON, PNG, MD)
└── data/               Corpus, hold-out eval set, prepared splits

docker-compose.yml      ModSecurity + OWASP CRS baseline environment
docs/                   Chapter 3 runbook and HTML explainers
```

Models **and** data are committed, so the app runs immediately after cloning
(~70 MB). The LSTM is not deterministically reproducible run-to-run, so the
exact trained artifacts behind the numbers above are versioned rather than
regenerated.

## About the dataset

The corpus is **not** captured live-attacker traffic, and this matters when
citing it. It is a **synthetic payload overlay on real flow metadata**:

| From WEB-IDS23 (real) | Generated (synthetic) |
|---|---|
| Ground-truth attack labels | Payload strings |
| Timestamps and inter-arrival timing | URIs |
| Client/server IPs → session grouping | User-agents, public IPs |

WEB-IDS23 flow records carry no request bodies, so payloads are generated
combinatorially per attack family and grafted onto real flows. **36,635 rows**,
near-balanced (18,410 benign / 18,225 attack), 71% of attacks obfuscated as a
deliberate stress-test prior.

Full provenance, the generator's own defect-audit history, and every feature
definition are in [`dashboard/METHODOLOGY.md`](dashboard/METHODOLOGY.md).

## Reproducing the results

From `dashboard/`, in order — later steps read what earlier ones write:

```bash
python scripts/build_holdout_eval.py            # the 396-row ruler (seed 1234)
python scripts/build_training_augmentation.py   # +228 benign, +43 attack (seed 4242)
python scripts/18_train_stacked.py --epochs 6   # retrain RF + 2-layer LSTM + meta
python scripts/17_evaluate_csv.py               # headline detection / FPR
python scripts/19_eval_by_type.py               # per-type breakdown + ROC curves
python scripts/20_significance_holdout.py       # McNemar + effect sizes
python scripts/16_claude_redteam.py             # independent red-team
python scripts/13_statistical_significance.py   # bootstrap CIs
python scripts/14_ablation_study.py             # 6-condition ablation
python scripts/15_evaluate_llm_corpus.py        # LLM evasion corpus

# External baseline (needs Docker Desktop running)
docker network create modsec-net && docker compose up -d
python scripts/21_modsec_holdout.py --host localhost --port 8080
```

Training takes ~20 minutes on CPU (the two-layer LSTM is the slow part;
TensorFlow has no GPU support on native Windows).

## Honest limitations

Read this before presenting the project anywhere.

- **False-positive rate carries real run-to-run variance** (SD 2.71% across 5
  seeded runs; one seed produced 8.1%). Always quote the ± , never a single run.
  Detection is far more stable (SD 1.26%).
- **The corpus is synthetic in its payloads.** Labels, timing and session
  structure are real; the attack strings are generated. Distributional realism
  is unproven.
- **The clean test split is fully saturated** (stacked F1 = 1.0000, zero false
  positives) and has no power to rank detectors. All model comparisons must use
  the 396-row adversarial hold-out.
- **The ensemble is not statistically better than Random Forest alone**
  (p = 0.388 on the hold-out; odds ratio 2.0 in its favour, but not
  significant). Its defensible advantages are a lower false-alarm rate (95% CI
  on the difference excludes zero) and reduced run-to-run variance. RF alone
  achieves perfect recall (100.00 ± 0.00%) at roughly double the false-alarm
  rate (6.97% vs 3.64%) — the ensemble's case rests on false alarms, not
  detection.
- **Plain-language attacks are detected 0% of the time, by design.** "Drop the
  users table from the database" carries no injection syntax. ModSecurity misses
  the same attacks, making this a shared limitation of signature-based and
  character-level neural detection rather than a defect unique to this system.
  The evaluation set retains 4 such rows (too few to support a rate — treat as a
  documented blind spot, not a measurement).
- **The LLM evasion corpus is weak evidence.** 23 payloads from a 1.5B-parameter
  local model (`qwen2.5-coder:1.5b`); 91% came back using one obfuscation
  technique, and several generations are near-identical to their inputs.
- **The 32.8% and 70.2% ModSecurity false-positive rates are both valid — they
  measure different traffic.** 32.8% is CRS against ~2,733 ordinary clean
  requests; 70.2% is CRS against the 198 deliberately hard benign rows (source
  code, apostrophe surnames, angle brackets in prose). Only the 70.2% figure is
  like-for-like with the ensemble's 2.0%, because only it uses identical inputs.
  Note that CRS at paranoia 2 also scores the *client*: a default Python HTTP
  client trips scanner-detection (rule 913101) and the missing `Accept` header
  (920300), which alone exceeds the block threshold. Both measurements above
  avoid this — the original harness sends a custom user-agent, and the
  like-for-like harness sends full browser headers (re-measured: 72.2% vs 70.2%,
  a 2-point difference).
- **`mock_attacker_results.json` and the mock `.jsonl` profiles are
  placeholders**, not real model output. Do not cite them.
- This runs on Flask's development server — **do not expose it to the internet
  as-is.**

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
