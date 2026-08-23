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

Measured 2026-08-23 on a 396-row adversarial hold-out set (198 attack / 198
benign) that is disjoint from training. Two-layer LSTM, seed 42.

| Stacked ensemble | Before improvement | **After** |
|---|---:|---:|
| False-positive rate | 57.6% (114/198) | **2.0%** (4/198) |
| Detection rate | 95.0% (188/198) | **95.0%** (188/198) |

**False alarms fell 29× with detection unchanged** — not one detection was
traded away.

### Versus ModSecurity + OWASP CRS, on identical inputs

| | ModSecurity (CRS, PL2) | AI-GIS Stacked |
|---|---:|---:|
| Detection | 95.5% (189/198) | 95.0% (188/198) |
| **False-positive rate** | **70.2%** (139/198) | **2.0%** (4/198) |

At effectively identical detection — one attack apart — the rule-based WAF
raises **139 false alarms to the ensemble's 4**. Both systems miss the *same*
9 plain-language attacks.

### By attack type

| Segment | n | Detection | AUC |
|---|---:|---:|---:|
| XSS | 77 | **100.0%** | 0.9997 |
| SQLi | 102 | 94.1% | 0.9986 |
| Plain-language intent | 4 | **50.0%** | 0.9798 |

> ⚠️ **These are single-run point estimates.** Repeat runs of the same pipeline
> have spanned 5.1% / 2.5% / 2.0% FPR, so the run-to-run spread is comparable to
> the differences being reported. A seeded multi-run study
> (`scripts/22_multirun_variance.py`) is written but has not yet been run.
> Treat every figure above as a measurement, not a settled final number.

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

- **All figures are single-run point estimates.** The seeded multi-run variance
  study has not been run. Run-to-run spread is comparable to the effects being
  reported.
- **The corpus is synthetic in its payloads.** Labels, timing and session
  structure are real; the attack strings are generated. Distributional realism
  is unproven.
- **The clean test split is saturated** (F1 ≈ 0.999 for every model) and cannot
  rank detectors. All discriminating signal is in the 396-row hold-out.
- **The ensemble is not statistically better than Random Forest alone**
  (p = 0.845 on the hold-out). It *is* significantly better than the LSTM
  (p = 0.013), and its lower false-positive rate against RF is a real effect
  (95% CI excludes zero). RF alone achieves perfect recall (198/198) at a higher
  FPR (6.1% vs 2.0%) — the ensemble's case rests on false alarms, not detection.
- **Plain-language attacks are the system's blind spot.** "Drop the users table
  from the database" is detected 50% of the time by the ensemble and **0%** by
  the LSTM. ModSecurity misses these too, which makes it a shared limitation of
  both paradigms rather than a defect unique to this system.
- **The LLM evasion corpus is weak evidence.** 23 payloads from a 1.5B-parameter
  local model (`qwen2.5-coder:1.5b`); 91% came back using one obfuscation
  technique, and several generations are near-identical to their inputs.
- **A previously reported 32.8% ModSecurity false-positive rate is likely
  invalid.** CRS at paranoia 2 scores the *client*, not just the payload: a
  default Python HTTP client trips the scanner-detection rule and the missing
  `Accept` header, exceeding the block threshold before the payload is
  evaluated. The 70.2% figure above was measured with browser headers.
- **`mock_attacker_results.json` and the mock `.jsonl` profiles are
  placeholders**, not real model output. Do not cite them.
- This runs on Flask's development server — **do not expose it to the internet
  as-is.**

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
