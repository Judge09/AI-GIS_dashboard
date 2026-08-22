# AI-GIS Dashboard

A local Flask web app for an **AI-based web-attack detection system**. It trains
and serves an ensemble of models (Random Forest v2 + LSTM + a stacked
meta-learner) on a honeypot dataset of SQL-injection, XSS, and benign traffic,
and gives you an interactive dashboard to explore the data, inspect model
performance, run an evasion stress test, and get **live predictions** on any
text you paste in.

> **Full setup, usage, troubleshooting, and pipeline docs live in
> [`dashboard/README.md`](dashboard/README.md).** This top-level file is a
> project overview.

## What it does

| Page | What it shows |
|------|---------------|
| **Dashboard** | Dataset stats, clean-test performance, evasion + false-positive stress charts |
| **Try a Payload** | Paste any text → live RF v2 / LSTM / Stacked verdict with confidence |
| **Evasion Results** | Real (23+15) and mock (150+150) evasion attempts by attack family |
| **Dataset Browser** | Sample rows straight from the honeypot log |
| **Baseline vs AI-GIS** | ModSecurity + OWASP CRS (paranoia 2) against the ensemble |
| **Statistics** | Bootstrap 95% CIs + McNemar's test on the held-out test set |
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
port conflicts, etc.).

## Repository layout

```
dashboard/
├── app.py              Flask backend (routes + live prediction)
├── requirements.txt    Python dependencies
├── templates/          Jinja2 HTML pages
├── static/             CSS + locally-bundled Chart.js (works offline, no CDN)
├── models/             Trained RF v2, LSTM, meta-learner, n-gram vectorizer  ✔ committed
├── scripts/            The ML pipeline (data generation, feature building, evaluation)
├── reports/            Generated evaluation artifacts (JSON)  ✔ committed
└── data/               Honeypot log + train/val/test splits + results  (large; not committed — see below)

docker-compose.yml      ModSecurity + OWASP CRS baseline environment
docs/                   Chapter 3 runbook, thesis docx, and HTML explainers
```

## The evaluation pipeline

Scripts 11–15 produce the numbers shown on the four evaluation pages. Run them
from `dashboard/`:

```bash
# LLM evasion corpus (needs Ollama running locally)
python scripts/11_generate_evasion_corpus.py --model qwen2.5-coder:1.5b
python scripts/15_evaluate_llm_corpus.py

# ModSecurity baseline (needs Docker)
docker compose up -d
python scripts/12_evaluate_modsec_baseline.py --host localhost --port 8080

# Statistical rigour + ablation (no external services)
python scripts/13_statistical_significance.py
python scripts/14_ablation_study.py
```

Each page renders a "not generated yet" notice with the exact command if its
artifact is missing, so the app always runs.

## About the data

The trained models in `dashboard/models/` **are committed**, so the app runs
immediately after cloning. The large data artifacts (`honeypot_final.log` and
the prepared `.csv` / `.npz` splits, ~86 MB) are **not** committed — they are
regenerable from the pipeline in `dashboard/scripts/`. See
[`dashboard/README.md`](dashboard/README.md#re-running-the-pipeline-from-scratch)
for how to regenerate them (you supply the WebIDS23 source CSVs).

The small results files (`results.json`, `mock_attacker_results.json`, the mock
`.jsonl` profiles) are committed so the Dashboard and Evasion pages render
without regenerating anything.

## Honest limitations

Please read the **Honest limitations** section in
[`dashboard/README.md`](dashboard/README.md#honest-limitations--read-before-presenting-this-anywhere)
before presenting this anywhere. Current state, after the evaluation pipeline was merged in:

- **LLM evasion corpus — done.** 23 machine-generated payloads
  (`qwen2.5-coder:1.5b`); the stacked ensemble caught 23/23. Small sample, and
  the generator leaned heavily on hex encoding, so technique coverage is uneven.
- **Statistical significance — done, and it does not say what you might hope.**
  Every McNemar comparison returns p > 0.05: on this test set the ensemble is
  *not* statistically better than its base models. Bootstrap CIs are zero-width
  because the test set is saturated. The defensible claim is that stacking does
  not degrade clean performance while improving stress-test robustness.
- **Ablation — done.** Only the "LR on 11 base features" condition degrades
  (F1 0.9888), which supports the *feature engineering*, not the stacking.
- **ModSecurity baseline — not run here.** Requires Docker, which was not
  installed on this machine. `docker-compose.yml` and the script are ready.
- **The mock attacker data** (`mock_attacker_results.json`) is still a
  placeholder, superseded by the real LLM corpus above.
- This runs on Flask's development server — **do not expose it to the internet
  as-is.**

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
