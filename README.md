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
├── scripts/            The ML pipeline (data generation, feature building, evasion tests)
└── data/               Honeypot log + train/val/test splits + results  (large; not committed — see below)
```

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
before presenting this anywhere. In short: the mock attacker data is a
placeholder (not real LLM output), the real evasion test set is small (23+15),
there is no ModSecurity/CRS baseline for comparison, and this runs on Flask's
development server — **do not expose it to the internet as-is.**

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
