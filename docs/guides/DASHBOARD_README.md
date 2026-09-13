# AI-GIS Dashboard — one-stop shop

A local web app that visualizes the honeypot dataset, the trained model
results, the evasion stress test, and lets you paste any text and get a
live prediction from all three models (RF v2, LSTM, and the meta-learner
stack).

## Setup

### Windows — PowerShell (this is what `PS C:\...>` in your terminal means)

```powershell
# from the project root
python -m venv venv
.\app\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app/app.py
```

**If `Activate.ps1` fails with "running scripts is disabled on this
system"** — that's Windows' script-execution policy, not a bug in this
project. Fix it for just this terminal session (safe, doesn't change any
system setting permanently):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\app\venv\Scripts\Activate.ps1
```

### Windows — Command Prompt (cmd.exe)

```cmd
# from the project root
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
python app/app.py
```

### macOS / Linux

```bash
# from the project root
python3 -m venv venv
source app/venv/bin/activate
pip install -r requirements.txt
python3 app/app.py
```

**Common mistake to avoid on any platform**: never run the activate
script *through* `python` (e.g. `python venv/Scripts/activate`) — it's a
shell script, not a Python script. Windows PowerShell needs
`.\app\venv\Scripts\Activate.ps1` typed and run directly at the prompt;
cmd.exe needs `venv\Scripts\activate.bat`; bash needs
`source app/venv/bin/activate`. Picking the wrong one for your shell is what
produced the `SyntaxError: unmatched ')'` — that error is Python trying
to parse a bash conditional (`CYGWIN*|MSYS*|MINGW*)`) as Python code.

### After activation (all platforms)

Your prompt should now show `(venv)` at the start of the line. Then:
```
pip install -r requirements.txt
python app/app.py     (or python3 app.py on macOS/Linux)
```

`tensorflow-cpu` is a few hundred MB — the install takes a few minutes.

**Windows-specific: if TensorFlow fails to import** with a DLL-load
error after installing, install the **Microsoft Visual C++
Redistributable for Visual Studio 2015–2022 (x64)** — TensorFlow on
Windows requires it and it usually isn't installed by default:
https://aka.ms/vs/17/release/vc_redist.x64.exe

**Python version**: 3.10 or 3.11 is the safest choice. `tensorflow-cpu`
does not yet support every very-new Python release; if `pip install`
can't find a `tensorflow-cpu` wheel for your Python version, that's why.
Check your version with `python --version` and install 3.11 from
python.org if needed.

Once running, open your browser to **http://127.0.0.1:5050**

## What's in the dashboard

| Page | What it shows |
|---|---|
| **Dashboard** | Dataset stats, clean-test performance chart, stress-test (evasion + false-positive) chart |
| **Try a Payload** | Paste any text, get a live RF v2 / LSTM / Stacked prediction with confidence bars |
| **Evasion Results** | The 23 real evasion attacks + 15 hard-benign sentences, plus the 150+150 mock CodeLlama/DeepSeek-style profiles, broken down by attack family with the specific missed examples |
| **Dataset Browser** | Sample rows straight from the generated honeypot log |

## Folder structure

```
app.py                  Flask backend
templates/               HTML pages (Jinja2)
static/                  CSS + locally-bundled Chart.js (no CDN dependency —
                          works fully offline)
models/                  Trained RF v2, meta-learner, LSTM, and the fitted
                          n-gram vectorizer
data/
  honeypot_final.log      The full 36,364-entry generated dataset
  prepared/                Train/val/test splits, ready to retrain from
  results.json             Real stress-test results (23 evasion + 15 benign)
  mock_attacker_results.json   Mock CodeLlama/DeepSeek-profile results
  mock_codellama_normal.jsonl      150 mock "normal"-profile payloads
  mock_deepseek_polymorphic.jsonl  150 mock "polymorphic"-profile payloads
scripts/                 The actual pipeline scripts (generation, feature
                          building, evasion definitions) — reference and
                          re-run material
```

## Re-running the pipeline from scratch

The scripts in `scripts/` are the real pipeline, not just for the app:

```bash
# 1. Generate the honeypot log from WEB-IDS23 CSVs (you'll need those separately)
python3 scripts/webids23_to_honeypot_log_v9.py \
  --sqli-http <path> --sqli-https <path> --xss-http <path> --xss-https <path> \
  --benign <path> --strategy match_min --benign-ratio 1.0 --seed 42 \
  -o data/honeypot_final.log

# 2. Prepare training data
python3 scripts/prepare_honeypot_for_training.py \
  --input data/honeypot_final.log --outdir data/prepared --smote

# 3. Build the improved RF features
python3 scripts/build_rf_features_v2.py \
  --input data/honeypot_final.log --outdir data/prepared

# 4. Generate fresh mock attacker payloads (placeholder, see script docstring)
python3 scripts/mock_ai_attacker.py --profile normal --count 150 -o data/mock_codellama_normal.jsonl
python3 scripts/mock_ai_attacker.py --profile polymorphic --count 150 -o data/mock_deepseek_polymorphic.jsonl
```

On Windows, use `python` instead of `python3` for all of the above (Windows
installs Python as `python`, not `python3`, in most cases).

Retraining the models themselves (RF, LSTM, meta-learner) isn't wired into
a single script yet in this folder — see the conversation history for
`08_train_lstm_properly.py` and the evaluation scripts if you need to
retrain from scratch rather than use the models already in `models/`.

## Troubleshooting quick reference

| Symptom | Fix |
|---|---|
| `SyntaxError: unmatched ')'` when activating venv | You ran the activate script through `python`, or used the wrong script for your shell. See Setup above — match the exact command to PowerShell/cmd/bash. |
| `running scripts is disabled on this system` (PowerShell) | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then retry activation. |
| TensorFlow import fails with a DLL error (Windows) | Install the VC++ Redistributable linked above. |
| `pip install` can't find `tensorflow-cpu` | Your Python version is too new/old for the available wheels. Use Python 3.10 or 3.11. |
| Port 5050 already in use | Another process is using it. Edit the last line of `app.py`, change `port=5050` to e.g. `port=5051`. |
| Page loads but charts are blank | Shouldn't happen — Chart.js is bundled locally in `static/`, not loaded from a CDN. If it does, check the browser console for a 404 on `chart.umd.js` and confirm `static/chart.umd.js` exists in your extracted folder. |

## Honest limitations — read before presenting this anywhere

1. **The mock attacker data is a placeholder.** There is no real Ollama /
   CodeLlama / DeepSeek-R1 inference in this dashboard. `mock_ai_attacker.py`
   generates payloads from the same public technique pool as the rest of
   the project, organized into two profiles that *approximate* a stylistic
   difference. It is not real LLM output. Swap in real files with the same
   JSONL schema (`label`, `attack_type`, `family`, `profile`, `payload`)
   the moment you have them — nothing else needs to change.
2. **The real evasion/hard-benign stress test is small** (23 + 15
   examples). Good enough to prove a mechanism, not a citable rate.
3. **No ModSecurity/CRS baseline is included.** This dashboard only shows
   your system's own numbers — there's no "vs." yet.
4. **This is a development server** (Flask's built-in one). Fine for local
   use and demos; do not expose this to the internet as-is.
