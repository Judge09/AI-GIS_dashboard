# Running the pipeline on this machine

Everything is already here. No zip, no upload, no download.

---

## Option A — just run it (no Jupyter needed)

Open PowerShell in the `dashboard` folder and run:

```powershell
cd "c:\Users\Lloyd\Downloads\AI-GIS_dashboard (9)\dashboard"
python run_pipeline.py
```

That is the whole thing. ~15 minutes (11 of which is training).

**Quicker version** — skips training, reuses the models already in `models/`:

```powershell
python run_pipeline.py --fast
```

~4 minutes. Use this when you only want the evaluation numbers.

`run_pipeline.py` is generated from the notebook, so it does exactly the same
13 steps in the same order. Same output, same checks, same reports.

---

## Option B — the actual notebook

Jupyter is not installed. To use the notebook interactively:

```powershell
pip install notebook
cd "c:\Users\Lloyd\Downloads\AI-GIS_dashboard (9)\dashboard\colab"
jupyter notebook end_to_end_pipeline.ipynb
```

Your browser opens; run cells top to bottom.

Use this if you want to change settings between steps or re-run one step on its
own. Otherwise Option A is simpler.

---

## What you get when it finishes

| File | What it is |
|---|---|
| `reports/run_report_<RUN_ID>.md` | **Read this first** — every step, timings, failed checks |
| `reports/run_log_<RUN_ID>.jsonl` | Machine-readable log, written as each step finishes |
| `reports/llm_holdout_results.json` | Your headline detection / false-alarm numbers |
| `reports/eval_by_type.json` | Broken down per attack type and per generator |
| `reports/ablation_study_results.json` | Which components earn their place |
| `reports/*redteam*.json`, `*probe*.json` | Where the detector fails |
| `models/` | The four retrained model files |
| `../aigis_<RUN_ID>.zip` | Everything above, bundled |

Old models are backed up to `models/_backup_<RUN_ID>/` before training
overwrites them, so a run is never destructive.

---

## Expect 3 `[FAIL]` lines — all intentional

1. **scikit-learn 1.9.0 vs the 1.8.0 pin.** Your models were saved under 1.8.0.
   Loading them under 1.9.0 can change predictions *silently*. A full run
   retrains, which fixes it. To silence it properly: `pip install scikit-learn==1.8.0`.
2. **DeepSeek XSS target not met.** Your AI-attack files are smoke tests — see below.
3. **ModSecurity not reachable.** Needs Docker:
   `docker compose -f ..\..\deploy\docker-compose.pl1.yml up -d`, then re-run.

None of these stop the pipeline.

---

## Two things that are OFF by default

Each is a switch at the top of its cell / section in `run_pipeline.py`.

**`RUN_STAGE2 = False`** — regenerating the honeypot corpus.
All five WEB-IDS23 source CSVs are present in `data/prepared/`, so this *can*
run. It is off because regenerating invalidates the committed models — you would
have to retrain and every downstream number changes.

**`RUN_STAGE6 = False`** — generating fresh AI attack payloads.
Needs Ollama plus a ~9 GB model download.

### This one matters for your thesis

With Stage 6 off, the run scores against your **existing** files, which are
smoke tests: `target_per_type` was **20**, not the 500/300 the protocol calls
for. That is **78 payloads, not ~1,600**.

Fine for confirming the pipeline works. **Not** enough to report a detection
rate from. For real figures set `RUN_STAGE6 = True` with the full batch counts
(~1 hour, needs Ollama).

Also known: **8 of the 38 DeepSeek payloads are leaked chain-of-thought**, not
attacks — text like `<think>` and "Let me start by recalling...". They are
labelled as attacks, so they drag the reported detection rate down.

---

## Last verified

Full run, all 14 cells including training: **81 checks, 0 errors, 15.3 min.**

Results (RF / LSTM / stacked):

| | Detection | False-alarm rate |
|---|---|---|
| Random Forest | 94.9 % | 4.04 % |
| LSTM | 76.9 % | 0.51 % |
| **Stacked** | **85.9 %** | **0.51 %** |

Identical before and after retraining — the pipeline is reproducible at seed 42.
