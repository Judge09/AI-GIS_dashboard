# Colab notebooks

Three notebooks for running AI-GIS work on Google Colab's free T4 GPU, since the
Azure for Students subscription has no VM quota. All enforce the Section 3.5
controlled-generation settings (`temperature=0, top_k=1`) and treat all
generated payloads as **held-out test data only**.

Upload a notebook via **colab.research.google.com → File → Upload notebook**,
then **Runtime → Change runtime type → T4 GPU**, and run cells top to bottom.

## `end_to_end_pipeline.ipynb` — the full study, fully instrumented

**Start here.** The complete pipeline in 13 stages, from the synthetic honeypot
corpus generator through training, evaluation, red-teaming and packaging. Unlike
the other two it also runs **locally** (Stage 1 auto-detects the checkout and
skips the clone), and it covers the stages the others omit entirely: honeypot
synthesis (`webids23_to_honeypot_log_v9.py`), the corpus audit, split/leakage
verification, ablation, significance, and the red-team probes.

Every stage runs inside an instrumentation harness that records, automatically:
stage banner with inputs and params, SHA-256 + size + mtime of every input and
output, wall-clock duration, live-streamed tagged subprocess output, explicit
PASS/FAIL content checks, and a JSON record appended to
`reports/run_log_<RUN_ID>.jsonl` as each stage finishes — so the audit trail
survives a kernel crash. Stage 13 emits a human-readable
`reports/run_report_<RUN_ID>.md` and zips the run.

Expensive or environment-dependent stages are off by default via `RUN_STAGE*`
flags; a skipped stage prints exactly which input is missing and which stage
produces it, rather than failing quietly. The appendix is a symptom-first
debugging playbook.

## `generate_corpus.ipynb` — generation only

Produces just the LLM payload subsets and downloads them as a zip:

- Code Llama 13B: ~500 SQLi + ~500 XSS
- DeepSeek-R1 14B (abliterated build): ~300 SQLi + ~300 XSS, **Round-1 only**
  (the Round-2 ModSecurity-PL1 feedback loop needs Docker, which Colab lacks)

Smoke-test with `BATCHES = 2` first; then set `BATCHES = 25` (Code Llama) and
`DS_BATCHES = 15` (DeepSeek) for the full run. Unzip the result into
`dashboard/data/eval/` and run the local assemble + evaluate steps.

## `full_pipeline.ipynb` — end to end

Clones the repo, generates the payloads, assembles the benchmark, retrains the
stacked ensemble on the T4, and evaluates — then zips every result + model for
download. ModSecurity (`21_*`) is skipped (needs Docker); run that step locally.

### Notes

- **`scikit-learn==1.8.0` is pinned** so the committed models unpickle without
  silently changing predictions.
- **`zstd` is installed before Ollama** — the installer and the model blobs are
  zstd-compressed, and Colab's base image lacks it.
- The full-pipeline notebook clones `github.com/Judge09/AI-GIS_dashboard`. Its
  generation/assembly logic is **embedded in the notebook**, so it does not
  depend on the newer local scripts (`25_`, `26_`, `27_`) being pushed to the
  remote. If you later push those, you can call them directly instead.
- **Keep the browser tab open** — free Colab sessions disconnect when idle.
- The DeepSeek namespace underscore is **not** a typo: `huihui_ai` is the Ollama
  registry namespace. The HuggingFace repo is `huihui-ai` (hyphen) and is not
  pullable by Ollama — there is no GGUF, so `ollama pull` returns a 400.

### Known environment drift (found by the Stage 1 pin check)

As of this writing the local environment has **scikit-learn 1.9.0** installed
while `requirements.txt` pins **1.8.0**, the version the committed `models/*.pkl`
were pickled under. Unpickling across a minor version can silently change
predictions, so scores produced from the committed models under 1.9.0 are not
trustworthy. Either `pip install scikit-learn==1.8.0`, or retrain (Stage 5) so
the models match the installed version.
