# data/

Most files in this folder are **large and not committed to git** (see the
root `.gitignore`). They are regenerable from the pipeline in `../scripts/`.

## Committed (small, needed for the app to render)
- `results.json` — real stress-test results (23 evasion + 15 hard-benign)
- `mock_attacker_results.json` — mock CodeLlama/DeepSeek-profile results
- `mock_codellama_normal.jsonl` / `mock_deepseek_polymorphic.jsonl` — mock payloads
- `prepared/split_manifest.json` — split metadata

## Not committed (regenerate — see ../README.md "Re-running the pipeline")
- `honeypot_final.log` — full generated dataset (~20 MB)
- `prepared/*.csv`, `prepared/*.npz` — train/val/test splits (~66 MB)

The dashboard's live tester needs `prepared/rf_train_v2.csv` at startup (it
reads the v2 feature column order from it). Regenerate it with
`build_rf_features_v2.py` before running `app.py`, or keep a local copy.
