# Scripts

    lib/      Shared modules. Imported, not run directly.
    stages/   The pipeline. Numbered files run in order; the rest are builders.
    *.json    Red-team case definitions used by stages/16 and 23.

`run_pipeline.py` drives the whole reproduction end to end;
`run_honeypot.py` regenerates the honeypot corpus standalone.

## lib/

`paths.py` is the single source of truth for where models, data and reports
live. Import from it rather than computing a root with `Path(__file__).parents[N]`
-- a script that computes its own root still imports and compiles after being
moved, but silently resolves to the wrong directory.

Other modules: `text_normalize` (Unicode/homoglyph folding, must match training),
`build_rf_features_v2` (the 319 structural features), `evasion_resistance_check`
(feature engineering shared with the app), `prepare_honeypot_for_training`,
`payload_validation`, `azure_ollama_client`.

## stages/

Numbered 04-28 in dependency order. Each writes its artifact to `reports/`.
Run them from the project root, e.g.:

    python scripts/stages/18_train_stacked.py --epochs 6 --seed 42

See section 10 of the top-level `README.md` for the full reproduction sequence.
