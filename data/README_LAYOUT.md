# Data layout

    raw/        WEB-IDS23 source CSVs, exactly as downloaded. Never written to.
    corpus/     The honeypot training corpus and LLM/mock attack corpora.
    prepared/   Generated splits and the fitted vectorizer. Reproducible.
    eval/       Held-out and red-team evaluation sets the dashboard reads.

Flow: `raw/` -> `scripts/stages/webids23_to_honeypot_log_v9.py` -> `corpus/honeypot_final.log`
-> `scripts/lib/prepare_honeypot_for_training.py` -> `prepared/`.

`raw/` and `prepared/` are regenerable; `corpus/honeypot_final.log` and `eval/`
are the committed inputs behind the reported figures. See `README.md` in this
directory for per-file provenance.
