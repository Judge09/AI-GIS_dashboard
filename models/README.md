# Models

    current/       The live model. app.py loads these four files and nothing else.
    experiments/   Superseded architectures, kept for the comparison in
                   docs/reports/ARCH_bilstm_vs_lstm.md. Not loaded at runtime.

`current/` holds the paper-matching checkpoint (97.9% detection / F1 0.925 /
19.6% FPR):

| File | What it is |
|---|---|
| `rf2.pkl` | Random Forest over 319 engineered features |
| `lstm_best.keras` | Two-layer stacked LSTM over raw characters |
| `meta.pkl` | Logistic-regression meta-learner |
| `ngram_vectorizer.pkl` | Fitted char n-gram TF-IDF |

A byte-identical copy is preserved at
`artifacts/preserved/CHECKPOINT_model_paper_97.9/`. Retraining
(`scripts/stages/18_train_stacked.py`) overwrites `current/` in place, so
restore from there if a run needs to be undone.

`experiments/hn/` is a hard-negative variant; `experiments/bilstm/` is a
bidirectional LSTM. Point a script at one with `--out-dir` to evaluate it.
