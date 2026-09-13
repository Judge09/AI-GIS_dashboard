"""Shared RF feature assembly for inference (app + every eval script).

Every scorer used to inline the same three-block concat with `range(300)`
hardcoded, so adding a fourth block (word-level TF-IDF) would have meant editing
nine call sites and silently breaking any that were missed. This module is the
one place that knows how an inference-time feature frame is built.

The word vectorizer is optional: models trained before it existed have no
word_* columns, and `v2_cols` (read off the training CSV header) simply will not
ask for any.
"""

import pickle

import pandas as pd

from build_rf_features_v2 import structural_features
from evasion_resistance_check import engineer_rf_features


def load_word_vectorizer(models_dir):
    """Return the fitted word vectorizer, or None if this model predates it."""
    path = models_dir / "word_vectorizer.pkl"
    if not path.exists():
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


def build_rf_frame(texts, vec, v2_cols, word_vec=None, method="GET"):
    """Assemble the inference feature frame, column-aligned to v2_cols.

    texts must already be normalised (normalize_text) by the caller, exactly as
    the trainer does before fitting.
    """
    agg = pd.DataFrame([engineer_rf_features(t, method) for t in texts])
    struct = pd.DataFrame([structural_features(t) for t in texts])

    ngram_arr = vec.transform(texts).toarray()
    ngram = pd.DataFrame(
        ngram_arr, columns=[f"ngram_{i}" for i in range(ngram_arr.shape[1])])

    parts = [agg.reset_index(drop=True),
             struct.reset_index(drop=True),
             ngram.reset_index(drop=True)]

    if word_vec is not None:
        word_arr = word_vec.transform(texts).toarray()
        parts.append(pd.DataFrame(
            word_arr,
            columns=[f"word_{i}" for i in range(word_arr.shape[1])]
        ).reset_index(drop=True))

    return pd.concat(parts, axis=1)[v2_cols]


def rf_feature_columns(rf, fallback_csv=None):
    """The column contract the fitted RF actually expects.

    Scorers used to read this off data/prepared/rf_train_v2.csv, which is a
    separate artifact from the model: after a retrain that adds features the two
    disagree and every predict_proba dies on a feature-name mismatch. The RF
    itself is authoritative about what it was fitted on.
    """
    names = getattr(rf, "feature_names_in_", None)
    if names is not None:
        return list(names)
    if fallback_csv is not None:  # RF fitted on a bare ndarray (older checkpoints)
        import pandas as pd
        return list(pd.read_csv(fallback_csv).drop(columns=["label"]).columns)
    raise ValueError("RF has no feature_names_in_ and no fallback CSV was given")
