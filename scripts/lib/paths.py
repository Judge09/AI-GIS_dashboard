"""Canonical project paths.

Every entry point -- the Flask app, the pipeline driver, and each script under
scripts/stages/ -- resolves its inputs and outputs through this module rather
than recomputing a root with Path(__file__).parents[N].

That indirection exists because the per-file approach failed silently: a script
moved one directory deeper still imported and still compiled, but its root
pointed at the wrong place, so it read missing inputs or wrote outputs into a
directory nobody looked at. Keeping the arithmetic in one file means a future
move touches this module and nothing else.

ROOT is found by walking up from this file until a directory containing the
top-level marker directories appears, so the values are correct whether a
script is run from the project root, from inside scripts/stages/, or imported
by the app.
"""

from pathlib import Path

_MARKERS = ("models", "data", "scripts")


def _find_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if all((candidate / m).is_dir() for m in _MARKERS):
            return candidate
    # Fall back to the historical layout (scripts/lib/paths.py -> project root)
    # rather than raising: a partially-checked-out tree should still import.
    return start.parents[2]


ROOT = _find_root(Path(__file__).resolve().parent)

# Code
APP = ROOT / "app"
SCRIPTS = ROOT / "scripts"
LIB = SCRIPTS / "lib"
STAGES = SCRIPTS / "stages"

# Models: current/ is what the app loads; experiments/ holds superseded
# architectures kept for the comparison reported in docs/reports/.
MODELS = ROOT / "models"
MODELS_CURRENT = MODELS / "current"
MODELS_EXPERIMENTS = MODELS / "experiments"

# Data
DATA = ROOT / "data"
DATA_RAW = DATA / "raw"
DATA_PREPARED = DATA / "prepared"
DATA_EVAL = DATA / "eval"
DATA_CORPUS = DATA / "corpus"

# Outputs
REPORTS = ROOT / "reports"

__all__ = [
    "ROOT", "APP", "SCRIPTS", "LIB", "STAGES",
    "MODELS", "MODELS_CURRENT", "MODELS_EXPERIMENTS",
    "DATA", "DATA_RAW", "DATA_PREPARED", "DATA_EVAL", "DATA_CORPUS",
    "REPORTS",
]
