#!/usr/bin/env python3
# =====================================================================
# run_pipeline.py - the notebook as a plain script (no Jupyter needed).
# Auto-generated from colab/end_to_end_pipeline.ipynb - do not hand-edit;
# regenerate if the notebook changes.
#
#   python run_pipeline.py          # full run, ~15 min (trains the models)
#   python run_pipeline.py --fast   # skip training, ~4 min
#
# --fast reuses the models already in models/ instead of retraining.
# =====================================================================
import sys
FAST = "--fast" in sys.argv

# ==========================================================================
# STAGE 0 - INSTRUMENTATION HARNESS
# Defines the logging / hashing / timing machinery every later stage uses.
# Touches no data. Safe to re-run: it resets the harness, never the artifacts.
# ==========================================================================
import os, sys, json, time, hashlib, platform, subprocess, traceback, shutil, textwrap
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager

# Windows consoles default to cp1252; attack payloads routinely contain
# characters outside it (full-width quotes, CJK, emoji). Without this, printing
# a payload raises UnicodeEncodeError and kills an otherwise healthy run.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass          # Python < 3.7 or a stream that does not support it
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

RUN_ID      = datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
RUN_STARTED = time.time()
RUN_LOG     = []      # list of stage records (dicts)
_STAGE_SEQ  = [0]     # mutable counter so stages number themselves

IS_COLAB = ("google.colab" in sys.modules) or os.path.isdir("/content")

# Re-pointed at the repo in Stage 1, once ROOT is known.
RUN_LOG_PATH = Path("/content" if IS_COLAB else ".") / ("aigis_%s.jsonl" % RUN_ID)

try:
    _W = min(shutil.get_terminal_size().columns, 100)
except Exception:
    _W = 100
_W = max(_W, 70)

def rule(ch="="):
    print(ch * _W)

def fmt_bytes(n):
    """Human-readable byte count (keeps stage banners scannable)."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0

def sha256_file(path, chunk=1 << 20):
    """Full-file SHA-256 - used to prove an artifact changed (or did not)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()

def describe(path, label=None):
    """Fingerprint a file/dir: existence, size, sha256, mtime.

    Returns a dict that is embedded in the run log. It deliberately prints
    nothing itself - stage() does the printing so ordering stays consistent.
    """
    p = Path(path)
    label = label or str(p)
    if not p.exists():
        return {"label": label, "path": str(p), "exists": False}
    st = p.stat()
    if p.is_dir():
        files = sorted(x for x in p.rglob("*") if x.is_file())
        return {"label": label, "path": str(p), "exists": True, "is_dir": True,
                "n_files": len(files),
                "bytes": sum(x.stat().st_size for x in files)}
    return {"label": label, "path": str(p), "exists": True, "is_dir": False,
            "bytes": st.st_size,
            "sha256": sha256_file(p),
            "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()}

def _print_desc(d, prefix="   "):
    if not d["exists"]:
        print("%s[MISSING] %s  ->  %s" % (prefix, d["label"], d["path"]))
    elif d.get("is_dir"):
        print("%s[dir ] %s: %d files, %s" % (prefix, d["label"], d["n_files"],
                                             fmt_bytes(d["bytes"])))
    else:
        print("%s[file] %s: %s  sha256=%s...  mtime=%sZ"
              % (prefix, d["label"], fmt_bytes(d["bytes"]),
                 d["sha256"][:16], d["mtime"][:19]))

_CURRENT = {"rec": None}   # the stage record currently being filled

def check(cond, msg, fatal=False):
    """Explicit, recorded assertion.

    A stage that 'ran without error' but produced an empty file is the single
    most common silent failure here, so stages assert on the CONTENT of what
    they produced, not merely on an exit code.
    """
    ok = bool(cond)
    print("   [%s] %s" % ("PASS" if ok else "FAIL", msg))
    rec = _CURRENT["rec"]
    if rec is not None:
        rec["checks"].append({"ok": ok, "msg": msg})
    if not ok and fatal:
        raise AssertionError(msg)
    return ok

def sh(cmd, cwd=None, env=None, timeout=None, echo=True):
    """Run a command, streaming output live AND capturing it to the run log.

    Returns (returncode, lines). Use this instead of ! magics everywhere.
    """
    if isinstance(cmd, str):
        shown = cmd
        popen_args = {"args": cmd, "shell": True}
    else:
        shown = " ".join(str(c) for c in cmd)
        popen_args = {"args": [str(c) for c in cmd], "shell": False}
    if echo:
        print("   $ %s" % shown)
    t0 = time.time()
    lines = []
    proc = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=str(cwd) if cwd else None, env=env,
                            text=True, bufsize=1, errors="replace", **popen_args)
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            print("   | %s" % line)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        lines.append("*** TIMEOUT after %ss ***" % timeout)
        print("   | *** TIMEOUT after %ss ***" % timeout)
    dur = time.time() - t0
    rc = proc.returncode
    print("   -> exit=%s in %.1fs (%d lines)" % (rc, dur, len(lines)))
    rec = _CURRENT["rec"]
    if rec is not None:
        rec["commands"].append({"cmd": shown, "returncode": rc,
                                "seconds": round(dur, 2),
                                "output_tail": lines[-40:]})
    return rc, lines

@contextmanager
def stage(name, purpose, inputs=None, outputs=None, params=None, optional=False):
    """Wrap one pipeline stage in a documented, timed, fingerprinted block.

    Prints a banner (purpose / params / input fingerprints), runs the body, then
    re-fingerprints the declared outputs so you can see exactly what changed.
    Exceptions are captured into the record and re-raised unless optional=True.
    """
    _STAGE_SEQ[0] += 1
    n = _STAGE_SEQ[0]
    rec = {"run_id": RUN_ID, "stage_seq": n, "name": name, "purpose": purpose,
           "params": params or {}, "optional": optional,
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "commands": [], "checks": [], "notes": [],
           "inputs": [], "outputs": [], "status": "running"}
    prev = _CURRENT["rec"]
    _CURRENT["rec"] = rec

    rule("=")
    print("STAGE %d: %s" % (n, name))
    rule("=")
    print("PURPOSE : %s" % purpose)
    if params:
        print("PARAMS  :")
        for k, v in params.items():
            print("   %s = %r" % (k, v))
    if inputs:
        print("INPUTS  :")
        for lbl, p in inputs.items():
            d = describe(p, lbl); rec["inputs"].append(d); _print_desc(d)
    print("START   : %sZ" % rec["started_utc"][:19])
    rule("-")

    t0 = time.time()
    try:
        yield rec
        if rec["status"] == "running":
            rec["status"] = "ok"
    except Exception as e:
        rec["status"] = "error"
        rec["error"] = {"type": type(e).__name__, "message": str(e),
                        "traceback": traceback.format_exc()}
        rule("-")
        print("!! STAGE %d FAILED: %s: %s" % (n, type(e).__name__, e))
        print(textwrap.indent(traceback.format_exc(), "   "))
        if not optional:
            _finish(rec, t0, outputs, prev)
            raise
    _finish(rec, t0, outputs, prev)

def _finish(rec, t0, outputs, prev):
    rec["seconds"] = round(time.time() - t0, 2)
    rule("-")
    if outputs:
        print("OUTPUTS :")
        for lbl, p in outputs.items():
            d = describe(p, lbl); rec["outputs"].append(d); _print_desc(d)
    n_fail = sum(1 for c in rec["checks"] if not c["ok"])
    verdict = rec["status"].upper()
    if rec["status"] == "ok" and n_fail:
        verdict = "OK (with %d FAILED check%s)" % (n_fail, "s" if n_fail > 1 else "")
    print("RESULT  : %s   duration=%ss   checks=%d passed=%d failed=%d"
          % (verdict, rec["seconds"], len(rec["checks"]),
             len(rec["checks"]) - n_fail, n_fail))
    rule("=")
    print()
    RUN_LOG.append(rec)
    _CURRENT["rec"] = prev
    try:
        with open(RUN_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        print("   [warn] could not append to run log: %s" % e)

def note(msg):
    """Attach a human-readable note to the current stage record (and print it)."""
    print("   * %s" % msg)
    if _CURRENT["rec"] is not None:
        _CURRENT["rec"]["notes"].append(msg)

def skip(reason, produced_by=None):
    """Record that a stage was skipped, naming what would produce its input."""
    print("   [SKIP] %s" % reason)
    if produced_by:
        print("          -> produced by: %s" % produced_by)
    if _CURRENT["rec"] is not None:
        _CURRENT["rec"]["status"] = "skipped"
        _CURRENT["rec"]["notes"].append("SKIPPED: " + reason)

def preview_json(path, max_chars=1400):
    """Print a JSON report inline so results live next to the code that made them."""
    p = Path(path)
    if not p.exists():
        print("   [MISSING] %s" % p); return None
    obj = json.loads(p.read_text(encoding="utf-8"))
    # ensure_ascii=True: results JSONs embed raw attack payloads. Escaping them
    # keeps this printable on any console, and the returned object is unescaped.
    txt = json.dumps(obj, indent=2, ensure_ascii=True)
    print(textwrap.indent(txt[:max_chars], "   "))
    if len(txt) > max_chars:
        print("   ... (%d more chars; full object returned)" % (len(txt) - max_chars))
    return obj

print("Harness ready.  RUN_ID=%s" % RUN_ID)
print("Environment   : %s" % ("Google Colab" if IS_COLAB else "local"))
print("Run log       : %s" % RUN_LOG_PATH)
print("Defined       : stage(), sh(), check(), describe(), note(), skip(),")
print("                preview_json(), RUN_LOG")

# ==========================================================================
# STAGE 1 - ENVIRONMENT, REPOSITORY, VERSION PINNING
# ==========================================================================
REPO_URL   = "https://github.com/Judge09/AI-GIS_dashboard.git"
SKLEARN_PIN = "1.8.0"          # must match requirements.txt - see markdown above
INSTALL_DEPS = IS_COLAB        # locally we assume the venv is already set up

with stage(
    "Environment + repository",
    "Locate dashboard/, record the exact software stack, and flag any drift from "
    "the scikit-learn pin that would silently change model predictions.",
    params={"REPO_URL": REPO_URL, "SKLEARN_PIN": SKLEARN_PIN,
            "IS_COLAB": IS_COLAB, "INSTALL_DEPS": INSTALL_DEPS},
) as rec:

    # ---- 1a. locate or clone the repo -------------------------------------
    def find_root():
        """Return the dashboard/ dir, searching cwd and its parents."""
        for base in [Path.cwd()] + list(Path.cwd().parents):
            if (base / "dashboard" / "scripts" / "18_train_stacked.py").exists():
                return base / "dashboard"
            if (base / "scripts" / "18_train_stacked.py").exists():
                return base
        return None

    ROOT = find_root()
    if ROOT is None and IS_COLAB:
        note("No checkout found - cloning the repo (Colab).")
        sh(["git", "clone", "--depth", "1", REPO_URL, "/content/AI-GIS_dashboard"])
        ROOT = Path("/content/AI-GIS_dashboard/dashboard")
    if ROOT is None:
        raise FileNotFoundError(
            "Could not find dashboard/scripts/18_train_stacked.py in the cwd or any "
            "parent. Run this notebook from inside the repo, or set ROOT by hand.")

    ROOT    = ROOT.resolve()
    SCRIPTS = ROOT / "scripts" / "lib"
    STAGES  = ROOT / "scripts" / "stages"
    DATA    = ROOT / "data"
    DATA_CORPUS = DATA / "corpus"
    EVAL    = DATA / "eval"
    PREP    = DATA / "prepared"
    MODELS  = ROOT / "models" / "current"
    REPORTS = ROOT / "reports"
    for d in (DATA, DATA_CORPUS, EVAL, PREP, MODELS, REPORTS):
        d.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)          # every script resolves paths relative to dashboard/
    note("ROOT = %s" % ROOT)

    # Move the run log into the repo now that we know where it lives.
    _old = RUN_LOG_PATH
    RUN_LOG_PATH = REPORTS / ("run_log_%s.jsonl" % RUN_ID)
    if _old.exists():
        RUN_LOG_PATH.write_text(_old.read_text(encoding="utf-8"), encoding="utf-8")
    note("Run log now at %s" % RUN_LOG_PATH)

    # ---- 1b. optional dependency install (Colab) --------------------------
    if INSTALL_DEPS:
        note("Installing pinned deps on Colab (quiet).")
        sh("pip -q install 'scikit-learn==%s' pandas numpy scipy tensorflow "
           "imbalanced-learn" % SKLEARN_PIN)

    # ---- 1c. record the environment ---------------------------------------
    ENV = {"python": sys.version.split()[0], "platform": platform.platform(),
           "processor": platform.processor() or "unknown", "cwd": str(Path.cwd())}
    for mod in ("numpy", "pandas", "scipy", "sklearn", "tensorflow",
                "imblearn", "matplotlib"):
        try:
            m = __import__(mod)
            ENV[mod] = getattr(m, "__version__", "?")
        except Exception as e:
            ENV[mod] = "NOT INSTALLED (%s)" % type(e).__name__

    rc, git_lines = sh("git rev-parse HEAD && git status --porcelain | head -20",
                       cwd=ROOT, echo=True)
    ENV["git"] = git_lines[0] if git_lines and rc == 0 else "not a git checkout"
    ENV["git_dirty_files"] = [l for l in git_lines[1:]] if rc == 0 else []

    print("\n   ENVIRONMENT")
    for k, v in ENV.items():
        if k != "git_dirty_files":
            print("      %-12s %s" % (k, v))
    if ENV["git_dirty_files"]:
        print("      %-12s %d file(s) modified vs HEAD:" % ("git-dirty", len(ENV["git_dirty_files"])))
        for l in ENV["git_dirty_files"]:
            print("                   %s" % l)
    rec["environment"] = ENV

    # ---- 1d. the pin check that actually matters --------------------------
    print()
    sk = ENV.get("sklearn", "")
    check(sk == SKLEARN_PIN,
          "scikit-learn == %s (installed: %s) - a mismatch can SILENTLY change "
          "predictions from the committed pickles" % (SKLEARN_PIN, sk))
    if sk != SKLEARN_PIN:
        note("MITIGATION: either `pip install scikit-learn==%s` and restart the "
             "runtime, or retrain from scratch in Stage 5 so the models match "
             "the installed version. Do NOT trust scores from committed pickles "
             "under a mismatched version." % SKLEARN_PIN)

    # ---- 1e. GPU -----------------------------------------------------------
    GPU_AVAILABLE = False
    try:
        import tensorflow as tf
        gpus = tf.config.list_physical_devices("GPU")
        GPU_AVAILABLE = len(gpus) > 0
        print("   TensorFlow sees %d GPU(s): %s" % (len(gpus), gpus))
    except Exception as e:
        print("   TensorFlow GPU probe failed: %s" % e)
    note("GPU_AVAILABLE=%s -> LSTM epochs are ~%s"
         % (GPU_AVAILABLE, "10-20 s (T4)" if GPU_AVAILABLE else "~165 s (CPU)"))
    rec["environment"]["gpu_available"] = GPU_AVAILABLE

    # ---- 1f. inventory ------------------------------------------------------
    print("\n   REPO INVENTORY (what already exists before this run)")
    KEY_ARTIFACTS = {
        "honeypot log":        DATA_CORPUS / "honeypot_final.log",
        "hold-out eval CSV":   EVAL / "holdout_eval.csv",
        "RF model":            MODELS / "rf2.pkl",
        "LSTM model":          MODELS / "lstm_best.keras",
        "meta-learner":        MODELS / "meta.pkl",
        "n-gram vectorizer":   MODELS / "ngram_vectorizer.pkl",
        "prepared splits dir": PREP,
        "reports dir":         REPORTS,
    }
    for lbl, p in KEY_ARTIFACTS.items():
        _print_desc(describe(p, lbl))
    check((DATA_CORPUS / "honeypot_final.log").exists(),
          "training corpus data/corpus/honeypot_final.log is present "
          "(if missing, Stage 2 must generate it from the WEB-IDS23 CSVs)")

# ==========================================================================
# STAGE 2 - SYNTHETIC HONEYPOT GENERATION (optional; skipped by default)
# ==========================================================================
RUN_STAGE2 = False          # <-- set True ONLY if you have the WEB-IDS23 CSVs

# The WEB-IDS23 flow CSVs actually live in data/prepared/ in this repo
# (NOT data/). Verified row counts, all 6 required columns present, 0 rows
# lost to dropna on id.orig_h/id.resp_h:
#     sqli_http   74,300     xss_http   4,558
#     sqli_https 102,584     xss_https  4,533
WEBIDS_SQLI_HTTP  = PREP / "web-ids23_sql_injection_http (3).csv"
WEBIDS_SQLI_HTTPS = PREP / "web-ids23_sql_injection_https (2).csv"
WEBIDS_XSS_HTTP   = PREP / "web-ids23_xss_http (1).csv"
WEBIDS_XSS_HTTPS  = PREP / "web-ids23_xss_https (1).csv"
# 825,187 rows - far more than the ~18k needed (match_min uses ~2.2% of it).
# NOTE: only 59,393 of these are service=http; the rest are dns/ssl/smtp/ntp/
# ftp/ssh and 51,382 with service=NaN. The generator does not filter on
# service - it only tests `service == "http"` to pick port 80 vs 443, so a
# DNS or NTP flow becomes an HTTPS-looking web request envelope. That is a
# real modelling wrinkle, not a crash: see the note printed by this stage.
WEBIDS_BENIGN     = PREP / "web-ids23_benign (1).csv"

HONEYPOT_LOG   = DATA_CORPUS / "honeypot_final.log"
GEN_SEED       = 42
OBFUSCATE_PROB = 0.4        # fraction of attack payloads passed through obfuscation
GEN_STRATEGY   = "match_min"
BENIGN_RATIO   = 1.0

with stage(
    "Synthetic honeypot corpus generation",
    "Synthesise the labelled honeypot JSONL training corpus from WEB-IDS23 flow "
    "seeds, with enforced payload uniqueness and realistic request envelopes.",
    inputs={"generator script": STAGES / "webids23_to_honeypot_log_v9.py",
            "WEB-IDS23 sqli http":  WEBIDS_SQLI_HTTP,
            "WEB-IDS23 sqli https": WEBIDS_SQLI_HTTPS,
            "WEB-IDS23 xss http":   WEBIDS_XSS_HTTP,
            "WEB-IDS23 xss https":  WEBIDS_XSS_HTTPS,
            "WEB-IDS23 benign":     WEBIDS_BENIGN},
    outputs={"honeypot log": HONEYPOT_LOG},
    params={"RUN_STAGE2": RUN_STAGE2, "seed": GEN_SEED,
            "obfuscate_prob": OBFUSCATE_PROB, "strategy": GEN_STRATEGY,
            "benign_ratio": BENIGN_RATIO},
    optional=True,
) as rec:

    missing = [str(p) for p in (WEBIDS_SQLI_HTTP, WEBIDS_SQLI_HTTPS, WEBIDS_XSS_HTTP,
                                WEBIDS_XSS_HTTPS, WEBIDS_BENIGN) if not p.exists()]

    # Show the target arithmetic BEFORE running - match_min makes the smaller
    # class the binding constraint, which is easy to not notice.
    present = [(lbl, p) for lbl, p in
               (("sqli_http", WEBIDS_SQLI_HTTP), ("sqli_https", WEBIDS_SQLI_HTTPS),
                ("xss_http", WEBIDS_XSS_HTTP), ("xss_https", WEBIDS_XSS_HTTPS))
               if p.exists()]
    if present:
        import pandas as _pd
        print("   SOURCE FLOW COUNTS + TARGET ARITHMETIC")
        counts = {}
        for lbl, p in present:
            counts[lbl] = sum(len(c) for c in
                              _pd.read_csv(p, usecols=["uid"], chunksize=200000))
            print("      %-12s %8d rows" % (lbl, counts[lbl]))
        sqli_nat = counts.get("sqli_http", 0) + counts.get("sqli_https", 0)
        xss_nat  = counts.get("xss_http", 0) + counts.get("xss_https", 0)
        print("      SQLi natural %d | XSS natural %d" % (sqli_nat, xss_nat))
        if GEN_STRATEGY == "match_min" and sqli_nat and xss_nat:
            tgt = min(sqli_nat, xss_nat)
            ben = round(BENIGN_RATIO * (tgt + tgt))
            print("      match_min -> SQLi=%d XSS=%d benign=%d  TOTAL=%d"
                  % (tgt, tgt, ben, tgt * 2 + ben))
            binding = "XSS" if xss_nat < sqli_nat else "SQLi"
            unused  = max(sqli_nat, xss_nat) - tgt
            note("%s is the binding constraint; %d %s flows go UNUSED under "
                 "match_min. Use --strategy custom if you want more."
                 % (binding, unused, "SQLi" if binding == "XSS" else "XSS"))
            if WEBIDS_BENIGN.exists():
                bser = _pd.read_csv(WEBIDS_BENIGN, usecols=["service"])
                bn = len(bser)
                http_n = int((bser["service"] == "http").sum())
                print("      benign available %d rows -> need %d (%.1f%%)"
                      % (bn, ben, 100.0 * ben / max(bn, 1)))
                check(bn >= ben,
                      "benign pool (%d) covers the target (%d)" % (bn, ben))
                print("      benign service mix: http=%d (%.1f%%), other/NaN=%d"
                      % (http_n, 100.0 * http_n / max(bn, 1), bn - http_n))
                note("Only %.1f%% of benign flows are service=http. The generator "
                     "does NOT filter on service - it just maps http->port 80 and "
                     "everything else->443, so dns/ssl/smtp/ntp flows become "
                     "HTTPS-looking web requests. Benign payloads are synthesised "
                     "regardless, so this affects envelope realism (port/host), "
                     "not label correctness. Pre-filter to service==http if you "
                     "want the benign envelopes to be genuinely web traffic."
                     % (100.0 * http_n / max(bn, 1)))

    if not RUN_STAGE2:
        skip("RUN_STAGE2 is False - using the committed data/corpus/honeypot_final.log. "
             "Regenerating would invalidate the committed models.")
        note("All five source CSVs ARE present in data/prepared/, so setting "
             "RUN_STAGE2=True will work - but you must then re-run Stage 5, "
             "and every downstream number changes.")
    elif not WEBIDS_BENIGN.exists():
        skip("RUN_STAGE2 is True but the BENIGN CSV is missing - refusing to run.",
             produced_by="the WEB-IDS23 benign subset")
        print("          missing: %s" % WEBIDS_BENIGN)
        note("Without --benign the generator writes an ATTACK-ONLY log: no "
             "label=0 rows at all. Training on that produces a model that "
             "cannot discriminate. This is a hard stop, not a warning.")
    elif missing:
        skip("RUN_STAGE2 is True but %d source CSV(s) are missing." % len(missing),
             produced_by="the WEB-IDS23 dataset (not distributed in this repo)")
        for m in missing:
            print("          missing: %s" % m)
    else:
        if HONEYPOT_LOG.exists():
            backup = HONEYPOT_LOG.with_suffix(".log.bak_%s" % RUN_ID)
            shutil.copy2(HONEYPOT_LOG, backup)
            note("Backed up the existing log to %s (regeneration overwrites it)."
                 % backup.name)
        rc, _ = sh([sys.executable, str(STAGES / "webids23_to_honeypot_log_v9.py"),
                    "--sqli-http",  WEBIDS_SQLI_HTTP,
                    "--sqli-https", WEBIDS_SQLI_HTTPS,
                    "--xss-http",   WEBIDS_XSS_HTTP,
                    "--xss-https",  WEBIDS_XSS_HTTPS,
                    "--benign",     WEBIDS_BENIGN,
                    "--strategy",   GEN_STRATEGY,
                    "--benign-ratio", str(BENIGN_RATIO),
                    "--seed",       str(GEN_SEED),
                    "--obfuscate-prob", str(OBFUSCATE_PROB),
                    "-o", str(HONEYPOT_LOG)], cwd=ROOT)
        check(rc == 0, "generator exited 0")
        check(HONEYPOT_LOG.exists() and HONEYPOT_LOG.stat().st_size > 0,
              "honeypot log was written and is non-empty")
        note("Stage 3 audits this log. Pay attention to the forced_unique_nonce "
             "count there - it should be ~0.")

# ==========================================================================
# STAGE 3 - CORPUS AUDIT (never skipped; ground truth for everything below)
# ==========================================================================
import collections

EXPECTED_KEYS = {"time", "source_ip", "host", "method", "uri", "user_agent",
                 "request_body", "referer", "flow_uid", "dup_index", "session_id",
                 "session_seq", "label", "attack_family", "obfuscated",
                 "synthetic_duplicate", "forced_unique_nonce"}

with stage(
    "Corpus audit",
    "Establish exactly what is in the training corpus - counts, balance, schema, "
    "family mix, duplication rates - before any training consumes it.",
    inputs={"honeypot log": HONEYPOT_LOG},
    params={"expected_schema_keys": len(EXPECTED_KEYS)},
) as rec:

    if not HONEYPOT_LOG.exists():
        skip("data/corpus/honeypot_final.log is absent.",
             produced_by="Stage 2 (webids23_to_honeypot_log_v9.py)")
        raise FileNotFoundError("honeypot log required; cannot continue past Stage 3")

    rows, bad_lines = [], []
    with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                bad_lines.append((i, str(e)))

    n = len(rows)
    labels   = collections.Counter(r.get("label") for r in rows)
    families = collections.Counter(r.get("attack_family") for r in rows)
    sessions = {r.get("session_id") for r in rows}
    keys_seen = set().union(*(set(r.keys()) for r in rows)) if rows else set()

    print("   ROWS")
    print("      parsed ................ %d" % n)
    print("      malformed lines ....... %d" % len(bad_lines))
    for ln, err in bad_lines[:5]:
        print("         line %d: %s" % (ln, err))
    print("      unique session_id ..... %d  (avg %.1f rows/session)"
          % (len(sessions), n / max(len(sessions), 1)))

    print("\n   LABEL BALANCE")
    for lab in sorted(labels, key=lambda x: (x is None, x)):
        print("      label=%-5s %7d  (%5.1f%%)"
              % (lab, labels[lab], 100.0 * labels[lab] / max(n, 1)))

    print("\n   ATTACK FAMILY DISTRIBUTION")
    for fam, c in families.most_common():
        print("      %-20s %7d  (%5.1f%%)" % (fam, c, 100.0 * c / max(n, 1)))

    # ---- duplication metrics: the v5 fixes, verified ----------------------
    def payload_of(r):
        """Same text the trainer sees: URI query + body."""
        return "%s %s" % (r.get("uri", ""), r.get("request_body", "") or "")

    payloads   = [payload_of(r) for r in rows]
    uniq       = len(set(payloads))
    dup_rate   = 100.0 * (n - uniq) / max(n, 1)
    nonce_n    = sum(1 for r in rows if r.get("forced_unique_nonce"))
    syndup_n   = sum(1 for r in rows if r.get("synthetic_duplicate"))
    atk        = [r for r in rows if r.get("label") == 1]
    obf_n      = sum(1 for r in atk if r.get("obfuscated"))

    print("\n   DUPLICATION / UNIQUENESS  (the v5 correctness fixes)")
    print("      unique uri+body ....... %d / %d   (exact-duplicate rate %.2f%%)"
          % (uniq, n, dup_rate))
    print("      forced_unique_nonce ... %d   (payload-level collision fallback)" % nonce_n)
    print("      synthetic_duplicate ... %d   (flow-level oversampling; different thing)" % syndup_n)
    print("      obfuscated attacks .... %d / %d  (%.1f%% of attack rows)"
          % (obf_n, len(atk), 100.0 * obf_n / max(len(atk), 1)))

    lens = sorted(len(p) for p in payloads)
    def pct(q):
        return lens[min(int(q * len(lens)), len(lens) - 1)] if lens else 0
    over = sum(1 for L in lens if L > 200)
    print("\n   PAYLOAD LENGTH (chars; LSTM truncates at MAXLEN=200)")
    print("      min/p50/p90/p99/max ... %d / %d / %d / %d / %d"
          % (lens[0], pct(.50), pct(.90), pct(.99), lens[-1]))
    print("      longer than 200 ....... %d  (%.1f%% - truncated for the LSTM branch)"
          % (over, 100.0 * over / max(n, 1)))

    print()
    check(n > 0, "corpus is non-empty")
    check(not bad_lines, "every line parsed as JSON (%d malformed)" % len(bad_lines))
    missing_keys = EXPECTED_KEYS - keys_seen
    check(not missing_keys,
          "schema has all %d expected keys%s"
          % (len(EXPECTED_KEYS),
             "" if not missing_keys else " - MISSING: %s" % sorted(missing_keys)))
    check(set(labels) <= {0, 1}, "labels are strictly 0/1")
    bal = min(labels.get(0, 0), labels.get(1, 0)) / max(max(labels.get(0, 0), labels.get(1, 1)), 1)
    check(bal > 0.8, "classes are roughly balanced (minority/majority = %.2f)" % bal)
    check(dup_rate < 5.0,
          "exact-duplicate payload rate %.2f%% is below 5%% (v4 was 72.9%%)" % dup_rate)
    # Tiered, because the generator's docstring says "expect ~0" without
    # quantifying it. Observed baseline on the committed corpus is 1.11%
    # (407/36594) with a 0.00% duplicate rate - i.e. the fallback doing its job.
    # Only a LARGE share indicates a family's component space actually shrank.
    nonce_pct = 100.0 * nonce_n / max(n, 1)
    print("      forced_unique_nonce rate %.2f%% (committed-corpus baseline: 1.11%%)"
          % nonce_pct)
    check(nonce_pct < 5.0,
          "forced_unique_nonce rate %.2f%% is below 5%% - above that, a family's "
          "component space has shrunk and payload diversity is degraded" % nonce_pct)
    if nonce_pct > 2.0:
        note("nonce rate %.2f%% is above the 1.11%% baseline; worth checking which "
             "family is colliding if you regenerated the corpus." % nonce_pct)
    check(len(sessions) > 100,
          "enough distinct sessions (%d) for a group-wise split" % len(sessions))

    CORPUS_STATS = {"rows": n, "malformed": len(bad_lines), "labels": dict(labels),
                    "families": dict(families), "sessions": len(sessions),
                    "unique_payloads": uniq, "dup_rate_pct": round(dup_rate, 3),
                    "forced_unique_nonce": nonce_n,
                    "synthetic_duplicate": syndup_n,
                    "obfuscated_attacks": obf_n,
                    "len_p50": pct(.50), "len_p99": pct(.99), "len_max": lens[-1]}
    rec["corpus_stats"] = CORPUS_STATS
    note("CORPUS_STATS captured into the run log for the Stage 13 report.")

# ==========================================================================
# STAGE 4 - SPLIT GEOMETRY + LEAKAGE VERIFICATION (diagnostic)
# Stage 5 redoes this internally and overwrites data/prepared/*, so this stage
# exists to SHOW the split, not to produce artifacts training depends on.
# ==========================================================================
RUN_STAGE4 = True     # cheap (CPU, ~1-2 min); set False to jump straight to training

SPLIT_SEED = 42       # must match the seed used in Stage 5 for these to describe it

with stage(
    "Split geometry + leakage verification",
    "Show the 70/15/15 session-grouped split and PROVE no session_id straddles "
    "train/val/test, before spending GPU time on training.",
    inputs={"honeypot log": HONEYPOT_LOG,
            "prep module": SCRIPTS / "prepare_honeypot_for_training.py"},
    params={"RUN_STAGE4": RUN_STAGE4, "seed": SPLIT_SEED,
            "split": "70/15/15 GroupShuffleSplit on session_id"},
    optional=True,
) as rec:

    if not RUN_STAGE4:
        skip("RUN_STAGE4 is False - Stage 5 performs its own identical split anyway.")
    else:
        import importlib.util
        def _load_module(path, name):
            spec = importlib.util.spec_from_file_location(name, path)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m

        note("Importing prepare_honeypot_for_training.py (same code path as Stage 5).")
        _prep = _load_module(SCRIPTS / "prepare_honeypot_for_training.py", "prep")
        sys.path.insert(0, str(SCRIPTS))
        from text_normalize import normalize_text

        t0 = time.time()
        df = _prep.load_log(HONEYPOT_LOG)
        note("load_log() -> %d rows x %d engineered columns in %.1fs"
             % (len(df), df.shape[1], time.time() - t0))

        # Stage 5 normalises BEFORE splitting; mirror that exactly.
        df["_payload_text"] = df["_payload_text"].astype(str).map(normalize_text)

        tr, va, te = _prep.session_grouped_split(df, SPLIT_SEED)

        print("\n   SPLIT SIZES")
        tot = len(df)
        for nm, part in (("train", tr), ("val", va), ("test", te)):
            pos = int(part["label"].sum())
            print("      %-6s %7d rows (%4.1f%%)   attack=%6d (%4.1f%%)   sessions=%d"
                  % (nm, len(part), 100.0 * len(part) / tot, pos,
                     100.0 * pos / max(len(part), 1), part["_session_id"].nunique()))

        s_tr = set(tr["_session_id"]); s_va = set(va["_session_id"]); s_te = set(te["_session_id"])
        print("\n   LEAKAGE CHECK (session_id overlap between splits)")
        print("      train n val ........... %d" % len(s_tr & s_va))
        print("      train n test .......... %d" % len(s_tr & s_te))
        print("      val   n test .......... %d" % len(s_va & s_te))

        print("\n   FAMILY MIX PER SPLIT (a family absent from test = untestable claim)")
        fams = sorted(df["attack_family"].unique())
        print("      %-20s %8s %8s %8s" % ("family", "train", "val", "test"))
        for fam in fams:
            print("      %-20s %8d %8d %8d"
                  % (fam, int((tr["attack_family"] == fam).sum()),
                     int((va["attack_family"] == fam).sum()),
                     int((te["attack_family"] == fam).sum())))

        print()
        check(not (s_tr & s_va), "no session_id shared between train and val")
        check(not (s_tr & s_te), "no session_id shared between train and test")
        check(not (s_va & s_te), "no session_id shared between val and test")
        check(len(tr) + len(va) + len(te) == tot, "splits partition the corpus exactly")
        check(abs(len(tr) / tot - 0.70) < 0.05, "train share is ~70%% (got %.1f%%)"
              % (100.0 * len(tr) / tot))
        for fam in fams:
            if (df["attack_family"] == fam).sum() > 50:
                check(int((te["attack_family"] == fam).sum()) > 0,
                      "family '%s' is represented in the test split" % fam)

        SPLIT_STATS = {"train": len(tr), "val": len(va), "test": len(te),
                       "sessions": {"train": len(s_tr), "val": len(s_va), "test": len(s_te)},
                       "overlap": {"train_val": len(s_tr & s_va),
                                   "train_test": len(s_tr & s_te),
                                   "val_test": len(s_va & s_te)}}
        rec["split_stats"] = SPLIT_STATS
        del df, tr, va, te      # free memory before the LSTM stage

# ==========================================================================
# STAGE 5 - TRAIN THE STACKED ENSEMBLE (RF + LSTM + meta)
# Overwrites models/*.pkl, models/lstm_best.keras, and data/prepared/*.
# ==========================================================================
RUN_STAGE5   = not FAST   # --fast reuses existing models
TRAIN_EPOCHS = 6        # early stopping on val_auc (patience 3) usually halts sooner
TRAIN_SEED   = 42       # keep equal to SPLIT_SEED so Stage 4's geometry describes this run
BACKUP_MODELS = True

MODEL_FILES = {"RF":         MODELS / "rf2.pkl",
               "LSTM":       MODELS / "lstm_best.keras",
               "meta":       MODELS / "meta.pkl",
               "vectorizer": MODELS / "ngram_vectorizer.pkl"}

with stage(
    "Train stacked ensemble",
    "Fit RF v2 + 2-layer LSTM + logistic meta-learner from the honeypot log, and "
    "rewrite data/prepared/* so downstream eval reads the SAME split.",
    inputs=dict({"honeypot log": HONEYPOT_LOG,
                 "trainer": STAGES / "18_train_stacked.py"},
                **{"model BEFORE: " + k: v for k, v in MODEL_FILES.items()}),
    outputs=dict({"prepared splits": PREP},
                 **{"model AFTER: " + k: v for k, v in MODEL_FILES.items()}),
    params={"RUN_STAGE5": RUN_STAGE5, "epochs": TRAIN_EPOCHS, "seed": TRAIN_SEED,
            "gpu": GPU_AVAILABLE, "backup": BACKUP_MODELS},
) as rec:

    if not RUN_STAGE5:
        skip("RUN_STAGE5 is False - keeping the committed models. Valid ONLY if "
             "scikit-learn matches the %s pin (see Stage 1)." % SKLEARN_PIN)
    else:
        # Record pre-training hashes so 'did the model actually change?' is answerable.
        before = {k: (sha256_file(p) if p.exists() else None)
                  for k, p in MODEL_FILES.items()}

        if BACKUP_MODELS:
            bdir = MODELS / ("_backup_%s" % RUN_ID)
            bdir.mkdir(exist_ok=True)
            for k, p in MODEL_FILES.items():
                if p.exists():
                    shutil.copy2(p, bdir / p.name)
            note("Backed up existing models to %s" % bdir)

        if not GPU_AVAILABLE:
            note("No GPU: expect ~165 s/epoch (vs ~10-20 s on a T4). "
                 "%d epochs ~ %d min." % (TRAIN_EPOCHS, TRAIN_EPOCHS * 165 // 60))

        rc, lines = sh([sys.executable, str(STAGES / "18_train_stacked.py"),
                        "--log", str(HONEYPOT_LOG),
                        "--epochs", str(TRAIN_EPOCHS),
                        "--seed", str(TRAIN_SEED)], cwd=ROOT)
        check(rc == 0, "18_train_stacked.py exited 0")

        # Surface the trainer's own val_auc / test lines rather than making you scroll.
        interesting = [l for l in lines
                       if any(t in l.lower() for t in
                              ("val_auc", "auc:", "f1", "test", "train=", "epoch"))]
        if interesting:
            print("\n   TRAINER HIGHLIGHTS (val_auc ~0.5 => suspect seed/mask, not architecture)")
            for l in interesting[-25:]:
                print("      %s" % l)

        print()
        after = {}
        for k, p in MODEL_FILES.items():
            ok = p.exists()
            check(ok, "model artifact written: %s" % p.name)
            if ok:
                after[k] = sha256_file(p)
                changed = before[k] != after[k]
                # An UNCHANGED hash is not a failure here: training is seeded, so
                # a rerun at the same seed on the same corpus reproduces RF and
                # the TF-IDF vectorizer byte-for-byte. That is determinism working.
                # (The LSTM and meta still differ - float non-determinism in the
                # CPU/GPU kernels.) What actually matters is that the file was
                # REWRITTEN, so verify mtime, not content.
                fresh = p.stat().st_mtime >= (RUN_STARTED - 5)
                print("        %-11s %s, %s  sha256=%s..."
                      % (k, "rewritten" if fresh else "NOT rewritten",
                         "content changed" if changed else "byte-identical (seeded determinism)",
                         after[k][:16]))
                check(fresh,
                      "%s was rewritten by this training run (checks mtime, not "
                      "content - a seeded rerun legitimately reproduces identical "
                      "bytes)" % k)

        for f in ("rf_train_v2.csv", "rf_val_v2.csv", "rf_test_v2.csv",
                  "lstm_train.npz", "lstm_val.npz", "lstm_test.npz"):
            check((PREP / f).exists(),
                  "prepared split rewritten: %s (Stages 9's scripts read these; "
                  "stale files here produce garbage)" % f)
        rec["model_hashes"] = {"before": before, "after": after}

# ==========================================================================
# STAGE 6 - OLLAMA + LLM PAYLOAD GENERATION (optional; committed CSVs by default)
# ==========================================================================
RUN_STAGE6 = False          # True => pull ~8-9GB models and regenerate

CODELLAMA_TAG = "codellama:13b"
DEEPSEEK_TAG  = "huihui_ai/deepseek-r1-abliterated:14b-qwen-distill"
CL_BATCHES, CL_TARGET = 25, 500     # smoke-test with CL_BATCHES=2 first
DS_BATCHES, DS_TARGET = 15, 300
OLLAMA_HOST, OLLAMA_PORT = "localhost", 11434

GEN_FILES = {
    "codellama": {"holdout":  EVAL / "codellama_holdout.csv",
                  "rejects":  EVAL / "codellama_rejects.csv",
                  "manifest": EVAL / "codellama_run_manifest.json"},
    "deepseek":  {"holdout":  EVAL / "deepseek_holdout.csv",
                  "rejects":  EVAL / "deepseek_rejects.csv",
                  "manifest": EVAL / "deepseek_run_manifest.json"},
}

with stage(
    "LLM payload generation (held-out corpus)",
    "Produce the LLM-authored SQLi/XSS evasion payloads used ONLY as test data "
    "(Section 3.5), or stage the committed corpora if not regenerating.",
    outputs={"%s %s" % (m, k): v
             for m, d in GEN_FILES.items() for k, v in d.items()},
    params={"RUN_STAGE6": RUN_STAGE6, "codellama": CODELLAMA_TAG,
            "deepseek": DEEPSEEK_TAG,
            "cl_batches/target": "%d/%d" % (CL_BATCHES, CL_TARGET),
            "ds_batches/target": "%d/%d" % (DS_BATCHES, DS_TARGET),
            "decoding": "temperature=0, top_k=1 (controlled generation)"},
    optional=True,
) as rec:

    if not RUN_STAGE6:
        skip("RUN_STAGE6 is False - staging the committed corpora instead of "
             "regenerating (~8-9 GB of model pulls avoided).")
        # The committed CSVs live in colab/; Stage 7 reads data/eval/. Copy them
        # across, but NEVER overwrite a fresher file already in data/eval/.
        staged = 0
        for model, files in GEN_FILES.items():
            for kind, dest in files.items():
                src = ROOT / "colab" / dest.name
                if src.exists() and not dest.exists():
                    shutil.copy2(src, dest); staged += 1
                    print("      staged colab/%s -> data/eval/%s" % (src.name, dest.name))
                elif src.exists() and dest.exists():
                    same = sha256_file(src) == sha256_file(dest)
                    print("      data/eval/%s already present (%s colab/ copy)"
                          % (dest.name, "identical to" if same else "DIFFERS from"))
        note("Staged %d file(s) from colab/ into data/eval/." % staged)
    else:
        # -- 6a. zstd BEFORE ollama (both the installer and the blobs need it) --
        if IS_COLAB:
            sh("apt-get -qq update && apt-get -qq install -y zstd")
            sh("curl -fsSL https://ollama.com/install.sh | sh")
            subprocess.Popen("ollama serve > /content/ollama.log 2>&1", shell=True)
            note("Started `ollama serve` in the background (log: /content/ollama.log).")

        # -- 6b. wait for the daemon, explicitly -------------------------------
        import urllib.request
        up = False
        for attempt in range(30):
            try:
                urllib.request.urlopen("http://%s:%d/api/tags" % (OLLAMA_HOST, OLLAMA_PORT),
                                       timeout=3)
                up = True; break
            except Exception:
                time.sleep(2)
        check(up, "Ollama daemon reachable at %s:%d after %d attempts"
                  % (OLLAMA_HOST, OLLAMA_PORT, attempt + 1))
        if not up:
            note("If this failed on Colab, read /content/ollama.log - the usual "
                 "cause is zstd missing when the installer unpacked.")
            raise RuntimeError("Ollama not reachable; cannot generate.")

        # -- 6c. pull the tags -------------------------------------------------
        for tag in (CODELLAMA_TAG, DEEPSEEK_TAG):
            rc, _ = sh(["ollama", "pull", tag], timeout=3600)
            check(rc == 0, "pulled %s" % tag)
        sh(["ollama", "list"])

        # -- 6d. generate ------------------------------------------------------
        rc, _ = sh([sys.executable, str(STAGES / "25_generate_codellama_corpus.py"),
                    "--model", CODELLAMA_TAG, "--host", OLLAMA_HOST,
                    "--port", str(OLLAMA_PORT), "--batches", str(CL_BATCHES),
                    "--target-per-type", str(CL_TARGET)], cwd=ROOT, timeout=14400)
        check(rc == 0, "Code Llama generation exited 0")

        ds_cmd = [sys.executable, str(STAGES / "26_generate_deepseek_corpus.py"),
                  "--model", DEEPSEEK_TAG, "--host", OLLAMA_HOST,
                  "--port", str(OLLAMA_PORT), "--batches", str(DS_BATCHES),
                  "--target-per-type", str(DS_TARGET)]
        if IS_COLAB:
            ds_cmd.append("--no-round2")
            note("--no-round2: the ModSecurity-PL1 feedback loop needs Docker, "
                 "which Colab does not provide. Round-1 payloads only.")
        rc, _ = sh(ds_cmd, cwd=ROOT, timeout=14400)
        check(rc == 0, "DeepSeek generation exited 0")

    # -- 6e. audit whatever we ended up with (generated OR staged) -------------
    # Imported locally: Stage 6 must run standalone, not only after Stage 3.
    import csv as _csv, collections
    print("\n   GENERATED CORPUS AUDIT")
    GEN_STATS = {}
    for model, files in GEN_FILES.items():
        hp, rp = files["holdout"], files["rejects"]
        if not hp.exists():
            print("      %-10s [MISSING] %s" % (model, hp.name))
            check(False, "%s hold-out CSV exists" % model)
            continue
        with open(hp, newline="", encoding="utf-8") as f:
            rows = list(_csv.DictReader(f))
        n_rej = 0
        if rp.exists():
            with open(rp, newline="", encoding="utf-8") as f:
                n_rej = sum(1 for _ in _csv.DictReader(f))
        by_type = collections.Counter(r.get("attack_type") for r in rows)
        by_fam  = collections.Counter(r.get("attack_family") for r in rows)
        uniq    = len({r.get("payload") for r in rows})
        total   = len(rows) + n_rej
        print("      %-10s accepted=%-5d rejected=%-5d  accept-rate=%.1f%%  unique=%d"
              % (model, len(rows), n_rej,
                 100.0 * len(rows) / max(total, 1), uniq))
        print("                 by type: %s" % dict(by_type))
        print("                 by family: %s" % dict(by_fam))
        GEN_STATS[model] = {"accepted": len(rows), "rejected": n_rej,
                            "unique": uniq, "by_type": dict(by_type)}
        check(len(rows) > 0, "%s produced at least one accepted payload" % model)
        check(uniq == len(rows),
              "%s payloads are all unique (%d unique / %d rows)" % (model, uniq, len(rows)))
        # ---- the manifest is where smoke-test-vs-full-run is decided --------
        if files["manifest"].exists():
            man = json.loads(files["manifest"].read_text(encoding="utf-8"))
            tgt = man.get("target_per_type")
            acc = man.get("acceptance_rate")
            met = man.get("target_met", {})
            print("                 model_tag  : %s" % man.get("model_tag"))
            print("                 digest     : %s" % str(man.get("model_digest"))[:16])
            print("                 decoding   : %s" % man.get("controlled_generation"))
            print("                 target/type: %s   acceptance: %s" % (tgt, acc))
            print("                 target_met : %s" % met)
            GEN_STATS[model]["manifest"] = {"target_per_type": tgt,
                                            "acceptance_rate": acc,
                                            "target_met": met}
            # A run that did not hit its per-type target is not reportable.
            for k, v in (met or {}).items():
                check(bool(v), "%s: %s target was met" % (model, k))
            # Distinguish a smoke test from a full protocol run, loudly.
            full_target = CL_TARGET if model == "codellama" else DS_TARGET
            if tgt is not None and tgt < full_target:
                note("%s ran with target_per_type=%s but the full protocol is %d. "
                     "This is a SMOKE TEST (%d accepted payloads). Enough to "
                     "exercise the pipeline; NOT enough to report a detection "
                     "rate from. Set RUN_STAGE6=True with the full batch counts "
                     "for thesis figures." % (model, tgt, full_target, len(rows)))
            if acc is not None and acc < 0.5:
                note("%s acceptance rate is %.1f%% - low yield is itself a "
                     "finding; %s documents every rejection reason."
                     % (model, 100 * acc, rp.name))
            if man.get("round2_enabled") is False:
                note("%s Round-2 (ModSecurity PL1 feedback) was DISABLED, so "
                     "these are Round-1 payloads only." % model)
    rec["generation_stats"] = GEN_STATS

# ==========================================================================
# STAGE 7 - ASSEMBLE THE LLM HOLD-OUT BENCHMARK
# ==========================================================================
BENIGN_TARGET   = 600
LLM_HOLDOUT_CSV = EVAL / "llm_holdout_full.csv"
LLM_MANIFEST    = EVAL / "llm_holdout_manifest.json"

with stage(
    "Assemble LLM hold-out benchmark",
    "Merge both LLM attack subsets with held-out benign rows into one labelled "
    "CSV, preserving the generator column so results stay disaggregated.",
    inputs={"codellama holdout": GEN_FILES["codellama"]["holdout"],
            "deepseek holdout":  GEN_FILES["deepseek"]["holdout"],
            "benign source":     EVAL / "holdout_eval.csv"},
    outputs={"assembled benchmark": LLM_HOLDOUT_CSV, "manifest": LLM_MANIFEST},
    params={"benign_target": BENIGN_TARGET},
) as rec:

    rc, _ = sh([sys.executable, str(STAGES / "27_assemble_llm_holdout.py"),
                "--benign-target", str(BENIGN_TARGET),
                "--out", str(LLM_HOLDOUT_CSV)], cwd=ROOT)
    check(rc == 0, "27_assemble_llm_holdout.py exited 0")

    import pandas as pd
    check(LLM_HOLDOUT_CSV.exists(), "assembled CSV was written", fatal=True)
    hold = pd.read_csv(LLM_HOLDOUT_CSV)

    print("\n   ASSEMBLED BENCHMARK")
    print("      rows ................. %d" % len(hold))
    print("      columns .............. %s" % hold.columns.tolist())
    print("      label counts ......... %s" % hold["label"].value_counts().to_dict())
    if "generator" in hold:
        print("\n      rows by generator:")
        for g, c in hold["generator"].value_counts().items():
            print("         %-18s %5d" % (g, c))
    if "attack_type" in hold:
        print("\n      rows by attack_type:")
        for t, c in hold["attack_type"].value_counts().items():
            print("         %-18s %5d" % (t, c))

    n_benign = int((hold["label"] == 0).sum())
    n_attack = int((hold["label"] == 1).sum())
    fpr_res  = 100.0 / max(n_benign, 1)
    print("\n   MEASUREMENT RESOLUTION (read this before quoting an FPR)")
    print("      benign rows .......... %d" % n_benign)
    print("      smallest non-zero FPR  %.3f%%  (= 1/%d)" % (fpr_res, n_benign))
    print("      => a reported FPR of 0.0%% means 'no false positives among %d rows',"
          % n_benign)
    print("         NOT 'a zero false-positive rate'.")
    if n_benign < BENIGN_TARGET:
        note("SHORTFALL: %d benign rows available vs target %d. This is expected - "
             "holdout_eval.csv holds 198 negatives - but it bounds FPR resolution "
             "as printed above." % (n_benign, BENIGN_TARGET))

    print()
    check(len(hold) > 0, "benchmark is non-empty")
    check({"text", "label"} <= set(hold.columns), "required columns text,label present")
    check("generator" in hold.columns,
          "generator column preserved (Section 3.5 requires disaggregated results)")
    check(n_attack > 0 and n_benign > 0, "both classes present (attack=%d benign=%d)"
          % (n_attack, n_benign))
    check(hold["text"].isna().sum() == 0, "no null payload text")
    dupes = int(hold.duplicated(subset=["text"]).sum())
    check(dupes == 0, "no duplicate payload text across the benchmark (%d dupes)" % dupes)
    rec["holdout_stats"] = {"rows": len(hold), "attack": n_attack, "benign": n_benign,
                            "fpr_resolution_pct": round(fpr_res, 4),
                            "by_generator": hold["generator"].value_counts().to_dict()
                            if "generator" in hold else {}}
    HOLDOUT_DF = hold

# ==========================================================================
# STAGE 8 - EVALUATION (headline, segmented, significance)
# ==========================================================================
RES_HEADLINE = REPORTS / "llm_holdout_results.json"
RES_BY_TYPE  = REPORTS / "eval_by_type.json"
RES_SIGNIF   = REPORTS / "significance_holdout.json"

with stage(
    "Evaluate on the LLM-generated hold-out",
    "Headline detection/FPR, per-type + per-generator segmentation, and a "
    "significance test of the stack against its individual base learners.",
    inputs={"benchmark": LLM_HOLDOUT_CSV,
            "RF": MODELS / "rf2.pkl", "LSTM": MODELS / "lstm_best.keras",
            "meta": MODELS / "meta.pkl", "vectorizer": MODELS / "ngram_vectorizer.pkl"},
    outputs={"headline": RES_HEADLINE, "by type": RES_BY_TYPE,
             "significance": RES_SIGNIF, "ROC plot": REPORTS / "roc_by_type.png"},
    params={"csv": str(LLM_HOLDOUT_CSV)},
) as rec:

    for lbl, p in (("RF", MODELS / "rf2.pkl"), ("LSTM", MODELS / "lstm_best.keras"),
                   ("meta", MODELS / "meta.pkl"),
                   ("vectorizer", MODELS / "ngram_vectorizer.pkl")):
        if not check(p.exists(), "model present: %s" % p.name):
            skip("models are missing", produced_by="Stage 5 (18_train_stacked.py)")
            raise FileNotFoundError("cannot evaluate without %s" % p)

    # ---- 8a. headline ------------------------------------------------------
    print("\n   [8a] HEADLINE - overall detection rate + FPR")
    rc, _ = sh([sys.executable, str(STAGES / "17_evaluate_csv.py"),
                "--csv", str(LLM_HOLDOUT_CSV), "--out", str(RES_HEADLINE)], cwd=ROOT)
    check(rc == 0, "17_evaluate_csv.py exited 0")
    HEADLINE = preview_json(RES_HEADLINE) if RES_HEADLINE.exists() else None
    check(HEADLINE is not None, "headline results JSON written")

    # ---- 8b. segmented -----------------------------------------------------
    print("\n   [8b] SEGMENTED - per attack type and per generator")
    rc, _ = sh([sys.executable, str(STAGES / "19_eval_by_type.py"),
                "--csv", str(LLM_HOLDOUT_CSV)], cwd=ROOT)
    check(rc == 0, "19_eval_by_type.py exited 0")
    BY_TYPE = preview_json(RES_BY_TYPE, max_chars=2000) if RES_BY_TYPE.exists() else None
    check(BY_TYPE is not None, "per-type results JSON written")
    note("nl_intent rows number 2 in the whole corpus (see Stage 3) - treat any "
         "nl_intent metric as descriptive, never as a statistic.")

    # ---- 8c. significance --------------------------------------------------
    print("\n   [8c] SIGNIFICANCE - stack vs its individual base learners")
    rc, _ = sh([sys.executable, str(STAGES / "20_significance_holdout.py")], cwd=ROOT)
    check(rc == 0, "20_significance_holdout.py exited 0")
    SIGNIF = preview_json(RES_SIGNIF) if RES_SIGNIF.exists() else None
    check(SIGNIF is not None, "significance JSON written")

    rec["results"] = {"headline": HEADLINE, "by_type": BY_TYPE, "significance": SIGNIF}
    note("These three JSONs are the evaluation record; Stage 13 bundles them.")

# ==========================================================================
# STAGE 9 - ABLATION + INTERNAL SIGNIFICANCE (optional)
# Guarded: refuses to run against prepared splits older than the models.
# ==========================================================================
RUN_STAGE9 = True

RES_ABLATION = REPORTS / "ablation_study_results.json"
RES_STATS    = REPORTS / "statistical_significance.json"

with stage(
    "Ablation study + internal significance",
    "Six-condition ablation and significance testing on the internal test split, "
    "guarded against the stale-prepared-splits failure that produces plausible "
    "but meaningless numbers.",
    inputs={"rf_train_v2": PREP / "rf_train_v2.csv",
            "rf_test_v2":  PREP / "rf_test_v2.csv",
            "lstm_test":   PREP / "lstm_test.npz",
            "RF model":    MODELS / "rf2.pkl"},
    outputs={"ablation": RES_ABLATION, "significance": RES_STATS},
    params={"RUN_STAGE9": RUN_STAGE9},
    optional=True,
) as rec:

    # Defined locally so Stage 9 can run without Stage 5 having executed this
    # session (e.g. re-running only the evaluation half of the notebook).
    MODEL_FILES = {"RF":         MODELS / "rf2.pkl",
                   "LSTM":       MODELS / "lstm_best.keras",
                   "meta":       MODELS / "meta.pkl",
                   "vectorizer": MODELS / "ngram_vectorizer.pkl"}

    needed = [PREP / "rf_train_v2.csv", PREP / "rf_val_v2.csv", PREP / "rf_test_v2.csv",
              PREP / "lstm_train.npz", PREP / "lstm_val.npz", PREP / "lstm_test.npz"]
    absent = [p for p in needed if not p.exists()]

    if not RUN_STAGE9:
        skip("RUN_STAGE9 is False.")
    elif absent:
        skip("%d prepared split file(s) missing." % len(absent),
             produced_by="Stage 5 (18_train_stacked.py rewrites data/prepared/*)")
        for p in absent:
            print("          missing: %s" % p.name)
    else:
        # ---- the freshness guard -------------------------------------------
        model_mtime = max(p.stat().st_mtime for p in MODEL_FILES.values() if p.exists())
        prep_mtime  = min(p.stat().st_mtime for p in needed)
        stale_by    = model_mtime - prep_mtime
        print("   FRESHNESS GUARD")
        print("      newest model mtime ....... %s"
              % datetime.fromtimestamp(model_mtime, timezone.utc).isoformat()[:19])
        print("      oldest prepared mtime .... %s"
              % datetime.fromtimestamp(prep_mtime, timezone.utc).isoformat()[:19])
        fresh = stale_by <= 60      # 60s slack: Stage 5 writes models then splits
        check(fresh,
              "prepared splits are no older than the models (delta %.0fs) - if this "
              "FAILS the splits are stale and results would be meaningless" % stale_by)

        # Shape agreement is the second, stronger check.
        import pandas as pd, numpy as np
        rf_te   = pd.read_csv(needed[2], nrows=1)
        n_rf_te = sum(1 for _ in open(needed[2], encoding="utf-8")) - 1
        lstm_te = np.load(needed[5])
        print("\n   SHAPE AGREEMENT")
        print("      rf_test_v2.csv ....... %d rows x %d cols" % (n_rf_te, rf_te.shape[1]))
        print("      lstm_test.npz ........ X%s y%s"
              % (lstm_te["X"].shape, lstm_te["y"].shape))
        same_n = (n_rf_te == lstm_te["X"].shape[0])
        check(same_n,
              "RF and LSTM test splits describe the SAME rows (%d vs %d) - a "
              "mismatch means they came from different runs"
              % (n_rf_te, lstm_te["X"].shape[0]))
        check(rf_te.shape[1] - 1 == 319,
              "RF feature width is 319 (19 structural + 300 n-gram); got %d"
              % (rf_te.shape[1] - 1))

        if not (fresh and same_n):
            skip("Refusing to run: prepared splits do not match the current models. "
                 "Re-run Stage 5 (RUN_STAGE5=True) first.")
        else:
            print("\n   [9a] ABLATION")
            rc, _ = sh([sys.executable, str(STAGES / "14_ablation_study.py")], cwd=ROOT)
            check(rc == 0, "14_ablation_study.py exited 0")
            ABLATION = preview_json(RES_ABLATION, max_chars=2200) if RES_ABLATION.exists() else None
            check(ABLATION is not None, "ablation JSON written")

            print("\n   [9b] INTERNAL SIGNIFICANCE")
            rc, _ = sh([sys.executable, str(STAGES / "13_statistical_significance.py")],
                       cwd=ROOT)
            check(rc == 0, "13_statistical_significance.py exited 0")
            STATS = preview_json(RES_STATS) if RES_STATS.exists() else None
            check(STATS is not None, "significance JSON written")
            rec["results"] = {"ablation": ABLATION, "significance": STATS}

# ==========================================================================
# STAGE 10 - ADVERSARIAL RED-TEAM PROBES (read-only w.r.t. models)
# ==========================================================================
RUN_STAGE10 = True

PROBES = [
    ("hand-crafted red-team", STAGES / "16_claude_redteam.py",
     REPORTS / "claude_redteam_results.json",
     "Fixed adversarial cases from scripts/redteam_cases.json"),
    ("targeted evasion probe", STAGES / "23_claude_evasion_probe.py",
     REPORTS / "claude_evasion_probe.json",
     "Targeted evasion attempts against known decision boundaries"),
    ("polymorphic probe", STAGES / "24_polymorphic_probe.py",
     REPORTS / "polymorphic_probe.json",
     "Form-mutation robustness vs expression fragility"),
]

with stage(
    "Adversarial red-team probes",
    "Score fixed adversarial case sets against the current models to record where "
    "the detector fails - these are reported limitations, not defects to tune away.",
    inputs={"RF": MODELS / "rf2.pkl", "LSTM": MODELS / "lstm_best.keras",
            "red-team cases": ROOT / "scripts" / "redteam_cases.json"},
    outputs={name: out for name, _, out, _ in PROBES},
    params={"RUN_STAGE10": RUN_STAGE10, "probes": len(PROBES)},
    optional=True,
) as rec:

    if not RUN_STAGE10:
        skip("RUN_STAGE10 is False.")
    else:
        PROBE_RESULTS = {}
        for name, script, out, why in PROBES:
            print("\n   PROBE: %s" % name)
            print("      rationale: %s" % why)
            if not script.exists():
                check(False, "%s exists" % script.name); continue
            # PYTHONIOENCODING: the probe scripts print attack payloads containing
            # non-cp1252 characters (full-width quotes, CJK, emoji). On a Windows
            # console that raises UnicodeEncodeError and kills an otherwise
            # healthy run. Force UTF-8 for the child process.
            probe_env = dict(os.environ, PYTHONIOENCODING="utf-8")
            rc, _ = sh([sys.executable, str(script)], cwd=ROOT, timeout=3600,
                       env=probe_env)
            check(rc == 0, "%s exited 0" % script.name)
            if out.exists():
                PROBE_RESULTS[name] = preview_json(out, max_chars=1200)
                check(True, "%s written" % out.name)
            else:
                check(False, "%s written" % out.name)
        rec["probe_results"] = PROBE_RESULTS
        note("Expected shape of the result: high catch rate on form mutations, "
             "low catch rate on rephrased intent. If BOTH are high, verify the "
             "probe actually loaded the current models rather than silently failing.")

# ==========================================================================
# STAGE 11 - MODSECURITY CRS PL1 BASELINE (requires Docker; skipped on Colab)
# ==========================================================================
RUN_STAGE11   = not IS_COLAB
MODSEC_HOST   = "localhost"
MODSEC_PORT   = 8080
RES_MODSEC    = REPORTS / "modsec_holdout.json"

with stage(
    "ModSecurity CRS PL1 baseline",
    "Score the identical hold-out through a rules-based WAF so the ML detection "
    "rate has a like-for-like industry baseline to be compared against.",
    inputs={"benchmark": LLM_HOLDOUT_CSV,
            "compose file": ROOT.parent / "docker-compose.pl1.yml"},
    outputs={"modsec results": RES_MODSEC},
    params={"RUN_STAGE11": RUN_STAGE11, "endpoint": "%s:%d" % (MODSEC_HOST, MODSEC_PORT)},
    optional=True,
) as rec:

    if not RUN_STAGE11:
        skip("Docker is unavailable here (Colab provides no Docker daemon).",
             produced_by="run locally: docker compose -f docker-compose.pl1.yml up -d, "
                         "then python scripts/21_modsec_holdout.py")
    else:
        import urllib.request, urllib.error
        reachable = False
        try:
            urllib.request.urlopen("http://%s:%d/" % (MODSEC_HOST, MODSEC_PORT), timeout=5)
            reachable = True
        except urllib.error.HTTPError:
            reachable = True          # a 403/404 still proves the WAF is listening
        except Exception as e:
            note("ModSecurity endpoint probe failed: %s" % e)
        check(reachable, "ModSecurity reachable at %s:%d" % (MODSEC_HOST, MODSEC_PORT))

        if not reachable:
            skip("Nothing listening on %s:%d." % (MODSEC_HOST, MODSEC_PORT),
                 produced_by="docker compose -f docker-compose.pl1.yml up -d")
        else:
            rc, _ = sh([sys.executable, str(STAGES / "21_modsec_holdout.py"),
                        "--host", MODSEC_HOST, "--port", str(MODSEC_PORT),
                        "--csv", str(LLM_HOLDOUT_CSV),
                        "--out", str(RES_MODSEC)], cwd=ROOT, timeout=7200)
            check(rc == 0, "21_modsec_holdout.py exited 0")
            MODSEC = preview_json(RES_MODSEC) if RES_MODSEC.exists() else None
            check(MODSEC is not None, "ModSecurity results JSON written")
            rec["results"] = MODSEC

# ==========================================================================
# STAGE 12 - MULTI-SEED VARIANCE (5x full training; off by default)
# ==========================================================================
RUN_STAGE12       = False       # set True for the reportable mean +/- SD
VARIANCE_RUNS     = 5
VARIANCE_EPOCHS   = 6
ALLOW_CPU_VARIANCE = False      # override the CPU guard (expect hours)

RES_VARIANCE = REPORTS / "multirun_variance.json"

with stage(
    "Multi-seed variance study",
    "Retrain the stack under 5 seeds to produce the reportable mean +/- SD, since "
    "a single-run figure cannot separate architecture from seed luck.",
    inputs={"honeypot log": HONEYPOT_LOG},
    outputs={"variance results": RES_VARIANCE},
    params={"RUN_STAGE12": RUN_STAGE12, "runs": VARIANCE_RUNS,
            "epochs": VARIANCE_EPOCHS, "gpu": GPU_AVAILABLE},
    optional=True,
) as rec:

    if not RUN_STAGE12:
        skip("RUN_STAGE12 is False - this costs 5x a full training run. "
             "Enable it when you need the reportable mean +/- SD.")
    elif not GPU_AVAILABLE and not ALLOW_CPU_VARIANCE:
        skip("No GPU detected and ALLOW_CPU_VARIANCE is False. On CPU this is "
             "~%d min of training and will outlive a Colab session."
             % (VARIANCE_RUNS * VARIANCE_EPOCHS * 165 // 60),
             produced_by="set ALLOW_CPU_VARIANCE=True to override, or use a T4")
    else:
        note("This OVERWRITES models/ on each of the %d runs; the final models are "
             "from the LAST seed, not necessarily the best." % VARIANCE_RUNS)
        rc, _ = sh([sys.executable, str(STAGES / "22_multirun_variance.py"),
                    "--runs", str(VARIANCE_RUNS),
                    "--epochs", str(VARIANCE_EPOCHS),
                    "--two-layer",
                    "--out", str(RES_VARIANCE)], cwd=ROOT, timeout=28800)
        check(rc == 0, "22_multirun_variance.py exited 0")
        VARIANCE = preview_json(RES_VARIANCE, max_chars=2500) if RES_VARIANCE.exists() else None
        check(VARIANCE is not None, "variance JSON written")
        rec["results"] = VARIANCE
        note("Quote mean +/- SD from this file for any headline figure.")

# ==========================================================================
# STAGE 13 - RUN REPORT + PACKAGE
# ==========================================================================
with stage(
    "Run report + package",
    "Emit a human-readable audit of every stage (status, duration, failed checks, "
    "artifact fingerprints) and bundle the run for download.",
    params={"stages_recorded": len(RUN_LOG)},
) as rec:

    total_s   = time.time() - RUN_STARTED
    n_ok      = sum(1 for r in RUN_LOG if r["status"] == "ok")
    n_skip    = sum(1 for r in RUN_LOG if r["status"] == "skipped")
    n_err     = sum(1 for r in RUN_LOG if r["status"] == "error")
    all_checks = [(r["name"], c) for r in RUN_LOG for c in r["checks"]]
    failed     = [(n, c) for n, c in all_checks if not c["ok"]]

    L = []
    L.append("# AI-GIS pipeline run `%s`\n" % RUN_ID)
    L.append("- **Started:** %s" % datetime.fromtimestamp(RUN_STARTED, timezone.utc)
             .isoformat()[:19] + "Z")
    L.append("- **Duration:** %.1f min" % (total_s / 60.0))
    L.append("- **Stages:** %d ok, %d skipped, %d errored" % (n_ok, n_skip, n_err))
    L.append("- **Checks:** %d run, **%d failed**" % (len(all_checks), len(failed)))
    L.append("- **Environment:** python %s, sklearn %s, tensorflow %s, GPU=%s"
             % (ENV.get("python"), ENV.get("sklearn"), ENV.get("tensorflow"),
                ENV.get("gpu_available")))
    L.append("- **Git:** `%s`" % ENV.get("git"))
    L.append("")

    if failed:
        L.append("## FAILED CHECKS (read these first)\n")
        for nm, c in failed:
            L.append("- **%s** - %s" % (nm, c["msg"]))
        L.append("")
    else:
        L.append("## All checks passed\n")

    L.append("## Stages\n")
    L.append("| # | Stage | Status | Duration | Checks | Notes |")
    L.append("|---|---|---|---|---|---|")
    for r in RUN_LOG:
        nf = sum(1 for c in r["checks"] if not c["ok"])
        L.append("| %d | %s | %s | %.1fs | %d/%d | %s |"
                 % (r["stage_seq"], r["name"], r["status"], r.get("seconds", 0),
                    len(r["checks"]) - nf, len(r["checks"]),
                    (r["notes"][0][:70] + "...") if r["notes"] else ""))
    L.append("")

    L.append("## Artifacts produced\n")
    L.append("| Stage | Artifact | Size | SHA-256 |")
    L.append("|---|---|---|---|")
    for r in RUN_LOG:
        for o in r["outputs"]:
            if o.get("exists") and not o.get("is_dir"):
                L.append("| %d | `%s` | %s | `%s` |"
                         % (r["stage_seq"], Path(o["path"]).name,
                            fmt_bytes(o["bytes"]), o["sha256"][:24]))
    L.append("")

    if any("corpus_stats" in r for r in RUN_LOG):
        cs = next(r["corpus_stats"] for r in RUN_LOG if "corpus_stats" in r)
        L.append("## Training corpus\n")
        L.append("- rows **%d**, sessions **%d**, labels %s"
                 % (cs["rows"], cs["sessions"], cs["labels"]))
        L.append("- exact-duplicate payload rate **%.2f%%**, forced_unique_nonce **%d**"
                 % (cs["dup_rate_pct"], cs["forced_unique_nonce"]))
        L.append("")

    if any("holdout_stats" in r for r in RUN_LOG):
        hs = next(r["holdout_stats"] for r in RUN_LOG if "holdout_stats" in r)
        L.append("## Hold-out benchmark\n")
        L.append("- %d rows (attack %d / benign %d)"
                 % (hs["rows"], hs["attack"], hs["benign"]))
        L.append("- FPR resolution floor: **%.3f%%** - a reported 0.0%% means "
                 "'none among %d benign rows'" % (hs["fpr_resolution_pct"], hs["benign"]))
        L.append("- by generator: %s" % hs["by_generator"])
        L.append("")

    L.append("## Reproducing this run\n")
    L.append("```bash")
    L.append("git checkout %s" % ENV.get("git", "HEAD").split()[0])
    L.append("pip install -r dashboard/requirements.txt   # scikit-learn==%s is load-bearing"
             % SKLEARN_PIN)
    L.append("# then run this notebook with the same RUN_STAGE* flags:")
    # globals().get(): a stage cell that was not run this session simply has no
    # flag defined; report that instead of crashing the final report.
    for nm in ("RUN_STAGE2", "RUN_STAGE4", "RUN_STAGE5", "RUN_STAGE6",
               "RUN_STAGE9", "RUN_STAGE10", "RUN_STAGE11", "RUN_STAGE12"):
        L.append("#   %-12s = %s" % (nm, globals().get(nm, "(cell not run)")))
    L.append("```")

    REPORT_MD = REPORTS / ("run_report_%s.md" % RUN_ID)
    REPORT_MD.write_text("\n".join(L), encoding="utf-8")
    print("   Wrote %s" % REPORT_MD)
    print()
    print("\n".join(L[:40]))

    check(REPORT_MD.exists(), "run report written")
    check(n_err == 0, "no stage errored (%d errored)" % n_err)
    check(not failed, "no check failed across the whole run (%d failed)" % len(failed))

    # ---- package ------------------------------------------------------------
    import zipfile
    ZIP_PATH = Path("/content" if IS_COLAB else str(ROOT.parent)) / ("aigis_%s.zip" % RUN_ID)
    to_pack = []
    for pat in ("data/eval/*.csv", "data/eval/*.json", "reports/*.json",
                "reports/*.md", "reports/*.png", "reports/*.jsonl",
                "models/*.pkl", "models/*.keras"):
        to_pack.extend(sorted(ROOT.glob(pat)))
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as z:
        for p in to_pack:
            z.write(p, p.relative_to(ROOT))
    print("\n   Packaged %d files -> %s (%s)"
          % (len(to_pack), ZIP_PATH, fmt_bytes(ZIP_PATH.stat().st_size)))
    check(ZIP_PATH.exists() and ZIP_PATH.stat().st_size > 0, "zip bundle written")

    if IS_COLAB:
        try:
            from google.colab import files
            files.download(str(ZIP_PATH))
        except Exception as e:
            note("Auto-download failed (%s) - fetch it from the Files pane." % e)

print("=" * 70)
print("RUN COMPLETE: %s" % RUN_ID)
print("  report   : %s" % REPORT_MD)
print("  run log  : %s" % RUN_LOG_PATH)
print("=" * 70)