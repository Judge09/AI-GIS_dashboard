#!/usr/bin/env python3
# =============================================================================
# PLAIN-ENGLISH SUMMARY  (read this first)
# =============================================================================
# WHAT THIS FILE IS:
#   The wrapper / "one button" runner around the honeypot generator. It is the
#   notebook version converted into a plain script, and it adds an audit trail:
#   it records file sizes, SHA-256 hashes, row counts and timings for every
#   step, so a run can be independently verified afterwards.
#
# TWO WAYS TO RUN IT -- note the difference:
#   python run_honeypot.py              <- SAFE. Read-only. Audits the corpus
#                                          that already exists and prints the
#                                          statistics. Changes nothing.
#   python run_honeypot.py --generate   <- REBUILDS the corpus from the
#                                          WEB-IDS23 CSVs. Overwrites the
#                                          existing log (it takes a timestamped
#                                          backup first).
#
#   If you only want to CHECK the work, use the first form.
#
# WHAT IT EXPECTS TO FIND:
#   The five WEB-IDS23 source CSVs in data/prepared/. Those are the public
#   dataset files and are NOT included in this bundle because of their size
#   (~284 MB combined) -- see BUNDLE_README.md for where they belong.
# =============================================================================

# Auto-generated from colab/1_honeypot_generator.ipynb - run notebook 1 without Jupyter.
#   python run_honeypot.py            # audit the existing corpus (safe, read-only)
#   python run_honeypot.py --generate # BUILD A NEW corpus (overwrites, backs up first)
import sys
GENERATE = "--generate" in sys.argv
# ==========================================================================
# HARNESS - logging / hashing / timing used by every step below.
# Touches no data. Safe to re-run.
# ==========================================================================
import os, sys, json, time, hashlib, platform, subprocess, traceback, shutil, textwrap
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager

# Attack payloads contain characters outside cp1252 (full-width quotes, CJK).
# Without this, printing one raises UnicodeEncodeError and kills a healthy run.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

RUN_ID      = datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
RUN_STARTED = time.time()
RUN_LOG     = []
_STAGE_SEQ  = [0]
IS_COLAB    = ("google.colab" in sys.modules) or os.path.isdir("/content")
RUN_LOG_PATH = Path("/content" if IS_COLAB else ".") / ("aigis_%s.jsonl" % RUN_ID)

_W = 78
def rule(ch="="): print(ch * _W)

def fmt_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024.0 or u == "GB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024.0

def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()

def describe(path, label=None):
    p = Path(path); label = label or str(p)
    if not p.exists():
        return {"label": label, "path": str(p), "exists": False}
    st = p.stat()
    if p.is_dir():
        fs = sorted(x for x in p.rglob("*") if x.is_file())
        return {"label": label, "path": str(p), "exists": True, "is_dir": True,
                "n_files": len(fs), "bytes": sum(x.stat().st_size for x in fs)}
    return {"label": label, "path": str(p), "exists": True, "is_dir": False,
            "bytes": st.st_size, "sha256": sha256_file(p),
            "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()}

def _pd(d, pre="   "):
    if not d["exists"]:
        print("%s[MISSING] %s  ->  %s" % (pre, d["label"], d["path"]))
    elif d.get("is_dir"):
        print("%s[dir ] %s: %d files, %s" % (pre, d["label"], d["n_files"], fmt_bytes(d["bytes"])))
    else:
        print("%s[file] %s: %s  sha256=%s...  mtime=%sZ"
              % (pre, d["label"], fmt_bytes(d["bytes"]), d["sha256"][:16], d["mtime"][:19]))

_CURRENT = {"rec": None}

def check(cond, msg, fatal=False):
    """Recorded assertion. A step that 'ran fine' but produced nothing must fail loudly."""
    ok = bool(cond)
    print("   [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if _CURRENT["rec"] is not None:
        _CURRENT["rec"]["checks"].append({"ok": ok, "msg": msg})
    if not ok and fatal:
        raise AssertionError(msg)
    return ok

def sh(cmd, cwd=None, env=None, timeout=None, echo=True):
    """Run a command, streaming output live AND capturing it to the run log."""
    if isinstance(cmd, str):
        shown, kw = cmd, {"args": cmd, "shell": True}
    else:
        shown, kw = " ".join(str(c) for c in cmd), {"args": [str(c) for c in cmd], "shell": False}
    if echo: print("   $ %s" % shown)
    t0, lines = time.time(), []
    pr = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(cwd) if cwd else None,
                          env=env, text=True, bufsize=1, errors="replace", **kw)
    try:
        for line in pr.stdout:
            line = line.rstrip("\n"); lines.append(line); print("   | %s" % line)
        pr.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pr.kill(); lines.append("*** TIMEOUT ***"); print("   | *** TIMEOUT after %ss ***" % timeout)
    print("   -> exit=%s in %.1fs (%d lines)" % (pr.returncode, time.time() - t0, len(lines)))
    if _CURRENT["rec"] is not None:
        _CURRENT["rec"]["commands"].append({"cmd": shown, "returncode": pr.returncode,
                                           "seconds": round(time.time() - t0, 2),
                                           "output_tail": lines[-40:]})
    return pr.returncode, lines

@contextmanager
def stage(name, purpose, inputs=None, outputs=None, params=None, optional=False):
    _STAGE_SEQ[0] += 1; n = _STAGE_SEQ[0]
    rec = {"run_id": RUN_ID, "stage_seq": n, "name": name, "purpose": purpose,
           "params": params or {}, "optional": optional,
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "commands": [], "checks": [], "notes": [], "inputs": [], "outputs": [],
           "status": "running"}
    prev = _CURRENT["rec"]; _CURRENT["rec"] = rec
    rule("="); print("STEP %d: %s" % (n, name)); rule("=")
    print("PURPOSE : %s" % purpose)
    if params:
        print("PARAMS  :")
        for k, v in params.items(): print("   %s = %r" % (k, v))
    if inputs:
        print("INPUTS  :")
        for l, p in inputs.items():
            d = describe(p, l); rec["inputs"].append(d); _pd(d)
    print("START   : %sZ" % rec["started_utc"][:19]); rule("-")
    t0 = time.time()
    try:
        yield rec
        if rec["status"] == "running": rec["status"] = "ok"
    except Exception as e:
        rec["status"] = "error"
        rec["error"] = {"type": type(e).__name__, "message": str(e),
                        "traceback": traceback.format_exc()}
        rule("-"); print("!! STEP %d FAILED: %s: %s" % (n, type(e).__name__, e))
        print(textwrap.indent(traceback.format_exc(), "   "))
        if not optional:
            _finish(rec, t0, outputs, prev); raise
    _finish(rec, t0, outputs, prev)

def _finish(rec, t0, outputs, prev):
    rec["seconds"] = round(time.time() - t0, 2)
    rule("-")
    if outputs:
        print("OUTPUTS :")
        for l, p in outputs.items():
            d = describe(p, l); rec["outputs"].append(d); _pd(d)
    nf = sum(1 for c in rec["checks"] if not c["ok"])
    v = rec["status"].upper()
    if rec["status"] == "ok" and nf: v = "OK (with %d FAILED check%s)" % (nf, "s" if nf > 1 else "")
    print("RESULT  : %s   duration=%ss   checks=%d passed=%d failed=%d"
          % (v, rec["seconds"], len(rec["checks"]), len(rec["checks"]) - nf, nf))
    rule("="); print()
    RUN_LOG.append(rec); _CURRENT["rec"] = prev
    try:
        with open(RUN_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        print("   [warn] run-log append failed: %s" % e)

def note(msg):
    print("   * %s" % msg)
    if _CURRENT["rec"] is not None: _CURRENT["rec"]["notes"].append(msg)

def skip(reason, produced_by=None):
    print("   [SKIP] %s" % reason)
    if produced_by: print("          -> produced by: %s" % produced_by)
    if _CURRENT["rec"] is not None:
        _CURRENT["rec"]["status"] = "skipped"
        _CURRENT["rec"]["notes"].append("SKIPPED: " + reason)

def preview_json(path, max_chars=1400):
    p = Path(path)
    if not p.exists(): print("   [MISSING] %s" % p); return None
    obj = json.loads(p.read_text(encoding="utf-8"))
    txt = json.dumps(obj, indent=2, ensure_ascii=True)
    print(textwrap.indent(txt[:max_chars], "   "))
    if len(txt) > max_chars: print("   ... (%d more chars)" % (len(txt) - max_chars))
    return obj

def checkpoint(title, fields):
    """Compact copy-pasteable block for sharing run state."""
    print()
    print("+" + "-" * 66 + "+")
    print("| %-64s |" % (title + " - copy between the +---+ lines"))
    print("+" + "-" * 66 + "+")
    for k, v in fields.items():
        print("%-15s: %s" % (k, v))
    fails = [c["msg"] for r in RUN_LOG for c in r["checks"] if not c["ok"]]
    print("%-15s: %d" % ("failed checks", len(fails)))
    for f in fails: print("   - %s" % f[:76])
    print("+" + "-" * 66 + "+")

print("Harness ready.  RUN_ID=%s   env=%s" % (RUN_ID, "Colab" if IS_COLAB else "local"))

# ========================================================================
# EMBEDDED GENERATOR - this notebook carries its own code.
#
# Each file below is gzip+base64 embedded here and written to scripts/
# at runtime. Nothing is downloaded; no external .py is required.
#
# Written to disk rather than exec()'d inline because the scripts import
# each other and several are launched as subprocesses (so a crash cannot
# kill the kernel, and each stage can capture its own stdout).
#
# A file is overwritten ONLY when its content differs, and every such
# overwrite is reported - a local edit is never silently clobbered.
#
# 1 files, 40 KB raw
# ========================================================================
import base64, gzip, os
from pathlib import Path

_EMBEDDED = {
    "webids23_to_honeypot_log_v9.py":
        "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",
}

def materialize_scripts(target_dir, verbose=True):
    """Write the embedded files to `target_dir`; report what changed."""
    target = Path(target_dir); target.mkdir(parents=True, exist_ok=True)
    new, same, upd = [], [], []
    for name, blob in sorted(_EMBEDDED.items()):
        data = gzip.decompress(base64.b64decode(blob))
        dest = target / name
        if dest.exists():
            if dest.read_bytes() == data:
                same.append(name); continue
            upd.append(name)
        else:
            new.append(name)
        dest.write_bytes(data)
    if verbose:
        print("Embedded code -> %s" % target)
        print("   new %d | updated %d | already ok %d" % (len(new), len(upd), len(same)))
        for u in upd:
            print("      overwrote (differed): %s" % u)
    return {"new": new, "updated": upd, "identical": same}

# ==========================================================================
# STEP 2 - LOCATE PROJECT + UNPACK THE GENERATOR
# ==========================================================================
REPO_URL = "https://github.com/Judge09/AI-GIS_dashboard.git"

def find_root():
    """Locate dashboard/, anchored on DATA - never on a script, since the
    generator is written out by this very cell (that would be circular)."""
    for base in [Path.cwd()] + list(Path.cwd().parents):
        for a in ("data/prepared", "data"):
            if (base / "dashboard" / a).exists(): return base / "dashboard"
            if (base / a).exists(): return base
    return None

with stage("Locate project + unpack generator",
           "Find dashboard/, then write the embedded generator to scripts/.") as rec:
    ROOT = find_root()
    if ROOT is None and IS_COLAB:
        sh(["git", "clone", "--depth", "1", REPO_URL, "/content/AI-GIS_dashboard"])
        ROOT = Path("/content/AI-GIS_dashboard/dashboard")
    if ROOT is None:
        raise FileNotFoundError("No dashboard/data directory found. Run this from "
                                "inside the project, or create data/prepared/ and "
                                "put the WEB-IDS23 CSVs there.")
    ROOT = ROOT.resolve()
    SCRIPTS, DATA = ROOT / "scripts", ROOT / "data"
    PREP, REPORTS = DATA / "prepared", ROOT / "reports"
    for d in (SCRIPTS, DATA, PREP, REPORTS): d.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)
    note("ROOT = %s" % ROOT)

    RUN_LOG_PATH = REPORTS / ("run_log_%s.jsonl" % RUN_ID)
    materialize_scripts(SCRIPTS)
    GEN = SCRIPTS / "webids23_to_honeypot_log_v9.py"
    check(GEN.exists(), "generator written to scripts/")

    import platform as _pl
    print("\n   python %s on %s" % (sys.version.split()[0], _pl.system()))
    try:
        import pandas as pd; print("   pandas %s" % pd.__version__)
    except ImportError:
        if IS_COLAB: sh("pip -q install pandas"); import pandas as pd
        else: raise

# ==========================================================================
# STEP 3 - CHECK THE SOURCE CSVs
# ==========================================================================
SRC = {
    "--sqli-http":  PREP / "web-ids23_sql_injection_http (3).csv",
    "--sqli-https": PREP / "web-ids23_sql_injection_https (2).csv",
    "--xss-http":   PREP / "web-ids23_xss_http (1).csv",
    "--xss-https":  PREP / "web-ids23_xss_https (1).csv",
    "--benign":     PREP / "web-ids23_benign (1).csv",
}
NEEDED_COLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]

with stage("Check source CSVs",
           "Fingerprint each WEB-IDS23 file and confirm it has the 6 columns the "
           "generator reads.",
           inputs={k: v for k, v in SRC.items()}) as rec:
    import pandas as pd
    missing, counts = [], {}
    for flag, p in SRC.items():
        if not p.exists():
            missing.append(p.name); check(False, "%s present" % flag); continue
        head = pd.read_csv(p, nrows=1)
        lack = [c for c in NEEDED_COLS if c not in head.columns]
        check(not lack, "%s has all 6 required columns%s"
              % (flag, "" if not lack else " - MISSING %s" % lack))
        counts[flag] = sum(len(c) for c in pd.read_csv(p, usecols=["uid"], chunksize=200_000))
        print("      %-14s %8d rows" % (flag, counts[flag]))
    SOURCES_OK = not missing
    if missing:
        print("\n   MISSING %d file(s): %s" % (len(missing), missing))
        print("   Put them in %s" % PREP)
        note("Generation cannot run. You can still audit an existing log in Step 6.")
    rec["source_counts"] = counts

# ==========================================================================
# STEP 4 - SETTINGS + SIZE ARITHMETIC
# ==========================================================================
SEED             = 42
OBFUSCATE_PROB   = 0.4
STRATEGY         = "match_min"     # match_min | match_max | custom
BENIGN_RATIO     = 1.0
CUSTOM_SQLI      = None            # only used when STRATEGY == "custom"
CUSTOM_XSS       = None
BENIGN_HTTP_ONLY = False           # True => pre-filter benign to service == "http"

OUT_LOG = DATA / "honeypot_final.log"

with stage("Plan the corpus size",
           "Compute exactly how many rows this configuration will produce, "
           "before spending time generating them.",
           params={"seed": SEED, "strategy": STRATEGY, "obfuscate_prob": OBFUSCATE_PROB,
                   "benign_ratio": BENIGN_RATIO, "benign_http_only": BENIGN_HTTP_ONLY}) as rec:
    if not SOURCES_OK:
        skip("source CSVs missing - cannot plan", produced_by="Step 3")
        PLAN = None
    else:
        import pandas as pd
        sqli_nat = counts["--sqli-http"] + counts["--sqli-https"]
        xss_nat  = counts["--xss-http"]  + counts["--xss-https"]
        ben_nat  = counts["--benign"]

        if STRATEGY == "match_min":   sqli_t = xss_t = min(sqli_nat, xss_nat)
        elif STRATEGY == "match_max": sqli_t = xss_t = max(sqli_nat, xss_nat)
        else:
            sqli_t = CUSTOM_SQLI if CUSTOM_SQLI is not None else sqli_nat
            xss_t  = CUSTOM_XSS  if CUSTOM_XSS  is not None else xss_nat
        ben_t = round(BENIGN_RATIO * (sqli_t + xss_t))

        print("   HOW MANY ROWS THIS WILL MAKE")
        print("      SQLi attacks ....... %6d   (from %d available)" % (sqli_t, sqli_nat))
        print("      XSS  attacks ....... %6d   (from %d available)" % (xss_t, xss_nat))
        print("      benign ............. %6d   (from %d available)" % (ben_t, ben_nat))
        print("      %s" % ("-" * 42))
        print("      TOTAL .............. %6d rows" % (sqli_t + xss_t + ben_t))

        check(ben_t <= ben_nat,
              "benign pool covers the target (%d needed, %d available)" % (ben_t, ben_nat))
        if STRATEGY == "match_min" and sqli_nat != xss_nat:
            binding = "XSS" if xss_nat < sqli_nat else "SQLi"
            note("%s is the cap; %d %s flows go unused. Use STRATEGY='custom' "
                 "to draw on more." % (binding, max(sqli_nat, xss_nat) - min(sqli_nat, xss_nat),
                                       "SQLi" if binding == "XSS" else "XSS"))

        bser = pd.read_csv(SRC["--benign"], usecols=["service"])
        http_n = int((bser["service"] == "http").sum())
        print("\n      benign service mix: http=%d (%.1f%%), other/NaN=%d"
              % (http_n, 100.0 * http_n / len(bser), len(bser) - http_n))
        if BENIGN_HTTP_ONLY:
            check(http_n >= ben_t, "http-only benign pool covers the target "
                  "(%d needed, %d available)" % (ben_t, http_n))
        else:
            note("BENIGN_HTTP_ONLY is False: %.1f%% of benign envelopes will be "
                 "non-web flows shaped as HTTPS requests. Affects realism, not labels."
                 % (100.0 - 100.0 * http_n / len(bser)))
        PLAN = {"sqli": sqli_t, "xss": xss_t, "benign": ben_t,
                "total": sqli_t + xss_t + ben_t, "benign_http_available": http_n}
        rec["plan"] = PLAN

# ==========================================================================
# STEP 5 - GENERATE THE CORPUS
# ==========================================================================
RUN_GENERATION = GENERATE      # <-- set True to build a new corpus

with stage("Generate honeypot corpus",
           "Synthesise labelled attack and benign HTTP rows onto real WEB-IDS23 flows.",
           inputs=dict(SRC, **{"generator": GEN}),
           outputs={"honeypot log": OUT_LOG},
           params={"RUN_GENERATION": RUN_GENERATION}, optional=True) as rec:
    if not RUN_GENERATION:
        skip("RUN_GENERATION is False - keeping the existing corpus.")
        note("Set RUN_GENERATION = True to build a new one, then re-run notebook 3.")
    elif not SOURCES_OK:
        skip("source CSVs missing", produced_by="the WEB-IDS23 dataset")
    else:
        benign_path = SRC["--benign"]
        if BENIGN_HTTP_ONLY:
            import pandas as pd
            filt = PREP / "web-ids23_benign_http_only.csv"
            note("Pre-filtering benign to service == 'http' -> %s" % filt.name)
            first = True
            n_out = 0
            for chunk in pd.read_csv(benign_path, chunksize=200_000):
                sub = chunk[chunk["service"] == "http"]
                n_out += len(sub)
                sub.to_csv(filt, mode="w" if first else "a", header=first, index=False)
                first = False
            print("      wrote %d http-only benign rows" % n_out)
            benign_path = filt

        if OUT_LOG.exists():
            bak = OUT_LOG.with_suffix(".log.bak_%s" % RUN_ID)
            shutil.copy2(OUT_LOG, bak); note("Backed up old corpus -> %s" % bak.name)

        cmd = [sys.executable, str(GEN),
               "--sqli-http",  str(SRC["--sqli-http"]),
               "--sqli-https", str(SRC["--sqli-https"]),
               "--xss-http",   str(SRC["--xss-http"]),
               "--xss-https",  str(SRC["--xss-https"]),
               "--benign",     str(benign_path),
               "--strategy", STRATEGY, "--benign-ratio", str(BENIGN_RATIO),
               "--seed", str(SEED), "--obfuscate-prob", str(OBFUSCATE_PROB),
               "-o", str(OUT_LOG)]
        if STRATEGY == "custom":
            if CUSTOM_SQLI is not None: cmd += ["--custom-sqli-count", str(CUSTOM_SQLI)]
            if CUSTOM_XSS  is not None: cmd += ["--custom-xss-count",  str(CUSTOM_XSS)]
        rc, _ = sh(cmd, cwd=ROOT, timeout=7200)
        check(rc == 0, "generator exited 0")
        check(OUT_LOG.exists() and OUT_LOG.stat().st_size > 0, "corpus written and non-empty")
        note("Corpus replaced. Re-run notebook 3 (training) - the current models are now stale.")

# ==========================================================================
# STEP 6 - AUDIT THE CORPUS
# ==========================================================================
import collections

EXPECTED_KEYS = {"time","source_ip","host","method","uri","user_agent","request_body",
                 "referer","flow_uid","dup_index","session_id","session_seq","label",
                 "attack_family","obfuscated","synthetic_duplicate","forced_unique_nonce"}

with stage("Audit the corpus",
           "Establish exactly what is in the training data - counts, balance, "
           "schema, duplication - before anything trains on it.",
           inputs={"honeypot log": OUT_LOG}) as rec:
    if not OUT_LOG.exists():
        skip("no corpus found", produced_by="Step 5")
        raise FileNotFoundError("%s not found" % OUT_LOG)

    rows, bad = [], []
    with open(OUT_LOG, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except json.JSONDecodeError as e: bad.append((i, str(e)))

    n = len(rows)
    labels   = collections.Counter(r.get("label") for r in rows)
    families = collections.Counter(r.get("attack_family") for r in rows)
    sessions = {r.get("session_id") for r in rows}
    keys     = set().union(*(set(r) for r in rows)) if rows else set()

    print("   ROWS      %d parsed, %d malformed" % (n, len(bad)))
    print("   SESSIONS  %d  (avg %.1f rows each)" % (len(sessions), n / max(len(sessions), 1)))
    print("\n   LABELS")
    for lab in sorted(labels, key=lambda x: (x is None, x)):
        print("      label=%-4s %7d  (%5.1f%%)" % (lab, labels[lab], 100.0*labels[lab]/n))
    print("\n   FAMILIES")
    for fam, c in families.most_common():
        flag = "   <-- too few to report on" if 0 < c < 50 else ""
        print("      %-18s %7d  (%5.1f%%)%s" % (fam, c, 100.0*c/n, flag))

    payloads = ["%s %s" % (r.get("uri",""), r.get("request_body","") or "") for r in rows]
    uniq     = len(set(payloads))
    dup_pct  = 100.0*(n-uniq)/n
    nonce_n  = sum(1 for r in rows if r.get("forced_unique_nonce"))
    atk      = [r for r in rows if r.get("label") == 1]
    obf      = sum(1 for r in atk if r.get("obfuscated"))

    print("\n   UNIQUENESS")
    print("      unique payloads .... %d / %d  (duplicate rate %.2f%%)" % (uniq, n, dup_pct))
    print("      nonce fallback ..... %d  (%.2f%%)" % (nonce_n, 100.0*nonce_n/n))
    print("      obfuscated attacks . %d / %d  (%.1f%%)" % (obf, len(atk), 100.0*obf/max(len(atk),1)))

    lens = sorted(len(p) for p in payloads)
    pct = lambda q: lens[min(int(q*len(lens)), len(lens)-1)]
    print("\n   LENGTH  min/p50/p90/p99/max = %d / %d / %d / %d / %d"
          % (lens[0], pct(.50), pct(.90), pct(.99), lens[-1]))

    print()
    check(n > 0, "corpus is non-empty")
    check(not bad, "every line parsed (%d malformed)" % len(bad))
    check(not (EXPECTED_KEYS - keys), "schema has all 17 keys")
    check(set(labels) <= {0,1}, "labels strictly 0/1")
    check(min(labels.get(0,0), labels.get(1,0)) / max(labels.get(0,1), labels.get(1,1)) > 0.8,
          "classes roughly balanced")
    check(dup_pct < 5.0, "duplicate rate %.2f%% below 5%%" % dup_pct)
    check(100.0*nonce_n/n < 5.0, "nonce fallback %.2f%% below 5%%" % (100.0*nonce_n/n))
    check(len(sessions) > 100, "enough sessions (%d) for a grouped split" % len(sessions))
    check(pct(.99) <= 200, "p99 length %d fits the 200-char LSTM window" % pct(.99))
    thin = [f for f, c in families.items() if 0 < c < 50]
    if thin:
        note("Families with <50 rows: %s - too few for a per-family metric. "
             "Either generate more or exclude them from per-type reporting." % thin)

    CORPUS = {"rows": n, "attack": labels.get(1,0), "benign": labels.get(0,0),
              "sessions": len(sessions), "dup_pct": round(dup_pct,3),
              "nonce": nonce_n, "families": dict(families)}
    rec["corpus"] = CORPUS

# ==========================================================================
# STEP 7 - SAMPLE THE OUTPUT
# ==========================================================================
import random, urllib.parse
random.seed(0)

def show(title, subset, k=8):
    """Always print the PAYLOAD - a POST keeps it in the body, so showing only
    the URI hides exactly what you came to inspect."""
    print("\n" + "=" * 74); print(title); print("=" * 74)
    for r in random.sample(subset, min(k, len(subset))):
        uri  = r.get("uri", "")
        body = r.get("request_body", "") or ""
        raw  = uri.split("?", 1)[1] if "?" in uri else body
        try: dec = urllib.parse.unquote_plus(raw)
        except Exception: dec = raw
        print("   [%s] %s %s" % (r.get("attack_family","?"), r.get("method",""),
                                 uri.split("?",1)[0]))
        print("        %s" % (dec[:100] if dec else "(none)"))

SQLI_F = {"tautology","union_based","time_based_blind","boolean_blind",
          "error_based","stacked_query","auth_bypass"}
XSS_F  = {"reflected","stored","dom_based"}

show("SQLi", [r for r in rows if r.get("attack_family") in SQLI_F])
show("XSS",  [r for r in rows if r.get("attack_family") in XSS_F], 6)
show("BENIGN - the false-positive surface",
     [r for r in rows if r.get("label") == 0], 10)

print("\n" + "=" * 74); print("ONE EXAMPLE PER FAMILY"); print("=" * 74)
seen_f = {}
for r in rows:
    f = r.get("attack_family")
    if f not in seen_f: seen_f[f] = r
for f in sorted(seen_f):
    r = seen_f[f]
    uri = r.get("uri",""); body = r.get("request_body","") or ""
    raw = uri.split("?",1)[1] if "?" in uri else body
    print("   %-18s %s" % (f, urllib.parse.unquote_plus(raw)[:78]))

# ==========================================================================
# STEP 8 - CHECKPOINT
# ==========================================================================
checkpoint("NOTEBOOK 1 - HONEYPOT CORPUS", {
    "RUN_ID":        RUN_ID,
    "regenerated":   RUN_GENERATION,
    "strategy":      "%s, seed=%s, obfuscate=%s, benign_http_only=%s"
                     % (STRATEGY, SEED, OBFUSCATE_PROB, BENIGN_HTTP_ONLY),
    "total rows":    CORPUS["rows"],
    "attack/benign": "%d / %d" % (CORPUS["attack"], CORPUS["benign"]),
    "sessions":      CORPUS["sessions"],
    "duplicate %":   CORPUS["dup_pct"],
    "nonce rows":    CORPUS["nonce"],
    "families":      ", ".join("%s=%d" % (k, v) for k, v in
                               sorted(CORPUS["families"].items())),
    "corpus sha256": describe(OUT_LOG)["sha256"][:24],
})

print()
print("NEXT: notebook 2 (llm_attack_generator) makes the held-out test attacks,")
print("      then notebook 3 (end_to_end_pipeline) trains and evaluates.")
if RUN_GENERATION:
    print()
    print("!! You regenerated the corpus, so models/ is now STALE.")
    print("   Notebook 3 must be re-run with training enabled.")