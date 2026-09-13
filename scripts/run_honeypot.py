#!/usr/bin/env python3
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
        "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"
        "d0gdRy/xeL/0yVf/G8DTKh2vngAA"
    ,
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
    DATA_CORPUS = DATA / "corpus"
    PREP, REPORTS = DATA / "prepared", ROOT / "reports"
    for d in (SCRIPTS, DATA, DATA_CORPUS, PREP, REPORTS): d.mkdir(parents=True, exist_ok=True)
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

OUT_LOG = DATA_CORPUS / "honeypot_final.log"

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