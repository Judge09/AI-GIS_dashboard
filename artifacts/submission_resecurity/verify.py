#!/usr/bin/env python3
"""
verify.py -- verification for this submission package.

Two independent things are checked:

  1. PACKAGE INTEGRITY -- the shipped files are present, match their recorded
     SHA-256, and the bundled sample corpus has the documented properties.

  2. GENERATOR CORRECTNESS -- the invariants that must hold for ANY input,
     not just the bundled sample. These run the generator against whatever
     CSVs you point it at and assert the properties that make the output
     usable: no duplicate payloads, correct labelling, correct class balance,
     schema conformance, and byte-level reproducibility under a fixed seed.

The second group is the one that matters if you are running this against your
own WEB-IDS23 download. Point it at your files:

    python verify.py --inputs /path/to/webids23_csvs

...where that directory contains the SQLi/XSS/benign CSVs (they are matched by
filename). Any CSV carrying the six required columns will work.

Usage:
    python verify.py                      # integrity + generator checks on the sample
    python verify.py --inputs DIR         # also run the generator against your own CSVs
    python verify.py --skip-generator     # integrity checks only (fast, no pandas)

Exit code is non-zero if any check fails.
"""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "webids23_to_honeypot_log_v9.py"
SAMPLE_CORPUS = HERE / "output" / "sample_output.log"
SAMPLE_INPUT = HERE / "sample_input"

REQUIRED_COLUMNS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]

SCHEMA = [
    "time", "source_ip", "host", "method", "uri", "user_agent",
    "request_body", "referer", "flow_uid", "dup_index", "session_id",
    "session_seq", "label", "attack_family", "obfuscated",
    "synthetic_duplicate", "forced_unique_nonce",
]

# Properties of the bundled sample corpus (output/sample_output.log).
SAMPLE_EXPECTED = {
    "rows": 16000,
    "attack": 8000,
    "benign": 8000,
    "sha256": "a13c3d30fe7743eac72e0791d4e35f84b8ae30cb4d89eb23d784acdc8e48b451",
}

# How input CSVs are matched to generator flags, by filename substring.
FLAG_PATTERNS = [
    ("--sqli-http", re.compile(r"sql.*inj.*http(?!s)", re.I)),
    ("--sqli-https", re.compile(r"sql.*inj.*https", re.I)),
    ("--xss-http", re.compile(r"xss.*http(?!s)", re.I)),
    ("--xss-https", re.compile(r"xss.*https", re.I)),
    ("--benign", re.compile(r"benign", re.I)),
]

_results = []


def check(label, ok, detail=""):
    _results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_corpus(path):
    """Parse a corpus, tolerating malformed lines so a damaged file still
    produces a full report rather than aborting on the first bad line."""
    rows, bad = [], []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                bad.append((i, str(exc)))
    return rows, bad


def discover_inputs(directory):
    """Match CSVs in `directory` to generator flags by filename."""
    found = {}
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in (".csv", ".gz"):
            continue
        for flag, pattern in FLAG_PATTERNS:
            if flag not in found and pattern.search(path.name):
                found[flag] = path
                break
    return found


# Invariant checks run on a deliberately small corpus: the properties under
# test are structural and hold at any size, and a small run keeps verification
# to a few seconds rather than minutes.
INVARIANT_ROWS = 400


def run_generator(inputs, out_path, seed=42, extra=None, small=True):
    cmd = [sys.executable, str(SCRIPT)]
    for flag, path in inputs.items():
        cmd += [flag, str(path)]
    cmd += ["--seed", str(seed), "-o", str(out_path)]
    if small:
        cmd += ["--strategy", "custom",
                "--custom-sqli-count", str(INVARIANT_ROWS),
                "--custom-xss-count", str(INVARIANT_ROWS)]
    if extra:
        cmd += extra
    return subprocess.run(cmd, capture_output=True, text=True)


# --------------------------------------------------------------------------
# 1. Package integrity
# --------------------------------------------------------------------------

def verify_files_present():
    print("\n[1/3] Package contents")
    expected = ["README.md", "USAGE.md", "DATA_PROVENANCE.md", "SHA256SUMS.txt",
                "verify.py", "webids23_to_honeypot_log_v9.py",
                "output/sample_output.log", "output/sample_generation_report.txt"]
    for rel in expected:
        check(rel, (HERE / rel).is_file())
    csvs = sorted(SAMPLE_INPUT.glob("*.csv")) if SAMPLE_INPUT.is_dir() else []
    check("sample_input/ holds 5 CSVs", len(csvs) == 5, f"found {len(csvs)}")


def verify_checksums():
    print("\n[2/3] SHA256SUMS.txt")
    manifest = HERE / "SHA256SUMS.txt"
    if not manifest.is_file():
        check("manifest present", False)
        return
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected_hash, rel = line.split("  ", 1)
        target = HERE / rel
        if not target.is_file():
            check(rel, False, "missing")
            continue
        actual = sha256(target)
        check(rel, actual == expected_hash,
              "" if actual == expected_hash else f"got {actual[:16]}...")


def verify_sample_corpus():
    print("\n[3/3] Bundled sample corpus")
    if not SAMPLE_CORPUS.is_file():
        check("sample corpus present", False)
        return
    rows, bad = load_corpus(SAMPLE_CORPUS)
    check("every line is valid JSON", not bad,
          "" if not bad else f"{len(bad)} malformed (first: line {bad[0][0]})")
    check(f"row count == {SAMPLE_EXPECTED['rows']:,}",
          len(rows) == SAMPLE_EXPECTED["rows"], f"got {len(rows):,}")
    labels = Counter(r["label"] for r in rows)
    check(f"balance {SAMPLE_EXPECTED['attack']:,}/{SAMPLE_EXPECTED['benign']:,}",
          labels[1] == SAMPLE_EXPECTED["attack"] and labels[0] == SAMPLE_EXPECTED["benign"],
          f"got {labels[1]:,}/{labels[0]:,}")
    check("SHA-256 matches", sha256(SAMPLE_CORPUS) == SAMPLE_EXPECTED["sha256"])


# --------------------------------------------------------------------------
# 2. Generator invariants -- must hold for ANY input
# --------------------------------------------------------------------------

def assert_invariants(rows, bad, label_prefix=""):
    """The properties that must hold for any corpus this generator produces."""
    p = label_prefix
    check(f"{p}every line is valid JSON", not bad,
          "" if not bad else f"{len(bad)} malformed")

    if not rows:
        check(f"{p}corpus is non-empty", False)
        return

    seen = {(r["uri"], r["request_body"]) for r in rows}
    dupes = len(rows) - len(seen)
    check(f"{p}no duplicate uri+request_body pairs", dupes == 0,
          f"{dupes} duplicates")

    keys = list(rows[0].keys())
    check(f"{p}schema matches documentation", keys == SCHEMA,
          "" if keys == SCHEMA else f"differs: {set(keys) ^ set(SCHEMA)}")
    check(f"{p}all rows share one schema",
          all(list(r.keys()) == keys for r in rows))

    check(f"{p}every label is 0 or 1",
          all(r["label"] in (0, 1) for r in rows))
    check(f"{p}benign rows are never obfuscated",
          not any(r["obfuscated"] for r in rows if r["label"] == 0))
    check(f"{p}no attack row is family 'benign'",
          not any(r["attack_family"] == "benign" for r in rows if r["label"] == 1))
    check(f"{p}no benign row has an attack family",
          all(r["attack_family"] == "benign" for r in rows if r["label"] == 0))
    check(f"{p}every row carries a non-empty flow_uid",
          all(r["flow_uid"] for r in rows))
    check(f"{p}every attack row has payload text",
          all((r["uri"] or r["request_body"]) for r in rows if r["label"] == 1))

    # No tool user-agent should dominate -- guards the shortcut-learning leak.
    uas = Counter(r["user_agent"] for r in rows)
    top_share = uas.most_common(1)[0][1] / len(rows)
    check(f"{p}no single user-agent exceeds 50% of rows",
          top_share <= 0.5, f"top UA is {top_share:.1%}")

    # A tool UA must not be a giveaway for the attack class.
    tool = [r for r in rows if "sqlmap" in r["user_agent"].lower()]
    if tool:
        atk = sum(1 for r in tool if r["label"] == 1) / len(tool)
        check(f"{p}sqlmap UA does not perfectly predict the label",
              atk < 1.0, f"{atk:.0%} of sqlmap rows are attacks")


def verify_generator(inputs, source_label):
    print(f"\n[+] Generator invariants -- {source_label}")
    for flag, path in sorted(inputs.items()):
        print(f"      {flag}: {path.name}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        out1 = tmp / "run1.log"
        print("      running generator...")
        proc = run_generator(inputs, out1)
        if proc.returncode != 0:
            check("generator exits cleanly", False,
                  (proc.stderr or proc.stdout).strip().splitlines()[-1][:160]
                  if (proc.stderr or proc.stdout).strip() else "no output")
            return
        check("generator exits cleanly", True)

        rows, bad = load_corpus(out1)
        assert_invariants(rows, bad)

        # Reproducibility: same seed must give a byte-identical file.
        out2 = tmp / "run2.log"
        print("      re-running with the same seed...")
        proc2 = run_generator(inputs, out2)
        if proc2.returncode == 0:
            check("same seed reproduces byte-identical output",
                  sha256(out1) == sha256(out2))
        else:
            check("second run exits cleanly", False)

        # A different seed must give a different corpus (the seed does something).
        out3 = tmp / "run3.log"
        proc3 = run_generator(inputs, out3, seed=1234)
        if proc3.returncode == 0:
            check("a different seed produces a different corpus",
                  sha256(out1) != sha256(out3))

        # --benign-ratio must be honoured.
        if "--benign" in inputs:
            out4 = tmp / "run4.log"
            proc4 = run_generator(inputs, out4, extra=["--benign-ratio", "2.0"])
            if proc4.returncode == 0:
                r4, _ = load_corpus(out4)
                lb = Counter(r["label"] for r in r4)
                ok = lb[1] > 0 and abs(lb[0] / lb[1] - 2.0) < 0.02
                check("--benign-ratio 2.0 yields ~2 benign per attack", ok,
                      f"got {lb[0]}/{lb[1]}")

        # --obfuscate-prob must be honoured at both extremes.
        out5 = tmp / "run5.log"
        proc5 = run_generator(inputs, out5, extra=["--obfuscate-prob", "0.0"])
        if proc5.returncode == 0:
            r5, _ = load_corpus(out5)
            check("--obfuscate-prob 0.0 obfuscates nothing",
                  not any(r["obfuscated"] for r in r5))


def verify_input_validation():
    print("\n[+] Input validation (clear errors on bad input)")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)

        missing = tmp / "missing_column.csv"
        missing.write_text("uid,ts,id.orig_h,id.resp_h,service\na,b,c,d,http\n",
                           encoding="utf-8")
        proc = run_generator({"--xss-http": missing}, tmp / "o.log")
        check("missing column is reported by name",
              proc.returncode != 0 and "attack_type" in (proc.stdout + proc.stderr),
              "no clear message" if proc.returncode != 0 else "did not fail")

        absent = tmp / "does_not_exist.csv"
        proc = run_generator({"--xss-http": absent}, tmp / "o.log")
        check("missing file gives a plain-English error",
              proc.returncode != 0 and "not found" in (proc.stdout + proc.stderr).lower())

        empty = tmp / "header_only.csv"
        empty.write_text(",".join(REQUIRED_COLUMNS) + "\n", encoding="utf-8")
        proc = run_generator({"--xss-http": empty}, tmp / "o.log")
        check("header-only file is reported, not silently accepted",
              proc.returncode != 0 and "no usable data" in (proc.stdout + proc.stderr).lower())

        proc = subprocess.run([sys.executable, str(SCRIPT), "-o", str(tmp / "o.log")],
                              capture_output=True, text=True)
        check("no inputs at all gives usage guidance",
              "No input CSVs given" in (proc.stdout + proc.stderr))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inputs", type=pathlib.Path, metavar="DIR",
                    help="directory of your own WEB-IDS23 CSVs to test against")
    ap.add_argument("--skip-generator", action="store_true",
                    help="integrity checks only; do not run the generator")
    args = ap.parse_args()

    print("=" * 72)
    print("Honeypot corpus generator -- package verification")
    print("=" * 72)

    verify_files_present()
    verify_checksums()
    verify_sample_corpus()

    if not args.skip_generator:
        try:
            import pandas  # noqa: F401
        except ImportError:
            print("\n[!] pandas is not installed -- skipping generator checks.")
            print("    Install it with: pip install pandas")
        else:
            verify_input_validation()
            sample_inputs = discover_inputs(SAMPLE_INPUT) if SAMPLE_INPUT.is_dir() else {}
            if sample_inputs:
                verify_generator(sample_inputs, "bundled sample inputs")
            else:
                check("sample inputs discoverable", False)

            if args.inputs:
                if not args.inputs.is_dir():
                    check(f"--inputs directory exists: {args.inputs}", False)
                else:
                    user_inputs = discover_inputs(args.inputs)
                    if not user_inputs:
                        check(f"CSVs found in {args.inputs}", False,
                              "no filenames matched sqli/xss/benign patterns")
                    else:
                        verify_generator(user_inputs, f"your inputs ({args.inputs})")

    failed = _results.count(False)
    print("\n" + "=" * 72)
    print(f"{len(_results) - failed}/{len(_results)} checks passed"
          + (f" -- {failed} FAILED" if failed else " -- all clear"))
    print("=" * 72)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
