#!/usr/bin/env python3
"""
26_generate_deepseek_corpus.py   (Chapter 3, Section 3.5 -- adaptive generator)

Produces the held-out DeepSeek-R1 14B adversarial subset: ~300 SQLi + ~300 XSS
payloads via the documented adaptive two-round protocol.

  Round 1  produce an obfuscated candidate from a preserved prompt template.
  Round 2  submit each Round-1 payload to a local ModSecurity PL1 instance in
           DetectionOnly mode; feed the matched CRS rule IDs / descriptions
           back to the model for ONE additional mutation.

DISCLOSED CIRCULARITY (Section 3.5 + Scope): the Round-2 subset is partially
optimised against ModSecurity rule logic before evaluation. This is why
Chapter 4 must report Code Llama and DeepSeek results SEPARATELY, and why the
Code Llama subset is the structurally clean, non-circular measurement. The
evaluation baseline is PL2; the feedback loop here is PL1.

ABLITERATED BUILD (Section 3.5, ref [40]): the standard aligned DeepSeek-R1
refuses payload generation, which breaks an automated pipeline. The thesis
uses the disclosed abliterated build, OFFLINE ONLY, purely to produce a
held-out defensive test corpus. Pull that exact tag onto the Azure VM. If you
instead point --model at an aligned build, expect a high 'model_refusal'
reject rate -- that is the aligned model working as designed, not a bug here.

BACKENDS:
  --host / --port         Ollama server (Azure GPU VM via SSH tunnel)
  --modsec-host/-port     ModSecurity PL1 container (Round-2 feedback source)

USAGE (from dashboard/):
  # start a PL1 WAF for the feedback loop (see AZURE_RUNBOOK.md for a PL1 compose)
  python scripts/26_generate_deepseek_corpus.py \
      --model huihui_ai/deepseek-r1-abliterated:14b-qwen-distill \
      --host localhost --modsec-host localhost --modsec-port 8081
  # skip Round 2 entirely (no WAF available) -- produces Round-1-only, disclosed as such
  python scripts/26_generate_deepseek_corpus.py --model <tag> --no-round2
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from azure_ollama_client import OllamaClient, sha256_of, strip_fences   # noqa: E402
from payload_validation import clean, validate, normalized_key          # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from paths import ROOT as _ROOT  # noqa: E402
ROOT = _ROOT
OUT = ROOT / "data" / "eval"
OUT.mkdir(parents=True, exist_ok=True)

BASE_SEED = 42
DEFAULT_BATCHES = 15
BATCH_SIZE = 20
SQLI_FAMILIES = ["boolean_blind", "union_based", "time_based_blind",
                 "error_based", "hex_obfuscation", "stacked_query"]
XSS_FAMILIES = ["reflected", "stored", "dom_based", "attribute_based"]

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

R1_SYSTEM = (
    "You are a security researcher building a held-out WAF/IDS evaluation "
    "corpus for a DEFENSIVE research project in an isolated offline lab. "
    "Produce novel obfuscated attack payloads used only to test an "
    "already-trained detector. Output ONLY a JSON array of raw payload "
    "strings -- no markdown, no commentary. Each payload must be a functional "
    "example of the requested technique, and vary in structure from the others."
)
R2_SYSTEM = (
    "You are refining a single WAF-evasion test payload for a DEFENSIVE "
    "offline research corpus. You are told which rules a WAF matched on the "
    "previous version. Produce ONE improved payload that preserves the same "
    "attack semantics but is more likely to avoid those specific rule "
    "patterns, using different encoding/spacing/structure. Output ONLY the raw "
    "payload string -- no JSON, no markdown, no explanation."
)

_FAMILY_BRIEF = {
    "boolean_blind": "boolean-based blind SQL injection",
    "union_based": "UNION-based SQL injection",
    "time_based_blind": "time-based blind SQL injection using a delay function",
    "error_based": "error-based SQL injection",
    "hex_obfuscation": "SQL injection using hexadecimal / mixed encoding",
    "stacked_query": "stacked-query SQL injection",
    "reflected": "reflected XSS",
    "stored": "stored XSS",
    "dom_based": "DOM-based XSS",
    "attribute_based": "attribute-injection XSS with an event handler",
}


def r1_prompt(attack_type, family, k):
    return (f"Generate {k} distinct {_FAMILY_BRIEF[family]} payloads "
            f"({attack_type.upper()}). Output ONLY a JSON array of {k} raw strings:")


def r2_prompt(payload, matched_rules):
    rules = "; ".join(matched_rules) if matched_rules else "none reported"
    return (f"Previous payload:\n{payload}\n\n"
            f"WAF matched these rules: {rules}\n\n"
            f"Produce ONE improved payload with the same attack intent that "
            f"avoids those patterns. Output ONLY the raw payload:")


def parse_array(raw):
    raw = strip_fences(raw)
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return [str(x) for x in v]
    except json.JSONDecodeError:
        pass
    out = []
    for l in (x.strip().strip(",").strip() for x in raw.splitlines()):
        if l and l not in ("[", "]"):
            if len(l) >= 2 and l[0] == l[-1] and l[0] in "'\"":
                l = l[1:-1]
            out.append(l)
    return out


# ── ModSecurity PL1 feedback (Round 2) ───────────────────────────────────────
# The PL1 feedback WAF runs with the rule engine ON (blocking): on a match it
# returns 403 and names the matched CRS rule IDs in the response headers, which
# we read here. A DetectionOnly engine would return 200 and write matches only
# to its stdout audit log, unreadable by this dependency-free HTTP client -- so
# docker-compose.pl1.yml deliberately runs blocking to expose the signal over
# HTTP. The block decision + rule IDs are the Round-2 mutation signal; when a
# payload is blocked but no ID surfaces in headers, a generic hint is used.
_RULE_HDR = re.compile(r"id\s+\"?(\d{5,7})\"?", re.I)


def modsec_feedback(base, payload, timeout=10.0):
    """Return (blocked, [rule descriptions]) for one payload sent as GET+POST."""
    matched, blocked = [], False
    for send in ("GET", "POST"):
        try:
            if send == "GET":
                url = f"{base}/?q={urllib.parse.quote(payload, safe='')}"
                req = urllib.request.Request(url, method="GET")
            else:
                data = urllib.parse.urlencode({"q": payload}).encode()
                req = urllib.request.Request(base + "/", data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            for k, v in BROWSER_HEADERS.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                code = r.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
            hdrs = " ".join(f"{k}:{v}" for k, v in (e.headers or {}).items())
            matched += _RULE_HDR.findall(hdrs)
        except Exception:      # noqa: BLE001
            code = -1
        if code == 403:
            blocked = True
    # Deduplicate rule IDs into human hints; if none surfaced, give a generic one.
    ids = sorted(set(matched))
    hints = [f"CRS rule {rid}" for rid in ids] or (
        ["generic SQLi/XSS signature matched"] if blocked else [])
    return blocked, hints


def probe_waf(base, timeout=8.0):
    try:
        urllib.request.urlopen(base, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:          # noqa: BLE001
        return False


def gen_type(client, model, atype, fams, batches, target, seen,
             modsec_base, use_r2):
    accepted, rejected, r2_events = [], [], 0
    fam_i = 0
    for b in range(batches):
        if len(accepted) >= target:
            break
        fam = fams[fam_i % len(fams)]
        fam_i += 1
        seed = BASE_SEED + b
        print(f"  [{atype}] batch {b+1}/{batches}  family={fam}  seed={seed}")
        try:
            raw = client.generate(model, r1_prompt(atype, fam, BATCH_SIZE), R1_SYSTEM, seed)
        except RuntimeError as e:
            print(f"    {e}")
            continue
        for cand in parse_array(raw):
            if len(accepted) >= target:
                break
            p1 = clean(cand)
            ok, reason = validate(p1, atype)
            if not ok:
                rejected.append((p1, atype, fam, seed, 1, reason))
                continue
            final, rnd, rules = p1, 1, []
            # ── Round 2: ModSecurity-feedback mutation ──────────────────────
            if use_r2 and modsec_base:
                blocked, rules = modsec_feedback(modsec_base, p1)
                if blocked:
                    try:
                        raw2 = client.generate(model, r2_prompt(p1, rules), R2_SYSTEM, seed)
                        p2 = clean(strip_fences(raw2))
                        ok2, _ = validate(p2, atype)
                        if ok2:
                            final, rnd, r2_events = p2, 2, r2_events + 1
                    except RuntimeError as e:
                        print(f"    round2 failed, keeping round1: {e}")
            key = normalized_key(final)
            if key in seen:
                rejected.append((final, atype, fam, seed, rnd, "duplicate"))
                continue
            seen.add(key)
            accepted.append((final, atype, fam, seed, rnd, "|".join(rules)))
    return accepted, rejected, r2_events


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model",
                    default="huihui_ai/deepseek-r1-abliterated:14b-qwen-distill")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=11434)
    ap.add_argument("--modsec-host", default="localhost")
    ap.add_argument("--modsec-port", type=int, default=8081,
                    help="PL1 WAF for Round-2 feedback (distinct from the PL2 eval WAF on 8080).")
    ap.add_argument("--no-round2", action="store_true",
                    help="Skip the ModSecurity feedback loop; produce Round-1-only, disclosed as such.")
    ap.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    ap.add_argument("--target-per-type", type=int, default=300)
    ap.add_argument("--auth-token", default=None)
    args = ap.parse_args()

    client = OllamaClient(host=args.host, port=args.port, auth_token=args.auth_token)
    rec = client.check_model(args.model)

    modsec_base = f"http://{args.modsec_host}:{args.modsec_port}"
    use_r2 = not args.no_round2
    if use_r2:
        if probe_waf(modsec_base):
            print(f"  [OK] ModSecurity PL1 reachable at {modsec_base} (Round-2 feedback on)")
        else:
            print(f"  [WARN] no WAF at {modsec_base}; falling back to Round-1-only.")
            use_r2 = False

    t0 = time.time()
    seen: set[str] = set()
    print(f"\nGenerating SQLi (target {args.target_per_type}) ...")
    s_ok, s_bad, s_r2 = gen_type(client, args.model, "sqli", SQLI_FAMILIES,
                                 args.batches, args.target_per_type, seen, modsec_base, use_r2)
    print(f"Generating XSS  (target {args.target_per_type}) ...")
    x_ok, x_bad, x_r2 = gen_type(client, args.model, "xss", XSS_FAMILIES,
                                 args.batches, args.target_per_type, seen, modsec_base, use_r2)

    accepted = s_ok + x_ok
    rejected = s_bad + x_bad

    corpus = OUT / "deepseek_holdout.csv"
    with open(corpus, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "attack_type", "attack_family", "seed", "round",
                    "matched_rules", "label", "generator", "model_tag", "payload_sha256"])
        for p, atype, fam, seed, rnd, rules in accepted:
            w.writerow([p, atype, fam, seed, rnd, rules, 1, "deepseek-r1",
                        args.model, sha256_of(p)])

    rej = OUT / "deepseek_rejects.csv"
    with open(rej, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "attack_type", "attack_family", "seed", "round", "reject_reason"])
        w.writerows(rejected)

    r2_total = s_r2 + x_r2
    manifest = {
        "generator": "deepseek-r1",
        "model_tag": args.model,
        "model_digest": rec.get("digest", ""),
        "abliterated_build": "huihui-ai" in args.model or "abliterated" in args.model.lower(),
        "backend_host": f"{args.host}:{args.port}",
        "round2_enabled": use_r2,
        "round2_feedback_waf": modsec_base if use_r2 else None,
        "round2_mutations_applied": r2_total,
        "controlled_generation": {"temperature": 0.0, "top_k": 1, "top_p": 1.0},
        "base_seed": BASE_SEED,
        "target_per_type": args.target_per_type,
        "accepted": {"sqli": len(s_ok), "xss": len(x_ok), "total": len(accepted)},
        "rejected_total": len(rejected),
        "acceptance_rate": round(len(accepted) / max(len(accepted) + len(rejected), 1), 4),
        "elapsed_seconds": round(time.time() - t0, 1),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "disclosed_circularity": ("Round-2 payloads were partially optimised against "
                                  "ModSecurity PL1 rule logic; evaluation uses PL2. Report "
                                  "Code Llama and DeepSeek results separately (Section 3.5)."),
        "note": "Held-out only. Never used for training, tuning, or threshold selection.",
    }
    with open(OUT / "deepseek_run_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 64)
    print(f"Accepted: {len(accepted)}  (SQLi {len(s_ok)} / XSS {len(x_ok)})")
    print(f"Round-2 mutations applied: {r2_total}")
    print(f"Rejected: {len(rejected)}  acceptance rate {manifest['acceptance_rate']*100:.1f}%")
    print(f"Corpus  : {corpus}")
    print("=" * 64)


if __name__ == "__main__":
    main()
