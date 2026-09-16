#!/usr/bin/env python3
"""
Export the Flask dashboard as a standalone static site.

The live app needs a Python backend for /tester (it runs real inference), but every
reporting page is read-only HTML rendered from data/current_results.json and
reports/*.json. This renders those pages through Flask's test client, rewrites the
links to relative filenames, and drops the result in a directory that can be opened
from disk or published anywhere static files are served.

Usage: python3 scripts/export_static_dashboard.py [outdir] [--artifact]

Default outdir: build/static_dashboard/

--artifact produces the same pages for a sandboxed host that only allows scripts from
an approved CDN and serves the entry page inside its own document skeleton: the
stylesheet is inlined, Chart.js is loaded from cdnjs at the pinned version this repo
vendors, and index.html ships as a fragment rather than a full document.
"""

import re
import shutil
import sys
from pathlib import Path

CHART_CDN = "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from app import app  # noqa: E402

# route -> output filename
PAGES = {
    "/": "index.html",
    "/holdout": "holdout.html",
    "/baseline": "baseline.html",
    "/ablation": "ablation.html",
    "/statistics": "statistics.html",
    "/evasion": "evasion.html",
    "/llm": "llm.html",
    "/dataset": "dataset.html",
}

# The tester runs live model inference, so it cannot be exported. Its nav entry is
# turned into an inert label rather than a dead link.
TESTER_LINK_RE = re.compile(
    r'<a href="/tester"[^>]*>(.*?)</a>', re.S)

BANNER = """<div class="notice" style="margin-bottom:24px;">
  <h3>Static export</h3>
  <p>This is a read-only snapshot of the AI-GIS dashboard. Every figure is rendered from
     <code>data/current_results.json</code> and <code>reports/*.json</code> in the repository.
     The live payload tester is not included — it runs real model inference and needs the
     Flask app (<code>python3 app.py</code>).</p>
</div>
"""


def rewrite(html: str, artifact: bool, css: str) -> str:
    if artifact:
        html = html.replace(
            '<link rel="stylesheet" href="/static/style.css">',
            f"<style>\n{css}\n</style>")
        html = html.replace('src="/static/chart.umd.js"', f'src="{CHART_CDN}"')
    else:
        html = html.replace('href="/static/style.css"', 'href="style.css"')
        html = html.replace('src="/static/chart.umd.js"', 'src="chart.umd.js"')
    # Longest routes first so "/" does not clobber "/holdout".
    for route, out in sorted(PAGES.items(), key=lambda kv: -len(kv[0])):
        html = html.replace(f'href="{route}"', f'href="{out}"')
    html = TESTER_LINK_RE.sub(
        r'<span style="color:#6B717A;font-size:14px;font-weight:600;'
        r'padding:4px 0;cursor:not-allowed;" '
        r'title="Needs the live Flask app">\1</span>', html)
    html = html.replace('<main class="wrap">', f'<main class="wrap">\n{BANNER}')
    return html


def strip_document_wrapper(html: str) -> str:
    """Return title + head links + style + body contents, with no <html>/<head>/<body>.

    The artifact host wraps the entry page in its own document skeleton, so shipping a
    second complete document would nest one inside the other.
    """
    head = html[html.index("<head>") + len("<head>"):html.index("</head>")]
    body = html[html.index("<body>") + len("<body>"):html.index("</body>")]
    keep = [line for line in head.splitlines()
            if line.strip().startswith(("<title>", "<script src=",
                                        "<link rel=\"preconnect\"",
                                        "<link href=\"https://fonts."))]
    style = head[head.index("<style>"):head.index("</style>") + len("</style>")]
    return "\n".join(keep) + "\n" + style + "\n" + body


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    artifact = "--artifact" in sys.argv
    out = Path(args[0]) if args else BASE / "build" / "static_dashboard"
    out.mkdir(parents=True, exist_ok=True)

    css = (BASE / "static" / "style.css").read_text(encoding="utf-8")
    client = app.test_client()
    written = 0
    for route, name in PAGES.items():
        resp = client.get(route)
        if resp.status_code != 200:
            raise SystemExit(f"{route} returned {resp.status_code}; aborting export")
        html = rewrite(resp.get_data(as_text=True), artifact, css)
        if artifact and name == "index.html":
            html = strip_document_wrapper(html)
            # The entry page's <title> becomes the artifact's name in a gallery, so it
            # gets a standalone name rather than the in-app "<page> — <app>" pattern.
            html = html.replace("<title>Dashboard — AI-GIS</title>",
                                "<title>AI-GIS Detection Dashboard</title>", 1)
        (out / name).write_text(html, encoding="utf-8")
        written += 1
        print(f"  {route:<12} -> {name}")

    if not artifact:
        for asset in ("style.css", "chart.umd.js"):
            shutil.copy(BASE / "static" / asset, out / asset)
            written += 1
            print(f"  static/{asset} -> {asset}")

    print(f"\nWrote {written} files to {out}" + (" (artifact mode)" if artifact else ""))


if __name__ == "__main__":
    main()
