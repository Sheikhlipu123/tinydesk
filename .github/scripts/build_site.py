#!/usr/bin/env python3
"""Build the Tiny Desk GitHub Pages site.

Inputs : README.md, docs/template.html, other static files in docs/,
         GitHub API (repo info, latest release, recent releases).
Output : _site/  (index.html, sitemap.xml, robots.txt, llms.txt,
         llms-full.txt, 404.html, .nojekyll + copied static assets)

Run locally:  pip install markdown nh3 && python .github/scripts/build_site.py
"""
import datetime as dt
import html
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

import markdown
import nh3

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
OUT = ROOT / "_site"
TEMPLATE = DOCS / "template.html"
NOT_COPIED = {"template.html"}

REPO = os.environ.get("GITHUB_REPOSITORY", "Sheikhlipu123/tinydesk")
OWNER, NAME = REPO.split("/", 1)
REPO_URL = f"https://github.com/{REPO}"
SITE = f"https://{OWNER.lower()}.github.io/{NAME}/"
BASE = f"/{NAME}/"
TOKEN = os.environ.get("GITHUB_TOKEN")
NOW = dt.datetime.now(dt.timezone.utc)

FALLBACK_DESC = (
    "Self-hosted, JavaScript-free notice board and anonymous message desk "
    "for Tor onion services. Flask + SQLite, one Python file, AES-256-GCM at rest."
)

FAQ = [
    ("What is Tiny Desk?",
     "Tiny Desk is a minimal, JavaScript-free notice board and anonymous message desk "
     "for Tor onion services, built with Flask and SQLite in a single Python file."),
    ("Does Tiny Desk require JavaScript?",
     "No. Pages are server-rendered. Message threads refresh through a meta-refresh iframe."),
    ("Is Tiny Desk end-to-end encrypted?",
     "No. Messages are encrypted at rest with AES-256-GCM, but the operator can read them. "
     "Tor protects the transport."),
    ("Do visitors need an account?",
     "No. Visitors receive a Ticket and Key after sending a message. "
     "No account, e-mail or name is required."),
    ("Can I run it without Tor?",
     "Yes, for local or internal use. Set <code>COOKIE_SECURE=0</code> when serving plain "
     "HTTP and keep the default <code>1</code> behind HTTPS."),
    ("How is Tiny Desk different from Hush Line, SecureDrop or GlobaLeaks?",
     "Those projects target whistleblowing and tip lines, where messages should stay "
     "unreadable to the server. Tiny Desk is a lighter self-hosted desk with public notices, "
     "downloads and two-way anonymous threads using a Ticket and Key. Messages are encrypted "
     "at rest, but the operator can read them, so it is not a substitute for a whistleblowing platform."),
]

esc = html.escape


# ---------------------------------------------------------------- GitHub API
def api(path):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "tinydesk-site-builder",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(f"https://api.github.com{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"warn: GET {path} failed: {e}", file=sys.stderr)
        return None


# ------------------------------------------------------------------ Markdown
ATTRS = {k: set(v) for k, v in nh3.ALLOWED_ATTRIBUTES.items()}
ATTRS.setdefault("*", set()).update({"id", "class"})


def render_md(text, default_branch="main", demote=False, strip_h1=False):
    md = markdown.Markdown(extensions=["fenced_code", "tables", "toc", "sane_lists"])
    out = md.convert(text)
    toc_tokens = md.toc_tokens

    if strip_h1:
        out = re.sub(r"<h1[^>]*>.*?</h1>", "", out, count=1, flags=re.S)
    if demote:  # h5->h6 ... h2->h3 (descending avoids double bumps)
        for n in range(5, 1, -1):
            out = out.replace(f"<h{n}", f"<h{n + 1}").replace(f"</h{n}>", f"</h{n + 1}>")

    out = nh3.clean(out, attributes=ATTRS)
    return rewrite_links(out, default_branch), toc_tokens


def rewrite_links(doc, branch):
    """Make repo-relative links/images point at GitHub."""
    def fix(m):
        attr, val = m.group(1), m.group(2)
        if val.startswith(("#", "//", "mailto:")) or re.match(r"^[a-z][a-z0-9+.-]*:", val, re.I):
            return m.group(0)
        rel = val.lstrip("./").lstrip("/")
        if attr == "src":
            return f'src="https://raw.githubusercontent.com/{REPO}/{branch}/{rel}"'
        return f'href="{REPO_URL}/blob/{branch}/{rel}"'
    return re.sub(r'\b(href|src)="([^"]*)"', fix, doc)


def toc_html(tokens):
    if len(tokens) == 1 and tokens[0]["level"] == 1:
        tokens = tokens[0]["children"]
    if not tokens:
        return ""
    items = "".join(
        f'<li><a href="#{esc(t["id"])}">{esc(html.unescape(t["name"]))}</a></li>'
        for t in tokens
    )
    return f'<details class="toc"><summary>On this page</summary><ul>{items}</ul></details>'


# ------------------------------------------------------------------- helpers
def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def day(iso):
    return (iso or "")[:10]


def strip_tags(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s))


def read_readme():
    for p in ROOT.iterdir():
        if p.is_file() and p.name.lower() == "readme.md":
            return p.read_text(encoding="utf-8")
    print("warn: README.md not found", file=sys.stderr)
    return "_README.md not found._"


# ------------------------------------------------------------ release block
def release_section(latest, recent, branch):
    if not latest:
        return "", ""
    tag = latest.get("tag_name", "")
    title = latest.get("name") or tag
    notes_src = (latest.get("body") or "").strip() or "_No release notes._"
    notes, _ = render_md(notes_src, branch, demote=True)

    assets = "".join(
        f'<li><a href="{esc(a["browser_download_url"])}">{esc(a["name"])}</a> '
        f'<span>{fmt_size(a["size"])} · {a.get("download_count", 0)} downloads</span></li>'
        for a in latest.get("assets", [])
    )
    sources = (
        f'<li><a href="{REPO_URL}/archive/refs/tags/{esc(tag)}.zip">Source code (zip)</a></li>'
        f'<li><a href="{REPO_URL}/archive/refs/tags/{esc(tag)}.tar.gz">Source code (tar.gz)</a></li>'
    )

    older = ""
    others = [r for r in (recent or []) if r.get("tag_name") != tag and not r.get("draft")][:4]
    if others:
        rows = "".join(
            f'<li><a href="{esc(r["html_url"])}">{esc(r.get("name") or r["tag_name"])}</a> '
            f'<span>{day(r.get("published_at"))}</span></li>'
            for r in others
        )
        older = f'<h3>Previous releases</h3><ul class="plain">{rows}</ul>'

    pre = ' <span class="pill warn-pill">Pre-release</span>' if latest.get("prerelease") else ""
    section = f"""
<section id="release">
  <div class="wrap">
    <h2>Latest release</h2>
    <div class="card release">
      <div class="rel-head">
        <h3>{esc(title)} <span class="pill">Latest</span>{pre}</h3>
        <span class="muted">Published {day(latest.get("published_at"))}</span>
      </div>
      <div class="md">{notes}</div>
      <h3>Downloads</h3>
      <ul class="plain">{assets}{sources}</ul>
      <p><a href="{esc(latest["html_url"])}">View on GitHub &rarr;</a></p>
      {older}
    </div>
  </div>
</section>"""
    return section, '<a href="#release">Release</a>'


# ----------------------------------------------------------------------- main
def main():
    template = TEMPLATE.read_text(encoding="utf-8")

    repo = api(f"/repos/{REPO}") or {}
    branch = repo.get("default_branch", "main")
    latest = api(f"/repos/{REPO}/releases/latest")
    recent = api(f"/repos/{REPO}/releases?per_page=6")
    if isinstance(latest, dict) and "tag_name" not in latest:
        latest = None

    version = latest["tag_name"] if latest else ""
    description = repo.get("description") or FALLBACK_DESC
    pushed = day(repo.get("pushed_at")) or NOW.strftime("%Y-%m-%d")
    license_info = repo.get("license") or {}
    spdx = license_info.get("spdx_id")

    # README -> HTML
    readme_src = read_readme()
    readme_html, toc_tokens = render_md(readme_src, branch, demote=True, strip_h1=True)

    # Release + stats
    release_html, nav_release = release_section(latest, recent, branch)

    stats = []
    if version:
        stats.append(f'<a class="stat" href="{esc(latest["html_url"])}">{esc(version)}</a>')
    if "stargazers_count" in repo:
        stats.append(f'<a class="stat" href="{REPO_URL}/stargazers">★ {repo["stargazers_count"]}</a>')
    stats.append(f'<span class="stat">Updated {pushed}</span>')
    if spdx and spdx != "NOASSERTION":
        stats.append(f'<span class="stat">{esc(spdx)}</span>')

    # FAQ (HTML + JSON-LD from one source)
    faq = list(FAQ)
    if version:
        faq.append(("What is the latest version of Tiny Desk?",
                    f"The latest release is {esc(version)}, published {day(latest.get('published_at'))}."))
    faq_html = "".join(
        f"<details{' open' if i == 0 else ''}><summary>{esc(q)}</summary><p>{a}</p></details>"
        for i, (q, a) in enumerate(faq)
    )

    software = {
        "@type": "SoftwareSourceCode",
        "@id": SITE + "#software",
        "name": "Tiny Desk",
        "alternateName": ["TinyDesk", "Tiny Desk Tor onion message desk"],
        "description": description,
        "codeRepository": REPO_URL,
        "programmingLanguage": "Python",
        "runtimePlatform": "Python 3.10+",
        "author": {"@type": "Person", "name": OWNER, "url": f"https://github.com/{OWNER}"},
        "keywords": "tor, onion service, anonymous messaging, flask, sqlite, notice board, privacy, self-hosted",
        "url": SITE,
        "dateModified": pushed,
    }
    if version:
        software["softwareVersion"] = version
        software["datePublished"] = day(latest.get("published_at"))
    if spdx and spdx != "NOASSERTION":
        software["license"] = f"https://spdx.org/licenses/{spdx}.html"
    graph = {
        "@context": "https://schema.org",
        "@graph": [
            software,
            {"@type": "WebSite", "@id": SITE + "#website", "url": SITE, "name": "Tiny Desk", "inLanguage": "en"},
            {"@type": "FAQPage", "mainEntity": [
                {"@type": "Question", "name": q,
                 "acceptedAnswer": {"@type": "Answer", "text": strip_tags(a)}} for q, a in faq]},
        ],
    }
    jsonld = json.dumps(graph, indent=2, ensure_ascii=False).replace("</", "<\\/")

    values = {
        "BASE": BASE,
        "SITE": SITE,
        "REPO_URL": REPO_URL,
        "JSONLD": jsonld,
        "STATS": "".join(stats),
        "NAV_RELEASE": nav_release,
        "RELEASE_SECTION": release_html,
        "TOC": toc_html(toc_tokens),
        "README": readme_html,
        "FAQ": faq_html,
        "OWNER": esc(OWNER),
        "YEAR": str(NOW.year),
        "BUILT": NOW.strftime("%Y-%m-%d %H:%M UTC"),
    }
    page = template
    for k, v in values.items():
        page = page.replace("{{" + k + "}}", v)
    left = set(re.findall(r"\{\{[A-Z_]+\}\}", page))
    if left:
        print(f"warn: unreplaced placeholders: {left}", file=sys.stderr)

    # Output directory
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    for item in DOCS.iterdir():
        if item.name in NOT_COPIED:
            continue
        dest = OUT / item.name
        shutil.copytree(item, dest) if item.is_dir() else shutil.copy2(item, dest)

    (OUT / "index.html").write_text(page, encoding="utf-8")
    (OUT / ".nojekyll").write_text("")

    (OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{SITE}</loc><lastmod>{pushed}</lastmod>"
        "<changefreq>weekly</changefreq><priority>1.0</priority></url>\n"
        "</urlset>\n", encoding="utf-8")

    (OUT / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\n\nSitemap: {SITE}sitemap.xml\n", encoding="utf-8")

    llms = ["# Tiny Desk", "", f"> {description}", ""]
    if version:
        llms += [f"Latest release: {version} ({day(latest.get('published_at'))})", ""]
    llms += [
        "## Links", "",
        f"- [Website]({SITE})",
        f"- [Source code]({REPO_URL})",
        f"- [Full README for LLMs]({SITE}llms-full.txt)",
        f"- [Releases]({REPO_URL}/releases)",
        f"- [Security reporting]({REPO_URL}/security)",
        "",
    ]
    (OUT / "llms.txt").write_text("\n".join(llms), encoding="utf-8")
    (OUT / "llms-full.txt").write_text(
        f"# Tiny Desk (generated {NOW.strftime('%Y-%m-%d')}"
        + (f", release {version}" if version else "") + ")\n\n" + readme_src, encoding="utf-8")

    (OUT / "404.html").write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="robots" content="noindex"><title>Not found · Tiny Desk</title>'
        "<style>body{margin:0;display:grid;place-items:center;min-height:100vh;background:#0f0e1f;"
        "color:#ece9ff;font:16px/1.6 system-ui,sans-serif;text-align:center}a{color:#b8adff}</style>"
        f'</head><body><main><h1>404</h1><p>Page not found.</p><p><a href="{BASE}">Back to Tiny Desk</a></p>'
        "</main></body></html>", encoding="utf-8")

    print(f"Built {OUT} (version={version or 'none'}, branch={branch})")


if __name__ == "__main__":
    main()
