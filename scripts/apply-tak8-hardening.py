#!/usr/bin/env python3
"""TAK-8 — CASCAVEL headers/hosting hardening (idempotent).

Applies the remediation from the TAK-6 security report:
  F-SEC-2  single CSP source of truth (remove duplicate <meta> security headers)
  F-SEC-1  externalize the 2 inline scripts; drop 'unsafe-inline' from script-src
  F-SEC-3  override Cloudflare's wildcard CORS to the canonical origin
  F-SEO-3  real HTTP 404 via 404.html
  F-SEC-4  robots.txt: remove signpost Disallow entries
  F-SEO-2  sitemap.xml: add plugin doc routes with lastmod

Safe to run multiple times. Run from the repository root.
"""
from __future__ import annotations
import re
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LASTMOD = "2026-06-01"

FRAME_JS = "if (window.top !== window.self) { window.top.location = window.self.location; }\n"

META_BLOCK_RE = re.compile(
    r'\n[ \t]*<!--[^\n]*Security Hardening Headers[^\n]*-->'
    r'(?:[ \t\r\n]*<meta http-equiv="(?:Content-Security-Policy|X-Content-Type-Options|'
    r'X-Frame-Options|Referrer-Policy|Permissions-Policy)"[^>]*/>)+',
    re.DOTALL,
)
META_REPLACEMENT = (
    "\n  <!-- Security headers are served via HTTP (_headers) as the single source of truth.\n"
    "       CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy\n"
    "       are intentionally NOT duplicated here (a <meta> frame-ancestors is inert per spec). -->"
)
FRAME_INLINE_RE = re.compile(
    r'<script>if\s*\(window\.top!==window\.self\)\{window\.top\.location=window\.self\.location;\}</script>'
)


def dedent_block(body: str) -> str:
    lines = body.split("\n")
    while lines and lines[0].strip() == "":
        lines.pop(0)
    while lines and lines[-1].strip() == "":
        lines.pop()
    return textwrap.dedent("\n".join(lines)) + "\n"


def process_html(rel_path: str, ui_out: str, prefix: str) -> None:
    path = ROOT / rel_path
    html = path.read_text(encoding="utf-8")

    # 1) remove duplicate security metas (idempotent: only matches if metas still present)
    html, n = META_BLOCK_RE.subn(META_REPLACEMENT, html)

    # 2) externalize the two inline scripts (only the bare <script>...</script>, not ld+json/src)
    inline = list(re.finditer(r"<script>(.*?)</script>", html, re.DOTALL))
    if inline:
        # the UI block is the larger / last bare inline script; frame-buster is the tiny one
        ui_match = max(inline, key=lambda m: len(m.group(1)))
        ui_body = dedent_block(ui_match.group(1))
        (ROOT / ui_out).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / ui_out).write_text(ui_body, encoding="utf-8", newline="\n")
        ui_src = ("../" if "/" in rel_path else "") + ui_out
        html = html[: ui_match.start()] + f'<script src="{ui_src}" defer></script>' + html[ui_match.end():]

        fb_src = ("../" if "/" in rel_path else "") + "assets/js/frame-buster.js"
        html = FRAME_INLINE_RE.sub(f'<script src="{fb_src}"></script>', html)

    path.write_text(html, encoding="utf-8", newline="\n")
    remaining = len(re.findall(r"<script>(?!</)", html))
    print(f"  {rel_path}: metas_removed_block={n} bare_inline_scripts_remaining={remaining}")


def write_frame_buster() -> None:
    p = ROOT / "assets/js/frame-buster.js"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(FRAME_JS, encoding="utf-8", newline="\n")


def patch_headers() -> None:
    p = ROOT / "_headers"
    txt = p.read_text(encoding="utf-8")

    new_csp = (
        "  # CSP is the single source of truth (no duplicate <meta> in HTML).\n"
        "  # script-src has NO 'unsafe-inline': all scripts are external ('self'); JSON-LD blocks are non-executable data.\n"
        "  # style-src keeps 'unsafe-inline' intentionally for the static page's inline <style>/style=\"\" (low risk, no user input).\n"
        "  # img-src restricted to the exact hosts in use (logo/favicon, shields, OpenSSF badge) instead of the https: wildcard.\n"
        "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://raw.githubusercontent.com https://img.shields.io https://www.bestpractices.dev; "
        "font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; connect-src 'self'; object-src 'none'; "
        "worker-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
    )
    txt = re.sub(r"^[ \t]*Content-Security-Policy:.*$", new_csp, txt, count=1, flags=re.MULTILINE)

    # CORS override (idempotent)
    if "Access-Control-Allow-Origin" not in txt:
        cors = (
            "\n  # --- CORS (decision: restrict to own origin) ---\n"
            "  # Cloudflare Pages injects \"Access-Control-Allow-Origin: *\" on static assets by default.\n"
            "  # This is a 100% public/static site with no credentials/cookies, so wildcard CORS exposes\n"
            "  # nothing today, but it is unnecessary. We override it to the canonical origin so no other\n"
            "  # origin can read responses via fetch/XHR. CORP: same-origin already covers no-cors embedding.\n"
            "  Access-Control-Allow-Origin: https://cascavel.pages.dev\n"
        )
        anchor = "  Cross-Origin-Resource-Policy: same-origin\n"
        txt = txt.replace(anchor, anchor + cors, 1)

    p.write_text(txt, encoding="utf-8", newline="\n")
    print("  _headers: CSP tightened, CORS override ensured")


def patch_robots() -> None:
    p = ROOT / "robots.txt"
    txt = p.read_text(encoding="utf-8")
    txt = re.sub(
        r"# Block sensitive paths\n(?:Disallow:.*\n?)+",
        "# No Disallow signposts: this is a fully public static site with no private paths.\n"
        "# Listing paths here would only advertise them. /.git/ is never published (asserted at\n"
        "# build time via scripts/assert-no-git-published.sh and .wranglerignore).\n",
        txt,
    )
    p.write_text(txt, encoding="utf-8", newline="\n")
    print("  robots.txt: signpost Disallow removed" if "Disallow:" not in txt else "  robots.txt: WARNING Disallow still present")


def patch_sitemap() -> None:
    p = ROOT / "sitemap.xml"
    txt = p.read_text(encoding="utf-8")
    for route, prio in (("plugins_pt", "0.8"), ("plugins_en", "0.8")):
        loc = f"https://cascavel.pages.dev/{route}"
        if loc in txt:
            continue
        entry = (
            f"  <url>\n"
            f"    <loc>{loc}</loc>\n"
            f"    <lastmod>{LASTMOD}</lastmod>\n"
            f"    <changefreq>weekly</changefreq>\n"
            f"    <priority>{prio}</priority>\n"
            f"  </url>\n"
        )
        txt = txt.replace("</urlset>", entry + "</urlset>", 1)
    p.write_text(txt, encoding="utf-8", newline="\n")
    print("  sitemap.xml: plugin doc routes ensured")


def main() -> int:
    print("Applying TAK-8 hardening from repo root:", ROOT)
    write_frame_buster()
    process_html("index.html", "assets/js/ui.js", "")
    process_html("en/index.html", "assets/js/ui.en.js", "../")
    patch_headers()
    patch_robots()
    patch_sitemap()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
