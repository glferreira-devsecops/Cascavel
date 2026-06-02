#!/usr/bin/env python3
"""Rebuild the #plugins section in index.html / en/index.html from PLUGINS.md.

Root cause this fixes: apply_plugins_html.py duplicated the plugin tables
~196x, bloating each page to ~5.2MB and rendering 2744 tables / 16660 rows
instead of 14 categories / 85 plugins. This regenerates the section from the
canonical PLUGINS.md and wires a CSP-strict-safe search/filter control to the
external assets/js/plugin-search.js.

Idempotent: safe to re-run.
"""
import html as html_mod
import re

PLUGINS_MD = "PLUGINS.md"

PAGES = [
    {
        "file": "index.html",
        "lang": "pt",
        "heading": "Plugin Categories",
        "subtitle": "85 plugins organizados em 14 categorias especializadas de ataque.",
        "th": ("Plugin", "Arquivo", "Técnicas"),
        "src": "assets/js/plugin-search.js",
    },
    {
        "file": "en/index.html",
        "lang": "en",
        "heading": "Plugin Categories",
        "subtitle": "85 plugins organized into 14 specialized attack categories.",
        "th": ("Plugin", "File", "Techniques"),
        "src": "../assets/js/plugin-search.js",
    },
]


def parse_plugins_md(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    categories = []
    # Each category: "## <icon> <name>" then a markdown table whose header is
    # "| Plugin | File | Techniques |". The intro "## Plugin Categories"
    # overview table has a different header and is therefore skipped.
    pattern = re.compile(
        r"^## (?P<title>.+?)\n+"
        r"\| Plugin \| File \| Techniques \|\n"
        r"\|[-\s|]+\|\n"
        r"(?P<rows>(?:\|.*\n?)+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(content):
        title = m.group("title").strip()
        parts = title.split(" ", 1)
        icon = parts[0] if len(parts) > 1 else ""
        name = parts[1].strip() if len(parts) > 1 else title

        plugins = []
        for line in m.group("rows").splitlines():
            line = line.strip()
            if not line.startswith("|"):
                continue
            cols = [c.strip() for c in line.split("|")[1:-1]]
            if len(cols) < 3:
                continue
            pname = cols[0].replace("**", "").strip()
            pfile = cols[1].replace("`", "").strip()
            ptech = cols[2].strip()
            plugins.append((pname, pfile, ptech))
        if plugins:
            categories.append({"icon": icon, "name": name, "plugins": plugins})
    return categories


def esc(s):
    return html_mod.escape(s, quote=False)


def render_blocks(categories, th):
    out = []
    for cat in categories:
        count = len(cat["plugins"])
        rows = "\n".join(
            "          <tr><td><strong>%s</strong></td><td><code>%s</code></td>"
            "<td class=\"techniques\">%s</td></tr>"
            % (esc(p[0]), esc(p[1]), esc(p[2]))
            for p in cat["plugins"]
        )
        block = (
            '  <div class="plugin-category-block" style="margin-bottom: 2rem;">\n'
            '    <h3 style="color: var(--cyan); margin-bottom: 1rem; '
            "border-bottom: 1px solid rgba(0, 255, 229, 0.2); "
            'padding-bottom: 0.5rem;"><span class="cat-icon">%s</span> %s '
            '<span class="badge-count" style="font-size: 0.8rem; '
            'vertical-align: middle; margin-left: 0.5rem;">%d</span></h3>\n'
            '    <div class="table-wrapper">\n'
            '      <table class="plugin-table">\n'
            "        <thead><tr><th style=\"width: 25%%;\">%s</th>"
            "<th style=\"width: 25%%;\">%s</th><th>%s</th></tr></thead>\n"
            "        <tbody>\n"
            "%s\n"
            "        </tbody>\n"
            "      </table>\n"
            "    </div>\n"
            "  </div>"
        ) % (esc(cat["icon"]), esc(cat["name"]), count, th[0], th[1], th[2], rows)
        out.append(block)
    return "\n".join(out)


def build_section(page, blocks_html):
    return (
        '  <section id="plugins">\n'
        '    <div class="container">\n'
        '      <h2 class="section-title reveal">%s</h2>\n'
        '      <p class="section-subtitle reveal">%s</p>\n'
        '      <div class="table-wrapper reveal">\n'
        '        <div class="plugin-categories-detailed">\n'
        "%s\n"
        "        </div>\n"
        "      </div>\n"
        "    </div>\n"
        "  </section>"
    ) % (page["heading"], page["subtitle"], blocks_html)


def replace_section(doc, new_section):
    start = doc.find('<section id="plugins">')
    if start == -1:
        raise SystemExit("ERROR: <section id=\"plugins\"> not found")
    line_start = doc.rfind("\n", 0, start) + 1
    end = doc.find("</section>", start)
    if end == -1:
        raise SystemExit("ERROR: closing </section> not found")
    end += len("</section>")
    return doc[:line_start] + new_section + doc[end:]


def ensure_script_tag(doc, src):
    tag = '<script src="%s" defer></script>' % src
    if tag in doc:
        return doc
    idx = doc.rfind("</body>")
    if idx == -1:
        raise SystemExit("ERROR: </body> not found")
    return doc[:idx] + "  " + tag + "\n" + doc[idx:]


def main():
    categories = parse_plugins_md(PLUGINS_MD)
    total = sum(len(c["plugins"]) for c in categories)
    print("Parsed PLUGINS.md: %d categories, %d plugins" % (len(categories), total))

    for page in PAGES:
        blocks_html = render_blocks(categories, page["th"])
        with open(page["file"], "r", encoding="utf-8") as f:
            doc = f.read()
        before = len(doc)
        doc = replace_section(doc, build_section(page, blocks_html))
        doc = ensure_script_tag(doc, page["src"])
        with open(page["file"], "w", encoding="utf-8") as f:
            f.write(doc)
        print(
            "OK: %s  %d -> %d bytes  (%d tables)"
            % (page["file"], before, len(doc), doc.count('class="plugin-table"'))
        )


if __name__ == "__main__":
    main()
