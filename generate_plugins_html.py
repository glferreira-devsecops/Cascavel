import re
import sys

def parse_plugins_md(md_file):
    with open(md_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    categories = []
    
    # regex to find categories like "## 💉 Injection & Code Execution"
    # followed by the table
    cat_pattern = re.compile(r'## (.*?)\n\n.*?\| Plugin \| File \| Techniques \|\n\|---\|---\|---\|\n(.*?)(?=\n## |\Z)', re.DOTALL)
    
    # Adjust regex to catch the table properly
    cat_pattern = re.compile(r'## (.*?)\n\n\| Plugin \| File \| Techniques \|\n\|-*?\|-*?\|-*?\|\n(.*?)(?=\n## |\Z)', re.DOTALL)
    
    matches = cat_pattern.findall(content)
    
    for match in matches:
        title = match[0].strip()
        icon = title.split(' ')[0]
        name = ' '.join(title.split(' ')[1:])
        
        table_str = match[1].strip()
        plugins = []
        for line in table_str.split('\n'):
            line = line.strip()
            if not line or not line.startswith('|'):
                continue
            parts = [p.strip() for p in line.split('|')[1:-1]]
            if len(parts) >= 3:
                plugin_name = parts[0].replace('**', '')
                plugin_file = parts[1].replace('`', '')
                techniques = parts[2]
                plugins.append({
                    "name": plugin_name,
                    "file": plugin_file,
                    "techniques": techniques
                })
        categories.append({
            "icon": icon,
            "name": name,
            "plugins": plugins
        })
        
    return categories

def generate_html(categories, lang="pt"):
    html = ['<div class="plugin-categories-detailed">']
    for cat in categories:
        count = len(cat["plugins"])
        html.append(f'  <div class="plugin-category-block" style="margin-bottom: 2rem;">')
        html.append(f'    <h3 style="color: var(--cyan); margin-bottom: 1rem; border-bottom: 1px solid rgba(0, 255, 229, 0.2); padding-bottom: 0.5rem;"><span class="cat-icon">{cat["icon"]}</span> {cat["name"]} <span class="badge-count" style="font-size: 0.8rem; vertical-align: middle; margin-left: 0.5rem;">{count}</span></h3>')
        html.append(f'    <div class="table-wrapper">')
        html.append(f'      <table class="plugin-table">')
        
        if lang == "pt":
            html.append(f'        <thead><tr><th style="width: 25%;">Plugin</th><th style="width: 25%;">Arquivo</th><th>Técnicas</th></tr></thead>')
        else:
            html.append(f'        <thead><tr><th style="width: 25%;">Plugin</th><th style="width: 25%;">File</th><th>Techniques</th></tr></thead>')
            
        html.append(f'        <tbody>')
        for p in cat["plugins"]:
            html.append(f'          <tr><td><strong>{p["name"]}</strong></td><td><code>{p["file"]}</code></td><td class="techniques">{p["techniques"]}</td></tr>')
        html.append(f'        </tbody>')
        html.append(f'      </table>')
        html.append(f'    </div>')
        html.append(f'  </div>')
    html.append('</div>')
    return "\n".join(html)

def main():
    categories = parse_plugins_md("PLUGINS.md")
    
    html_pt = generate_html(categories, lang="pt")
    with open("plugins_pt.html", "w", encoding="utf-8") as f:
        f.write(html_pt)
        
    html_en = generate_html(categories, lang="en")
    with open("plugins_en.html", "w", encoding="utf-8") as f:
        f.write(html_en)

if __name__ == "__main__":
    main()
