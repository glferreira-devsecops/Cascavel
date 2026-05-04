import re

def replace_in_file(filename, replacement_file):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
        
    with open(replacement_file, "r", encoding="utf-8") as f:
        replacement = f.read()
        
    pattern = re.compile(r'<table class="plugin-table">.*?</table>', re.DOTALL)
    
    new_content = pattern.sub(replacement, content)
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(new_content)

replace_in_file("index.html", "plugins_pt.html")
replace_in_file("en/index.html", "plugins_en.html")
