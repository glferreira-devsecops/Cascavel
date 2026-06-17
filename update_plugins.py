import glob

for filepath in glob.glob("plugins/*.py"):
    with open(filepath) as f:
        content = f.read()

    # Check if it uses the old signature
    if "def run(target, ip, open_ports, banners):" in content:
        content = content.replace(
            "def run(target, ip, open_ports, banners):",
            "def run(target, ip, open_ports, banners, context=None):"
        )
    elif "def run(target, ip, ports, banners):" in content:
        content = content.replace(
            "def run(target, ip, ports, banners):",
            "def run(target, ip, ports, banners, context=None):"
        )

    with open(filepath, "w") as f:
        f.write(content)
print("Plugins updated.")
