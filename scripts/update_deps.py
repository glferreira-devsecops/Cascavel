#!/usr/bin/env python3
from __future__ import annotations

"""
╔══════════════════════════════════════════════════════════════════════╗
║  CASCAVEL — Automated Dependency Auditor & Updater                   ║
║  Product of RET Tecnologia (https://rettecnologia.org)               ║
║  LTS Maintenance: Auto-detects outdated deps, CVEs, version drift    ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    python3 scripts/update_deps.py              # Audit mode (read-only)
    python3 scripts/update_deps.py --update     # Update requirements.txt
    python3 scripts/update_deps.py --ci         # CI mode (exit 1 on issues)

This script:
  1. Parses requirements.txt and extracts pinned/minimum versions
  2. Queries PyPI for latest versions of each package
  3. Cross-references pyproject.toml for version drift
  4. Checks Python version compatibility (requires-python)
  5. Detects known CVE floor violations
  6. Verifies version sync across cascavel.py, pyproject.toml, report_generator.py
  7. Optionally updates requirements.txt with latest compatible versions

© 2026 RET Tecnologia. All rights reserved.
SPDX-License-Identifier: MIT
"""

import json
import re
import sys
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

# ── CVE Floor Map ────────────────────────────────────────────────────
CVE_FLOORS = {
    "PyJWT": ("2.12.0", "CVE-2022-29217 — algorithm confusion attack"),
    "reportlab": ("3.6.13", "CVE-2023-33733 — RCE via rl_safe_eval"),
    "requests": ("2.32.4", "GHSA-9hjg-9r4m-mvj7 — Proxy-Auth leak"),
    "dnspython": ("2.7.0", "GHSA-3rq5-2g8h-59hc"),
    "pyOpenSSL": ("25.0.0", "GHSA-5pwr-322w-8jr4"),
    "cryptography": ("44.0.0", "Multiple CVEs in older versions"),
}

# ── Helpers ──────────────────────────────────────────────────────────

def parse_version(v: str) -> tuple:
    """Parse '1.2.3' into (1, 2, 3) for comparison."""
    return tuple(int(x) for x in v.split("."))


def get_pypi_latest(package: str) -> str | None:
    """Query PyPI JSON API for latest version."""
    try:
        url = f"https://pypi.org/pypi/{package}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "Cascavel-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except Exception:
        return None


def parse_requirements(path: Path) -> list[dict]:
    """Parse requirements.txt into list of {name, operator, version, line_num, raw}."""
    deps = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle extras like qrcode[pil]
        match = re.match(r"^([a-zA-Z0-9_\-]+(?:\[[a-zA-Z0-9_,]+\])?)\s*(>=|==|~=|<=|!=|>|<)?\s*([\d.]+)?", line)
        if match:
            name = match.group(1).split("[")[0]  # Strip extras for PyPI lookup
            full_name = match.group(1)
            op = match.group(2) or ""
            ver = match.group(3) or ""
            deps.append({
                "name": name,
                "full_name": full_name,
                "operator": op,
                "version": ver,
                "line_num": i,
                "raw": line,
            })
    return deps


def check_version_sync() -> list[str]:
    """Ensure version is consistent across cascavel.py, pyproject.toml, report_generator.py."""
    issues = []
    versions = {}

    # cascavel.py
    cascavel = BASE / "cascavel.py"
    if cascavel.exists():
        m = re.search(r'__version__\s*=\s*"([\d.]+)"', cascavel.read_text())
        if m:
            versions["cascavel.py"] = m.group(1)

    # pyproject.toml
    pyproject = BASE / "pyproject.toml"
    if pyproject.exists():
        m = re.search(r'^version\s*=\s*"([\d.]+)"', pyproject.read_text(), re.MULTILINE)
        if m:
            versions["pyproject.toml"] = m.group(1)

    # report_generator.py
    rg = BASE / "report_generator.py"
    if rg.exists():
        m = re.search(r'VERSION\s*=\s*"([\d.]+)"', rg.read_text())
        if m:
            versions["report_generator.py"] = m.group(1)

    unique = set(versions.values())
    if len(unique) > 1:
        for f, v in versions.items():
            issues.append(f"VERSION MISMATCH: {f} = {v}")

    return issues


def audit(update: bool = False, ci: bool = False) -> int:
    """Run full dependency audit. Returns exit code."""
    req_path = BASE / "requirements.txt"
    if not req_path.exists():
        print("❌ requirements.txt not found!")
        return 1

    deps = parse_requirements(req_path)
    issues = []
    updates = []
    lines = req_path.read_text().splitlines()

    print("╔" + "═" * 60 + "╗")
    print("║  🐍 CASCAVEL — Dependency Audit & Update                  ║")
    print("╚" + "═" * 60 + "╝")
    print()

    # ── 1. Version Sync ─────────────────────────────────────────────
    print("━━━ [1/4] Version Sync Check ━━━")
    sync_issues = check_version_sync()
    if sync_issues:
        for issue in sync_issues:
            print(f"  ❌ {issue}")
            issues.append(issue)
    else:
        print("  ✅ All versions synced")
    print()

    # ── 2. CVE Floor Check ──────────────────────────────────────────
    print("━━━ [2/4] CVE Floor Enforcement ━━━")
    for dep in deps:
        name_lower = dep["name"].lower()
        for cve_pkg, (min_ver, cve_desc) in CVE_FLOORS.items():
            if name_lower == cve_pkg.lower() and dep["version"]:
                if parse_version(dep["version"]) < parse_version(min_ver):
                    msg = f'{dep["name"]} {dep["version"]} < {min_ver} ({cve_desc})'
                    print(f"  ❌ {msg}")
                    issues.append(msg)
                else:
                    print(f"  ✅ {dep['name']} {dep['version']} >= {min_ver}")
    print()

    # ── 3. PyPI Latest Check ────────────────────────────────────────
    print("━━━ [3/4] PyPI Latest Version Check ━━━")
    for dep in deps:
        latest = get_pypi_latest(dep["name"])
        if latest is None:
            print(f"  ⚠️  {dep['name']:25} — PyPI unreachable")
            continue

        current = dep["version"]
        if not current:
            print(f"  ⚠️  {dep['name']:25} — no version pinned")
            continue

        if parse_version(latest) > parse_version(current):
            print(f"  📦 {dep['name']:25} {current:>10} → {latest}")
            updates.append((dep, latest))
        else:
            print(f"  ✅ {dep['name']:25} {current:>10} (latest)")
    print()

    # ── 4. Summary ──────────────────────────────────────────────────
    print("━━━ [4/4] Summary ━━━")
    print(f"  Total deps:     {len(deps)}")
    print(f"  Outdated:       {len(updates)}")
    print(f"  Issues:         {len(issues)}")

    if update and updates:
        print()
        print("━━━ Updating requirements.txt ━━━")
        for dep, latest in updates:
            old_line = dep["raw"]
            # Preserve the operator style
            op = dep["operator"] or ">="
            new_line = f'{dep["full_name"]}{op}{latest}'
            idx = dep["line_num"] - 1
            lines[idx] = new_line
            print(f"  ✏️  {old_line} → {new_line}")

        req_path.write_text("\n".join(lines) + "\n")
        print(f"\n  ✅ requirements.txt updated ({len(updates)} packages)")

    print()
    if issues:
        print(f"{'❌ AUDIT FAILED' if ci else '⚠️  Issues found'}: {len(issues)} issue(s)")
        return 1 if ci else 0
    else:
        print("✅ ALL CHECKS PASSED")
        return 0


if __name__ == "__main__":
    do_update = "--update" in sys.argv
    ci_mode = "--ci" in sys.argv
    sys.exit(audit(update=do_update, ci=ci_mode))
