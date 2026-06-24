"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Pre-flight System Checks                         ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import socket
import sys

from rich import box
from rich.console import Console
from rich.table import Table

from .constants import PLUGINS_PATH, REPORTS_PATH, S_CYAN, S_DIM, S_GREEN, S_WHITE

console = Console()


def preflight_check() -> bool:
    """Pre-flight system validation — 9 checks antes de qualquer scan."""
    checks = []

    # 1. Python version
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python ≥ 3.10", py_ok, f"{sys.version_info.major}.{sys.version_info.minor}", "Atualize Python"))

    # 2. Diretórios
    dirs_ok = True
    for _dir_name, path in [("plugins", PLUGINS_PATH), ("reports", REPORTS_PATH)]:
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
            except OSError:
                dirs_ok = False
        if not os.access(path, os.W_OK):
            dirs_ok = False
    checks.append(("Diretórios R/W", dirs_ok, "plugins/ reports/", "Verifique permissões"))

    # 3. Rich
    rich_ok = True
    try:
        import rich  # noqa: F401
    except ImportError:
        rich_ok = False
    checks.append(("Rich library", rich_ok, "Importada", "pip install rich"))

    # 4. Encoding
    encoding = getattr(sys.stdout, "encoding", "unknown") or "unknown"
    enc_ok = encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32")
    checks.append(("Terminal UTF-8", enc_ok, encoding, "export LANG=en_US.UTF-8"))

    # 5. Disco
    disk_ok = True
    try:
        stat = os.statvfs(REPORTS_PATH)
        free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
        disk_ok = free_mb >= 50
    except (OSError, AttributeError):
        free_mb = -1
    checks.append(("Disco ≥ 50MB", disk_ok, f"{free_mb:.0f}MB livres" if free_mb >= 0 else "N/A", "Libere espaço"))

    # 6. DNS
    dns_ok = False
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo("dns.google", None)
        dns_ok = True
    except (TimeoutError, socket.gaierror, OSError):
        pass
    finally:
        socket.setdefaulttimeout(None)
    checks.append(("DNS funcional", dns_ok, "dns.google", "Verifique rede"))

    # 7. Plugins
    from .engine import _count_plugins
    plugin_count = _count_plugins()
    checks.append(("Plugins ≥ 1", plugin_count > 0, f"{plugin_count} plugins", "Verifique plugins/"))

    # 8. Tools
    from .tools import detect_tools
    tools_avail = detect_tools()
    tools_count = sum(1 for v in tools_avail.values() if v)
    checks.append(("Tools externas ≥ 1", tools_count > 0, f"{tools_count}/{len(tools_avail)}", "Instale: nmap, curl"))

    # 9. Escrita
    write_ok = os.access(REPORTS_PATH, os.W_OK) if os.path.isdir(REPORTS_PATH) else False
    checks.append(("Escrita reports/", write_ok, str(REPORTS_PATH), "chmod 755 reports/"))

    # Display
    table = Table(
        title=f"[{S_GREEN}]🔍 PRE-FLIGHT CHECK[/]", box=box.ROUNDED,
        border_style="green", header_style=f"{S_WHITE} on dark_green",
    )
    table.add_column("Check", style=S_CYAN, min_width=18)
    table.add_column("Status", justify="center", width=6)
    table.add_column("Detalhe", style=S_DIM, min_width=25)

    all_ok = True
    for name, ok, detail, fix in checks:
        icon = "[green]✓[/]" if ok else "[red]✗[/]"
        detail_str = detail if ok else f"[red]{detail}[/] — {fix}"
        table.add_row(name, icon, detail_str)
        if not ok:
            all_ok = False

    console.print(table)
    console.print()

    if not all_ok:
        console.print(f"  [{S_YELLOW}]⚠ Alguns checks falharam. O scan pode ter limitações.[/]")
        console.print()

    return all_ok
