"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — UI Components                                    ║
║  Banner, preloader, dashboard, notifications                 ║
╚═══════════════════════════════════════════════════════════════╝
"""

import datetime
import logging
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from typing import Any

logger = logging.getLogger(__name__)

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    import pyfiglet
except ImportError:
    pyfiglet = None

try:
    from notifypy import Notify as DesktopNotify
except ImportError:
    DesktopNotify = None

from .constants import S_CYAN, S_DIM, S_GREEN, S_RED, S_WHITE, S_YELLOW, SEV_MAP, __version__
from .engine import _classify, _count_plugins, _count_sev

console = Console()

IS_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# ═══════════════════════════════════════════════════════════════════════════════
# ASCII ART
# ═══════════════════════════════════════════════════════════════════════════════
CASCAVEL_LOGO_ASCII = [
    "  ██████╗  █████╗ ███████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗    ",
    " ██╔════╝ ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔════╝██║    ",
    " ██║      ███████║███████╗██║      ███████║██║   ██║█████╗  ██║    ",
    " ██║      ██╔══██║╚════██║██║      ██╔══██║╚██╗ ██╔╝██╔══╝  ██║    ",
    " ╚██████╗ ██║  ██║███████║╚██████╗ ██║  ██║ ╚████╔╝ ███████╗███████╗",
    "  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝",
]

COBRA_ART = [
    "                            ___               ",
    "                         .~)))>>              ",
    "                        .~)>>                 ",
    "                      .~))))>>>               ",
    "                    .~))>>                    ",
    "                  .~))>>)>                    ",
    "                .~))>>                        ",
    "              .~))>>                          ",
    "            .~))>>                            ",
    "          .~)>>                               ",
    "         .~)>>                                ",
]

SNAKE_ART = r"""[green]
                    ___
                 .~))>>
                .~)>>
              .~))))>>>
            .~))>>              [bold bright_green]Advanced Security Framework[/]
          .~))>>)>              [bold bright_green]v{ver} — {plugins} plugins[/]
        .~))>>
      .~))>>
    .~))>>
  .~)>>                        [bold yellow]⚡ github.com/glferreira-devsecops[/]
 .~)>>[/]"""

BOOT_SEQUENCE = [
    ("SYS", f"Iniciando CASCAVEL Advanced Security Framework v{__version__}"),
    ("CPU", "Detectando plataforma: {platform}"),
    ("MEM", "Python runtime: {python}"),
    ("NET", "Verificando conectividade de rede..."),
    ("SEC", "Carregando motor de plugins..."),
    ("PLG", "Plugins detectados: {plugins}"),
    ("ARM", "Inicializando arsenal de ferramentas..."),
    ("FWT", "Ferramentas externas: {tools_count}"),
    ("RDY", "Sistema operacional. Pronto para combate."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PRELOADER
# ═══════════════════════════════════════════════════════════════════════════════
def _typewriter(text: str, speed: float = 0.02) -> None:
    if not IS_TTY:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    try:
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        raise


def _boot_line(tag: str, msg: str, delay: float = 0.08) -> None:
    _now = datetime.datetime.now()
    ts_str = _now.strftime("%H:%M:%S") + "." + f"{_now.microsecond // 1000:03d}"
    sys.stdout.write(f"  \033[2m{ts_str}\033[0m \033[1;32m[{tag}]\033[0m ")
    sys.stdout.flush()
    _typewriter(msg, speed=delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _get_terminal_height() -> int:
    try:
        return os.get_terminal_size().lines
    except (AttributeError, ValueError, OSError):
        return 24


def _fade_in_logo() -> None:
    if not IS_TTY:
        for line in COBRA_ART:
            console.print(f"[green]{line}[/]")
        for line in CASCAVEL_LOGO_ASCII:
            console.print(f"[bold bright_green]{line}[/]")
        return

    term_height = _get_terminal_height()
    logo_count = len(CASCAVEL_LOGO_ASCII)
    cobra_count = len(COBRA_ART)
    total_needed = cobra_count + logo_count + 3
    use_cursor_movement = term_height >= total_needed + 4

    try:
        green_ramp = [22, 22, 28, 28, 34, 34, 35, 40, 41, 46, 46]
        try:
            for i, line in enumerate(COBRA_ART):
                ci = green_ramp[i] if i < len(green_ramp) else 46
                color = f"\033[38;5;{ci}m"
                sys.stdout.write(f"{color}{line}\033[0m\n")
                sys.stdout.flush()
                time.sleep(0.05)
        except KeyboardInterrupt:
            sys.stdout.write("\033[0m\n")
            sys.stdout.flush()
            raise

        time.sleep(0.2)

        fade_codes = ["\033[2;90m", "\033[0;90m", "\033[0;32m", "\033[1;32m", "\033[1;92m"]
        for stage_idx, ansi in enumerate(fade_codes):
            if stage_idx > 0 and use_cursor_movement:
                sys.stdout.write(f"\033[{logo_count}A")
            elif stage_idx > 0:
                continue
            for line in CASCAVEL_LOGO_ASCII:
                sys.stdout.write(f"  {ansi}{line}\033[0m\n")
            sys.stdout.flush()
            time.sleep(0.10)

        time.sleep(0.2)
        subtitle = f"  Advanced Security Framework v{__version__} — Red Team Intelligence"
        console.print()
        console.print(f"  [bold bright_cyan]{subtitle}[/]")
        time.sleep(0.4)
    except OSError:
        for line in CASCAVEL_LOGO_ASCII:
            console.print(f"[bold bright_green]{line}[/]")


def _clear_block(num_lines: int) -> None:
    if not IS_TTY:
        return
    try:
        term_h = _get_terminal_height()
        safe_lines = min(num_lines, max(term_h - 2, 1))
        sys.stdout.write("\033[s")
        sys.stdout.write(f"\033[{safe_lines}A")
        for _ in range(safe_lines):
            sys.stdout.write("\033[2K\n")
        sys.stdout.write(f"\033[{safe_lines}A")
        sys.stdout.write("\033[u")
        sys.stdout.flush()
    except OSError:
        pass


def run_preloader(plugin_count: int, tools_count: int, *, target_hint: str | None = None) -> None:
    try:
        _run_preloader_impl(plugin_count, tools_count, target_hint=target_hint)
    except (OSError, Exception) as e:
        console.print(f"\n  [bold bright_green]🐍 CASCAVEL v{__version__} — ONLINE[/]")
        console.print(f"  [dim]Preloader desativado: {type(e).__name__}[/]\n")


def _run_preloader_impl(plugin_count: int, tools_count: int, *, target_hint: str | None = None) -> None:
    os_name = f"{platform.system()} {platform.release()}"
    py_ver = f"{sys.version.split()[0]}"

    console.print()
    _fade_in_logo()
    time.sleep(0.5)

    total_logo_lines = len(COBRA_ART) + len(CASCAVEL_LOGO_ASCII) + 3
    _clear_block(total_logo_lines)

    boot_title = "[bold green]▶ SYSTEM BOOT SEQUENCE[/]"
    if target_hint:
        boot_title = f"[bold green]▶ SYSTEM BOOT SEQUENCE[/]  [bold bright_red]⚡ {target_hint}[/]"

    console.print(Panel(boot_title, border_style="green", box=box.HEAVY, width=68))
    console.print()

    replacements = {
        "{platform}": os_name,
        "{python}": py_ver,
        "{plugins}": str(plugin_count),
        "{tools_count}": str(tools_count),
    }

    for tag, msg in BOOT_SEQUENCE:
        for key, val in replacements.items():
            msg = msg.replace(key, val)
        _boot_line(tag, msg)
        time.sleep(random.uniform(0.06, 0.18))

    if target_hint:
        console.print()
        console.print(f"  [{S_RED}]█▓▒░  TARGET LOCKED: [bold]{target_hint}[/]  ░▒▓█[/]")
        time.sleep(0.3)

    console.print()

    loading_label = "[bold green]Armando sistema...[/]"
    if target_hint:
        loading_label = f"[bold green]Preparando ataque: [bright_red]{target_hint}[/][/]"

    with Progress(
        SpinnerColumn("dots2"),
        TextColumn(loading_label),
        BarColumn(bar_width=40, complete_style="bright_green"),
        TextColumn("[bold]{task.percentage:>3.0f}%[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("boot", total=100)
        for step in range(100):
            progress.advance(task)
            if step < 30:
                time.sleep(0.015)
            elif step < 70:
                time.sleep(0.025)
            else:
                time.sleep(0.012)

    if target_hint:
        console.print(
            f"  [bold bright_green]✓ CASCAVEL v{__version__} — [bright_red]{target_hint}[/] LOCKED & LOADED[/]\n"
        )
    else:
        console.print(f"  [bold bright_green]✓ CASCAVEL v{__version__} — ONLINE[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER & CARDS
# ═══════════════════════════════════════════════════════════════════════════════
def print_header() -> None:
    console.print()
    if pyfiglet:
        figlet_text = pyfiglet.figlet_format("CASCAVEL", font="ansi_shadow")
        styled = Text(figlet_text)
        styled.stylize(S_GREEN)
        console.print(Align.center(styled))
    else:
        fallback = Text(
            "  ██████╗  █████╗ ███████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗\n"
            " ██╔════╝ ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔════╝██║\n"
            " ██║      ███████║███████╗██║      ███████║██║   ██║█████╗  ██║\n"
            " ██║      ██╔══██║╚════██║██║      ██╔══██║╚██╗ ██╔╝██╔══╝  ██║\n"
            " ╚██████╗ ██║  ██║███████║╚██████╗ ██║  ██║ ╚████╔╝ ███████╗███████╗\n"
            "  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝\n"
        )
        fallback.stylize(S_GREEN)
        console.print(Align.center(fallback))

    snake = SNAKE_ART.format(ver=__version__, plugins=_count_plugins())
    console.print(Text.from_markup(snake))
    console.print()

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style=S_CYAN)
    info_table.add_column(style="white")
    info_table.add_column(style=S_CYAN)
    info_table.add_column(style="white")
    info_table.add_row(
        "🕐 Timestamp",
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "💻 Plataforma",
        f"{sys.platform} | Python {sys.version.split()[0]}",
    )
    info_table.add_row("👤 Autor", "DevFerreiraG", "📦 Versão", f"v{__version__}")

    console.print(
        Panel(
            Align.center(info_table),
            border_style="bright_green",
            title=f"[{S_GREEN}]🐍 CASCAVEL[/]",
            subtitle="[dim]Advanced Security Framework[/]",
            box=box.DOUBLE_EDGE,
        )
    )
    console.print()


def print_target_card(target: str, ip: str) -> None:
    grid = Table(show_header=False, box=None, padding=(0, 3))
    grid.add_column(style=S_WHITE, width=12)
    grid.add_column(style="bold bright_cyan", min_width=30)
    grid.add_row("🎯 Target", target)
    grid.add_row("📡 IP", ip)
    grid.add_row("🕐 Início", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    grid.add_row("🐍 Versão", f"v{__version__}")
    console.print(
        Panel(Align.center(grid), title=f"[{S_RED}]⚡ TARGET ACQUISITION ⚡[/]", border_style="red", box=box.HEAVY)
    )
    console.print()


def print_tools_status(tools: dict[str, bool]) -> None:
    present = sorted(t for t, v in tools.items() if v)
    absent = sorted(t for t, v in tools.items() if not v)
    items = []
    for t in present:
        items.append(Text(f" ● {t} ", style="green"))
    for t in absent:
        items.append(Text(f" ○ {t} ", style="dim red"))
    console.print(
        Panel(
            Columns(items, column_first=True, expand=True, padding=(0, 1)),
            title=f"[{S_CYAN}]🔧 FERRAMENTAS EXTERNAS ({len(present)}/{len(tools)})[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()


def print_dashboard(
    target: str, ip: str, results: list[dict[str, Any]], elapsed_total: float, report_path: str
) -> None:
    console.print(Rule(f"[{S_GREEN}]📊 MISSION REPORT[/]", style="bright_green"))
    console.print()

    total_ok: int = 0
    total_vuln: int = 0
    total_err: int = 0
    agg: dict[str, int] = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}

    for r in results:
        cls, _, _ = _classify(r)
        if cls == "erro":
            total_err += 1
        elif cls == "vuln":
            total_vuln += 1
            for k, v in _count_sev(r.get("resultados", "")).items():
                agg[k] = agg.get(k, 0) + v
        else:
            total_ok += 1

    total_findings = sum(agg.values())

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column(style=S_WHITE, width=14)
    info.add_column(style="bright_cyan", min_width=25)
    info.add_column(style=S_WHITE, width=14)
    info.add_column(style="bright_cyan", min_width=25)
    info.add_row("🎯 Target", target, "📡 IP", ip)
    info.add_row("⏱️  Duração", f"{elapsed_total:.1f}s", "📦 Plugins", str(len(results)))
    info.add_row("📄 Report", os.path.basename(report_path), "🐍 Versão", f"v{__version__}")
    console.print(Panel(info, border_style="bright_green", box=box.DOUBLE_EDGE))
    console.print()

    sev_table = Table(
        title=f"[{S_WHITE}]SEVERITY BREAKDOWN[/]",
        box=box.HEAVY_EDGE,
        border_style="bright_green",
        header_style=f"{S_WHITE} on dark_green",
        show_lines=True,
    )
    sev_table.add_column("Severidade", justify="center", width=15)
    sev_table.add_column("Count", justify="center", width=8)
    sev_table.add_column("Barra", min_width=30)

    max_c: int = max(agg.values()) if any(agg.values()) else 1
    for sev, count in agg.items():
        sty, icon = SEV_MAP.get(sev, (S_DIM, "○"))
        bar_len: int = int(count * 25 // max_c) if count > 0 else 0
        bar = f"[{sty}]{'█' * bar_len}{'░' * (25 - bar_len)}[/]"
        sev_table.add_row(f"[{sty}]{icon} {sev}[/]", f"[{sty}]{count}[/]", bar)
    console.print(sev_table)
    console.print()

    parts = [
        f"[green]✓ Limpos: {total_ok}[/]",
        f"[{S_RED}]⚠ Vulns: {total_vuln}[/]",
        f"[red]✗ Erros: {total_err}[/]",
        f"[{S_WHITE}]Findings: {total_findings}[/]",
    ]
    console.print(Panel(Align.center(Text.from_markup("  │  ".join(parts))), border_style="cyan", box=box.ROUNDED))
    console.print()

    if agg["CRITICO"] > 0:
        risk_style, risk_label = "bold white on red", "██ RISCO CRÍTICO ██"
    elif agg["ALTO"] > 0:
        risk_style, risk_label = "bold white on dark_red", "▓▓ RISCO ALTO ▓▓"
    elif agg["MEDIO"] > 0:
        risk_style, risk_label = "bold black on yellow", "░░ RISCO MÉDIO ░░"
    elif agg["BAIXO"] > 0:
        risk_style, risk_label = "bold white on blue", "·· RISCO BAIXO ··"
    else:
        risk_style, risk_label = "bold white on green", "✓✓ SUPERFÍCIE LIMPA ✓✓"

    console.print(Align.center(Text(f"  {risk_label}  ", style=risk_style)))
    console.print()
    console.print(f"  [{S_DIM}]📄 Relatório:[/] [{S_CYAN}]{report_path}[/]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════
def send_notification(target: str, report_path: str, findings: int) -> None:
    title = "🐍 CASCAVEL — Scan Concluído"
    message = f"Target: {target}\nFindings: {findings}\nRelatório: {os.path.basename(report_path)}"

    if DesktopNotify:
        try:
            n = DesktopNotify()
            n.title = title
            n.message = message
            n.send()
            return
        except Exception as _exc:
            pass

    if sys.platform == "darwin":
        try:
            safe_msg = message.replace("\n", " ").replace('"', '\\"').replace("'", "\\'")
            safe_title = title.replace("\n", " ").replace('"', '\\"').replace("'", "\\'")
            script = f'display notification "{safe_msg}" with title "{safe_title}"'
            subprocess.run(["osascript", "-e", script], timeout=5, capture_output=True)
        except Exception as _exc:
            logger.debug("Non-critical error suppressed")
    elif shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", "--", title, message], timeout=5)
        except Exception as _exc:
            logger.debug("Non-critical error suppressed")


def open_folder(path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    if sys.platform == "darwin":
        subprocess.run(["open", folder], capture_output=True)
    elif sys.platform == "linux":
        subprocess.run(["xdg-open", folder], capture_output=True)


def post_scan_menu(report_path: str) -> None:
    """Menu interativo pós-scan."""
    from .validators import inputx, validate_target

    console.print(Rule(f"[{S_GREEN}]🐍 O QUE DESEJA FAZER?[/]", style="bright_green"))
    console.print()

    menu = Table(show_header=False, box=box.ROUNDED, border_style="green", padding=(0, 2))
    menu.add_column(style=S_GREEN, width=4, justify="center")
    menu.add_column(style=S_WHITE, min_width=40)
    menu.add_row("1", "📂 Abrir pasta do relatório")
    menu.add_row("2", "🔄 Executar novo scan")
    menu.add_row("3", "📋 Listar plugins disponíveis")
    menu.add_row("0", "🚪 Sair")

    console.print(Align.center(menu))
    console.print()

    valid_choices = {"0", "1", "2", "3"}
    choice = ""
    for _attempt in range(3):
        raw = inputx("Opção [0-3]: ").strip()
        if raw in valid_choices:
            choice = raw
            break
        console.print(f"  [{S_YELLOW}]⚠ Opção inválida: '{raw}'.[/]")
    else:
        console.print(f"\n  [{S_DIM}]🐍 Até a próxima missão.[/]\n")
        return

    if choice == "1":
        open_folder(report_path)
        console.print(f"  [{S_GREEN}]✓ Pasta aberta.[/]\n")
    elif choice == "2":
        console.print(f"  [{S_CYAN}]▶ Novo scan[/]")
        from .validators import inputx, validate_target

        new_target_raw = inputx("Novo target (IP/domain): ")
        new_target = validate_target(new_target_raw)
        if new_target:
            from .__main__ import run_scan

            run_scan(new_target, no_notify=False, output_format="md", global_timeout=90)
        else:
            console.print(f"  [{S_RED}]✗ Target inválido.[/]")
    elif choice == "3":
        list_plugins_table()
    else:
        console.print(f"\n  [{S_GREEN}]🐍 Até a próxima missão.[/]\n")


def list_plugins_table() -> None:
    """Lista todos os plugins disponíveis em tabela."""
    import glob

    from .constants import PLUGINS_PATH

    plugin_files = sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py")))
    valid = [
        os.path.splitext(os.path.basename(f))[0]
        for f in plugin_files
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
    ]

    table = Table(
        title=f"[{S_GREEN}]🔌 PLUGINS DISPONÍVEIS ({len(valid)})[/]",
        box=box.ROUNDED,
        border_style="green",
        header_style=f"{S_WHITE} on dark_green",
    )
    table.add_column("#", style=S_DIM, width=4, justify="right")
    table.add_column("Plugin", style=S_CYAN, min_width=30)
    table.add_column("Categoria", style=S_DIM, min_width=15)

    categories = {
        "sqli": "Injection",
        "xss": "Injection",
        "ssrf": "Injection",
        "xxe": "Injection",
        "ssti": "Injection",
        "lfi": "Injection",
        "rce": "Injection",
        "nosql": "Injection",
        "csrf": "Web",
        "cors": "Web",
        "crlf": "Web",
        "clickjacking": "Web",
        "open_redirect": "Web",
        "host_header": "Web",
        "http_smuggling": "Web",
        "http2": "Web",
        "web_cache": "Web",
        "websocket": "Web",
        "graphql": "Web",
        "grpc": "Web",
        "jwt": "Auth",
        "oauth": "Auth",
        "saml": "Auth",
        "oidc": "Auth",
        "session": "Auth",
        "password": "Auth",
        "idor": "Auth",
        "subdomain": "Recon",
        "dns": "Recon",
        "whois": "Recon",
        "wayback": "Recon",
        "shodan": "Recon",
        "email": "Recon",
        "tech_fingerprint": "Recon",
        "nmap": "Network",
        "ssl": "Network",
        "security_headers": "Network",
        "waf": "Network",
        "rate_limit": "Network",
        "k8s": "Cloud",
        "docker": "Cloud",
        "cloud": "Cloud",
        "s3": "Cloud",
        "redis": "Infra",
        "mongodb": "Infra",
        "elastic": "Infra",
        "smb": "Infra",
        "ftp": "Infra",
        "ssh": "Infra",
        "smtp": "Infra",
        "supply_chain": "2026",
        "secrets_deep": "2026",
        "container_escape": "2026",
        "cloud_exploitation": "2026",
        "ad_detection": "2026",
        "adversary": "2026",
        "mobile": "2026",
        "firmware": "2026",
        "fuzzing": "2026",
        "http3": "2026",
        "wireless": "2026",
        "mitm": "2026",
        "printer": "2026",
        "osint": "2026",
        "api_fuzzing": "2026",
        "dns_recon": "2026",
        "subdomain_takeover": "2026",
        "privilege": "2026",
        "persistence": "2026",
        "cobalt": "2026",
        "phishing": "2026",
        "wifi_rogue": "2026",
        "firmware_emulation": "2026",
        "bluetooth": "2026",
        "blockchain": "2026",
        "ics": "2026",
        "zero_trust": "2026",
    }

    for idx, name in enumerate(valid, 1):
        cat = "Other"
        for prefix, category in categories.items():
            if name.startswith(prefix) or prefix in name:
                cat = category
                break
        table.add_row(str(idx), name, cat)

    console.print(table)
    console.print()
