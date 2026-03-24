#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Quantum Security Framework v2.1.0                ║
║  Por DevFerreiraG | github.com/glferreira-devsecops          ║
║  Framework de automação pentest plugável, multi-plataforma   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import datetime
import socket
import glob
import importlib.util
import json
import signal
import shutil
import re
import argparse
import shlex
import time
import random
import platform
import urllib.request
import threading
from typing import List, Dict, Any, Optional

__version__ = "2.1.0"

# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════════════
REQUIRED_LIBS = {"rich": "rich", "requests": "requests"}
IS_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# Graceful shutdown on CTRL+C
_shutdown_requested = False


def _signal_handler(sig, frame):
    """Graceful shutdown handler — signal-safe (no print/logging to avoid deadlock)."""
    global _shutdown_requested
    _shutdown_requested = True
    # SEGURANÇA: os.write() é async-signal-safe. console.print()/logging NÃO são.
    # Usar print/logging em signal handler causa deadlock por reentrância de locks.
    try:
        os.write(sys.stderr.fileno(), b"\n  \x1b[91m\xe2\x9c\x97 SIGINT recebido \xe2\x80\x94 encerrando...\x1b[0m\n")
    except OSError:
        pass
    os._exit(130)  # 128 + SIGINT(2) = exit code padrão Unix


signal.signal(signal.SIGINT, _signal_handler)


def _check_deps() -> None:
    missing = []
    for lib in REQUIRED_LIBS:
        try:
            __import__(lib)
        except ImportError:
            missing.append(lib)
    if missing:
        print(f"\n\033[91m[✗] Faltando: {', '.join(missing)}\033[0m")
        print("\033[96mInstale: pip install -r requirements.txt\033[0m\n")
        sys.exit(1)


_check_deps()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.live import Live
from rich.layout import Layout
from rich import box

try:
    import pyfiglet
except ImportError:
    pyfiglet = None

try:
    from notifypy import Notify as DesktopNotify
except ImportError:
    DesktopNotify = None

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# STYLE CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
S_GREEN = "bold bright_green"
S_RED = "bold red"
S_CYAN = "bold cyan"
S_WHITE = "bold white"
S_DIM = "dim"
S_YELLOW = "bold yellow"

SEV_MAP = {
    "CRITICO": (S_RED, "💀"),
    "ALTO":    ("red", "🔴"),
    "MEDIO":   ("yellow", "🟡"),
    "BAIXO":   ("cyan", "🔵"),
    "INFO":    (S_DIM, "⚪"),
}

# ═══════════════════════════════════════════════════════════════════════════════
# 🧠 SECURITY INTEL — RETENÇÃO DE ATENÇÃO
# ═══════════════════════════════════════════════════════════════════════════════
SECURITY_INTEL = [
    ("💀 FACT", "O ransomware Ryuk causou $61M em danos só em 2019."),
    ("🔐 TIP", "Sempre valide JWT com algoritmo fixo — nunca confie no header 'alg'."),
    ("⚡ FACT", "86% dos ataques web exploram vulnerabilidades conhecidas com patches disponíveis."),
    ("🛡️ TIP", "Use Content-Security-Policy com 'strict-dynamic' para bloquear XSS refletido."),
    ("💣 FACT", "O worm Morris de 1988 infectou 10% de toda a internet em 24 horas."),
    ("🔑 TIP", "Rate limiting por IP + account previne credential stuffing eficazmente."),
    ("🌐 FACT", "94% dos malwares são entregues via email — phishing é o vetor #1."),
    ("🧬 TIP", "Prototype Pollution em Node.js pode escalar para RCE via gadget chains."),
    ("💰 FACT", "Bug bounties já pagaram mais de $100M a pesquisadores de segurança."),
    ("🔒 TIP", "HSTS com includeSubDomains e preload fecha a janela de SSL stripping."),
    ("⚠️ FACT", "O SolarWinds hack comprometeu 18.000 organizações via supply chain."),
    ("🧪 TIP", "Teste SSRF com DNS rebinding — TTL=0 bypass firewalls internos."),
    ("📡 FACT", "Shodan indexa 7+ bilhões de dispositivos conectados à internet."),
    ("🔓 TIP", "Ataques de desserialização Java podem ser prevenidos com SerialKiller."),
    ("🕷️ FACT", "O Stuxnet usou 4 zero-days diferentes para sabotar centrífugas iranianas."),
    ("🛡️ TIP", "HTTP/2 Rapid Reset (CVE-2023-44487) afeta 62% dos servidores web."),
    ("💀 FACT", "Hackers conseguem comprometer 93% das redes corporativas em 2 dias."),
    ("🔐 TIP", "Use SameSite=Lax ou Strict em cookies para prevenir CSRF."),
    ("⚡ FACT", "O Log4Shell (CVE-2021-44228) teve 10M+ tentativas de exploit por hora."),
    ("🧬 TIP", "Race conditions: use single-packet attack para bypass de rate limiting."),
    ("🌐 FACT", "DNS cache poisoning afeta ~30% dos resolvers públicos abertos."),
    ("💣 TIP", "GraphQL batching pode ser usado para brute force em queries autenticadas."),
    ("🔑 FACT", "68% das empresas não detectam breaches por mais de 200 dias."),
    ("🛡️ TIP", "Kubernetes RBAC com least-privilege previne lateral movement."),
    ("💰 FACT", "O custo médio de um data breach em 2024 é $4.88 milhões."),
    ("🔒 TIP", "Terraform state files podem conter passwords — use remote encrypted backend."),
    ("⚠️ FACT", "APIs são o vetor de ataque #1 em apps modernas (OWASP API Top 10)."),
    ("🧪 TIP", "Mass assignment: teste campos como 'role', 'isAdmin', 'verified'."),
    ("📡 FACT", "O NotPetya causou $10 bilhões em danos — o ciberataque mais caro da história."),
    ("🔓 TIP", "IMDSv2 no AWS previne SSRF para roubo de credenciais EC2."),
    ("🕷️ FACT", "Zero-days em iOS valem até $2M no mercado de exploits."),
    ("🛡️ TIP", "Redis sem auth = RCE via CONFIG SET + crontab/SSH key injection."),
    ("💀 FACT", "A Coreia do Norte roubou $1.7 bilhões em crypto via hacking em 2022."),
    ("🔐 TIP", "SAML XML Signature Wrapping permite bypass de autenticação."),
    ("⚡ FACT", "O MOVEit exploit (2023) comprometeu 2.600+ organizações de uma vez."),
    ("🧬 TIP", "CRLF injection pode envenenar caches HTTP e roubar sessões."),
    ("🌐 FACT", "95% dos incidentes de segurança em cloud são causados por misconfiguration."),
    ("💣 TIP", "Git exposed (.git/config) pode revelar remote URLs com tokens embutidos."),
    ("🔑 FACT", "O worm WannaCry se espalhou para 230.000 máquinas em 150 países em 1 dia."),
    ("🛡️ TIP", "Docker com --privileged + docker.sock mount = container escape trivial."),
]

# ═══════════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════════
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
EXPORTS_PATH = os.path.join(BASE_PATH, "exports")
REPORTS_PATH = os.path.join(BASE_PATH, "reports")
PLUGINS_PATH = os.path.join(BASE_PATH, "plugins")
WORDLISTS_PATH = os.path.join(BASE_PATH, "wordlists")
NUCLEI_TEMPLATES_PATH = os.path.join(BASE_PATH, "nuclei-templates")

for _p in [EXPORTS_PATH, REPORTS_PATH, PLUGINS_PATH, WORDLISTS_PATH, NUCLEI_TEMPLATES_PATH]:
    os.makedirs(_p, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 🎬 PRELOADER CINEMATOGRÁFICO — AWWWARDS EDITION
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

BOOT_SEQUENCE = [
    ("SYS", f"Iniciando CASCAVEL Quantum Security Framework v{__version__}"),
    ("CPU", "Detectando plataforma: {platform}"),
    ("MEM", "Python runtime: {python}"),
    ("NET", "Verificando conectividade de rede..."),
    ("SEC", "Carregando motor de plugins..."),
    ("PLG", "Plugins detectados: {plugins}"),
    ("ARM", "Inicializando arsenal de ferramentas..."),
    ("FWT", "Ferramentas externas: {tools_count}"),
    ("RDY", "Sistema operacional. Pronto para combate."),
]


def _typewriter(text: str, speed: float = 0.02) -> None:
    """Efeito typewriter cinematográfico. Fallback direto se não for TTY."""
    if not IS_TTY:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)


def _boot_line(tag: str, msg: str, delay: float = 0.08) -> None:
    """Linha de boot estilo sistema militar."""
    ts_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    console.print(
        f"  [dim]{ts_str}[/] [bold green][{tag}][/] ",
        end="",
    )
    _typewriter(msg, speed=delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _fade_in_logo() -> None:
    """Fade-in da logo: cobra slide-up + CASCAVEL text opacity transition."""
    if not IS_TTY:
        # Fallback sem animação
        for line in COBRA_ART:
            console.print(f"[green]{line}[/]")
        for line in CASCAVEL_LOGO_ASCII:
            console.print(f"[bold bright_green]{line}[/]")
        return

    # Phase 1: Cobra art — cada linha aparece com cor progressiva (escuro → verde)
    for i, line in enumerate(COBRA_ART):
        brightness = int(22 + (i / max(len(COBRA_ART) - 1, 1)) * 10)  # 22-32
        color = f"\033[38;5;{brightness}m"
        sys.stdout.write(f"{color}{line}\033[0m\n")
        sys.stdout.flush()
        time.sleep(0.05)

    time.sleep(0.2)

    # Phase 2: Logo text — 4 estágios de fade (dim gray → dim green → green → bold green)
    fade_codes = [
        "\033[2;90m",   # dim gray
        "\033[0;90m",   # gray
        "\033[0;32m",   # green
        "\033[1;32m",   # bold green
        "\033[1;92m",   # bold bright green
    ]

    logo_count = len(CASCAVEL_LOGO_ASCII)

    for stage_idx, ansi in enumerate(fade_codes):
        if stage_idx > 0:
            sys.stdout.write(f"\033[{logo_count}A")  # Move up

        for line in CASCAVEL_LOGO_ASCII:
            sys.stdout.write(f"  {ansi}{line}\033[0m\n")
        sys.stdout.flush()
        time.sleep(0.12)

    # Phase 3: Subtitle materializa com typewriter
    time.sleep(0.3)
    subtitle = f"  Quantum Security Framework v{__version__} — Red Team Intelligence"
    console.print()
    console.print(f"  [bold bright_cyan]{subtitle}[/]")
    time.sleep(0.5)


def _clear_block(num_lines: int) -> None:
    """Limpa um bloco de linhas acima do cursor."""
    if not IS_TTY:
        return
    sys.stdout.write(f"\033[{num_lines}A")
    for _ in range(num_lines):
        sys.stdout.write("\033[2K\n")
    sys.stdout.write(f"\033[{num_lines}A")
    sys.stdout.flush()


def run_preloader(plugin_count: int, tools_count: int) -> None:
    """Preloader cinematográfico Awwwards-level com logo fade."""
    os_name = f"{platform.system()} {platform.release()}"
    py_ver = f"{sys.version.split()[0]}"

    console.print()

    # === PHASE 1: Logo Fade-In ===
    _fade_in_logo()
    time.sleep(0.6)

    # === PHASE 2: Fade-Out (limpa para boot) ===
    total_logo_lines = len(COBRA_ART) + len(CASCAVEL_LOGO_ASCII) + 3  # +3 spacing/subtitle
    _clear_block(total_logo_lines)

    # === PHASE 3: Boot Sequence ===
    console.print(Panel(
        "[bold green]▶ SYSTEM BOOT SEQUENCE[/]",
        border_style="green",
        box=box.HEAVY,
        width=60,
    ))
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
        time.sleep(random.uniform(0.05, 0.15))

    console.print()

    # === PHASE 4: Loading bar ===
    with Progress(
        SpinnerColumn("dots2"),
        TextColumn("[bold green]Armando sistema...[/]"),
        BarColumn(bar_width=40, complete_style="bright_green"),
        TextColumn("[bold]{task.percentage:>3.0f}%[/]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("boot", total=100)
        for _ in range(100):
            progress.advance(task)
            time.sleep(0.01)

    console.print(f"  [bold bright_green]✓ CASCAVEL v{__version__} — ONLINE[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# 🐍 BANNER PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

SNAKE_ART = r"""[green]
                    ___
                 .~))>>
                .~)>>
              .~))))>>>
            .~))>>              [bold bright_green]Quantum Security Framework[/]
          .~))>>)>              [bold bright_green]v{ver} — {plugins} plugins[/]
        .~))>>
      .~))>>
    .~))>>
  .~)>>                        [bold yellow]⚡ github.com/glferreira-devsecops[/]
 .~)>>[/]"""


def _count_plugins() -> int:
    return sum(
        1 for f in glob.glob(os.path.join(PLUGINS_PATH, "*.py"))
        if not os.path.basename(f).startswith("__")
    )


def print_header() -> None:
    """Banner CASCAVEL em pyfiglet + cobra + info card."""
    console.print()

    if pyfiglet:
        figlet_text = pyfiglet.figlet_format("CASCAVEL", font="ansi_shadow")
        styled = Text(figlet_text)
        styled.stylize(S_GREEN)
        console.print(Align.center(styled))
    else:
        fallback = Text("  ██████╗  █████╗ ███████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗\n"
                        " ██╔════╝ ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔════╝██║\n"
                        " ██║      ███████║███████╗██║      ███████║██║   ██║█████╗  ██║\n"
                        " ██║      ██╔══██║╚════██║██║      ██╔══██║╚██╗ ██╔╝██╔══╝  ██║\n"
                        " ╚██████╗ ██║  ██║███████║╚██████╗ ██║  ██║ ╚████╔╝ ███████╗███████╗\n"
                        "  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝\n")
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
        "🕐 Timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "💻 Plataforma", f"{sys.platform} | Python {sys.version.split()[0]}",
    )
    info_table.add_row("👤 Autor", "DevFerreiraG", "📦 Versão", f"v{__version__}")

    console.print(Panel(
        Align.center(info_table),
        border_style="bright_green",
        title=f"[{S_GREEN}]🐍 CASCAVEL[/]",
        subtitle="[dim]Quantum Security Framework[/]",
        box=box.DOUBLE_EDGE,
    ))
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# TARGET CARD
# ═══════════════════════════════════════════════════════════════════════════════
def print_target_card(target: str, ip: str) -> None:
    grid = Table(show_header=False, box=None, padding=(0, 3))
    grid.add_column(style=S_WHITE, width=12)
    grid.add_column(style="bold bright_cyan", min_width=30)
    grid.add_row("🎯 Target", target)
    grid.add_row("📡 IP", ip)
    grid.add_row("🕐 Início", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    grid.add_row("🐍 Versão", f"v{__version__}")

    console.print(Panel(
        Align.center(grid),
        title=f"[{S_RED}]⚡ TARGET ACQUISITION ⚡[/]",
        border_style="red",
        box=box.HEAVY,
    ))
    console.print()


def print_tools_status(tools: Dict[str, bool]) -> None:
    present = sorted(t for t, v in tools.items() if v)
    absent = sorted(t for t, v in tools.items() if not v)

    items = []
    for t in present:
        items.append(Text(f" ● {t} ", style="green"))
    for t in absent:
        items.append(Text(f" ○ {t} ", style="dim red"))

    console.print(Panel(
        Columns(items, column_first=True, expand=True, padding=(0, 1)),
        title=f"[{S_CYAN}]🔧 FERRAMENTAS EXTERNAS ({len(present)}/{len(tools)})[/]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════════
def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_target(target: str, allow_self: bool = False) -> str:
    """Valida e normaliza o target. Bloqueia localhost/IPs privados por padrão.

    SEGURANÇA 2026: Uma ferramenta pentest que aceita localhost como alvo pode
    ser usada para atacar o próprio host (SSRF self-attack, cloud metadata leak).
    Use --allow-localhost para sobrescrever (red-teaming consentido).
    """
    target = target.strip()
    if not target:
        console.print(f"  [{S_RED}]\u2717 Target vazio. Abortando.[/]")
        sys.exit(1)

    # Strip protocol (http:// https://)
    for prefix in ("https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]

    # Strip trailing slashes and paths
    target = target.split("/")[0]

    # Strip trailing whitespace (again after manipulations)
    target = target.strip()

    # Allow domains, IPs, and targets with port (host:port)
    if not re.match(r'^[a-zA-Z0-9._\-]+(:\d{1,5})?$', target):
        console.print(f"  [{S_RED}]\u2717 Target inv\u00e1lido: {target}[/]")
        console.print(f"  [{S_DIM}]Formatos aceitos: dominio.com | 1.2.3.4 | host:porta[/]")
        sys.exit(1)

    # SEGURANÇA: Bloqueia localhost / IPs privados / cloud metadata
    if not allow_self:
        host_part = target.split(":")[0] if ":" in target else target
        _BLOCKED_HOSTS = {
            "localhost", "127.0.0.1", "0.0.0.0", "::1", "0177.0.0.1",
            "169.254.169.254",  # AWS/GCP/Azure cloud metadata
            "metadata.google.internal", "metadata.google.com",
        }
        _PRIVATE_PREFIXES = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "169.254.",
            "0000:", "fe80:", "::ffff:127.",
        )
        if host_part.lower() in _BLOCKED_HOSTS or host_part.startswith(_PRIVATE_PREFIXES):
            console.print(f"  [{S_RED}]\u2717 Target bloqueado: {host_part}[/]")
            console.print(f"  [{S_DIM}]Localhost/IPs privados s\u00e3o bloqueados por seguran\u00e7a.[/]")
            console.print(f"  [{S_DIM}]Use --allow-localhost para sobrescrever.[/]")
            sys.exit(1)

    return target


def inputx(prompt: str) -> str:
    try:
        return console.input(f"  [{S_CYAN}]❯ {prompt}[/]")
    except KeyboardInterrupt:
        console.print(f"\n  [{S_RED}]✗ Interrompido pelo usuário.[/]\n")
        sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
# FERRAMENTAS & INFRA
# ═══════════════════════════════════════════════════════════════════════════════
def detect_tools() -> Dict[str, bool]:
    tools = [
        "subfinder", "amass", "httpx", "nmap", "ffuf", "gobuster",
        "naabu", "nuclei", "feroxbuster", "curl", "nikto", "sqlmap",
        "wafw00f", "dnsrecon", "fierce", "hydra", "gau", "waybackurls",
        "katana", "dnsx", "asnmap", "mapcidr", "tshark", "sslscan",
        "whatweb", "wpscan", "john", "whois", "traceroute", "dig",
    ]
    return {tool: shutil.which(tool) is not None for tool in tools}


def get_wordlist(name: str = "common.txt") -> str:
    possible = [
        os.path.join(WORDLISTS_PATH, name),
        os.path.join(WORDLISTS_PATH, "dirb_common.txt"),
        os.path.join(WORDLISTS_PATH, "dirbuster.txt"),
    ]
    for p in possible:
        if os.path.isfile(p):
            return p
    url = f"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/{name}"
    dest = os.path.join(WORDLISTS_PATH, name)
    try:
        console.print(f"  [{S_YELLOW}]⬇ Baixando wordlist {name}...[/]")
        urllib.request.urlretrieve(url, dest)
        console.print(f"  [{S_GREEN}]✓ Wordlist: {dest}[/]")
        return dest
    except Exception as e:
        console.print(f"  [{S_RED}]✗ Erro wordlist: {e}[/]")
        return ""


def ensure_nuclei_templates() -> str:
    """Garante templates nuclei atualizados. Avisa sobre vers\u00f5es vulner\u00e1veis (CVE-2024-43405)."""
    if not shutil.which("nuclei"):
        return ""
    # CVE-2024-43405: nuclei < 3.3.2 tem template signature bypass (RCE)
    try:
        ver_out = subprocess.run(
            ["nuclei", "-version"], capture_output=True, text=True, timeout=10,
        )
        ver_str = (ver_out.stdout + ver_out.stderr).strip()
        if ver_str:
            # Parse version number
            ver_match = re.search(r'(\d+\.\d+\.\d+)', ver_str)
            if ver_match:
                parts = ver_match.group(1).split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                if (major, minor, patch) < (3, 3, 2):
                    console.print(
                        f"  [{S_YELLOW}]\u26a0 Nuclei {ver_match.group(1)} detect\u00e1vel \u2014 "
                        f"CVE-2024-43405 (template RCE). Atualize para \u2265 3.3.2![/]"
                    )
    except Exception:
        pass
    if not os.path.isdir(NUCLEI_TEMPLATES_PATH) or not os.listdir(NUCLEI_TEMPLATES_PATH):
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-ut", NUCLEI_TEMPLATES_PATH],
                check=True, timeout=120,
            )
        except Exception:
            return ""
    return NUCLEI_TEMPLATES_PATH


def detect_ip(target: str) -> str:
    """Resolve target IP with timeout and IPv6 fallback."""
    # Strip port if present (host:port → host)
    host = target.split(":")[0] if ":" in target else target
    try:
        # Use getaddrinfo for IPv4/IPv6 support with implicit timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)  # 5s DNS resolution timeout
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addrs:
                # Prefer IPv4 for display, fallback to IPv6
                ipv4 = [a[4][0] for a in addrs if a[0] == socket.AF_INET]
                ipv6 = [a[4][0] for a in addrs if a[0] == socket.AF_INET6]
                return ipv4[0] if ipv4 else (ipv6[0] if ipv6 else "N/A")
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return "N/A"


def run_cmd(cmd: str, timeout: int = 90) -> str:
    """Executa comando shell com process group kill on timeout.

    NOTA DE SEGURANÇA: shell=True é necessário porque o pipeline de ferramentas
    externas usa pipes (echo target | httpx). Todos os targets são pré-sanitizados
    com shlex.quote() em enum_tools(). O risco de injection é mitigado.
    """
    proc = None
    try:
        # start_new_session=True cria process group para matar filhos no timeout
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        # Decode com fallback para caracteres inválidos
        out = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
        return out + err
    except subprocess.TimeoutExpired:
        # Kill entire process group (não deixa zombies)
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        return f"[!] TIMEOUT ({timeout}s)"
    except FileNotFoundError:
        return "[!] Comando não encontrado"
    except PermissionError:
        return "[!] Sem permissão para executar"
    except OSError as e:
        return f"[!] ERRO OS: {e}"
    except Exception as e:
        return f"[!] ERRO: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE FERRAMENTAS EXTERNAS
# ═══════════════════════════════════════════════════════════════════════════════
def enum_tools(
    target: str, report: List[str],
    wordlist: str, nuclei_templates: str,
    timeouts: Dict[str, int], available: Dict[str, bool],
) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    safe = shlex.quote(target)
    tools = {
        "whois": f"whois {safe}",
        "subfinder": f"subfinder -silent -d {safe}",
        "amass": f"amass enum -d {safe} -timeout 2",
        "httpx": f"echo {safe} | httpx -silent -title -tech-detect -ip",
        "nmap": f"nmap -Pn -A {safe}",
        "ffuf": (f"ffuf -u http://{safe}/FUZZ -w {wordlist} "
                 "-mc 200,204,301,302,307,401,403 -t 40") if wordlist else "",
        "gobuster": f"gobuster dir -u http://{safe} -w {wordlist} -q" if wordlist else "",
        "naabu": f"echo {safe} | naabu -silent",
        "nuclei": f"echo {safe} | nuclei -silent -t {nuclei_templates}" if nuclei_templates else "",
        "curl": f"curl -sI http://{safe}",
        "katana": f"echo http://{safe} | katana -silent -d 2 -jc -ct 30",
        "gau": f"echo {safe} | gau --threads 3 --blacklist png,jpg,gif,css,woff",
        "dnsx": f"echo {safe} | dnsx -silent -a -aaaa -mx -ns -cname -resp",
        "nikto": f"nikto -h http://{safe} -maxtime 60s -nointeractive",
        "wafw00f": f"wafw00f {safe}",
        "dig": f"dig {safe} ANY +short",
        "traceroute": f"traceroute -m 15 -w 2 {safe}",
    }
    active = {k: v for k, v in tools.items() if v and available.get(k, False)}

    console.print(Rule(f"[{S_YELLOW}]⚡ EXTERNAL TOOLS PIPELINE[/]", style="yellow"))
    console.print()

    with Progress(
        SpinnerColumn("dots2"),
        TextColumn(f"[{S_CYAN}]" + "{task.fields[tool_name]}" + "[/]"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bright_green"),
        TextColumn(f"[{S_WHITE}]" + "{task.percentage:>3.0f}%" + "[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        overall = progress.add_task("Pipeline", total=len(active), tool_name="Inicializando...")
        for name, cmd in active.items():
            progress.update(overall, tool_name=name)
            t0 = time.time()
            out = run_cmd(cmd, timeout=timeouts.get(name, 90))
            elapsed = time.time() - t0
            results[name] = out
            report.append(f"\n### {name}\n```\n{out[:5000]}\n```")
            progress.advance(overall)
            console.print(f"    [green]✓[/] {name} [{S_DIM}]({elapsed:.1f}s)[/]")

    console.print()
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN DE PORTAS
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_port(line: str) -> Optional[int]:
    raw = line.strip().split(":")[-1] if ":" in line.strip() else line.strip()
    try:
        port = int(raw)
        return port if 0 < port < 65536 else None
    except ValueError:
        return None


def scan_ports(naabu_out: str) -> List[int]:
    ports = []
    for line in naabu_out.splitlines():
        port = _parse_port(line)
        if port is not None:
            ports.append(port)
    return sorted(set(ports))


def grab_banners(target: str, ports: List[int], timeout: int = 3) -> Dict[int, str]:
    """Grab banners dos primeiros 20 ports abertos com recv loop."""
    banners: Dict[int, str] = {}
    # Strip port from target if present (host:port -> host)
    host = target.split(":")[0] if ":" in target else target
    for port in ports[:20]:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            # TCP é stream: recv pode retornar dados parciais (partial read)
            chunks = []
            total = 0
            while total < 1024:  # Max 1KB banner
                try:
                    chunk = s.recv(512)
                    if not chunk:  # Conexão fechada pelo servidor
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                except (socket.timeout, OSError):
                    break
            banners[port] = b"".join(chunks).decode(errors="ignore").strip()[:512]
        except (socket.timeout, ConnectionRefusedError, OSError):
            banners[port] = "N/A"
        except Exception:
            banners[port] = "N/A"
        finally:
            if s:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
    return banners


# ═══════════════════════════════════════════════════════════════════════════════
# 🔌 PLUGIN ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
def _exec_plugin(
    path: str, name: str,
    target: str, ip: str, ports: List[int], banners: Dict[int, str],
    timeout: int = 120,
) -> Dict[str, Any]:
    """Executa um plugin com timeout guard (SIGALRM, 120s padrão).

    SEGURANÇA 2026: Plugins maliciosos ou bugados podem travar indefinidamente.
    O alarm garante que o framework não fica preso em nenhum plugin individual.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return {"plugin": name, "erro": "Módulo não resolvido"}

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if not hasattr(mod, "run"):
        return {"plugin": name, "erro": "Sem função run()"}

    # Per-plugin timeout via SIGALRM (Unix only)
    _has_alarm = hasattr(signal, "SIGALRM")

    class _PluginTimeout(Exception):
        pass

    def _alarm_handler(signum, frame):
        raise _PluginTimeout(f"Plugin '{name}' excedeu timeout de {timeout}s")

    old_handler = None
    if _has_alarm:
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(timeout)

    try:
        result = mod.run(target, ip, ports, banners)
        return result if result else {"plugin": name, "resultados": "Sem retorno"}
    except _PluginTimeout:
        return {"plugin": name, "erro": f"TIMEOUT ({timeout}s)"}
    except TypeError as e:
        return {"plugin": name, "erro": f"Assinatura: {e}"}
    except Exception as e:
        return {"plugin": name, "erro": str(e)}
    finally:
        if _has_alarm:
            signal.alarm(0)  # Cancel pending alarm
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


def _classify(result: Dict[str, Any]) -> tuple:
    """Classifica resultado de plugin como vuln, erro, deprecated ou limpo."""
    if "erro" in result:
        return "erro", S_RED, "✗"
    resultados = result.get("resultados", "")
    # String results
    if isinstance(resultados, str):
        return "limpo", "green", "✓"
    # Dict results
    if isinstance(resultados, dict):
        # Skip deprecated plugins in vuln counting
        status = resultados.get("status", "")
        if status == "DEPRECATED":
            return "limpo", S_DIM, "○"
        aviso = resultados.get("aviso", "")
        if "DEPRECATED" in str(aviso).upper():
            return "limpo", S_DIM, "○"
        if status == "vulneravel" or resultados.get("vulns"):
            return "vuln", S_RED, "⚠"
        return "limpo", "green", "✓"
    # List results (non-empty = vulns)
    if isinstance(resultados, list) and resultados:
        return "vuln", S_RED, "⚠"
    return "limpo", "green", "✓"


def _count_sev(resultados: Any) -> Dict[str, int]:
    counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
    vulns: list = []
    if isinstance(resultados, list):
        vulns = resultados
    elif isinstance(resultados, dict):
        vulns = resultados.get("vulns", resultados.get("forms_sem_csrf", []))
    for v in vulns:
        if isinstance(v, dict):
            sev = v.get("severidade", "INFO")
            if sev in counts:
                counts[sev] += 1
    return counts


def _build_intel_panel(intel_idx: int, scan_stats: Dict[str, int], elapsed: float) -> Panel:
    """Constrói painel lateral de Security Intel para retenção de atenção."""
    # Current intel tip
    tag, tip = SECURITY_INTEL[intel_idx % len(SECURITY_INTEL)]
    intel_text = Text()
    intel_text.append(f"\n  {tag}\n", style="bold bright_yellow")
    intel_text.append(f"  {tip}\n\n", style="white")

    # Live stats
    stats = Table(show_header=False, box=None, padding=(0, 1))
    stats.add_column(style=S_DIM, width=12)
    stats.add_column(style=S_WHITE, min_width=8)
    stats.add_row("⏱️  Tempo", f"{elapsed:.0f}s")
    stats.add_row("✓ Limpos", f"[green]{scan_stats.get('ok', 0)}[/]")
    stats.add_row("⚠ Vulns", f"[{S_RED}]{scan_stats.get('vuln', 0)}[/]")
    stats.add_row("✗ Erros", f"[red]{scan_stats.get('err', 0)}[/]")
    stats.add_row("💀 Críticos", f"[{S_RED}]{scan_stats.get('CRITICO', 0)}[/]")
    stats.add_row("🔴 Altos", f"[red]{scan_stats.get('ALTO', 0)}[/]")
    stats.add_row("🟡 Médios", f"[yellow]{scan_stats.get('MEDIO', 0)}[/]")

    # Next intel preview
    next_tag, next_tip = SECURITY_INTEL[(intel_idx + 1) % len(SECURITY_INTEL)]
    next_text = Text()
    next_text.append(f"\n  NEXT: {next_tag}\n", style="dim bright_cyan")
    next_text.append(f"  {next_tip[:60]}...\n", style="dim")

    from rich.console import Group
    content = Group(
        Panel(intel_text, border_style="bright_yellow", title="[bold yellow]🧠 SECURITY INTEL[/]", box=box.ROUNDED),
        Panel(stats, border_style="bright_green", title="[bold green]📊 LIVE STATS[/]", box=box.ROUNDED),
        Panel(next_text, border_style="dim cyan", title="[dim]PRÓXIMO[/]", box=box.SIMPLE),
    )
    return Panel(content, border_style="bright_cyan", title=f"[{S_CYAN}]🐍 CASCAVEL INTEL[/]", box=box.DOUBLE_EDGE)


def run_plugins(
    target: str, ip: str, ports: List[int],
    banners: Dict[int, str], report: List[str],
) -> List[Dict[str, Any]]:
    """Executa todos os plugins com split-screen: scan table + security intel."""
    results: List[Dict[str, Any]] = []
    plugin_files = sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py")))
    valid = [
        (f, os.path.splitext(os.path.basename(f))[0])
        for f in plugin_files
        if not os.path.basename(f).startswith("__")
    ]
    total = len(valid)
    scan_stats: Dict[str, int] = {"ok": 0, "vuln": 0, "err": 0,
                                   "CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}

    console.print(Rule(f"[bold magenta]🔌 PLUGIN ENGINE — {total} PLUGINS[/]", style="magenta"))
    console.print()

    # Randomize intel order for variety
    intel_order = list(range(len(SECURITY_INTEL)))
    random.shuffle(intel_order)
    intel_idx = 0
    scan_start = time.time()

    def _build_table(
        rows: list, current_idx: int, current_name: str,
    ) -> Table:
        """Constrói a tabela de resultados que atualiza em Live."""
        pct = int((current_idx / total) * 100) if total else 100
        bar_filled = int(pct / 5)
        bar_str = f"{'█' * bar_filled}{'░' * (20 - bar_filled)} {pct}%"

        t = Table(
            title=f"[{S_GREEN}]🐍 CASCAVEL — {current_idx}/{total} [{bar_str}][/]",
            box=box.ROUNDED,
            border_style="green",
            header_style=f"{S_WHITE} on dark_green",
            expand=True,
        )
        t.add_column("#", style=S_DIM, width=4, justify="right")
        t.add_column("Plugin", style=S_CYAN, min_width=20)
        t.add_column("Status", justify="center", width=6)
        t.add_column("Resultado", min_width=20)
        t.add_column("Sev", min_width=14)
        t.add_column("⏱️", style=S_DIM, width=6, justify="right")

        # Show last 15 rows to keep it compact
        display_rows = rows[-15:] if len(rows) > 15 else rows
        if len(rows) > 15:
            t.add_row("", f"[dim]... {len(rows) - 15} anteriores ...[/]", "", "", "", "")
        for row in display_rows:
            t.add_row(*row)

        # Current plugin indicator
        if current_idx <= total:
            t.add_row(
                str(current_idx), f"[bold yellow]▶ {current_name}[/]",
                "[yellow]⋯[/]", "[yellow]Executando...[/]", "", "",
            )

        return t

    def _build_layout(rows, current_idx, current_name, intel_i):
        """Split-screen: tabela de scan + painel de intel."""
        layout = Layout()
        layout.split_row(
            Layout(name="scan", ratio=3),
            Layout(name="intel", ratio=1, minimum_size=30),
        )
        layout["scan"].update(_build_table(rows, current_idx, current_name))
        layout["intel"].update(_build_intel_panel(
            intel_order[intel_i % len(intel_order)],
            scan_stats, time.time() - scan_start,
        ))
        return layout

    table_rows: list = []

    try:
      with Live(
        _build_layout(table_rows, 1, valid[0][1] if valid else "", 0),
        console=console,
        refresh_per_second=4,
    ) as live:

        for idx, (file_path, name) in enumerate(valid, 1):
            t0 = time.time()

            try:
                result = _exec_plugin(file_path, name, target, ip, ports, banners)
            except Exception as e:
                result = {"plugin": name, "erro": f"Crash: {e}"}
            results.append(result)

            elapsed = time.time() - t0
            cls, style, icon = _classify(result)

            if cls == "erro":
                desc = f"[red]{str(result.get('erro', '?'))[:30]}[/]"
                sev_str = ""
                scan_stats["err"] += 1
            elif cls == "vuln":
                sevs = _count_sev(result.get("resultados", ""))
                parts = []
                for sn, sc in sevs.items():
                    if sc > 0:
                        si = SEV_MAP.get(sn, (S_DIM, "○"))
                        parts.append(f"[{si[0]}]{si[1]}{sc}[/]")
                        scan_stats[sn] = scan_stats.get(sn, 0) + sc
                sev_str = " ".join(parts)
                total_v = sum(sevs.values())
                desc = f"[{S_RED}]{total_v} vulns[/]"
                scan_stats["vuln"] += 1
            else:
                r = result.get("resultados", "")
                desc = f"[green]{str(r)[:30]}[/]" if isinstance(r, str) else "[green]Limpo[/]"
                sev_str = "[green]—[/]"
                scan_stats["ok"] += 1

            table_rows.append((
                str(idx), name, f"[{style}]{icon}[/]",
                desc, sev_str or "[green]—[/]", f"{elapsed:.1f}s",
            ))

            # Rotate intel every 2 plugins
            if idx % 2 == 0:
                intel_idx += 1

            next_name = valid[idx][1] if idx < total else "Concluindo..."
            live.update(_build_layout(table_rows, idx + 1, next_name, intel_idx))
    except Exception as layout_err:
        # Fallback para terminais estreitos ou sem suporte a Live Layout
        console.print(f"  [dim]Live display falhou ({layout_err}), executando sem UI...[/]")
        for idx, (file_path, name) in enumerate(valid, 1):
            try:
                result = _exec_plugin(file_path, name, target, ip, ports, banners)
            except Exception as e:
                result = {"plugin": name, "erro": f"Crash: {e}"}
            results.append(result)
            cls, style, icon = _classify(result)
            console.print(f"  [{style}]{icon}[/] {name}")

    console.print()

    if results:
        report.append("\n## 🔌 Plugins\n")
        for r in results:
            content = json.dumps(r, indent=2, ensure_ascii=False)
            report.append(f"### {r.get('plugin', '?')}\n```json\n{content}\n```")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 📊 DASHBOARD FINAL
# ═══════════════════════════════════════════════════════════════════════════════
def print_dashboard(
    target: str, ip: str, results: List[Dict[str, Any]],
    elapsed_total: float, report_path: str,
) -> None:
    console.print(Rule(f"[{S_GREEN}]📊 MISSION REPORT[/]", style="bright_green"))
    console.print()

    total_ok = total_vuln = total_err = 0
    agg = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}

    for r in results:
        cls, _, _ = _classify(r)
        if cls == "erro":
            total_err += 1
        elif cls == "vuln":
            total_vuln += 1
            for k, v in _count_sev(r.get("resultados", "")).items():
                agg[k] += v
        else:
            total_ok += 1

    total_findings = sum(agg.values())

    # Info card
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

    # Severity table
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

    max_c = max(agg.values()) if any(agg.values()) else 1
    for sev, count in agg.items():
        sty, icon = SEV_MAP.get(sev, (S_DIM, "○"))
        bar_len = int((count / max_c) * 25) if count > 0 else 0
        bar = f"[{sty}]{'█' * bar_len}{'░' * (25 - bar_len)}[/]"
        sev_table.add_row(f"[{sty}]{icon} {sev}[/]", f"[{sty}]{count}[/]", bar)

    console.print(sev_table)
    console.print()

    # Summary
    parts = [
        f"[green]✓ Limpos: {total_ok}[/]",
        f"[{S_RED}]⚠ Vulns: {total_vuln}[/]",
        f"[red]✗ Erros: {total_err}[/]",
        f"[{S_WHITE}]Findings: {total_findings}[/]",
    ]
    console.print(Panel(
        Align.center(Text.from_markup("  │  ".join(parts))),
        border_style="cyan", box=box.ROUNDED,
    ))
    console.print()

    # Risk level
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
# 🔔 NOTIFICAÇÃO NATIVA
# ═══════════════════════════════════════════════════════════════════════════════
def send_notification(target: str, report_path: str, findings: int) -> None:
    """Envia notificação nativa do sistema (macOS/Linux)."""
    title = "🐍 CASCAVEL — Scan Concluído"
    message = f"Target: {target}\nFindings: {findings}\nRelatório: {os.path.basename(report_path)}"

    if DesktopNotify:
        try:
            n = DesktopNotify()
            n.title = title
            n.message = message
            n.send()
            return
        except Exception:
            pass

    # Fallback: osascript (macOS) / notify-send (Linux)
    if sys.platform == "darwin":
        try:
            # Sanitize strings for osascript
            safe_msg = message.replace('"', '\\"').replace("'", "\\'")
            safe_title = title.replace('"', '\\"').replace("'", "\\'")
            script = f'display notification "{safe_msg}" with title "{safe_title}"'
            subprocess.run(["osascript", "-e", script], timeout=5)
        except Exception:
            pass
    elif shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", title, message], timeout=5)
        except Exception:
            pass


def open_folder(path: str) -> None:
    """Abre pasta no file manager nativo. Silencia output."""
    folder = os.path.dirname(os.path.abspath(path))
    try:
        devnull = subprocess.DEVNULL
        if sys.platform == "darwin":
            subprocess.Popen(["open", folder], stdout=devnull, stderr=devnull)
        elif sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", folder], stdout=devnull, stderr=devnull)
        elif sys.platform == "win32":
            subprocess.Popen(["explorer", folder], stdout=devnull, stderr=devnull)
        else:
            console.print(f"  [{S_DIM}]Plataforma não suportada para abrir pasta.[/]")
    except Exception:
        console.print(f"  [{S_DIM}]Não foi possível abrir a pasta.[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# 📋 MENU PÓS-SCAN
# ═══════════════════════════════════════════════════════════════════════════════
def post_scan_menu(report_path: str) -> None:
    """Menu interativo pós-scan."""
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

    choice = inputx("Opção [0-3]: ").strip()

    if choice == "1":
        open_folder(report_path)
        console.print(f"  [{S_GREEN}]✓ Pasta aberta no file manager.[/]\n")
    elif choice == "2":
        new_target = inputx("Novo target (IP/domain): ")
        new_target = validate_target(new_target)
        run_scan(new_target)
    elif choice == "3":
        list_plugins_table()
    else:
        console.print(f"\n  [{S_GREEN}]🐍 Até a próxima missão.[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# FEROXBUSTER
# ═══════════════════════════════════════════════════════════════════════════════
def run_feroxbuster(target: str, wordlist: str, available: Dict[str, bool]) -> List[Dict[str, Any]]:
    if not available.get("feroxbuster") or not wordlist:
        return [{"aviso": "feroxbuster/wordlist não disponível"}]

    output_path = os.path.join(EXPORTS_PATH, f"ferox_{target.replace('.', '_')}.json")
    safe = shlex.quote(target)
    safe_wl = shlex.quote(wordlist)
    cmd = f"feroxbuster --url http://{safe} --wordlist {safe_wl} --json --silent --output {output_path}"
    console.print(f"  [{S_YELLOW}]⚡ feroxbuster...[/]")
    run_cmd(cmd, timeout=90)
    if os.path.isfile(output_path):
        try:
            with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                return [json.loads(l) for l in f if l.strip()]
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [{"error": "Erro ao parsear saída do feroxbuster"}]
    return [{"error": "Sem saída"}]


# ═══════════════════════════════════════════════════════════════════════════════
# RELATÓRIO
# ═══════════════════════════════════════════════════════════════════════════════
def save_report(content: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(REPORTS_PATH, f"cascavel_{ts}.md")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    return filename


def _sanitize_for_json(obj: Any) -> Any:
    """Sanitiza strings com surrogates inválidos antes de json.dumps.

    json.dumps(ensure_ascii=False) pode crashar com UnicodeEncodeError se
    strings contêm surrogate pairs órfãos (ex: output binário decodado).
    """
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(obj, dict):
        return {_sanitize_for_json(k): _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(i) for i in obj]
    return obj


def save_json_report(
    target: str, ip: str, plugin_results: List[Dict[str, Any]],
    elapsed: float,
) -> str:
    """Salva relatório em formato JSON estruturado com proteção contra surrogates."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(REPORTS_PATH, f"cascavel_{ts}.json")

    agg = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
    for r in plugin_results:
        cls, _, _ = _classify(r)
        if cls == "vuln":
            for k, v in _count_sev(r.get("resultados", "")).items():
                agg[k] += v

    report_obj = {
        "framework": "Cascavel",
        "version": __version__,
        "target": target,
        "ip": ip,
        "timestamp": timestamp(),
        "elapsed_seconds": round(elapsed, 2),
        "severity_counts": agg,
        "total_findings": sum(agg.values()),
        "plugins_executed": len(plugin_results),
        "results": _sanitize_for_json(plugin_results),
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2, ensure_ascii=False)
    return filename


# ═══════════════════════════════════════════════════════════════════════════════
# LIST PLUGINS
# ═══════════════════════════════════════════════════════════════════════════════
def list_plugins_table() -> None:
    table = Table(
        title=f"[{S_GREEN}]🐍 CASCAVEL — ARSENAL[/]",
        box=box.DOUBLE_EDGE,
        border_style="green",
        header_style=f"{S_WHITE} on dark_green",
        show_lines=True,
    )
    table.add_column("#", style=S_DIM, width=4, justify="right")
    table.add_column("Plugin", style=S_CYAN, min_width=24)
    table.add_column("Descrição", min_width=40)
    table.add_column("Status", justify="center", width=6)

    idx = 0
    for fp in sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py"))):
        name = os.path.splitext(os.path.basename(fp))[0]
        if name.startswith("__"):
            continue
        idx += 1
        try:
            spec = importlib.util.spec_from_file_location(name, fp)
            if spec is None or spec.loader is None:
                table.add_row(str(idx), name, "[red]Erro[/]", "[red]✗[/]")
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            doc = ""
            if hasattr(mod, "run") and mod.run.__doc__:
                doc = mod.run.__doc__.strip().split("\n")[0]
            table.add_row(str(idx), name, doc or "[dim]—[/]", "[green]●[/]")
        except Exception:
            table.add_row(str(idx), name, "[red]Erro[/]", "[red]✗[/]")

    console.print(table)
    console.print(f"\n  [{S_DIM}]Total: {idx} plugins[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cascavel",
        description="🐍 Cascavel — Quantum Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  cascavel -t target.com                 Full scan\n"
               "  cascavel -t target.com --plugins-only   Plugins only\n"
               "  cascavel -t target.com -q -o json       Quiet + JSON\n"
               "  cascavel --list-plugins                 Show arsenal\n"
               "  cascavel --check-tools                  Verify tools",
    )
    parser.add_argument("-t", "--target", help="Target (IP/domínio)")
    parser.add_argument("-v", "--version", action="version", version=f"v{__version__}")
    parser.add_argument("--list-plugins", action="store_true", help="Lista plugins disponíveis")
    parser.add_argument("--plugins-only", action="store_true", help="Executa apenas plugins (sem ferramentas externas)")
    parser.add_argument("--check-tools", action="store_true", help="Verifica ferramentas externas instaladas")
    parser.add_argument("--no-preloader", action="store_true", help="Desativa preloader cinematográfico")
    parser.add_argument("--no-notify", action="store_true", help="Desativa notificação nativa pós-scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso (sem preloader/banner/animações)")
    parser.add_argument("-o", "--output-format", choices=["md", "json", "pdf"], default="md",
                        help="Formato do relatório: md (padrão), json ou pdf")
    parser.add_argument("--pdf", action="store_true",
                        help="Gera relatório PDF profissional (equivalente a -o pdf)")
    def _positive_int(value: str) -> int:
        """Validação de argparse: aceita apenas inteiros positivos."""
        try:
            ivalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' não é um inteiro válido")
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f"Timeout deve ser > 0, recebido: {ivalue}")
        if ivalue > 600:
            raise argparse.ArgumentTypeError(f"Timeout máximo: 600s, recebido: {ivalue}")
        return ivalue

    parser.add_argument("--timeout", type=_positive_int, default=90,
                        help="Timeout global (1-600 segundos) para ferramentas externas (padrão: 90)")
    parser.add_argument("--allow-localhost", action="store_true",
                        help="Permite scan em localhost/IPs privados (red-teaming consentido)")
    return parser


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════
def run_scan(
    target: str, plugins_only: bool = False, no_notify: bool = False,
    output_format: str = "md", global_timeout: int = 90,
) -> None:
    """Executa o scan completo contra o target."""
    mission_start = time.time()

    with console.status(f"[{S_GREEN}]🐍 Resolvendo IP...[/]", spinner="dots"):
        ip = detect_ip(target)

    available = detect_tools()
    print_target_card(target, ip)
    print_tools_status(available)

    timeouts = {
        "subfinder": min(60, global_timeout), "amass": min(60, global_timeout),
        "httpx": min(30, global_timeout), "nmap": min(120, global_timeout),
        "ffuf": min(45, global_timeout), "gobuster": min(45, global_timeout),
        "naabu": min(30, global_timeout), "nuclei": min(90, global_timeout),
        "curl": min(10, global_timeout), "katana": min(60, global_timeout),
        "gau": min(60, global_timeout), "dnsx": min(20, global_timeout),
        "nikto": min(120, global_timeout), "wafw00f": min(20, global_timeout),
    }

    wordlist = get_wordlist()
    nuclei_templates = ensure_nuclei_templates()

    report = [
        "# 🐍 Cascavel Report\n",
        f"**Target**: `{target}`\n**IP**: `{ip}`\n**Timestamp**: `{timestamp()}`\n",
        f"**Versão**: `v{__version__}`\n",
    ]

    open_ports: List[int] = []
    banners: Dict[int, str] = {}

    if not plugins_only:
        results = enum_tools(target, report, wordlist, nuclei_templates, timeouts, available)
        ferox = run_feroxbuster(target, wordlist, available)
        report.append(f"\n### feroxbuster\n```json\n{json.dumps(ferox, indent=2, ensure_ascii=False)[:5000]}\n```")

        open_ports = scan_ports(results.get("naabu", ""))
        report.append(f"\n### Portas\n`{open_ports}`\n")

        banners = grab_banners(target, open_ports)
        report.append(f"\n### Banners\n```json\n{json.dumps(banners, indent=2, ensure_ascii=False)}\n```")
    else:
        console.print(Panel(
            f"[{S_YELLOW}]⚡ Modo --plugins-only: apenas plugins internos[/]",
            border_style="yellow", box=box.ROUNDED,
        ))
        console.print()

    # Plugins
    plugin_results = run_plugins(target, ip, open_ports, banners, report)

    # Report
    elapsed_total = time.time() - mission_start
    if output_format == "json":
        report_path = save_json_report(target, ip, plugin_results, elapsed_total)
    elif output_format == "pdf":
        try:
            from report_generator import generate_pdf_report
            pdf_vulns = []
            for r in plugin_results:
                cls, _, _ = _classify(r)
                if cls == "vuln":
                    pdf_vulns.append({
                        "plugin": r.get("plugin", "unknown"),
                        "severity": r.get("severidade", "INFO"),
                        "details": r.get("resultados", ""),
                        "remediation": r.get("correcao", ""),
                    })
            scan_data = {
                "vulns": pdf_vulns,
                "tools_count": sum(1 for v in detect_tools().values() if v),
                "plugins_count": _count_plugins(),
                "duration": elapsed_total,
            }
            report_path = generate_pdf_report(target, scan_data)
            console.print(f"  [bold bright_green]📄 PDF Report: {report_path}[/]")
        except ImportError:
            console.print(f"  [{S_YELLOW}]⚠ reportlab não instalado. Gerando MD.[/]")
            report_path = save_report("\n".join(report))
    else:
        report_path = save_report("\n".join(report))

    # Dashboard
    total_findings = sum(
        sum(_count_sev(r.get("resultados", "")).values())
        for r in plugin_results if _classify(r)[0] == "vuln"
    )
    print_dashboard(target, ip, plugin_results, elapsed_total, report_path)

    # Notificação nativa
    if not no_notify:
        send_notification(target, report_path, total_findings)

    # Menu pós-scan
    post_scan_menu(report_path)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    quiet = args.quiet
    available = detect_tools()
    plugin_count = _count_plugins()
    tools_count = sum(1 for v in available.values() if v)

    # Preloader cinematográfico
    if not quiet and not args.no_preloader and not args.list_plugins and not args.check_tools:
        run_preloader(plugin_count, tools_count)

    if not quiet:
        print_header()

    if args.check_tools:
        print_tools_status(available)
        sys.exit(0)

    if args.list_plugins:
        list_plugins_table()
        sys.exit(0)

    # Target
    allow_self = getattr(args, 'allow_localhost', False)
    target = validate_target(args.target, allow_self=allow_self) if args.target else validate_target(inputx("Target (IP/domain): "), allow_self=allow_self)

    out_fmt = "pdf" if args.pdf else args.output_format
    run_scan(
        target, plugins_only=args.plugins_only, no_notify=(args.no_notify or quiet),
        output_format=out_fmt, global_timeout=args.timeout,
    )

    # Final
    console.print(Rule(f"[{S_GREEN}]🐍 CASCAVEL — Missão Concluída[/]", style="bright_green"))
    console.print(Align.center(Text.from_markup(
        f"[{S_GREEN}]github.com/glferreira-devsecops/Cascavel[/]\n"
        f"[{S_DIM}]Making the web safer, one target at a time.[/]\n"
    )))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n  [{S_RED}]✗ Interrompido.[/]\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n  [{S_RED}]💀 ERRO FATAL: {e}[/]\n")
        sys.exit(1)
