#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Quantum Security Framework v3.0.0                ║
║  Por DevFerreiraG | github.com/glferreira-devsecops          ║
║  Framework de automação pentest plugável, multi-plataforma   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import argparse
import ast
import concurrent.futures
import datetime
import glob
import importlib.util
import ipaddress
import json
import os
import platform
import random
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import unicodedata
import urllib.request
from typing import Any, NoReturn

__version__ = "3.0.1"

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI ESCAPE SANITIZER — Anti-Terminal Injection (2026 Vector)
# ═══════════════════════════════════════════════════════════════════════════════
# Malicious plugins podem injetar CSI/OSC/DCS sequences para:
# - Reescrever conteúdo visível do terminal (cursor manipulation)
# - Exfiltrar dados via OSC copy-paste hijack
# - Executar comandos via iTerm2/Kitty OSC sequences
# Regex strips ALL non-SGR ANSI sequences, mantendo apenas cores.
_ANSI_DANGEROUS_RE = re.compile(
    r"\x1b"
    r"(?:"
    r"\].*?(?:\x07|\x1b\\)"  # OSC sequences (title change, clipboard)
    r"|P.*?\x1b\\"  # DCS sequences
    r"|\[(?:"
    r"\d*[ABCDEFGHJKST]"  # Cursor movement
    r"|\d*;?\d*[Hf]"  # Cursor positioning
    r"|[su]"  # Cursor save/restore
    r"|\?\d+[hl]"  # Private mode set/reset
    r"|\d*[JK]"  # Erase in display/line
    r")"
    r")",
    re.DOTALL,
)


def _sanitize_output(data: Any) -> Any:
    """Sanitiza saída de plugin contra ANSI escape injection.

    Remove sequências perigosas (cursor movement, OSC, DCS) mas preserva
    cores SGR básicas (\x1b[...m) para manter formatação visual.
    """
    if isinstance(data, str):
        return _ANSI_DANGEROUS_RE.sub("", data)
    if isinstance(data, dict):
        return {k: _sanitize_output(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_output(item) for item in data]
    return data


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════════════
REQUIRED_LIBS = {"rich": "rich", "requests": "requests"}
IS_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# Graceful shutdown on CTRL+C / SIGTERM
_shutdown_requested = False


def _signal_handler(sig, frame):
    """Graceful shutdown handler — signal-safe (no print/logging to avoid deadlock).

    SEGURANÇA 2026: os.write() é async-signal-safe. console.print()/logging NÃO são.
    Usar print/logging em signal handler causa deadlock por reentrância de locks internos.
    Suporta SIGINT (Ctrl+C) e SIGTERM (container/K8s graceful shutdown).
    """
    global _shutdown_requested
    _shutdown_requested = True
    sig_name = "SIGTERM" if sig == signal.SIGTERM else "SIGINT"
    exit_code = 128 + sig  # 130 para SIGINT, 143 para SIGTERM (padrão Unix)
    try:
        os.write(sys.stderr.fileno(), f"\n  \x1b[91m✗ {sig_name} recebido — encerrando...\x1b[0m\n".encode())
    except OSError:
        pass
    os._exit(exit_code)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# SIGPIPE: Previne BrokenPipeError quando saída é piped para head/less/grep.
# Python ignora SIGPIPE por padrão, causando exceções em write() para pipes fechados.
# Restaurar SIG_DFL faz o processo terminar silenciosamente como ferramentas Unix padrão.
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def _check_deps() -> None:
    missing: list[str] = []
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            missing.append(lib)
    if missing:
        print(f"\n\033[91m[✗] Faltando: {', '.join(missing)}\033[0m")
        print("\033[96mInstale: pip install -r requirements.txt\033[0m\n")
        sys.exit(1)


_check_deps()

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
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
    "ALTO": ("red", "🔴"),
    "MEDIO": ("yellow", "🟡"),
    "BAIXO": ("cyan", "🔵"),
    "INFO": (S_DIM, "⚪"),
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
    """Efeito typewriter cinematográfico.

    Fallback direto se não for TTY. Captura KeyboardInterrupt
    para não deixar texto parcial sem newline.
    """
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
        # Garante newline antes de propagar SIGINT
        sys.stdout.write("\n")
        sys.stdout.flush()
        raise


def _boot_line(tag: str, msg: str, delay: float = 0.08) -> None:
    """Linha de boot estilo sistema militar.

    Usa sys.stdout unified para evitar race condition entre
    Rich console buffer e stdout direto no typewriter.
    """
    _now = datetime.datetime.now()
    ts_str = _now.strftime("%H:%M:%S") + "." + f"{_now.microsecond // 1000:03d}"
    # Unificado: tudo via sys.stdout para evitar buffer mismatch
    sys.stdout.write(f"  \033[2m{ts_str}\033[0m \033[1;32m[{tag}]\033[0m ")
    sys.stdout.flush()
    _typewriter(msg, speed=delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _get_terminal_height() -> int:
    """Retorna altura do terminal com fallback seguro."""
    try:
        return os.get_terminal_size().lines
    except (AttributeError, ValueError, OSError):
        return 24  # Padrão POSIX


def _fade_in_logo() -> None:
    """Fade-in da logo: cobra slide-up + CASCAVEL text opacity transition.

    SEGURANÇA UX: Detecta terminal height antes de cursor manipulation
    para evitar crash em terminais pequenos ou pipes.
    """
    if not IS_TTY:
        # Fallback sem animação
        for line in COBRA_ART:
            console.print(f"[green]{line}[/]")
        for line in CASCAVEL_LOGO_ASCII:
            console.print(f"[bold bright_green]{line}[/]")
        return

    term_height = _get_terminal_height()
    logo_count = len(CASCAVEL_LOGO_ASCII)
    cobra_count = len(COBRA_ART)
    total_needed = cobra_count + logo_count + 3  # +3 spacing/subtitle

    # Se terminal é muito pequeno, pula animação de cursor movement
    use_cursor_movement = term_height >= total_needed + 4

    try:
        # Phase 1: Cobra art — cada linha com cor progressiva (verde escuro → bright green)
        # Palette 256-color: 22=darkgreen, 28, 34, 35, 40, 41, 46=bright green
        green_ramp = [22, 22, 28, 28, 34, 34, 35, 40, 41, 46, 46]
        try:
            for i, line in enumerate(COBRA_ART):
                ci = green_ramp[i] if i < len(green_ramp) else 46
                color = f"\033[38;5;{ci}m"
                sys.stdout.write(f"{color}{line}\033[0m\n")
                sys.stdout.flush()
                time.sleep(0.05)
        except KeyboardInterrupt:
            sys.stdout.write("\033[0m\n")  # Reset + newline
            sys.stdout.flush()
            raise

        time.sleep(0.2)

        # Phase 2: Logo text — 4 estágios de fade (dim gray → bold bright green)
        fade_codes = [
            "\033[2;90m",  # dim gray
            "\033[0;90m",  # gray
            "\033[0;32m",  # green
            "\033[1;32m",  # bold green
            "\033[1;92m",  # bold bright green
        ]

        for stage_idx, ansi in enumerate(fade_codes):
            if stage_idx > 0 and use_cursor_movement:
                sys.stdout.write(f"\033[{logo_count}A")  # Move up
            elif stage_idx > 0:
                # Terminal pequeno — sem cursor movement, só imprime o último
                continue

            for line in CASCAVEL_LOGO_ASCII:
                sys.stdout.write(f"  {ansi}{line}\033[0m\n")
            sys.stdout.flush()
            time.sleep(0.10)

        # Phase 3: Subtitle materializa
        time.sleep(0.2)
        subtitle = f"  Quantum Security Framework v{__version__} — Red Team Intelligence"
        console.print()
        console.print(f"  [bold bright_cyan]{subtitle}[/]")
        time.sleep(0.4)

    except OSError:
        # Fallback completo se CSI falhar (ex: terminal incompatível)
        for line in CASCAVEL_LOGO_ASCII:
            console.print(f"[bold bright_green]{line}[/]")


def _clear_block(num_lines: int) -> None:
    """Limpa um bloco de linhas acima do cursor.

    SEGURANÇA UX: Limita movimento de cursor ao tamanho real do terminal
    para evitar artifacts visuais e crashes em terminais pequenos.
    """
    if not IS_TTY:
        return
    try:
        term_h = _get_terminal_height()
        # Nunca mover mais linhas que o terminal tem (safety clamp)
        safe_lines = min(num_lines, max(term_h - 2, 1))
        # Save/restore cursor position para robustez
        sys.stdout.write("\033[s")  # Save cursor
        sys.stdout.write(f"\033[{safe_lines}A")
        for _ in range(safe_lines):
            sys.stdout.write("\033[2K\n")
        sys.stdout.write(f"\033[{safe_lines}A")
        sys.stdout.write("\033[u")  # Restore cursor ao ponto salvo
        sys.stdout.flush()
    except OSError:
        pass  # Silencia erros em terminais incompatíveis


def run_preloader(plugin_count: int, tools_count: int, *, target_hint: str | None = None) -> None:
    """Preloader cinematográfico Awwwards-level com logo fade.

    SEGURANÇA UX: Todo o preloader é wrapped em try/except para que
    terminais incompatíveis (dumb, pipe, CI) recebam fallback graceful.

    Args:
        plugin_count: Número de plugins disponíveis.
        tools_count: Número de ferramentas externas detectadas.
        target_hint: Target fornecido via CLI (exibido no boot sequence).
    """
    try:
        _run_preloader_impl(plugin_count, tools_count, target_hint=target_hint)
    except (OSError, Exception) as e:
        # Fallback: terminal incompatível — imprime versão estática
        console.print(f"\n  [bold bright_green]🐍 CASCAVEL v{__version__} — ONLINE[/]")
        console.print(f"  [dim]Preloader desativado: {type(e).__name__}[/]\n")


def _run_preloader_impl(plugin_count: int, tools_count: int, *, target_hint: str | None = None) -> None:
    """Implementação interna do preloader — isolada para try/except."""
    os_name = f"{platform.system()} {platform.release()}"
    py_ver = f"{sys.version.split()[0]}"

    console.print()

    # === PHASE 1: Logo Fade-In ===
    _fade_in_logo()
    time.sleep(0.5)

    # === PHASE 2: Fade-Out (limpa para boot) ===
    total_logo_lines = len(COBRA_ART) + len(CASCAVEL_LOGO_ASCII) + 3  # +3 spacing/subtitle
    _clear_block(total_logo_lines)

    # === PHASE 3: Boot Sequence ===
    boot_title = "[bold green]▶ SYSTEM BOOT SEQUENCE[/]"
    if target_hint:
        boot_title = f"[bold green]▶ SYSTEM BOOT SEQUENCE[/]  [bold bright_red]⚡ {target_hint}[/]"

    console.print(
        Panel(
            boot_title,
            border_style="green",
            box=box.HEAVY,
            width=68,
        )
    )
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

    # === PHASE 3.5: Target Acquisition (quando target é conhecido) ===
    if target_hint:
        console.print()
        console.print(f"  [{S_RED}]█▓▒░  TARGET LOCKED: [bold]{target_hint}[/]  ░▒▓█[/]")
        time.sleep(0.3)

    console.print()

    # === PHASE 4: Loading bar — 2s para leitura confortável ===
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
            # Velocidade variável: começa rápido, desacelera no meio, acelera no final
            if step < 30:
                time.sleep(0.015)
            elif step < 70:
                time.sleep(0.025)  # Pausa para leitura do boot sequence
            else:
                time.sleep(0.012)

    if target_hint:
        console.print(
            f"  [bold bright_green]✓ CASCAVEL v{__version__} — [bright_red]{target_hint}[/] LOCKED & LOADED[/]\n"
        )
    else:
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
        1
        for f in glob.glob(os.path.join(PLUGINS_PATH, "*.py"))
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
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
            subtitle="[dim]Quantum Security Framework[/]",
            box=box.DOUBLE_EDGE,
        )
    )
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

    console.print(
        Panel(
            Align.center(grid),
            title=f"[{S_RED}]⚡ TARGET ACQUISITION ⚡[/]",
            border_style="red",
            box=box.HEAVY,
        )
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


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════════
def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD METADATA SSRF BLOCKLIST (2026 Expanded)
# ═══════════════════════════════════════════════════════════════════════════════
_CLOUD_METADATA_HOSTS = {
    # AWS
    "169.254.169.254",
    "fd00:ec2::254",
    "169.254.169.123",
    # GCP
    "metadata.google.internal",
    "metadata.google.com",
    # Azure
    # Alibaba Cloud
    "100.100.100.200",
    # DigitalOcean
    # Oracle Cloud
    # Generic blocked
    "localhost",
    "0.0.0.0",
    "::1",
    "0177.0.0.1",
    "ip6-localhost",
    "ip6-loopback",
}


def _normalize_ip_representation(host: str) -> str | None:
    """Normaliza representações alternativas de IP para detecção de bypass.

    SEGURANÇA 2026: Atacantes usam formatos alternativos para evitar blocklists:
    - Octal: 0177.0.0.1 → 127.0.0.1
    - Hexadecimal: 0x7f000001 → 127.0.0.1
    - Decimal inteiro: 2130706433 → 127.0.0.1
    - IPv4-mapped IPv6: ::ffff:127.0.0.1
    - Bracket notation: [::1]
    """
    # Strip IPv6 brackets
    if host.startswith("[") and host.endswith("]"):
        host = host.removeprefix("[").removesuffix("]")

    # Decimal integer (e.g., 2130706433 = 127.0.0.1)
    if host.isdigit():
        try:
            val = int(host)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Hex integer (e.g., 0x7f000001)
    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Octal notation (e.g., 0177.0.0.1)
    if "." in host:
        parts = host.split(".")
        if all(p.startswith("0") and len(p) > 1 and p.isdigit() for p in parts if p):
            try:
                decimal_parts: list[str] = []
                for p in parts:
                    octal_val = int(p, 8)  # Explicit base-8 conversion
                    decimal_parts.append(str(octal_val))
                normalized = ".".join(decimal_parts)
                ipaddress.IPv4Address(normalized)  # Validate
                return normalized
            except (ValueError, ipaddress.AddressValueError):
                pass

    # Standard IP parse
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    return None


def _is_blocked_ip(ip_str: str) -> tuple[bool, str]:
    """Verifica se um IP é privado/reservado/loopback/link-local/multicast.

    Retorna (is_blocked, reason). Usa ipaddress nativo do Python que cobre:
    - RFC 1918 (10/8, 172.16/12, 192.168/16)
    - RFC 6598 CGNAT (100.64/10)
    - Link-local (169.254/16)
    - Loopback (127/8)
    - Multicast (224/4)
    - Reserved (240/4)
    - IPv6 equivalents
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, ""

    if addr.is_loopback:
        return True, "loopback (127.0.0.0/8)"
    if addr.is_private:
        return True, "rede privada (RFC 1918/6598)"
    if addr.is_reserved:
        return True, "IP reservado IETF"
    if addr.is_multicast:
        return True, "multicast (224.0.0.0/4)"
    if addr.is_link_local:
        return True, "link-local (169.254.0.0/16 — cloud metadata)"
    if addr.is_unspecified:
        return True, "IP não especificado (0.0.0.0)"

    # IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address):
        mapped: ipaddress.IPv4Address | None = addr.ipv4_mapped
        if mapped is not None:
            if mapped.is_loopback or mapped.is_private or mapped.is_link_local:
                return True, f"IPv4-mapped IPv6 → {mapped}"

    return False, ""


def _detect_idna_homograph(host: str) -> str | None:
    """Detecta domínios com Punycode (xn--) que podem ser homograph attacks.

    SEGURANÇA 2026: Atacantes registram domínios com caracteres Unicode
    visualmente idênticos a domínios legítimos (ex: аpple.com com 'а' cirílico).
    """
    # Check for xn-- prefix (Punycode encoded)
    labels = host.lower().split(".")
    for label in labels:
        if label.startswith("xn--"):
            return f"Punycode detectado: '{label}' — possível homograph attack"

    # Check for mixed scripts (Latin + Cyrillic/Greek etc.)
    if any(ord(c) > 127 for c in host):
        scripts = set()
        for c in host:
            if c in ".-":
                continue
            try:
                script = unicodedata.name(c, "").split()[0]
                scripts.add(script)
            except (ValueError, IndexError):
                pass
        if len(scripts) > 2:  # Domain + common + another script
            return f"Scripts misturados detectados: {scripts} — possível homograph"

    return None


def validate_target(target: str, allow_self: bool = False) -> str:
    """Valida e normaliza o target com 50+ edge cases.

    SEGURANÇA 2026 — Proteções:
    1. Strip protocolo, path, query, fragment
    2. Regex de formato (domínio/IP/host:porta)
    3. Normalização de IPs alternativos (octal, hex, decimal)
    4. ipaddress.is_private/is_loopback/is_reserved/is_link_local nativo
    5. Cloud metadata SSRF blocklist expandida
    6. IDNA/Punycode homograph attack detection
    7. DNS rebinding guard (resolve e re-verifica o IP)
    8. Port range validation (1-65535)
    """
    if not target or not target.strip():
        console.print(f"  [{S_RED}]✗ Target vazio.[/]")
        console.print(f"  [{S_DIM}]Exemplo: cascavel -t example.com[/]")
        return ""

    target = target.strip()

    # ── Phase 1: Strip protocol ──────────────────────────────────────────
    target_lower: str = target.lower()
    for prefix in ("https://", "http://", "ftp://", "ftps://"):
        if target_lower.startswith(prefix):
            clean_target: str = target.replace(prefix, "", 1) if target.lower().startswith(prefix) else target
            target = clean_target
            break

    # Strip userinfo (user:pass@host — URL injection vector)
    if "@" in target:
        at_parts: list[str] = target.split("@")
        target = at_parts[-1]

    # Strip path, query, fragment
    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]
    target = target.strip()

    # ── Phase 2: Format validation ───────────────────────────────────────
    if not target:
        console.print(f"  [{S_RED}]✗ Target vazio após normalização.[/]")
        return ""

    # Reject control characters and whitespace in middle
    _control_chars: str = "\t\n\r"
    if any(ord(c) < 32 or c in _control_chars for c in target):
        console.print(f"  [{S_RED}]✗ Target contém caracteres de controle.[/]")
        return ""

    # Extract host and port
    host_part = target
    port_part = None
    if ":" in target and not target.startswith("["):
        # Simple host:port — NOT IPv6
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host_part = parts[0]
            port_part = int(parts[1])

    # Port range validation
    if port_part is not None:
        if port_part < 1 or port_part > 65535:
            console.print(f"  [{S_RED}]✗ Porta fora do range (1-65535): {port_part}[/]")
            console.print(f"  [{S_DIM}]Exemplo: example.com:8080[/]")
            return ""

    # Regex: aceita domínios, IPs, e hostnames
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]*(:\d{1,5})?$", target):
        # Tenta aceitar xn-- (punycode) e Unicode antes de rejeitar
        has_unicode = any(ord(c) > 127 for c in target)
        has_punycode = any(label.startswith("xn--") for label in host_part.split("."))
        if not has_unicode and not has_punycode:
            console.print(f"  [{S_RED}]✗ Target inválido: {target}[/]")
            console.print(f"  [{S_DIM}]Formatos aceitos: dominio.com │ 1.2.3.4 │ host:porta[/]")
            console.print(f"  [{S_DIM}]Exemplos: example.com, 93.184.216.34, api.target.io:8443[/]")
            return ""

    # ── Phase 3: IDNA/Homograph detection ─────────────────────────────────
    homograph = _detect_idna_homograph(host_part)
    if homograph:
        console.print(f"  [{S_YELLOW}]⚠ ALERTA: {homograph}[/]")
        console.print(f"  [{S_DIM}]Verifique se o domínio é legítimo antes de prosseguir.[/]")
        # Warn but don't block — user may legitimately test punycode domains

    # ── Phase 4: IP normalization + private/reserved check ────────────────
    if not allow_self:
        # Normalize alternative IP representations
        normalized_ip = _normalize_ip_representation(host_part)
        if normalized_ip:
            blocked, reason = _is_blocked_ip(normalized_ip)
            if blocked:
                console.print(f"  [{S_RED}]✗ Target bloqueado: {host_part} → {normalized_ip}[/]")
                console.print(f"  [{S_DIM}]Motivo: {reason}[/]")
                console.print(f"  [{S_DIM}]Use --allow-localhost para red-teaming consentido.[/]")
                return ""

        # Check hostname against cloud metadata blocklist
        if host_part.lower() in _CLOUD_METADATA_HOSTS:
            console.print(f"  [{S_RED}]✗ Target bloqueado: {host_part}[/]")
            console.print(f"  [{S_DIM}]Motivo: cloud metadata / SSRF vector[/]")
            console.print(f"  [{S_DIM}]Use --allow-localhost para sobrescrever.[/]")
            return ""

    # ── Phase 5: DNS rebinding guard ──────────────────────────────────────
    if not allow_self and not _normalize_ip_representation(host_part):
        # It's a domain — resolve to check if it points to private IP
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5)
            try:
                addrs = socket.getaddrinfo(host_part, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for _family, _, _, _, sockaddr in addrs:
                    resolved_ip: str = str(sockaddr[0])
                    blocked, reason = _is_blocked_ip(resolved_ip)
                    if blocked:
                        console.print(f"  [{S_RED}]✗ DNS rebinding detectado![/]")
                        console.print(f"  [{S_DIM}]{host_part} resolve para {resolved_ip} ({reason})[/]")
                        console.print(f"  [{S_DIM}]Use --allow-localhost se isso é intencional.[/]")
                        return ""
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (TimeoutError, socket.gaierror, OSError):
            # DNS failed — target may not exist, but let the scan handle it
            console.print(f"  [{S_YELLOW}]⚠ DNS não resolveu {host_part} — continuando mesmo assim.[/]")

    return target


def inputx(prompt: str, max_retries: int = 3, validator=None) -> str:
    """Prompt interativo com retry loop, EOF protection e validação opcional.

    SEGURANÇA UX 2026:
    - Retry com contagem regressiva e exemplos contextuais
    - EOFError handling para pipes e redirecionamento
    - KeyboardInterrupt graceful
    - Validador customizável via callback
    """
    for attempt in range(1, max_retries + 1):
        try:
            value = console.input(f"  [{S_CYAN}]❯ {prompt}[/]")
            value = value.strip()
            if not value:
                remaining = max_retries - attempt
                if remaining > 0:
                    console.print(f"  [{S_YELLOW}]⚠ Entrada vazia. {remaining} tentativa(s) restante(s).[/]")
                    continue
                else:
                    console.print(f"  [{S_RED}]✗ Máximo de tentativas atingido. Abortando.[/]")
                    sys.exit(1)
            # Custom validation
            if validator:
                error = validator(value)
                if error:
                    remaining = max_retries - attempt
                    if remaining > 0:
                        console.print(f"  [{S_RED}]✗ {error}[/]")
                        console.print(f"  [{S_DIM}]{remaining} tentativa(s) restante(s).[/]")
                        continue
                    else:
                        console.print(f"  [{S_RED}]✗ {error} — máximo de tentativas.[/]")
                        sys.exit(1)
            return value
        except EOFError:
            console.print(f"\n  [{S_RED}]✗ EOF — entrada não disponível (pipe/redirecionamento).[/]")
            console.print(f"  [{S_DIM}]Use: cascavel -t target.com para modo não-interativo.[/]")
            sys.exit(1)
        except KeyboardInterrupt:
            console.print(f"\n  [{S_RED}]✗ Interrompido pelo usuário.[/]\n")
            sys.exit(0)
    console.print(f"  [{S_RED}]✗ Sem input válido. Abortando.[/]")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔍 PRE-FLIGHT SYSTEM CHECK
# ═══════════════════════════════════════════════════════════════════════════════
def _preflight_check() -> bool:
    """Pre-flight system validation — 9 checks antes de qualquer scan.

    Verifica integridade do ambiente: diretórios, Python, encoding, disco,
    permissões, DNS, e disponibilidade de ferramentas.
    """
    checks = []

    # 1. Python version
    py_ok = sys.version_info >= (3, 10)
    checks.append(
        (
            "Python ≥ 3.10",
            py_ok,
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "Atualize Python: python.org/downloads",
        )
    )

    # 2. Diretórios existem e são writable
    dirs_ok = True
    for _dir_name, path in [
        ("plugins", PLUGINS_PATH),
        ("reports", REPORTS_PATH),
        ("exports", EXPORTS_PATH),
        ("wordlists", WORDLISTS_PATH),
    ]:
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
            except OSError:
                dirs_ok = False
        if not os.access(path, os.W_OK):
            dirs_ok = False
    checks.append(
        (
            "Diretórios R/W",
            dirs_ok,
            "plugins/ reports/ exports/ wordlists/",
            "Verifique permissões: chmod 755 nos diretórios",
        )
    )

    # 3. Rich importável
    rich_ok = True
    try:
        import rich  # noqa: F401
    except ImportError:
        rich_ok = False
    checks.append(("Rich library", rich_ok, "Importada", "pip install rich"))

    # 4. Terminal encoding
    encoding = getattr(sys.stdout, "encoding", "unknown") or "unknown"
    enc_ok = encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32")
    checks.append(("Terminal UTF-8", enc_ok, encoding, "export LANG=en_US.UTF-8 ou PYTHONIOENCODING=utf-8"))

    # 5. Espaço em disco (≥50MB em reports/)
    disk_ok = True
    try:
        stat = os.statvfs(REPORTS_PATH)
        free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
        disk_ok = free_mb >= 50
    except (OSError, AttributeError):
        free_mb = -1
    checks.append(
        (
            "Disco ≥ 50MB",
            disk_ok,
            f"{free_mb:.0f}MB livres" if free_mb >= 0 else "N/A",
            "Libere espaço em disco para relatórios",
        )
    )

    # 6. DNS funcional
    dns_ok = False
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo("dns.google", None)
        dns_ok = True
    except (TimeoutError, socket.gaierror, OSError):
        pass
    finally:
        socket.setdefaulttimeout(None)
    checks.append(("DNS funcional", dns_ok, "dns.google", "Verifique sua conexão de rede e DNS"))

    # 7. Pelo menos 1 plugin
    plugin_count = _count_plugins()
    checks.append(("Plugins ≥ 1", plugin_count > 0, f"{plugin_count} plugins", "Verifique a pasta plugins/"))

    # 8. Pelo menos 1 ferramenta externa
    tools_avail = detect_tools()
    tools_count = sum(1 for v in tools_avail.values() if v)
    checks.append(
        (
            "Tools externas ≥ 1",
            tools_count > 0,
            f"{tools_count}/{len(tools_avail)}",
            "Instale: nmap, curl, whois (mínimo)",
        )
    )

    # 9. Permissão de escrita em reports/
    write_ok = os.access(REPORTS_PATH, os.W_OK) if os.path.isdir(REPORTS_PATH) else False
    checks.append(("Escrita reports/", write_ok, REPORTS_PATH, "chmod 755 reports/ ou execute como owner"))

    # Display
    table = Table(
        title=f"[{S_GREEN}]🔍 PRE-FLIGHT CHECK[/]",
        box=box.ROUNDED,
        border_style="green",
        header_style=f"{S_WHITE} on dark_green",
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


# ═══════════════════════════════════════════════════════════════════════════════
# FERRAMENTAS & INFRA
# ═══════════════════════════════════════════════════════════════════════════════
def _check_single_tool(tool: str) -> tuple[str, bool, str]:
    """Verifica uma ferramenta e retorna (nome, disponível, versão)."""
    path = shutil.which(tool)
    if not path:
        return (tool, False, "")
    # Tenta obter versão
    version = ""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = (result.stdout or "") + (result.stderr or "")
        # Extrai primeira versão encontrada (X.Y.Z ou X.Y)
        ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
        if ver_match:
            version = ver_match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, PermissionError):
        pass
    return (tool, True, version)


def detect_tools() -> dict[str, bool]:
    """Detecta ferramentas externas em paralelo com ThreadPoolExecutor.

    ~30 tools verificadas em ~3s (paralelo) vs ~15s (serial).
    """
    tools = [
        "subfinder",
        "amass",
        "httpx",
        "nmap",
        "ffuf",
        "gobuster",
        "naabu",
        "nuclei",
        "feroxbuster",
        "curl",
        "nikto",
        "sqlmap",
        "wafw00f",
        "dnsrecon",
        "fierce",
        "hydra",
        "gau",
        "waybackurls",
        "katana",
        "dnsx",
        "asnmap",
        "mapcidr",
        "tshark",
        "sslscan",
        "whatweb",
        "wpscan",
        "john",
        "whois",
        "traceroute",
        "dig",
    ]
    return {tool: shutil.which(tool) is not None for tool in tools}


def detect_tools_with_versions() -> dict[str, tuple[bool, str]]:
    """Versão estendida: retorna {tool: (disponível, versão)} em paralelo."""
    tools = [
        "subfinder",
        "amass",
        "httpx",
        "nmap",
        "ffuf",
        "gobuster",
        "naabu",
        "nuclei",
        "feroxbuster",
        "curl",
        "nikto",
        "sqlmap",
        "wafw00f",
        "dnsrecon",
        "fierce",
        "hydra",
        "gau",
        "waybackurls",
        "katana",
        "dnsx",
        "asnmap",
        "mapcidr",
        "tshark",
        "sslscan",
        "whatweb",
        "wpscan",
        "john",
        "whois",
        "traceroute",
        "dig",
    ]
    results = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(lambda t=t: _check_single_tool(t)): t for t in tools}
            for future in concurrent.futures.as_completed(futures, timeout=10):
                try:
                    name, available, version = future.result(timeout=5)
                    results[name] = (available, version)
                except (concurrent.futures.TimeoutError, Exception):
                    tool_name = futures[future]
                    results[tool_name] = (False, "")
    except Exception:
        # Fallback serial se ThreadPoolExecutor falhar
        for tool in tools:
            results[tool] = (shutil.which(tool) is not None, "")
    return results


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
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ver_str = (ver_out.stdout + ver_out.stderr).strip()
        if ver_str:
            # Parse version number
            ver_match = re.search(r"(\d+\.\d+\.\d+)", ver_str)
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
                check=True,
                timeout=120,
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
                ipv4: list[str] = [str(a[4][0]) for a in addrs if a[0] == socket.AF_INET]
                ipv6: list[str] = [str(a[4][0]) for a in addrs if a[0] == socket.AF_INET6]
                if ipv4:
                    return ipv4[0]
                if ipv6:
                    return ipv6[0]
                return "N/A"
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (TimeoutError, socket.gaierror, OSError):
        pass
    return "N/A"


def run_cmd(cmd: str, timeout: int = 90) -> str:
    """Executa comando shell com process group kill on timeout.

    STDERR SEPARATION (2026): stderr é capturado separadamente e logado
    via _stderr_log. Apenas stdout é retornado para o relatório, evitando
    poluir outputs com warnings de ferramentas externas.

    NOTA DE SEGURANÇA: shell=True é necessário porque o pipeline de ferramentas
    externas usa pipes (echo target | httpx). Todos os targets são pré-sanitizados
    com shlex.quote() em enum_tools(). O risco de injection é mitigado.
    """
    proc = None
    try:
        # start_new_session=True cria process group para matar filhos no timeout
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
        # Decode com fallback para caracteres inválidos
        raw_out: bytes = stdout_bytes if isinstance(stdout_bytes, bytes) else b""
        raw_err: bytes = stderr_bytes if isinstance(stderr_bytes, bytes) else b""
        out: str = raw_out.decode("utf-8", errors="replace")
        err: str = raw_err.decode("utf-8", errors="replace")

        # Stderr separation: log stderr se presente, não polui output
        if err.strip():
            # Loga stderr para debug, mas não adiciona ao resultado
            _cmd_name = cmd.split()[0] if cmd.strip() else "unknown"
            _stderr_log(_cmd_name, err.strip())

        return out
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


def _stderr_log(tool_name: str, stderr_content: str) -> None:
    """Loga stderr de ferramentas externas para debug.

    Arquivo: reports/stderr.log (rotacionado a cada 1MB).
    Formato: [timestamp] [tool] message
    """
    try:
        log_path = os.path.join(REPORTS_PATH, "stderr.log")
        # Rotação simples: se > 1MB, trunca
        if os.path.isfile(log_path) and os.path.getsize(log_path) > 1_048_576:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"--- LOG ROTATED {datetime.datetime.now().isoformat()} ---\n")
        with open(log_path, "a", encoding="utf-8") as f:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            stderr_lines: list[str] = stderr_content.split("\n")
            first_ten: list[str] = stderr_lines if len(stderr_lines) <= 10 else [stderr_lines[i] for i in range(10)]
            for line in first_ten:  # Max 10 linhas por tool
                f.write(f"[{ts}] [{tool_name}] {line}\n")
    except (PermissionError, OSError):
        pass  # Falha silenciosa — não deve interromper o scan


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE FERRAMENTAS EXTERNAS
# ═══════════════════════════════════════════════════════════════════════════════
def enum_tools(
    target: str,
    report: list[str],
    wordlist: str,
    nuclei_templates: str,
    timeouts: dict[str, int],
    available: dict[str, bool],
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    safe = shlex.quote(target)
    tools = {
        "whois": f"whois {safe}",
        "subfinder": f"subfinder -silent -d {safe}",
        "amass": f"amass enum -d {safe} -timeout 2",
        "httpx": f"echo {safe} | httpx -silent -title -tech-detect -ip",
        "nmap": f"nmap -Pn -A {safe}",
        "ffuf": (f"ffuf -u http://{safe}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t 40") if wordlist else "",
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
            # Sanitiza surrogates para evitar UnicodeEncodeError no report
            truncated_out: str = out if len(out) <= 5000 else "".join([out[i] for i in range(5000)])
            safe_out: str = truncated_out.encode("utf-8", errors="replace").decode("utf-8")
            report.append(f"\n### {name}\n```\n{safe_out}\n```")
            progress.advance(overall)
            console.print(f"    [green]✓[/] {name} [{S_DIM}]({elapsed:.1f}s)[/]")

    console.print()
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN DE PORTAS
# ═══════════════════════════════════════════════════════════════════════════════
def _parse_port(line: str) -> int | None:
    raw = line.strip().split(":")[-1] if ":" in line.strip() else line.strip()
    try:
        port = int(raw)
        return port if 0 < port < 65536 else None
    except ValueError:
        return None


def scan_ports(naabu_out: str) -> list[int]:
    ports = []
    for line in naabu_out.splitlines():
        port = _parse_port(line)
        if port is not None:
            ports.append(port)
    return sorted(set(ports))


def grab_banners(target: str, ports: list[int], timeout: int = 3) -> dict[int, str]:
    """Grab banners dos primeiros 20 ports abertos com recv loop."""
    banners: dict[int, str] = {}
    # Strip port from target if present (host:port -> host)
    host = target.split(":")[0] if ":" in target else target
    # Detecção de família: IPv6 literal usa AF_INET6
    _is_ipv6 = ":" in host
    _af = socket.AF_INET6 if _is_ipv6 else socket.AF_INET
    scan_ports_list: list[int] = [ports[i] for i in range(min(20, len(ports)))]
    for port in scan_ports_list:
        s = None
        try:
            s = socket.socket(_af, socket.SOCK_STREAM)
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
                except (TimeoutError, OSError):
                    break
            raw_banner: str = b"".join(chunks).decode(errors="ignore").strip()
            banners[port] = raw_banner if len(raw_banner) <= 512 else "".join([raw_banner[i] for i in range(512)])
        except (TimeoutError, ConnectionRefusedError, OSError):
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
    path: str,
    name: str,
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[int, str],
    timeout: int = 120,
) -> dict[str, Any]:
    """Executa um plugin com timeout guard (SIGALRM, 120s padrão).

    SEGURANÇA 2026: Plugins maliciosos ou bugados podem travar indefinidamente.
    O alarm garante que o framework não fica preso em nenhum plugin individual.
    """
    import importlib.machinery as _ilm

    spec: _ilm.ModuleSpec | None = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        return {"plugin": name, "erro": "Módulo não resolvido"}
    loader = spec.loader
    if loader is None:
        return {"plugin": name, "erro": "Loader não disponível"}

    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)

    if not hasattr(mod, "run"):
        return {"plugin": name, "erro": "Sem função run()"}

    # Per-plugin timeout via SIGALRM (Unix only)
    _has_alarm = hasattr(signal, "SIGALRM")

    class _PluginTimeoutError(Exception):
        pass

    def _alarm_handler(signum, frame):
        raise _PluginTimeoutError(f"Plugin '{name}' excedeu timeout de {timeout}s")

    old_handler = None
    if _has_alarm:
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(timeout)

    try:
        result = mod.run(target, ip, ports, banners)
        # SEGURANÇA 2026: Sanitiza saída contra ANSI escape injection
        result = _sanitize_output(result) if result else {"plugin": name, "resultados": "Sem retorno"}
        return result
    except _PluginTimeoutError:
        return {"plugin": name, "erro": f"TIMEOUT ({timeout}s)"}
    except TypeError as e:
        return {"plugin": name, "erro": f"Assinatura: {_sanitize_output(str(e))}"}
    except Exception as e:
        return {"plugin": name, "erro": _sanitize_output(str(e))}
    finally:
        if _has_alarm:
            signal.alarm(0)  # Cancel pending alarm
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
    # Pyre2 requer return explícito após finally — control flow garante unreachable
    return {"plugin": name, "erro": "Execução inesperada"}


def _classify(result: dict[str, Any]) -> tuple:
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
    # List results — filtra strings vazias e None antes de contar como vuln
    if isinstance(resultados, list):
        real_findings = [v for v in resultados if v and v != "" and v != "N/A"]
        if real_findings:
            return "vuln", S_RED, "⚠"
    return "limpo", "green", "✓"


def _count_sev(resultados: Any) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAIXO": 0, "INFO": 0}
    vulns: list[Any] = []
    if isinstance(resultados, list):
        vulns = list(resultados)
    elif isinstance(resultados, dict):
        raw_vulns: Any = resultados.get("vulns", resultados.get("forms_sem_csrf", []))
        vulns = list(raw_vulns) if isinstance(raw_vulns, list) else []
        # Plugins que retornam severidade no root level do dict (não dentro de vulns)
        if not vulns and "status" in resultados:
            root_sev = resultados.get("severidade", "INFO")
            if root_sev in counts and resultados.get("status") == "vulneravel":
                counts[root_sev] += 1
                return counts
    for v in vulns:
        if isinstance(v, dict):
            sev = v.get("severidade", "INFO")
            if sev in counts:
                counts[sev] += 1
    return counts


def _build_intel_panel(intel_idx: int, scan_stats: dict[str, int], elapsed: float) -> Panel:
    """Constrói painel lateral de Security Intel para retenção de atenção.

    Protege contra lista vazia e índices fora de range.
    """
    if not SECURITY_INTEL:
        return Panel("[dim]Sem intel disponível[/]", border_style="dim")

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
    # Trunca com boundary seguro para evitar cortar emoji no meio
    safe_len: int = min(55, len(next_tip))
    was_truncated: bool = len(next_tip) > safe_len
    tip_prefix: str = "".join([next_tip[i] for i in range(safe_len)])
    truncated: str = tip_prefix.rsplit(" ", 1)[0] if was_truncated else next_tip
    suffix = "..." if was_truncated else ""
    next_text.append(f"  {truncated}{suffix}\n", style="dim")

    from rich.console import Group  # noqa: E402 — import local para evitar circular em testes

    content = Group(
        Panel(intel_text, border_style="bright_yellow", title="[bold yellow]🧠 SECURITY INTEL[/]", box=box.ROUNDED),
        Panel(stats, border_style="bright_green", title="[bold green]📊 LIVE STATS[/]", box=box.ROUNDED),
        Panel(next_text, border_style="dim cyan", title="[dim]PRÓXIMO[/]", box=box.SIMPLE),
    )
    return Panel(content, border_style="bright_cyan", title=f"[{S_CYAN}]🐍 CASCAVEL INTEL[/]", box=box.DOUBLE_EDGE)


def run_plugins(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[int, str],
    report: list[str],
    plugin_filter: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Executa plugins com split-screen: scan table + security intel.

    Args:
        plugin_filter: If provided, only run plugins whose names are in this list.
                       None means run all plugins (default behavior).
    """
    results: list[dict[str, Any]] = []
    plugin_files = sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py")))
    valid = [
        (f, os.path.splitext(os.path.basename(f))[0])
        for f in plugin_files
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
    ]
    # Apply profile filter if specified
    if plugin_filter is not None:
        filter_set = set(plugin_filter)
        valid = [(f, n) for f, n in valid if n in filter_set]
    total = len(valid)
    scan_stats: dict[str, int] = {
        "ok": 0,
        "vuln": 0,
        "err": 0,
        "CRITICO": 0,
        "ALTO": 0,
        "MEDIO": 0,
        "BAIXO": 0,
        "INFO": 0,
    }

    console.print(Rule(f"[bold magenta]🔌 PLUGIN ENGINE — {total} PLUGINS[/]", style="magenta"))
    console.print()

    # Randomize intel order for variety
    intel_order = list(range(len(SECURITY_INTEL)))
    random.shuffle(intel_order)
    intel_idx = 0
    scan_start = time.time()

    def _build_table(
        rows: list,
        current_idx: int,
        current_name: str,
    ) -> Table:
        """Constrói a tabela de resultados que atualiza em Live."""
        pct = min(int((current_idx / total) * 100), 100) if total else 100
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
        row_count: int = len(rows)
        if row_count > 15:
            start_idx: int = row_count - 15
            display_rows: list = [rows[i] for i in range(start_idx, row_count)]
            t.add_row("", f"[dim]... {row_count - 15} anteriores ...[/]", "", "", "", "")
        else:
            display_rows = list(rows)
        for row in display_rows:
            t.add_row(*row)

        # Current plugin indicator
        if current_idx < total:
            t.add_row(
                str(current_idx),
                f"[bold yellow]▶ {current_name}[/]",
                "[yellow]⋯[/]",
                "[yellow]Executando...[/]",
                "",
                "",
            )

        return t

    def _build_layout(rows, current_idx, current_name, intel_i):
        """Split-screen: tabela de scan + painel de intel.

        Protege contra intel_order vazio (SECURITY_INTEL=[]).
        """
        layout = Layout()
        layout.split_row(
            Layout(name="scan", ratio=3),
            Layout(name="intel", ratio=1, minimum_size=30),
        )
        layout["scan"].update(_build_table(rows, current_idx, current_name))
        safe_intel_i = intel_order[intel_i % len(intel_order)] if intel_order else 0
        layout["intel"].update(
            _build_intel_panel(
                safe_intel_i,
                scan_stats,
                time.time() - scan_start,
            )
        )
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
                    err_desc: str = str(result.get("erro", "?"))
                    err_trunc: str = err_desc if len(err_desc) <= 30 else "".join([err_desc[i] for i in range(30)])
                    desc = f"[red]{err_trunc}[/]"
                    sev_str = ""
                    err_count: int = scan_stats.get("err", 0)
                    scan_stats["err"] = err_count + 1
                elif cls == "vuln":
                    sevs = _count_sev(result.get("resultados", ""))
                    parts: list[str] = []
                    for sn, sc in sevs.items():
                        if sc > 0:
                            si = SEV_MAP.get(sn, (S_DIM, "○"))
                            parts.append(f"[{si[0]}]{si[1]}{sc}[/]")
                            prev_sn: int = scan_stats.get(sn, 0)
                            scan_stats[sn] = prev_sn + sc
                    sev_str = " ".join(parts)
                    total_v = sum(sevs.values())
                    desc = f"[{S_RED}]{total_v} vulns[/]"
                    vuln_count: int = scan_stats.get("vuln", 0)
                    scan_stats["vuln"] = vuln_count + 1
                else:
                    r = result.get("resultados", "")
                    r_str: str = str(r)
                    r_trunc: str = r_str if len(r_str) <= 30 else "".join([r_str[i] for i in range(30)])
                    desc = f"[green]{r_trunc}[/]" if isinstance(r, str) else "[green]Limpo[/]"
                    sev_str = "[green]—[/]"
                    ok_count: int = scan_stats.get("ok", 0)
                    scan_stats["ok"] = ok_count + 1

                table_rows.append(
                    (
                        str(idx),
                        name,
                        f"[{style}]{icon}[/]",
                        desc,
                        sev_str or "[green]—[/]",
                        f"{elapsed:.1f}s",
                    )
                )

                # Rotate intel every 2 plugins
                if idx % 2 == 0:
                    intel_idx = intel_idx + 1

                # SEGURANÇA UX: Bounds check para evitar IndexError quando idx == total
                next_name = valid[idx][1] if idx < len(valid) else "Concluindo..."
                live.update(_build_layout(table_rows, min(idx + 1, total), next_name, intel_idx))
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
            # Track stats no fallback também para dashboard preciso
            if cls == "erro":
                scan_stats["err"] += 1
            elif cls == "vuln":
                scan_stats["vuln"] += 1
                for sn, sc in _count_sev(result.get("resultados", "")).items():
                    scan_stats[sn] = scan_stats.get(sn, 0) + sc
            else:
                scan_stats["ok"] += 1
            console.print(f"  [{style}]{icon}[/] {name} [dim]({idx}/{total})[/]")

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
    target: str,
    ip: str,
    results: list[dict[str, Any]],
    elapsed_total: float,
    report_path: str,
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
            total_err = total_err + 1
        elif cls == "vuln":
            total_vuln = total_vuln + 1
            for k, v in _count_sev(r.get("resultados", "")).items():
                prev_v: int = agg.get(k, 0)
                agg[k] = prev_v + v
        else:
            total_ok = total_ok + 1

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

    max_c: int = max(agg.values()) if any(agg.values()) else 1
    for sev, count in agg.items():
        sty, icon = SEV_MAP.get(sev, (S_DIM, "○"))
        bar_len: int = int(count * 25 // max_c) if count > 0 else 0
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
    console.print(
        Panel(
            Align.center(Text.from_markup("  │  ".join(parts))),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
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
            # Sanitize: remove newlines (injection vector) + escape quotes
            safe_msg = message.replace("\n", " ").replace('"', '\\"').replace("'", "\\'")
            safe_title = title.replace("\n", " ").replace('"', '\\"').replace("'", "\\'")
            script = f'display notification "{safe_msg}" with title "{safe_title}"'
            subprocess.run(["osascript", "-e", script], timeout=5, capture_output=True)
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
    """Menu interativo pós-scan com validação de input e retry.

    Opções:
        1 - Abrir pasta do relatório
        2 - Executar novo scan
        3 - Listar plugins
        4 - Exportar relatório como JSON
        5 - Exportar relatório como PDF
        0 - Sair
    """
    console.print(Rule(f"[{S_GREEN}]🐍 O QUE DESEJA FAZER?[/]", style="bright_green"))
    console.print()

    menu = Table(show_header=False, box=box.ROUNDED, border_style="green", padding=(0, 2))
    menu.add_column(style=S_GREEN, width=4, justify="center")
    menu.add_column(style=S_WHITE, min_width=40)
    menu.add_row("1", "📂 Abrir pasta do relatório")
    menu.add_row("2", "🔄 Executar novo scan")
    menu.add_row("3", "📋 Listar plugins disponíveis")
    menu.add_row("4", "📦 Exportar relatório como JSON")
    menu.add_row("5", "📄 Exportar relatório como PDF")
    menu.add_row("0", "🚪 Sair")

    console.print(Align.center(menu))
    console.print()

    # Validação de input com retry (máx 3 tentativas)
    valid_choices = {"0", "1", "2", "3", "4", "5"}
    choice = ""
    for _attempt in range(3):
        raw = inputx("Opção [0-5]: ").strip()
        if raw in valid_choices:
            choice = raw
            break
        console.print(f"  [{S_YELLOW}]⚠ Opção inválida: '{raw}'. Escolha 0-5.[/]")
    else:
        # 3 tentativas falharam
        console.print(f"\n  [{S_DIM}]🐍 Até a próxima missão.[/]\n")
        return

    if choice == "1":
        open_folder(report_path)
        console.print(f"  [{S_GREEN}]✓ Pasta aberta no file manager.[/]\n")

    elif choice == "2":
        console.print(f"  [{S_CYAN}]▶ Novo scan[/]")
        allow_self = False

        def _target_validator(val: str) -> str:
            result = validate_target(val, allow_self=allow_self)
            if not result:
                return "Target inválido. Formatos: dominio.com │ 1.2.3.4 │ host:porta"
            return ""

        new_target_raw = inputx("Novo target (IP/domain): ", validator=_target_validator)
        new_target = validate_target(new_target_raw, allow_self=allow_self)
        if new_target:
            run_scan(new_target, no_notify=False, output_format="md", global_timeout=90)
        else:
            console.print(f"  [{S_RED}]✗ Target inválido. Scan cancelado.[/]")

    elif choice == "3":
        list_plugins_table()

    elif choice == "4":
        # Exportar como JSON a partir do relatório MD existente
        if report_path and os.path.isfile(report_path):
            json_path = report_path.rsplit(".", 1)[0] + ".json"
            try:
                with open(report_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                report_data = {
                    "source": report_path,
                    "exported_at": datetime.datetime.now().isoformat(),
                    "format": "json",
                    "content": content,
                    "version": __version__,
                }
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False)
                console.print(f"  [{S_GREEN}]✓ JSON exportado: {json_path}[/]\n")
            except (OSError, json.JSONDecodeError) as e:
                console.print(f"  [{S_RED}]✗ Falha ao exportar JSON: {e}[/]")
        else:
            console.print(f"  [{S_YELLOW}]⚠ Relatório não encontrado: {report_path}[/]")

    elif choice == "5":
        # Exportar como PDF
        try:
            from report_generator import generate_pdf_report

            if report_path and os.path.isfile(report_path):
                with open(report_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                # Extrair target do nome do arquivo para o PDF
                report_path.rsplit(".", 1)[0] + ".pdf"
                console.print(f"  [{S_CYAN}]▶ Gerando PDF...[/]")
                # Usar report_generator se disponível
                scan_data = {"content": content, "exported_at": datetime.datetime.now().isoformat()}
                generated = generate_pdf_report("scan", scan_data)
                console.print(f"  [{S_GREEN}]✓ PDF gerado: {generated}[/]\n")
            else:
                console.print(f"  [{S_YELLOW}]⚠ Relatório não encontrado.[/]")
        except ImportError:
            console.print(f"  [{S_YELLOW}]⚠ reportlab não instalado. Use: pip install reportlab[/]")
        except Exception as e:
            console.print(f"  [{S_RED}]✗ Falha ao gerar PDF: {e}[/]")

    else:
        console.print(f"\n  [{S_GREEN}]🐍 Até a próxima missão.[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# FEROXBUSTER
# ═══════════════════════════════════════════════════════════════════════════════
def run_feroxbuster(target: str, wordlist: str, available: dict[str, bool]) -> list[dict[str, Any]]:
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
            with open(output_path, encoding="utf-8", errors="replace") as f:
                return [json.loads(line) for line in f if line.strip()]
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
    target: str,
    ip: str,
    plugin_results: list[dict[str, Any]],
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
        "elapsed_seconds": float(int(elapsed * 100)) / 100.0,
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
            import importlib.machinery as _ilm_p

            spec_p: _ilm_p.ModuleSpec | None = importlib.util.spec_from_file_location(name, fp)
            if spec_p is None:
                table.add_row(str(idx), name, "[red]Erro[/]", "[red]✗[/]")
                continue
            loader_p = spec_p.loader
            if loader_p is None:
                table.add_row(str(idx), name, "[red]Erro[/]", "[red]✗[/]")
                continue
            doc = ""
            try:
                with open(fp, encoding="utf-8", errors="replace") as src:
                    source = src.read()
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == "run":
                        fn_node: ast.FunctionDef = node
                        raw_doc = ast.get_docstring(fn_node)
                        if raw_doc:
                            doc = raw_doc.strip().split("\n")[0]
                        break
            except (SyntaxError, UnicodeDecodeError):
                # Fallback: executa módulo se AST parsing falhar
                mod = importlib.util.module_from_spec(spec_p)
                loader_p.exec_module(mod)
                if hasattr(mod, "run") and mod.run.__doc__:
                    doc = mod.run.__doc__.strip().split("\n")[0]
            table.add_row(str(idx), name, doc or "[dim]—[/]", "[green]●[/]")
        except Exception:
            table.add_row(str(idx), name, "[red]Erro[/]", "[red]✗[/]")

    console.print(table)
    console.print(f"\n  [{S_DIM}]Total: {idx} plugins[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# 🔄 SELF-UPDATE (GitHub Releases)
# ═══════════════════════════════════════════════════════════════════════════════
_GITHUB_REPO = "glferreira-devsecops/Cascavel"
_GITHUB_API_RELEASES = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"
_GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{_GITHUB_REPO}"


def _parse_semver(v: str) -> tuple[int, ...]:
    """Parse version string like '3.0.0' into comparable tuple."""
    return tuple(int(x) for x in v.lstrip("v").split("."))


def check_for_update(quiet: bool = False) -> str | None:
    """Check if a newer version is available on GitHub.

    Returns:
        Latest version string if update available, None otherwise.
    """
    import json
    import urllib.request

    try:
        req = urllib.request.Request(
            _GITHUB_API_RELEASES,
            headers={"User-Agent": f"Cascavel/{__version__}", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        latest = data.get("tag_name", "").lstrip("v")
        if not latest:
            return None

        if _parse_semver(latest) > _parse_semver(__version__):
            if not quiet:
                console.print(f"\n  [bold green]🆕 Nova versão disponível: v{latest}[/] (atual: v{__version__})")
                console.print("  [dim]Execute: cascavel --update[/]\n")
            return latest
        else:
            if not quiet:
                console.print(f"\n  [green]✅ Cascavel v{__version__} está atualizado.[/]\n")
            return None
    except Exception as e:
        if not quiet:
            console.print(f"  [yellow]⚠ Não foi possível verificar atualizações: {e}[/]")
        return None


def self_update() -> None:
    """Update Cascavel to the latest version from GitHub.

    Supports two update strategies:
      1. Git-based: If installed via git clone, uses 'git pull'
      2. Direct download: Downloads latest core files from GitHub raw
    """
    import json
    import urllib.request

    console.print("\n  [bold cyan]🔄 Cascavel Self-Update[/]")
    console.print(f"  [dim]Versão atual: v{__version__}[/]\n")

    # Check latest version
    try:
        req = urllib.request.Request(
            _GITHUB_API_RELEASES,
            headers={"User-Agent": f"Cascavel/{__version__}", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        latest = data.get("tag_name", "").lstrip("v")
        if not latest:
            console.print("  [red]❌ Não foi possível determinar a versão mais recente.[/]")
            return

        if _parse_semver(latest) <= _parse_semver(__version__):
            console.print(f"  [green]✅ Já está na versão mais recente (v{__version__}).[/]\n")
            return

        console.print(f"  [green]📦 Atualizando para v{latest}...[/]")
    except Exception as e:
        console.print(f"  [red]❌ Erro ao consultar GitHub: {e}[/]")
        return

    install_dir = os.path.dirname(os.path.abspath(__file__))
    git_dir = os.path.join(install_dir, ".git")

    # Strategy 1: Git-based update
    if os.path.isdir(git_dir):
        console.print("  [dim]Modo: git pull[/]")
        try:
            result = subprocess.run(  # noqa: S603, S607
                ["git", "-C", install_dir, "pull", "--rebase", "origin", "main"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                console.print(f"  [green]✅ Atualizado para v{latest} via git pull[/]")
                console.print(f"  [dim]{result.stdout.strip()}[/]\n")
                # Re-install dependencies if requirements changed
                req_file = os.path.join(install_dir, "requirements.txt")
                if os.path.isfile(req_file):
                    console.print("  [dim]Atualizando dependências...[/]")
                    subprocess.run(  # noqa: S603, S607
                        [sys.executable, "-m", "pip", "install", "-r", req_file, "-q"],
                        timeout=120,
                    )
                    console.print("  [green]✅ Dependências atualizadas[/]\n")
            else:
                console.print(f"  [red]❌ git pull falhou: {result.stderr.strip()}[/]")
        except Exception as e:
            console.print(f"  [red]❌ Erro no git pull: {e}[/]")
        return

    # Strategy 2: Direct download of core files
    console.print("  [dim]Modo: download direto (sem .git)[/]")
    core_files = ["cascavel.py", "sarif_exporter.py", "report_generator.py", "requirements.txt"]
    tag = f"v{latest}"
    updated = 0

    for fname in core_files:
        try:
            url = f"{_GITHUB_RAW_BASE}/{tag}/{fname}"
            req = urllib.request.Request(url, headers={"User-Agent": f"Cascavel/{__version__}"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()

            target_path = os.path.join(install_dir, fname)
            with open(target_path, "wb") as f:
                f.write(content)
            console.print(f"    ✅ {fname}")
            updated += 1
        except Exception as e:
            console.print(f"    ❌ {fname}: {e}")

    if updated > 0:
        console.print(f"\n  [green]✅ {updated}/{len(core_files)} arquivos atualizados para v{latest}[/]")
        # Update plugins directory
        console.print("  [dim]Para atualizar plugins, execute: cascavel --update-plugins[/]\n")
    else:
        console.print("  [red]❌ Nenhum arquivo atualizado.[/]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════
class CascavelArgumentParser(argparse.ArgumentParser):
    """ArgumentParser customizado com error handling amigável.

    Padrão clig.dev 2026: erros vão para stderr com exemplos contextuais.
    """

    def error(self, message: str) -> NoReturn:
        console.print(f"\n  [{S_RED}]✗ Erro de argumento: {message}[/]", highlight=False)
        console.print(f"  [{S_DIM}]Uso:[/]")
        console.print(f"  [{S_CYAN}]  cascavel target.com[/]                    [dim]# Scan direto[/]")
        console.print(f"  [{S_CYAN}]  cascavel -t target.com --plugins-only[/]  [dim]# Apenas plugins[/]")
        console.print(f"  [{S_CYAN}]  cascavel --help[/]                        [dim]# Ajuda completa[/]")
        console.print()
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = CascavelArgumentParser(
        prog="cascavel",
        description="🐍 Cascavel — Quantum Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  cascavel target.com                     Scan direto\n"
        "  cascavel -t target.com                  Full scan\n"
        "  cascavel -t target.com --plugins-only   Plugins only\n"
        "  cascavel -t target.com -q -o json       Quiet + JSON\n"
        "  cascavel --list-plugins                 Show arsenal\n"
        "  cascavel --check-tools                  Verify tools\n"
        "  cascavel --install-global               Instalar globalmente",
    )
    # Target posicional (opcional) — permite 'cascavel target.com'
    parser.add_argument(
        "target_positional", nargs="?", default=None, help="Target direto (IP/domínio) — ex: cascavel target.com"
    )
    parser.add_argument("-t", "--target", help="Target (IP/domínio) — forma alternativa")
    parser.add_argument("-v", "--version", action="version", version=f"v{__version__}")
    parser.add_argument("--list-plugins", action="store_true", help="Lista plugins disponíveis")
    parser.add_argument("--plugins-only", action="store_true", help="Executa apenas plugins (sem ferramentas externas)")
    parser.add_argument("--check-tools", action="store_true", help="Verifica ferramentas externas instaladas")
    parser.add_argument("--no-preloader", action="store_true", help="Desativa preloader cinematográfico")
    parser.add_argument("--no-notify", action="store_true", help="Desativa notificação nativa pós-scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso (sem preloader/banner/animações)")
    parser.add_argument(
        "-o",
        "--output-format",
        choices=["md", "json", "pdf", "sarif"],
        default="md",
        help="Formato do relatório: md (padrão), json, pdf ou sarif",
    )
    parser.add_argument("--pdf", action="store_true", help="Gera relatório PDF profissional (equivalente a -o pdf)")
    parser.add_argument("--sarif", action="store_true", help="Gera relatório SARIF v2.1.0 (equivalente a -o sarif)")
    parser.add_argument(
        "--profile",
        choices=["web", "api", "cloud", "network", "full"],
        default=None,
        help="Perfil de scan pré-configurado (web, api, cloud, network, full)",
    )
    parser.add_argument(
        "--install-global", action="store_true", help="Instala o Cascavel como comando global no sistema"
    )
    parser.add_argument(
        "--update", action="store_true", help="Atualiza o Cascavel para a versão mais recente (via git ou download)"
    )
    parser.add_argument("--check-update", action="store_true", help="Verifica se há atualizações disponíveis no GitHub")

    def _positive_int(value: str) -> int:
        """Validação de argparse: aceita apenas inteiros positivos."""
        try:
            ivalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' não é um inteiro válido") from None
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f"Timeout deve ser > 0, recebido: {ivalue}")
        if ivalue > 600:
            raise argparse.ArgumentTypeError(f"Timeout máximo: 600s, recebido: {ivalue}")
        return ivalue

    parser.add_argument(
        "--timeout",
        type=_positive_int,
        default=90,
        help="Timeout global (1-600 segundos) para ferramentas externas (padrão: 90)",
    )
    parser.add_argument(
        "--allow-localhost", action="store_true", help="Permite scan em localhost/IPs privados (red-teaming consentido)"
    )
    return parser


# ═══════════════════════════════════════════════════════════════════════════════
# 📋 SCAN PROFILES (YAML)
# ═══════════════════════════════════════════════════════════════════════════════
def _load_profile(profile_name: str) -> list[str] | None:
    """Load a scan profile from profiles/ directory.

    Returns:
        List of plugin names to include, or None for all plugins.
    """
    profiles_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
    profile_path = os.path.join(profiles_dir, f"{profile_name}.yaml")

    if not os.path.isfile(profile_path):
        console.print(f"  [{S_YELLOW}]⚠ Profile '{profile_name}' não encontrado. Usando todos os plugins.[/]")
        return None

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        # Fallback: parse YAML manually for simple lists
        console.print(f"  [{S_DIM}]PyYAML não instalado, parsing manual do profile...[/]")
        plugins: list[str] = []
        with open(profile_path, encoding="utf-8") as f:
            in_plugins = False
            for line in f:
                stripped = line.strip()
                if stripped == "plugins:":
                    in_plugins = True
                    continue
                if in_plugins:
                    if stripped.startswith("- "):
                        plugin_name = stripped[2:].strip()
                        if plugin_name and not plugin_name.startswith("#"):
                            plugins.append(plugin_name)
                    elif stripped and not stripped.startswith("#"):
                        in_plugins = False
                if stripped == "all_plugins: true":
                    return None
        return plugins if plugins else None

    with open(profile_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None

    # all_plugins: true → run everything
    if data.get("all_plugins"):
        return None

    plugin_list = data.get("plugins", [])
    if not isinstance(plugin_list, list) or not plugin_list:
        return None

    console.print(
        Panel(
            f"[{S_CYAN}]📋 Profile: {data.get('name', profile_name)}[/]\n"
            f"[{S_DIM}]{data.get('description', '')}[/]\n"
            f"[{S_GREEN}]{len(plugin_list)} plugins selecionados[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    return [str(p) for p in plugin_list]


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════
def run_scan(
    target: str,
    plugins_only: bool = False,
    no_notify: bool = False,
    output_format: str = "md",
    global_timeout: int = 90,
    profile: str | None = None,
) -> None:
    """Executa o scan completo contra o target.

    Args:
        profile: Nome do scan profile (web, api, cloud, network, full) ou None para todos.
    """
    mission_start = time.time()

    # Load scan profile if specified
    _profile_plugins: list[str] | None = None
    if profile:
        _profile_plugins = _load_profile(profile)

    with console.status(f"[{S_GREEN}]🐍 Resolvendo IP...[/]", spinner="dots"):
        ip = detect_ip(target)

    available = detect_tools()
    print_target_card(target, ip)
    print_tools_status(available)

    timeouts = {
        "subfinder": min(60, global_timeout),
        "amass": min(60, global_timeout),
        "httpx": min(30, global_timeout),
        "nmap": min(120, global_timeout),
        "ffuf": min(45, global_timeout),
        "gobuster": min(45, global_timeout),
        "naabu": min(30, global_timeout),
        "nuclei": min(90, global_timeout),
        "curl": min(10, global_timeout),
        "katana": min(60, global_timeout),
        "gau": min(60, global_timeout),
        "dnsx": min(20, global_timeout),
        "nikto": min(120, global_timeout),
        "wafw00f": min(20, global_timeout),
    }

    wordlist = get_wordlist()
    nuclei_templates = ensure_nuclei_templates()

    report = [
        "# 🐍 Cascavel Report\n",
        f"**Target**: `{target}`\n**IP**: `{ip}`\n**Timestamp**: `{timestamp()}`\n",
        f"**Versão**: `v{__version__}`\n",
    ]

    open_ports: list[int] = []
    banners: dict[int, str] = {}

    if not plugins_only:
        results = enum_tools(target, report, wordlist, nuclei_templates, timeouts, available)
        ferox = run_feroxbuster(target, wordlist, available)
        safe_ferox = _sanitize_for_json(ferox)
        ferox_json: str = json.dumps(safe_ferox, indent=2, ensure_ascii=False)
        ferox_truncated: str = ferox_json if len(ferox_json) <= 5000 else "".join([ferox_json[i] for i in range(5000)])
        report.append(f"\n### feroxbuster\n```json\n{ferox_truncated}\n```")

        open_ports = scan_ports(results.get("naabu", ""))
        report.append(f"\n### Portas\n`{open_ports}`\n")

        banners = grab_banners(target, open_ports)
        report.append(f"\n### Banners\n```json\n{json.dumps(banners, indent=2, ensure_ascii=False)}\n```")
    else:
        console.print(
            Panel(
                f"[{S_YELLOW}]⚡ Modo --plugins-only: apenas plugins internos[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        console.print()

    # Plugins
    plugin_results = run_plugins(target, ip, open_ports, banners, report, plugin_filter=_profile_plugins)

    # Report
    elapsed_total = time.time() - mission_start
    if output_format == "json":
        report_path = save_json_report(target, ip, plugin_results, elapsed_total)
    elif output_format == "sarif":
        try:
            from sarif_exporter import export_sarif

            report_path = export_sarif(target, ip, plugin_results, elapsed_total, output_dir=REPORTS_PATH)
            console.print(f"  [bold bright_green]📋 SARIF Report: {report_path}[/]")
        except ImportError:
            console.print(f"  [{S_YELLOW}]⚠ sarif_exporter não encontrado. Gerando MD.[/]")
            report_path = save_report("\n".join(report))
    elif output_format == "pdf":
        try:
            from report_generator import generate_pdf_report

            pdf_vulns = []
            for r in plugin_results:
                cls, _, _ = _classify(r)
                if cls == "vuln":
                    pdf_vulns.append(
                        {
                            "plugin": r.get("plugin", "unknown"),
                            "severity": r.get("severidade", "INFO"),
                            "details": r.get("resultados", ""),
                            "remediation": r.get("correcao", ""),
                        }
                    )
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
        sum(_count_sev(r.get("resultados", "")).values()) for r in plugin_results if _classify(r)[0] == "vuln"
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
def _install_global() -> None:
    """Instala o Cascavel como comando global no sistema.

    Cross-platform: Linux, macOS, Windows (Git Bash/WSL).
    Configura PATH permanente no shell profile do usuário.
    """
    console.print(
        Panel(
            f"[{S_GREEN}]⚡ CASCAVEL — INSTALAÇÃO GLOBAL[/]",
            border_style="green",
            box=box.HEAVY,
        )
    )
    console.print()

    # Detecta se pip install -e . é viável
    pyproject_path = os.path.join(BASE_PATH, "pyproject.toml")
    if not os.path.isfile(pyproject_path):
        console.print(f"  [{S_RED}]✗ pyproject.toml não encontrado em {BASE_PATH}[/]")
        console.print(f"  [{S_DIM}]Execute este comando dentro do diretório Cascavel.[/]")
        sys.exit(1)

    console.print(f"  [{S_CYAN}]▶ Instalando Cascavel via pip (editable mode)...[/]")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", BASE_PATH, "--no-cache-dir"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            # Fallback: tenta sem -e (install normal)
            console.print(f"  [{S_YELLOW}]⚠ Editable mode falhou. Tentando install padrão...[/]")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", BASE_PATH, "--no-cache-dir"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                console.print(f"  [{S_RED}]✗ pip install falhou:[/]")
                err_lines: list[str] = (result.stderr or result.stdout).strip().split("\n")
                tail_start: int = max(0, len(err_lines) - 5)
                for line in [err_lines[i] for i in range(tail_start, len(err_lines))]:
                    console.print(f"    [{S_DIM}]{line}[/]")
                sys.exit(1)
    except subprocess.TimeoutExpired:
        console.print(f"  [{S_RED}]✗ Timeout na instalação (>120s).[/]")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"  [{S_RED}]✗ pip não encontrado. Instale: python -m ensurepip[/]")
        sys.exit(1)

    console.print(f"  [{S_GREEN}]✓ Pacote instalado via pip.[/]")

    # Verificar se 'cascavel' já está no PATH
    cascavel_bin = shutil.which("cascavel")
    if cascavel_bin:
        console.print(f"  [{S_GREEN}]✓ Comando 'cascavel' disponível em: {cascavel_bin}[/]")
        console.print()
        console.print(f"  [{S_GREEN}]🎉 Pronto! Use de qualquer terminal:[/]")
        console.print(f"  [{S_CYAN}]  cascavel target.com[/]")
        console.print(f"  [{S_CYAN}]  cascavel -t target.com --plugins-only[/]")
        console.print(f"  [{S_CYAN}]  cascavel --help[/]")
        console.print()
        return

    # Se não está no PATH, detectar pip user-scripts e configurar
    console.print(f"  [{S_YELLOW}]⚠ 'cascavel' não encontrado no PATH. Configurando...[/]")

    # Detectar diretório de scripts do pip
    pip_scripts_dir = ""
    try:
        import sysconfig

        pip_scripts_dir = sysconfig.get_path("scripts")
    except Exception:
        pass

    # User scripts dir (--user install)
    user_scripts_dir = ""
    try:
        user_scripts_dir = subprocess.run(
            [sys.executable, "-m", "site", "--user-base"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        if user_scripts_dir:
            if sys.platform == "win32":
                user_scripts_dir = os.path.join(user_scripts_dir, "Scripts")
            else:
                user_scripts_dir = os.path.join(user_scripts_dir, "bin")
    except Exception:
        pass

    # Detectar qual dir usar
    target_dir = pip_scripts_dir or user_scripts_dir
    if not target_dir:
        console.print(f"  [{S_RED}]✗ Não foi possível detectar o diretório de scripts do pip.[/]")
        console.print(f"  [{S_DIM}]Adicione manualmente ao PATH: pip show cascavel[/]")
        return

    # Configurar PATH no shell profile (cross-platform)
    _configure_path_export(target_dir)

    console.print()
    console.print(f"  [{S_GREEN}]🎉 Instalação global completa![/]")
    console.print(f"  [{S_YELLOW}]⚠ Reinicie o terminal ou execute:[/]")
    console.print(f"  [{S_CYAN}]  source ~/.bashrc[/]  [dim]ou[/]  [{S_CYAN}]source ~/.zshrc[/]")
    console.print()
    console.print(f"  [{S_GREEN}]Depois, use de qualquer lugar:[/]")
    console.print(f"  [{S_CYAN}]  cascavel target.com[/]")
    console.print()


def _configure_path_export(scripts_dir: str) -> None:
    """Adiciona diretório ao PATH permanente no shell profile do usuário.

    Cross-platform: bash, zsh, fish, PowerShell, Windows CMD.
    NÃO duplica entradas existentes.
    """
    if sys.platform == "win32":
        # Windows: tenta setx
        try:
            current_path = os.environ.get("PATH", "")
            if scripts_dir.lower() not in current_path.lower():
                subprocess.run(
                    ["setx", "PATH", f"{scripts_dir};{current_path}"],
                    capture_output=True,
                    timeout=10,
                )
                console.print(f"  [{S_GREEN}]✓ PATH atualizado via setx: {scripts_dir}[/]")
            else:
                console.print(f"  [{S_GREEN}]✓ {scripts_dir} já está no PATH.[/]")
        except Exception as e:
            console.print(f"  [{S_YELLOW}]⚠ Falha no setx: {e}[/]")
            console.print(f"  [{S_DIM}]Adicione manualmente: {scripts_dir}[/]")
        return

    # Unix: detectar shells instalados e configurar todos
    home = os.path.expanduser("~")
    export_line = f'export PATH="{scripts_dir}:$PATH"'
    comment_line = "# Cascavel Security Framework — global command"

    shell_profiles = []

    # Bash
    for bashrc in [".bashrc", ".bash_profile", ".profile"]:
        path = os.path.join(home, bashrc)
        if os.path.isfile(path):
            shell_profiles.append(path)
            break
    else:
        # Nenhum encontrado — cria .bashrc
        shell_profiles.append(os.path.join(home, ".bashrc"))

    # Zsh
    zshrc = os.path.join(home, ".zshrc")
    if os.path.isfile(zshrc) or shutil.which("zsh"):
        shell_profiles.append(zshrc)

    # Fish
    fish_config = os.path.join(home, ".config", "fish", "config.fish")
    if os.path.isfile(fish_config) or shutil.which("fish"):
        shell_profiles.append(fish_config)

    for profile in shell_profiles:
        try:
            # Verifica se já está configurado
            existing = ""
            if os.path.isfile(profile):
                with open(profile, encoding="utf-8", errors="replace") as f:
                    existing = f.read()

            if scripts_dir in existing:
                console.print(f"  [{S_GREEN}]✓ PATH já configurado em {os.path.basename(profile)}[/]")
                continue

            # Fish usa sintaxe diferente
            if "fish" in profile:
                fish_line = f'set -gx PATH "{scripts_dir}" $PATH'
                fish_comment = "# Cascavel Security Framework"
                with open(profile, "a", encoding="utf-8") as f:
                    f.write(f"\n{fish_comment}\n{fish_line}\n")
                console.print(f"  [{S_GREEN}]✓ PATH adicionado em {os.path.basename(profile)} (fish)[/]")
            else:
                with open(profile, "a", encoding="utf-8") as f:
                    f.write(f"\n{comment_line}\n{export_line}\n")
                console.print(f"  [{S_GREEN}]✓ PATH adicionado em {os.path.basename(profile)}[/]")

        except (PermissionError, OSError) as e:
            console.print(f"  [{S_YELLOW}]⚠ Falha ao editar {os.path.basename(profile)}: {e}[/]")
            console.print(f"  [{S_DIM}]Adicione manualmente: {export_line}[/]")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # --install-global: instala e sai
    if args.install_global:
        _install_global()
        sys.exit(0)

    # --update: self-update e sai
    if args.update:
        self_update()
        sys.exit(0)

    # --check-update: verifica atualizações e sai
    if args.check_update:
        check_for_update()
        sys.exit(0)

    quiet = args.quiet

    # Resolver target: posicional tem prioridade sobre -t
    raw_target = args.target_positional or args.target

    # Cache resultado para evitar chamar detect_tools() duas vezes
    _cached_available = detect_tools()
    plugin_count = _count_plugins()
    tools_count = sum(1 for v in _cached_available.values() if v)

    # Preloader cinematográfico (com target na tela se disponível)
    if not quiet and not args.no_preloader and not args.list_plugins and not args.check_tools:
        run_preloader(plugin_count, tools_count, target_hint=raw_target)

    if not quiet:
        print_header()

    # Pre-flight check (antes de qualquer scan)
    if not quiet and not args.list_plugins and not args.check_tools:
        _preflight_check()

    if args.check_tools:
        print_tools_status(_cached_available)
        sys.exit(0)

    if args.list_plugins:
        list_plugins_table()
        sys.exit(0)

    # Target — resolve com retry loop
    allow_self = getattr(args, "allow_localhost", False)

    if raw_target:
        target = validate_target(raw_target, allow_self=allow_self)
        if not target:
            # validate_target retornou vazio — pede de novo
            console.print(f"  [{S_YELLOW}]⚠ Target inválido fornecido. Informe novamente:[/]")

            def _target_validator(val: str) -> str:
                result = validate_target(val, allow_self=allow_self)
                if not result:
                    return "Target inválido. Formatos: dominio.com │ 1.2.3.4 │ host:porta"
                return ""

            raw_input = inputx("Target (IP/domain): ", validator=_target_validator)
            target = validate_target(raw_input, allow_self=allow_self)
    else:
        # Nenhum target fornecido — modo interativo com retry
        def _target_validator(val: str) -> str:
            result = validate_target(val, allow_self=allow_self)
            if not result:
                return "Target inválido. Formatos: dominio.com │ 1.2.3.4 │ host:porta"
            return ""

        raw_input = inputx("Target (IP/domain): ", validator=_target_validator)
        target = validate_target(raw_input, allow_self=allow_self)

    if not target:
        console.print(f"  [{S_RED}]✗ Nenhum target válido. Abortando.[/]")
        sys.exit(1)

    out_fmt = "sarif" if args.sarif else ("pdf" if args.pdf else args.output_format)
    run_scan(
        target,
        plugins_only=args.plugins_only,
        no_notify=(args.no_notify or quiet),
        output_format=out_fmt,
        global_timeout=args.timeout,
        profile=getattr(args, "profile", None),
    )

    # Final
    console.print(Rule(f"[{S_GREEN}]🐍 CASCAVEL — Missão Concluída[/]", style="bright_green"))
    console.print(
        Align.center(
            Text.from_markup(
                f"[{S_GREEN}]github.com/glferreira-devsecops/Cascavel[/]\n"
                f"[{S_DIM}]Making the web safer, one target at a time.[/]\n"
            )
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n  [{S_RED}]✗ Interrompido.[/]\n")
        sys.exit(0)
    except BrokenPipeError:
        # Pipe fechado (e.g., python3 cascavel.py --list-plugins | head -5)
        # Flush e fechar stderr para suprimir mensagem Python padrão
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
        os._exit(141)  # 128 + SIGPIPE(13) = exit code padrão Unix
    except Exception as e:
        console.print(f"\n  [{S_RED}]💀 ERRO FATAL: {e}[/]\n")
        sys.exit(1)
