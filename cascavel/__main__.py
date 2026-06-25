"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Entry Point (__main__)                           ║
╚═══════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import sys
import time
from typing import NoReturn

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from .constants import S_CYAN, S_DIM, S_GREEN, S_RED, S_YELLOW, __version__
from .engine import _classify, _count_plugins, _count_sev, run_plugins
from .reporters import _sanitize_for_json, save_json_report, save_report
from .security import setup_signals
from .tools import (
    detect_ip,
    detect_tools,
    ensure_nuclei_templates,
    enum_tools,
    get_wordlist,
    grab_banners,
    run_feroxbuster,
    scan_ports,
)
from .ui import (
    list_plugins_table,
    print_dashboard,
    print_header,
    print_target_card,
    print_tools_status,
    run_preloader,
    send_notification,
)
from .updater import check_for_update, self_update
from .validators import inputx, validate_target

console = Console()

# Setup signal handlers
setup_signals()

# Suppress SSL warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CascavelArgumentParser(argparse.ArgumentParser):
    """ArgumentParser customizado com error handling amigável."""

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
        description="🐍 Cascavel — Advanced Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  cascavel target.com                     Scan direto\n"
        "  cascavel -t target.com                  Full scan\n"
        "  cascavel -t target.com --plugins-only   Plugins only\n"
        "  cascavel -t target.com -q -o json       Quiet + JSON\n"
        "  cascavel --list-plugins                 Show arsenal\n"
        "  cascavel --check-tools                  Verify tools\n"
        "  cascavel --install-global               Install globally",
    )
    parser.add_argument("target_positional", nargs="?", default=None, help="Target direto (IP/domínio)")
    parser.add_argument("-t", "--target", help="Target (IP/domínio)")
    parser.add_argument("-v", "--version", action="version", version=f"v{__version__}")
    parser.add_argument("--list-plugins", action="store_true", help="Lista plugins disponíveis")
    parser.add_argument("--plugins-only", action="store_true", help="Executa apenas plugins")
    parser.add_argument("--check-tools", action="store_true", help="Verifica ferramentas externas")
    parser.add_argument("--no-preloader", action="store_true", help="Desativa preloader")
    parser.add_argument("--no-notify", action="store_true", help="Desativa notificação pós-scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")
    parser.add_argument("-o", "--output-format", choices=["md", "json", "pdf", "sarif", "ocsf"], default="md")
    parser.add_argument("--pdf", action="store_true", help="Gera relatório PDF")
    parser.add_argument("--sarif", action="store_true", help="Gera relatório SARIF")
    parser.add_argument("--profile", choices=["web", "api", "cloud", "network", "full"], default=None)
    parser.add_argument("--install-global", action="store_true", help="Instala globalmente")
    parser.add_argument("--update", action="store_true", help="Atualiza o Cascavel")
    parser.add_argument("--check-update", action="store_true", help="Verifica atualizações")
    parser.add_argument("--stealth-eval", action="store_true", help="Injeta headers stealth")
    parser.add_argument("--ai-fix", action="store_true", help="Gera scripts de mitigação via IA")
    parser.add_argument("--plugin-filter", nargs="+", help="Filtra plugins específicos")

    def _positive_int(value: str) -> int:
        try:
            ivalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' não é um inteiro válido") from None
        if ivalue <= 0:
            raise argparse.ArgumentTypeError("Timeout deve ser > 0")
        if ivalue > 600:
            raise argparse.ArgumentTypeError("Timeout máximo: 600s")
        return ivalue

    parser.add_argument("--timeout", type=_positive_int, default=90, help="Timeout global (1-600s)")
    parser.add_argument("--allow-localhost", action="store_true", help="Permite scan em localhost")
    return parser


def _load_profile(profile_name: str) -> list[str] | None:
    """Load a scan profile from profiles/ directory."""
    import yaml

    from .constants import PROFILES_PATH

    profile_path = PROFILES_PATH / f"{profile_name}.yaml"
    if not profile_path.is_file():
        console.print(f"  [{S_YELLOW}]⚠ Profile '{profile_name}' não encontrado.[/]")
        return None

    with open(profile_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None
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
    return plugin_list


def run_scan(
    target: str,
    plugins_only: bool = False,
    no_notify: bool = False,
    output_format: str = "md",
    global_timeout: int = 90,
    profile: str | None = None,
    stealth_eval: bool = False,
    ai_fix: bool = False,
    plugin_filter: list[str] | None = None,
) -> None:
    """Executa o scan completo contra o target."""
    mission_start = time.time()

    if stealth_eval:
        console.print(f"  [{S_YELLOW}]🥷 Modo COST Ativado[/]")
        import requests

        _orig_request = requests.Session.request

        def _stealth_request(self, method, url, **kwargs):
            headers = kwargs.get("headers", {})
            if isinstance(headers, dict):
                h = dict(headers)
                h["X-Cascavel-Test"] = "true"
                h["X-COST-Simulation"] = "active"
                kwargs["headers"] = h
            return _orig_request(self, method, url, **kwargs)

        requests.Session.request = _stealth_request

    _active_plugins: list[str] | None = None
    if profile:
        _active_plugins = _load_profile(profile)

    if plugin_filter:
        if _active_plugins is not None:
            _active_plugins = list(set(_active_plugins).intersection(plugin_filter))
        else:
            _active_plugins = plugin_filter

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
        f"**Target**: `{target}`\n**IP**: `{ip}`\n**Timestamp**: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n",
        f"**Versão**: `v{__version__}`\n",
    ]

    open_ports: list[int] = []
    banners: dict[int, str] = {}

    if not plugins_only:
        results = enum_tools(target, report, wordlist, nuclei_templates, timeouts, available)
        ferox = run_feroxbuster(target, wordlist, available)
        safe_ferox = _sanitize_for_json(ferox)
        ferox_json: str = json.dumps(safe_ferox, indent=2, ensure_ascii=False)
        ferox_truncated: str = ferox_json[:5000] if len(ferox_json) > 5000 else ferox_json
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

    plugin_results = run_plugins(target, ip, open_ports, banners, report, plugin_filter=_active_plugins)

    # Threat Intel Enrichment
    try:
        from .threat_intel import enrich_results

        plugin_results = enrich_results(plugin_results, console)
    except ImportError:
        pass
    except Exception as e:
        console.print(f"  [{S_YELLOW}]⚠ Erro no Threat Intel: {e}[/]")

    # AI Remediation
    if ai_fix:
        try:
            from .ai_remediation import generate_ai_fixes

            plugin_results = generate_ai_fixes(plugin_results, console)
        except ImportError:
            pass
        except Exception as e:
            console.print(f"  [{S_YELLOW}]⚠ Erro na IA Remediation: {e}[/]")

    if plugin_results:
        report.append("\n## 🔌 Plugins\n")
        for r in plugin_results:
            content = json.dumps(r, indent=2, ensure_ascii=False)
            report.append(f"### {r.get('plugin', '?')}\n```json\n{content}\n```")

    elapsed_total = time.time() - mission_start
    if output_format == "json":
        report_path = save_json_report(target, ip, plugin_results, elapsed_total)
    elif output_format == "sarif":
        try:
            from .sarif_exporter import export_sarif

            report_path = export_sarif(target, ip, plugin_results, elapsed_total)
            console.print(f"  [bold bright_green]📋 SARIF Report: {report_path}[/]")
        except ImportError:
            report_path = save_report("\n".join(report))
    elif output_format == "pdf":
        try:
            from .report_generator import generate_pdf_report

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
            report_path = save_report("\n".join(report))
    elif output_format == "ocsf":
        try:
            from .ocsf_exporter import export_ocsf

            report_path = export_ocsf(target, ip, plugin_results, elapsed_total)
            console.print(f"  [bold bright_green]📋 OCSF Report: {report_path}[/]")
        except ImportError:
            report_path = save_report("\n".join(report))
    else:
        report_path = save_report("\n".join(report))

    total_findings = sum(
        sum(_count_sev(r.get("resultados", "")).values()) for r in plugin_results if _classify(r)[0] == "vuln"
    )
    print_dashboard(target, ip, plugin_results, elapsed_total, report_path)

    if not no_notify:
        send_notification(target, report_path, total_findings)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.install_global:
        from .updater import _install_global

        _install_global()
        sys.exit(0)

    if args.update:
        self_update()
        sys.exit(0)

    if args.check_update:
        check_for_update()
        sys.exit(0)

    quiet = args.quiet
    raw_target = args.target_positional or args.target

    _cached_available = detect_tools()
    plugin_count = _count_plugins()
    tools_count = sum(1 for v in _cached_available.values() if v)

    if not quiet and not args.no_preloader and not args.list_plugins and not args.check_tools:
        run_preloader(plugin_count, tools_count, target_hint=raw_target)

    if not quiet:
        print_header()

    if not quiet and not args.list_plugins and not args.check_tools:
        from .preflight import preflight_check

        preflight_check()

    if args.check_tools:
        print_tools_status(_cached_available)
        sys.exit(0)

    if args.list_plugins:
        list_plugins_table()
        sys.exit(0)

    allow_self = getattr(args, "allow_localhost", False)

    if raw_target:
        target = validate_target(raw_target, allow_self=allow_self)
        if not target:
            console.print(f"  [{S_YELLOW}]⚠ Target inválido. Informe novamente:[/]")

            def _target_validator(val: str) -> str:
                result = validate_target(val, allow_self=allow_self)
                if not result:
                    return "Target inválido. Formatos: dominio.com │ 1.2.3.4 │ host:porta"
                return ""

            raw_input = inputx("Target (IP/domain): ", validator=_target_validator)
            target = validate_target(raw_input, allow_self=allow_self)
    else:

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
        stealth_eval=getattr(args, "stealth_eval", False),
        ai_fix=getattr(args, "ai_fix", False),
        plugin_filter=getattr(args, "plugin_filter", None),
    )

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
        try:
            sys.stdout.close()
        except Exception as _exc:
            pass
        try:
            sys.stderr.close()
        except Exception as _exc:
            pass
        os._exit(141)
    except Exception as e:
        console.print(f"\n  [{S_RED}]💀 ERRO FATAL: {e}[/]\n")
        sys.exit(1)
