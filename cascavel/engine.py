"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Plugin Engine & Scan Orchestrator                ║
║  Plugin loading, execution, baselines, scan pipeline         ║
╚═══════════════════════════════════════════════════════════════╝
"""

import glob
import importlib.util
import os
import random
import signal
import time
import urllib.parse
import urllib.request
from typing import Any

import requests
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

from .constants import (
    PLUGINS_PATH,
    S_CYAN,
    S_DIM,
    S_GREEN,
    S_RED,
    S_WHITE,
    SEV_MAP,
)
from .security import _sanitize_output

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY INTEL — RETENÇÃO DE ATENÇÃO
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
# PLUGIN COUNT
# ═══════════════════════════════════════════════════════════════════════════════
def _count_plugins() -> int:
    return sum(
        1
        for f in glob.glob(os.path.join(PLUGINS_PATH, "*.py"))
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════
def _exec_plugin(
    path: str,
    name: str,
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[int, str],
    timeout: int = 120,
    global_context: dict | None = None,
) -> dict[str, Any]:
    """Executa um plugin com timeout guard (SIGALRM, 120s padrão)."""
    import importlib.machinery as _ilm

    spec: _ilm.ModuleSpec | None = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        return {"plugin": name, "erro": "Módulo não resolvido"}
    loader = spec.loader
    if loader is None:
        return {"plugin": name, "erro": "Loader não disponível"}

    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)

    try:
        import inspect

        sig = inspect.signature(mod.run)
        has_context = "context" in sig.parameters
    except Exception:
        has_context = False

    if not hasattr(mod, "run"):
        return {"plugin": name, "erro": "Sem função run()"}

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
        if not global_context:
            global_context = {"baseline_latency": 0.5, "baseline_404_len": 0, "discovered_params": []}

        if has_context:
            result = mod.run(target, ip, ports, banners, context=global_context)
        else:
            result = mod.run(target, ip, ports, banners)

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
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
    return {"plugin": name, "erro": "Execução inesperada"}


# ═══════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
def _classify(result: dict[str, Any]) -> tuple:
    """Classifica resultado de plugin como vuln, erro, deprecated ou limpo."""
    if "erro" in result:
        return "erro", S_RED, "✗"
    resultados = result.get("resultados", "")
    if isinstance(resultados, str):
        return "limpo", "green", "✓"
    if isinstance(resultados, dict):
        status = resultados.get("status", "")
        if status == "DEPRECATED":
            return "limpo", S_DIM, "○"
        aviso = resultados.get("aviso", "")
        if "DEPRECATED" in str(aviso).upper():
            return "limpo", S_DIM, "○"
        if status == "vulneravel" or resultados.get("vulns"):
            return "vuln", S_RED, "⚠"
        return "limpo", "green", "✓"
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


# ═══════════════════════════════════════════════════════════════════════════════
# BASELINES & PARAMETER DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
def _calculate_baselines(target: str) -> dict:
    """Calcula baselines dinâmicos para eliminação de Falsos Positivos."""
    latencies = []
    for _ in range(3):
        try:
            start = time.time()
            requests.get(f"http://{target}/", timeout=8)
            latencies.append(time.time() - start)
        except Exception:
            continue
    baseline_latency = sum(latencies) / len(latencies) if latencies else 0.5

    try:
        resp = requests.get(f"http://{target}/cascavel_nao_existe_12345", timeout=5)
        baseline_404_len = len(resp.text)
    except Exception:
        baseline_404_len = 0

    return {"baseline_latency": baseline_latency, "baseline_404_len": baseline_404_len}


def _discover_parameters(target: str) -> list[str]:
    """Spidering rápido para descoberta de parâmetros reais."""
    params: set[str] = set()
    if BeautifulSoup is None:
        default_params = ["id", "user", "username", "page", "name", "search", "query", "email", "key"]
        return default_params
    try:
        resp = requests.get(f"http://{target}/", timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")

        for a in soup.find_all("a", href=True):
            href_val = a["href"]
            if isinstance(href_val, list):
                href_val = href_val[0]
            parsed = urllib.parse.urlparse(str(href_val))
            query = urllib.parse.parse_qs(parsed.query)
            params.update(query.keys())

        for form in soup.find_all("form"):
            for input_tag in form.find_all(["input", "select", "textarea"]):
                name = input_tag.get("name")
                if name:
                    if isinstance(name, list):
                        name = name[0]
                    params.add(str(name))
    except Exception as exc:
        console.print(f"[yellow][!] Falha na descoberta de parâmetros: {exc}[/yellow]")

    default_params = ["id", "user", "username", "page", "name", "search", "query", "email", "key"]
    params.update(default_params)
    return list(params)


# ═══════════════════════════════════════════════════════════════════════════════
# INTEL PANEL
# ═══════════════════════════════════════════════════════════════════════════════
def _build_intel_panel(intel_idx: int, scan_stats: dict[str, int], elapsed: float) -> Panel:
    """Constrói painel lateral de Security Intel."""
    if not SECURITY_INTEL:
        return Panel("[dim]Sem intel disponível[/]", border_style="dim")

    tag, tip = SECURITY_INTEL[intel_idx % len(SECURITY_INTEL)]
    intel_text = Text()
    intel_text.append(f"\n  {tag}\n", style="bold bright_yellow")
    intel_text.append(f"  {tip}\n\n", style="white")

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

    next_tag, next_tip = SECURITY_INTEL[(intel_idx + 1) % len(SECURITY_INTEL)]
    next_text = Text()
    next_text.append(f"\n  NEXT: {next_tag}\n", style="dim bright_cyan")
    safe_len: int = min(55, len(next_tip))
    was_truncated: bool = len(next_tip) > safe_len
    tip_prefix: str = "".join([next_tip[i] for i in range(safe_len)])
    truncated: str = tip_prefix.rsplit(" ", 1)[0] if was_truncated else next_tip
    suffix = "..." if was_truncated else ""
    next_text.append(f"  {truncated}{suffix}\n", style="dim")

    from rich.console import Group

    content = Group(
        Panel(intel_text, border_style="bright_yellow", title="[bold yellow]🧠 SECURITY INTEL[/]", box=box.ROUNDED),
        Panel(stats, border_style="bright_green", title="[bold green]📊 LIVE STATS[/]", box=box.ROUNDED),
        Panel(next_text, border_style="dim cyan", title="[dim]PRÓXIMO[/]", box=box.SIMPLE),
    )
    return Panel(content, border_style="bright_cyan", title=f"[{S_CYAN}]🐍 CASCAVEL INTEL[/]", box=box.DOUBLE_EDGE)


# ═══════════════════════════════════════════════════════════════════════════════
# RUN PLUGINS
# ═══════════════════════════════════════════════════════════════════════════════
def run_plugins(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[int, str],
    report: list[str],
    plugin_filter: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Executa plugins com split-screen: scan table + security intel."""
    results: list[dict[str, Any]] = []
    plugin_files = sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py")))
    valid = [
        (f, os.path.splitext(os.path.basename(f))[0])
        for f in plugin_files
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
    ]
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

    with console.status("[bold cyan]🕸️ Calculando Baselines e Descobrindo Parâmetros...[/]", spinner="dots"):
        baselines = _calculate_baselines(target)
        discovered_params = _discover_parameters(target)
        global_context = {
            "baseline_latency": baselines["baseline_latency"],
            "baseline_404_len": baselines["baseline_404_len"],
            "discovered_params": discovered_params,
            "oob_server": f"{target}.oob.cascavel.io",
        }

    console.print(
        f"    [green]✓[/] Baselines: Latency={global_context['baseline_latency']:.2f}s | 404_Len={global_context['baseline_404_len']} bytes"
    )
    console.print(f"    [green]✓[/] Parâmetros Descobertos: {len(discovered_params)} parâmetros para fuzzing.\n")

    intel_order = list(range(len(SECURITY_INTEL)))
    random.shuffle(intel_order)
    intel_idx = 0
    scan_start = time.time()

    def _build_table(rows: list, current_idx: int, current_name: str) -> Table:
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

        row_count: int = len(rows)
        if row_count > 15:
            start_idx: int = row_count - 15
            display_rows: list = [rows[i] for i in range(start_idx, row_count)]
            t.add_row("", f"[dim]... {row_count - 15} anteriores ...[/]", "", "", "", "")
        else:
            display_rows = list(rows)
        for row in display_rows:
            t.add_row(*row)

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
        layout = Layout()
        layout.split_row(Layout(name="scan", ratio=3), Layout(name="intel", ratio=1, minimum_size=30))
        layout["scan"].update(_build_table(rows, current_idx, current_name))
        safe_intel_i = intel_order[intel_i % len(intel_order)] if intel_order else 0
        layout["intel"].update(_build_intel_panel(safe_intel_i, scan_stats, time.time() - scan_start))
        return layout

    table_rows: list = []

    try:
        with Live(
            _build_layout(table_rows, 1, valid[0][1] if valid else "", 0), console=console, refresh_per_second=4
        ) as live:
            for idx, (file_path, name) in enumerate(valid, 1):
                t0 = time.time()
                try:
                    result = _exec_plugin(file_path, name, target, ip, ports, banners, global_context=global_context)
                except Exception as e:
                    result = {"plugin": name, "erro": f"Crash: {e}"}
                results.append(result)

                elapsed = time.time() - t0
                cls, style, icon = _classify(result)

                if cls == "erro":
                    err_desc: str = str(result.get("erro", "?"))
                    err_trunc: str = err_desc if len(err_desc) <= 30 else err_desc[:30]
                    desc = f"[red]{err_trunc}[/]"
                    sev_str = ""
                    scan_stats["err"] = scan_stats.get("err", 0) + 1
                elif cls == "vuln":
                    sevs = _count_sev(result.get("resultados", ""))
                    parts: list[str] = []
                    for sn, sc in sevs.items():
                        if sc > 0:
                            si = SEV_MAP.get(sn, (S_DIM, "○"))
                            parts.append(f"[{si[0]}]{si[1]}{sc}[/]")
                            scan_stats[sn] = scan_stats.get(sn, 0) + sc
                    sev_str = " ".join(parts)
                    total_v = sum(sevs.values())
                    desc = f"[{S_RED}]{total_v} vulns[/]"
                    scan_stats["vuln"] = scan_stats.get("vuln", 0) + 1
                else:
                    r = result.get("resultados", "")
                    r_str: str = str(r)
                    r_trunc: str = r_str if len(r_str) <= 30 else r_str[:30]
                    desc = f"[green]{r_trunc}[/]" if isinstance(r, str) else "[green]Limpo[/]"
                    sev_str = "[green]—[/]"
                    scan_stats["ok"] = scan_stats.get("ok", 0) + 1

                table_rows.append(
                    (str(idx), name, f"[{style}]{icon}[/]", desc, sev_str or "[green]—[/]", f"{elapsed:.1f}s")
                )

                if idx % 2 == 0:
                    intel_idx = intel_idx + 1

                next_name = valid[idx][1] if idx < len(valid) else "Concluindo..."
                live.update(_build_layout(table_rows, min(idx + 1, total), next_name, intel_idx))
    except Exception as layout_err:
        console.print(f"  [dim]Live display falhou ({layout_err}), executando sem UI...[/]")
        for idx, (file_path, name) in enumerate(valid, 1):
            try:
                result = _exec_plugin(file_path, name, target, ip, ports, banners, global_context=global_context)
            except Exception as e:
                result = {"plugin": name, "erro": f"Crash: {e}"}
            results.append(result)
            cls, style, icon = _classify(result)
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
    return results
