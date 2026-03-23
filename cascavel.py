#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cascavel - Quantum Security Framework
Por DevFerreiraG | github.com/glferreira-devsecops | linkedin.com/in/DevFerreiraG

Framework de automação pentest plugável, autosuficiente, multi-plataforma (Mac/Linux),
integrando ferramentas modernas, plugins customizados e relatórios robustos.
"""

import os
import sys
import subprocess
import datetime
import socket
import glob
import importlib.util
import inspect
import json
import shutil
import re
import argparse
from typing import List, Dict, Any, Optional

__version__ = "2.0.0"

# --- Dependências Python obrigatórias ---
PYTHON_LIBS = {
    "colorama": "pip install colorama",
    "termcolor": "pip install termcolor",
    "requests": "pip install requests",
}


def check_python_deps():
    missing = []
    for lib, cmd in PYTHON_LIBS.items():
        try:
            __import__(lib)
        except ImportError:
            missing.append((lib, cmd))
    if missing:
        print("\n[!] Dependências Python faltando:")
        for lib, cmd in missing:
            print(f"    {lib}: {cmd}")
        print("\nInstale com: pip install -r requirements.txt\n")
        sys.exit(1)


check_python_deps()
from colorama import init
from termcolor import colored

init(autoreset=True)

# --- Caminhos padrão de execução ---
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
EXPORTS_PATH = os.path.join(BASE_PATH, "exports")
REPORTS_PATH = os.path.join(BASE_PATH, "reports")
PLUGINS_PATH = os.path.join(BASE_PATH, "plugins")
WORDLISTS_PATH = os.path.join(BASE_PATH, "wordlists")
NUCLEI_TEMPLATES_PATH = os.path.join(BASE_PATH, "nuclei-templates")

for p in [EXPORTS_PATH, REPORTS_PATH, PLUGINS_PATH, WORDLISTS_PATH, NUCLEI_TEMPLATES_PATH]:
    os.makedirs(p, exist_ok=True)


# --- Utilitários ---
def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str, color: str = "cyan") -> None:
    print(colored(f"[{timestamp()}] {msg}", color))


def inputx(prompt: str, helptext: str = "") -> str:
    if helptext:
        print(colored(helptext, "yellow"))
    try:
        return input(colored(prompt, "cyan", attrs=["bold"]))
    except KeyboardInterrupt:
        log("Execução interrompida pelo usuário.", "red")
        sys.exit(0)


def validate_target(target: str) -> str:
    """Sanitiza e valida o target contra injeção de comandos."""
    target = target.strip()
    if not target:
        log("Target vazio. Abortando.", "red")
        sys.exit(1)
    # Permitir apenas caracteres válidos para domínios/IPs
    if not re.match(r'^[a-zA-Z0-9._\-:]+$', target):
        log(f"Target inválido (caracteres proibidos): {target}", "red")
        sys.exit(1)
    return target


def print_header():
    banner = r"""
   ╔═══════════════════════════════════════════════╗
   ║   🐍 CASCAVEL — Quantum Security Framework   ║
   ║   github.com/glferreira-devsecops | MIT       ║
   ╚═══════════════════════════════════════════════╝
    """
    print(colored(banner, "green", attrs=["bold"]))
    print(colored(f"   v{__version__} | {timestamp()}\n", "green"))


def detect_tools() -> Dict[str, bool]:
    """Detecta ferramentas disponíveis no PATH."""
    tools = [
        "subfinder", "amass", "httpx", "nmap", "ffuf", "gobuster",
        "naabu", "nuclei", "feroxbuster", "curl", "nikto", "sqlmap",
        "wafw00f", "dnsrecon", "fierce", "hydra", "gau", "waybackurls",
        "katana", "dnsx", "asnmap", "mapcidr", "tshark", "sslscan",
        "whatweb", "wpscan", "john",
    ]
    available = {}
    for tool in tools:
        available[tool] = shutil.which(tool) is not None
    return available


def print_tools_status(tools: Dict[str, bool]):
    """Exibe status das ferramentas externas."""
    present = [t for t, v in tools.items() if v]
    absent = [t for t, v in tools.items() if not v]
    log(f"Ferramentas disponíveis ({len(present)}): {', '.join(present)}", "green")
    if absent:
        log(f"Ferramentas ausentes ({len(absent)}): {', '.join(absent)}", "yellow")


# --- Wordlists ---
def get_wordlist(name="common.txt") -> str:
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
        import urllib.request
        log(f"Wordlist não encontrada. Baixando {name}...", "yellow")
        urllib.request.urlretrieve(url, dest)
        log(f"Wordlist baixada: {dest}", "green")
        return dest
    except Exception as e:
        log(f"Erro ao baixar wordlist {name}: {e}", "red")
        return ""


# --- Nuclei Templates ---
def ensure_nuclei_templates() -> str:
    nuclei_path = NUCLEI_TEMPLATES_PATH
    if not shutil.which("nuclei"):
        log("nuclei não encontrado no PATH. Templates ignorados.", "yellow")
        return ""
    if not os.path.isdir(nuclei_path) or not os.listdir(nuclei_path):
        log("Baixando templates do nuclei...", "yellow")
        try:
            subprocess.run(
                f"nuclei -update-templates -ut {nuclei_path}",
                shell=True, check=True, timeout=120
            )
        except Exception as e:
            log(f"Erro ao baixar templates nuclei: {e}", "red")
            return ""
    return nuclei_path


# --- Resolução de IP ---
def detect_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return "?"


# --- Executor de comandos ---
def run(cmd: str, timeout: int = 90) -> str:
    try:
        proc = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, encoding="utf-8"
        )
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return f"[!] TIMEOUT ({timeout}s): {cmd}"
    except Exception as e:
        return f"[!] ERRO: {cmd} - {e}"


# --- Pipeline de Ferramentas ---
def enum_tools(
    target: str, ip: str, report: List[str],
    wordlist: str, nuclei_templates: str,
    timeouts: Dict[str, int], available: Dict[str, bool]
) -> Dict[str, Any]:
    """Executa ferramentas de enumeração, pulando as não disponíveis."""
    results = {}
    tools = {
        "subfinder": f"subfinder -silent -d {target}",
        "amass": f"amass enum -d {target} -timeout 2",
        "httpx": f"echo {target} | httpx -silent -title -tech-detect -ip",
        "nmap": f"nmap -Pn -A {target}",
        "ffuf": f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t 40" if wordlist else "",
        "gobuster": f"gobuster dir -u http://{target} -w {wordlist} -q" if wordlist else "",
        "naabu": f"echo {target} | naabu -silent",
        "nuclei": f"echo {target} | nuclei -silent -t {nuclei_templates}" if nuclei_templates else "",
        "curl": f"curl -sI http://{target}",
        "katana": f"echo http://{target} | katana -silent -d 2 -jc -ct 30",
        "gau": f"echo {target} | gau --threads 3 --blacklist png,jpg,gif,css,woff",
        "dnsx": f"echo {target} | dnsx -silent -a -aaaa -mx -ns -cname -resp",
        "nikto": f"nikto -h http://{target} -maxtime 60s -nointeractive",
        "wafw00f": f"wafw00f {target}",
    }

    for name, cmd in tools.items():
        if not cmd:
            continue
        if not available.get(name, False):
            log(f"⏭️  {name}: não disponível, pulando", "yellow")
            continue
        log(f"⚡ Executando: {name}", "yellow")
        out = run(cmd, timeout=timeouts.get(name, 90))
        results[name] = out
        report.append(f"\n### {name}\n```\n{out[:5000]}\n```")

    return results


# --- Scan de portas ---
def scan_ports_naabu(naabu_out: str) -> List[int]:
    ports = []
    for line in naabu_out.splitlines():
        line = line.strip()
        # naabu output: "host:port" ou just "port"
        if ":" in line:
            try:
                port = int(line.split(":")[-1])
                if 0 < port < 65536:
                    ports.append(port)
            except ValueError:
                continue
        else:
            try:
                port = int(line)
                if 0 < port < 65536:
                    ports.append(port)
            except ValueError:
                continue
    return sorted(set(ports))


# --- Plugin Runner ---
def run_plugins(
    target: str, ip: str, open_ports: List[int],
    banners: Dict[int, str], report: List[str]
) -> List[Dict[str, Any]]:
    """Carrega e executa todos os plugins com a assinatura padronizada."""
    results = []
    plugin_files = sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py")))

    for file_path in plugin_files:
        name = os.path.splitext(os.path.basename(file_path))[0]
        if name.startswith("__"):
            continue

        spec = importlib.util.spec_from_file_location(name, file_path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            if hasattr(module, "run"):
                log(f"🔌 Plugin: {name}", "magenta")
                try:
                    result = module.run(target, ip, open_ports, banners)
                    if result is None:
                        result = {"plugin": name, "resultados": "Plugin executado sem retorno"}
                    results.append(result)
                except TypeError as e:
                    # Fallback para plugins com assinatura antiga
                    log(f"⚠️  Plugin '{name}' com assinatura incompatível: {e}", "yellow")
                    results.append({"plugin": name, "erro": f"Assinatura incompatível: {e}"})
                except Exception as e:
                    results.append({"plugin": name, "erro": str(e)})
            else:
                results.append({"plugin": name, "erro": "Plugin sem função 'run()'"})
        except Exception as e:
            results.append({"plugin": name, "erro": f"Erro ao carregar: {e}"})

    # Adicionar ao relatório
    if results:
        report.append("\n## 🔌 Plugins\n")
        for result in results:
            content = json.dumps(result, indent=2, ensure_ascii=False)
            plugin_name = result.get("plugin", "unknown")
            report.append(f"### {plugin_name}\n```json\n{content}\n```")

    return results


def list_plugins() -> List[str]:
    """Lista todos os plugins disponíveis."""
    plugins = []
    for file_path in sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py"))):
        name = os.path.splitext(os.path.basename(file_path))[0]
        if name.startswith("__"):
            continue
        # Extrair docstring
        try:
            spec = importlib.util.spec_from_file_location(name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            doc = ""
            if hasattr(module, "run") and module.run.__doc__:
                doc = module.run.__doc__.strip().split("\n")[0]
            plugins.append(f"  {name:<25} {doc}")
        except Exception:
            plugins.append(f"  {name:<25} (erro ao carregar)")
    return plugins


# --- Banner Grabbing ---
def grab_banners(target: str, open_ports: List[int], timeout: int = 3) -> Dict[int, str]:
    banners = {}
    for port in open_ports[:20]:  # Limitar a 20 portas
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(512).decode(errors="ignore")
            banners[port] = banner.strip()
        except Exception:
            banners[port] = "N/A"
        finally:
            try:
                s.close()
            except Exception:
                pass
    return banners


# --- Feroxbuster ---
def parse_feroxbuster_json(raw_output: str) -> List[Dict[str, Any]]:
    try:
        return [json.loads(line) for line in raw_output.splitlines() if line.strip()]
    except Exception as e:
        return [{"error": f"Falha ao parsear JSON: {e}"}]


def run_feroxbuster(target: str, wordlist: str, available: Dict[str, bool]) -> List[Dict[str, Any]]:
    if not available.get("feroxbuster", False):
        return [{"aviso": "feroxbuster não disponível"}]
    if not wordlist:
        return [{"aviso": "wordlist não configurada"}]

    output_path = os.path.join(EXPORTS_PATH, f"ferox_{target.replace('.', '_')}.json")
    cmd = f"feroxbuster --url http://{target} --wordlist {wordlist} --json --silent --output {output_path}"
    log("⚡ Executando: feroxbuster", "yellow")
    run(cmd, timeout=90)
    if os.path.isfile(output_path):
        with open(output_path, "r") as f:
            raw = f.read()
        return parse_feroxbuster_json(raw)
    return [{"error": "feroxbuster não gerou saída"}]


# --- Relatório ---
def save_report(content: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(REPORTS_PATH, f"cascavel_{ts}.md")
    with open(filename, "w") as f:
        f.write(content)
    log(f"📄 Relatório salvo: {filename}", "green")
    return filename


# --- CLI ---
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cascavel",
        description="🐍 Cascavel — Quantum Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="GitHub: https://github.com/glferreira-devsecops/Cascavel",
    )
    parser.add_argument("-t", "--target", type=str, help="Target (IP/domínio)")
    parser.add_argument("-v", "--version", action="version", version=f"Cascavel v{__version__}")
    parser.add_argument("--list-plugins", action="store_true", help="Lista plugins disponíveis")
    parser.add_argument("--plugins-only", action="store_true", help="Executa apenas os plugins (sem ferramentas)")
    parser.add_argument("--check-tools", action="store_true", help="Verifica ferramentas instaladas")
    return parser


# --- Main ---
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print_header()

    # Detectar ferramentas disponíveis
    available = detect_tools()

    if args.check_tools:
        print_tools_status(available)
        sys.exit(0)

    if args.list_plugins:
        log("Plugins disponíveis:", "green")
        for p in list_plugins():
            print(p)
        sys.exit(0)

    # Obter target
    if args.target:
        target = validate_target(args.target)
    else:
        target = validate_target(inputx("Target (IP/domain): "))

    ip = detect_ip(target)
    print_tools_status(available)

    timeouts = {
        "subfinder": 60, "amass": 60, "httpx": 30, "nmap": 120,
        "ffuf": 45, "gobuster": 45, "naabu": 30, "nuclei": 90,
        "curl": 10, "katana": 60, "gau": 60, "dnsx": 20,
        "nikto": 120, "wafw00f": 20,
    }

    wordlist = get_wordlist()
    nuclei_templates = ensure_nuclei_templates()

    report = [
        f"# 🐍 Cascavel Report\n",
        f"**Target**: `{target}`\n**IP**: `{ip}`\n**Timestamp**: `{timestamp()}`\n",
        f"**Cascavel Version**: `v{__version__}`\n",
        f"**Ferramentas disponíveis**: {sum(1 for v in available.values() if v)}/{len(available)}\n",
    ]

    # Executar pipeline de ferramentas
    if not args.plugins_only:
        results = enum_tools(target, ip, report, wordlist, nuclei_templates, timeouts, available)
        ferox_data = run_feroxbuster(target, wordlist, available)
        report.append(f"\n### feroxbuster (JSON)\n```json\n{json.dumps(ferox_data, indent=2, ensure_ascii=False)[:5000]}\n```")

        # Scan de portas
        open_ports = scan_ports_naabu(results.get("naabu", ""))
        report.append(f"\n### Portas abertas\n`{open_ports}`\n")

        # Banners
        banners = grab_banners(target, open_ports)
        report.append(f"\n### Banners\n```json\n{json.dumps(banners, indent=2, ensure_ascii=False)}\n```")
    else:
        log("Modo --plugins-only: pulando ferramentas externas", "yellow")
        open_ports = []
        banners = {}

    # Plugins
    run_plugins(target, ip, open_ports, banners, report)

    # Salvar relatório
    save_report("\n".join(report))
    log("🐍 Cascavel executada com sucesso!", "green")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrompido pelo usuário.", "red")
        sys.exit(0)
    except Exception as e:
        log(f"ERRO FATAL: {e}", "red")
        sys.exit(1)
