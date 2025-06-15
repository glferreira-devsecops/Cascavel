#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cascavel - Quantum Security Framework
Por DevFerreiraG | github.com/futurodevjunior | linkedin.com/in/DevFerreiraG

Framework de automação pentest plugável, autosuficiente, multi-plataforma (Mac/Linux), integrando ferramentas modernas, plugins customizados e relatórios robustos.
"""

import os
import sys
import subprocess
import datetime
import socket
import glob
import importlib.util
import json
from typing import List, Dict, Any

# --- Depênências Python obrigatórias ---
PYTHON_LIBS = {
    "colorama": "pip install colorama",
    "termcolor": "pip install termcolor",
    "requests": "pip install requests"
}

def check_python_deps():
    for lib, cmd in PYTHON_LIBS.items():
        try:
            __import__(lib)
        except ImportError:
            print(f"\n[!] Dependência Python faltando: '{lib}'. Instale com:\n    {cmd}\n")
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

def print_header():
    print(colored("="*58, "green"))
    print(colored("Cascavel - Quantum Security Framework", "green", attrs=["bold"]))
    print(colored("github.com/futurodevjunior | MIT License", "green"))
    print(colored("="*58, "green"))

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
        log(f"Wordlist não encontrada. Baixando {name} em {dest}", "yellow")
        urllib.request.urlretrieve(url, dest)
        log(f"Wordlist baixada em {dest}", "green")
        return dest
    except Exception as e:
        log(f"Erro ao baixar wordlist {name}: {e}", "red")
        return ""

def ensure_nuclei_templates() -> str:
    nuclei_path = NUCLEI_TEMPLATES_PATH
    if not os.path.isdir(nuclei_path) or not os.listdir(nuclei_path):
        log("Baixando templates do nuclei (isso pode demorar alguns minutos)...", "yellow")
        try:
            subprocess.run(f"nuclei -update-templates -ut {nuclei_path}", shell=True, check=True)
        except Exception as e:
            log(f"Erro ao baixar templates nuclei: {e}", "red")
            return ""
    return nuclei_path

def detect_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return "?"

def run(cmd: str, timeout: int = 90) -> str:
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, encoding="utf-8")
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as e:
        return f"[!] TIMEOUT: {cmd} - {e}"
    except Exception as e:
        return f"[!] ERRO AO EXECUTAR: {cmd} - {e}"

def enum_tools(target: str, ip: str, report: List[str], wordlist: str, nuclei_templates: str, timeouts: Dict[str,int]) -> Dict[str,Any]:
    results = {}
    tools = {
        "subfinder": f"subfinder -silent -d {target}",
        "amass": f"amass enum -d {target}",
        "httpx": f"echo {target} | httpx -silent -title -tech-detect -ip",
        "nmap": f"nmap -Pn -A {target}",
        "ffuf": f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t 40" if wordlist else "",
        "gobuster": f"gobuster dir -u http://{target} -w {wordlist} -q" if wordlist else "",
        "naabu": f"echo {target} | naabu -silent",
        "nuclei": f"echo {target} | nuclei -silent -t {nuclei_templates}" if nuclei_templates else "",
        "curl": f"curl -I http://{target}",
    }
    for name, cmd in tools.items():
        log(f"Executando: {name}", "yellow")
        out = run(cmd, timeout=timeouts.get(name, 90)) if cmd else f"Pré-requisito ausente para {name}."
        results[name] = out
        report.append(f"\n### {name} ({cmd})\n```\n{out}\n```")
    return results

def scan_ports_naabu(naabu_out: str) -> List[int]:
    ports = []
    for line in naabu_out.splitlines():
        try:
            port = int(line.strip())
            if 0 < port < 65536:
                ports.append(port)
        except:
            continue
    return sorted(set(ports))

def run_plugins(target: str, ip: str, open_ports: List[int], banners: Dict[int,str], report: List[str]):
    results = []
    for file_path in sorted(glob.glob(os.path.join(PLUGINS_PATH, "*.py"))):
        name = os.path.splitext(os.path.basename(file_path))[0]
        spec = importlib.util.spec_from_file_location(name, file_path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            if hasattr(module, "run"):
                log(f"Rodando plugin '{name}'...", "magenta")
                try:
                    result = module.run(target, ip, open_ports, banners)
                    results.append((name, result))
                except Exception as e:
                    result = f"Erro ao rodar plugin '{name}': {e}"
                    results.append((name, result))
            else:
                results.append((name, "Plugin não tem função 'run'."))
        except Exception as e:
            results.append((name, f"Erro ao carregar plugin: {e}"))
    if results:
        report.append("\n## Plugins\n")
        for name, result in results:
            content = json.dumps(result, indent=2, ensure_ascii=False) if isinstance(result, (dict, list)) else str(result)
            report.append(f"### {name}\n```\n{content}\n```")

def grab_banners(target: str, open_ports: List[int], timeout: int = 3) -> Dict[int, str]:
    banners = {}
    for port in open_ports:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(512).decode(errors="ignore")
            banners[port] = banner.strip()
            s.close()
        except Exception:
            banners[port] = "N/A"
    return banners

def parse_feroxbuster_json(raw_output: str) -> List[Dict[str, Any]]:
    try:
        return [json.loads(line) for line in raw_output.splitlines() if line.strip()]
    except Exception as e:
        return [{"error": f"Falha ao parsear JSON: {e}"}]

def run_feroxbuster(target: str, wordlist: str) -> List[Dict[str, Any]]:
    output_path = os.path.join(EXPORTS_PATH, f"ferox_{target.replace('.', '_')}.json")
    cmd = f"feroxbuster --url http://{target} --wordlist {wordlist} --json --silent --output {output_path}"
    log("Executando: feroxbuster", "yellow")
    run(cmd, timeout=90)
    if os.path.isfile(output_path):
        with open(output_path, "r") as f:
            raw = f.read()
        return parse_feroxbuster_json(raw)
    return [{"error": "feroxbuster não gerou saída"}]

def save_report(content: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(REPORTS_PATH, f"cascavel_{ts}.md")
    with open(filename, "w") as f:
        f.write(content)
    log(f"Relatório salvo: {filename}", "yellow")
    return filename

def main() -> None:
    print_header()
    target = inputx("Target (IP/domain): ")
    ip = detect_ip(target)
    timeouts = {
        "subfinder": 60, "amass": 60, "httpx": 30, "nmap": 120,
        "ffuf": 45, "gobuster": 45, "naabu": 30, "nuclei": 90, "curl": 10
    }
    wordlist = get_wordlist()
    nuclei_templates = ensure_nuclei_templates()
    report = [f"# Cascavel Report\n**Target**: `{target}`\n**IP**: `{ip}`\n**Timestamp**: `{timestamp()}`\n"]
    results = enum_tools(target, ip, report, wordlist, nuclei_templates, timeouts)
    ferox_data = run_feroxbuster(target, wordlist)
    report.append(f"\n### feroxbuster (JSON)\n```json\n{json.dumps(ferox_data, indent=2, ensure_ascii=False)}\n```")
    open_ports = scan_ports_naabu(results.get("naabu", ""))
    report.append(f"\n### Portas abertas\n`{open_ports}`\n")
    banners = grab_banners(target, open_ports)
    report.append(f"\n### Banners\n```\n{json.dumps(banners, indent=2, ensure_ascii=False)}\n```")
    run_plugins(target, ip, open_ports, banners, report)
    save_report('\n'.join(report))
    log("Cascavel executada com sucesso!", "green")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        log(f"ERRO FATAL: {e}", "red")
