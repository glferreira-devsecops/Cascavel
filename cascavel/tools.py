"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — External Tools Pipeline                          ║
║  Detection, execution, wordlists, nuclei templates           ║
╚═══════════════════════════════════════════════════════════════╝
"""

import concurrent.futures
import datetime
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import time
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule

from .constants import (
    NUCLEI_TEMPLATES_PATH,
    REPORTS_PATH,
    S_CYAN,
    S_DIM,
    S_GREEN,
    S_RED,
    S_WHITE,
    S_YELLOW,
    WORDLISTS_PATH,
)

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
EXTERNAL_TOOLS = [
    "subfinder", "amass", "httpx", "nmap", "ffuf", "gobuster", "naabu",
    "nuclei", "feroxbuster", "curl", "nikto", "sqlmap", "wafw00f",
    "dnsrecon", "fierce", "hydra", "gau", "waybackurls", "katana",
    "dnsx", "asnmap", "mapcidr", "tshark", "sslscan", "whatweb",
    "wpscan", "john", "whois", "traceroute", "dig",
    # 2026 additions
    "trivy", "grype", "syft", "crackmapexec", "impacket", "pacu",
    "binwalk", "mobfs", "spiderfoot", "trufflehog", "gitleaks",
    "wfuzz", "aircrack-ng", "wifite2", "bettercap", "mitmproxy",
    "cdk", "peirates", "kube-hunter", "kubeaudit", "schemathesis",
    "massdns", "shuffledns", "subjack", "linpeas", "winpeas",
    "sliver", "evilginx2", "gophish", "ghidra", "radare2",
]


def _check_single_tool(tool: str) -> tuple[str, bool, str]:
    """Verifica uma ferramenta e retorna (nome, disponível, versão)."""
    path = shutil.which(tool)
    if not path:
        return (tool, False, "")
    version = ""
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=3,
        )
        out = (result.stdout or "") + (result.stderr or "")
        ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
        if ver_match:
            version = ver_match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, PermissionError):
        pass
    return (tool, True, version)


def detect_tools() -> dict[str, bool]:
    """Detecta ferramentas externas em paralelo com ThreadPoolExecutor."""
    return {tool: shutil.which(tool) is not None for tool in EXTERNAL_TOOLS}


def detect_tools_with_versions() -> dict[str, tuple[bool, str]]:
    """Versão estendida: retorna {tool: (disponível, versão)} em paralelo."""
    results = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(_check_single_tool, t): t for t in EXTERNAL_TOOLS}
            for future in concurrent.futures.as_completed(futures, timeout=10):
                try:
                    name, available, version = future.result(timeout=5)
                    results[name] = (available, version)
                except (concurrent.futures.TimeoutError, Exception):
                    tool_name = futures[future]
                    results[tool_name] = (False, "")
    except Exception:
        for tool in EXTERNAL_TOOLS:
            results[tool] = (shutil.which(tool) is not None, "")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════
def _stderr_log(tool_name: str, stderr_content: str) -> None:
    """Loga stderr de ferramentas externas para debug."""
    try:
        log_path = os.path.join(REPORTS_PATH, "stderr.log")
        if os.path.isfile(log_path) and os.path.getsize(log_path) > 1_048_576:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"--- LOG ROTATED {datetime.datetime.now().isoformat()} ---\n")
        with open(log_path, "a", encoding="utf-8") as f:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            stderr_lines: list[str] = stderr_content.split("\n")
            first_ten: list[str] = stderr_lines if len(stderr_lines) <= 10 else [stderr_lines[i] for i in range(10)]
            for line in first_ten:
                f.write(f"[{ts}] [{tool_name}] {line}\n")
    except (PermissionError, OSError):
        pass


def run_cmd(cmd: str, timeout: int = 90) -> str:
    """Executa comando shell com process group kill on timeout."""
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
        raw_out: bytes = stdout_bytes if isinstance(stdout_bytes, bytes) else b""
        raw_err: bytes = stderr_bytes if isinstance(stderr_bytes, bytes) else b""
        out: str = raw_out.decode("utf-8", errors="replace")
        err: str = raw_err.decode("utf-8", errors="replace")

        if err.strip():
            _cmd_name = cmd.split()[0] if cmd.strip() else "unknown"
            _stderr_log(_cmd_name, err.strip())

        return out
    except subprocess.TimeoutExpired:
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
# IP DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
def detect_ip(target: str) -> str:
    """Resolve target IP with timeout and IPv6 fallback."""
    host = target.split(":")[0] if ":" in target else target
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addrs:
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


# ═══════════════════════════════════════════════════════════════════════════════
# PORT SCANNING & BANNERS
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
    host = target.split(":")[0] if ":" in target else target
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
            chunks = []
            total = 0
            while total < 1024:
                try:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                except (TimeoutError, OSError):
                    break
            raw_banner: str = b"".join(chunks).decode(errors="ignore").strip()
            banners[port] = raw_banner if len(raw_banner) <= 512 else raw_banner[:512]
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
# WORDLISTS & NUCLEI TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════
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
        import requests
        resp = requests.get(url, timeout=(3.05, 10), stream=True, allow_redirects=False)
        resp.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        console.print(f"  [{S_GREEN}]✓ Wordlist: {dest}[/]")
        return dest
    except Exception as e:
        console.print(f"  [{S_RED}]✗ Erro wordlist: {e}[/]")
        return ""


def ensure_nuclei_templates() -> str:
    """Garante templates nuclei atualizados."""
    if not shutil.which("nuclei"):
        return ""
    try:
        ver_out = subprocess.run(
            ["nuclei", "-version"], capture_output=True, text=True, timeout=10,
        )
        ver_str = (ver_out.stdout + ver_out.stderr).strip()
        if ver_str:
            ver_match = re.search(r"(\d+\.\d+\.\d+)", ver_str)
            if ver_match:
                parts = ver_match.group(1).split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                if (major, minor, patch) < (3, 3, 2):
                    console.print(
                        f"  [{S_YELLOW}]⚠ Nuclei {ver_match.group(1)} — CVE-2024-43405. Atualize para ≥ 3.3.2![/]"
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
    return str(NUCLEI_TEMPLATES_PATH)


# ═══════════════════════════════════════════════════════════════════════════════
# EXTERNAL TOOLS PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════
def enum_tools(
    target: str, report: list[str], wordlist: str,
    nuclei_templates: str, timeouts: dict[str, int],
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
        "gobuster": (f"gobuster dir -u http://{safe} -w {wordlist} -q") if wordlist else "",
        "naabu": f"echo {safe} | naabu -silent",
        "nuclei": (f"echo {safe} | nuclei -silent -t {nuclei_templates}") if nuclei_templates else "",
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
            truncated_out: str = out if len(out) <= 5000 else out[:5000]
            safe_out: str = truncated_out.encode("utf-8", errors="replace").decode("utf-8")
            report.append(f"\n### {name}\n```\n{safe_out}\n```")
            progress.advance(overall)
            console.print(f"    [green]✓[/] {name} [{S_DIM}]({elapsed:.1f}s)[/]")

    console.print()
    return results


def run_feroxbuster(target: str, wordlist: str, available: dict[str, bool]) -> list[dict[str, Any]]:
    """Executa feroxbuster se disponível."""
    if not available.get("feroxbuster", False) or not wordlist:
        return []
    safe = shlex.quote(target)
    cmd = f"feroxbuster -u http://{safe} -w {wordlist} -q --silent --json"
    out = run_cmd(cmd, timeout=60)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                import json
                results.append(json.loads(line))
            except Exception:
                pass
    return results
