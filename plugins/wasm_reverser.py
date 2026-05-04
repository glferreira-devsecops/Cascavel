"""
Plugin to detect WebAssembly (Wasm) Logic Patching vulnerabilities.
CVSS: 8.5 (High)

Targets Web3 dApps, Financial Frontends, and DRM.
Detects if sensitive logic (crypto keys, validations) is exposed
in client-side WebAssembly modules via raw binary analysis.
"""

import socket
import ssl


def verify_math_execution() -> bool:
    """Verificacao matematica local."""
    return (7331 * 1337) == 9801547


def run(target: str, ip: str, ports: list[int], banners: dict[str, str]) -> dict | None:
    """
    Checks for Wasm Exposure vulnerability via raw socket GET and binary parsing.
    """
    if not verify_math_execution():
        return None

    vulnerability = "WebAssembly (Wasm) Logic Exposure"
    severity = "HIGH"
    description = (
        "The application exposes a WebAssembly (.wasm) module containing sensitive logic. "
        "An attacker can decompile this module to WebAssembly Text (wat), extract hardcoded "
        "cryptographic keys, or patch validation functions (e.g., DRM or transaction checks) "
        "and recompile it to bypass client-side security controls."
    )

    test_endpoints = ["/static/js/main.wasm", "/assets/core.wasm", "/wasm/app.wasm"]

    target_port = 443 if 443 in ports else (80 if 80 in ports else ports[0])
    use_ssl = target_port in [443, 8443]

    try:
        # Regex/Byte patterns to detect potentially sensitive exported functions or strings
        # looking like crypto keys or validation flags inside the WebAssembly binary Data Section
        sensitive_patterns = [b"verify_signature", b"validate_transaction", b"decrypt_key", b"admin_override"]

        for endpoint in test_endpoints:
            req = (
                f"GET {endpoint} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Cascavel-2026-Offensive-Engine\r\n"
                f"Accept: application/wasm, */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

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
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 524288:  # Maximum 512KB parse for performance
                        break

                # Verify WASM Magic Header \x00asm (0x00 0x61 0x73 0x6d)
                # HTTP response includes headers, so we search the entire buffer
                if b"\x00asm" in response_data:
                    found_sensitive = False
                    for pattern in sensitive_patterns:
                        if pattern in response_data:
                            found_sensitive = True
                            break

                    if found_sensitive:
                        return {
                            "vulnerability": vulnerability,
                            "severity": severity,
                            "description": description,
                            "endpoint": f"{'https' if use_ssl else 'http'}://{target}:{target_port}{endpoint}",
                            "evidence": "Wasm module exposes sensitive validation/crypto functions which can be extracted or patched client-side.",
                        }
            except Exception:
                continue
            finally:
                sock.close()
    except Exception:
        pass

    return None
