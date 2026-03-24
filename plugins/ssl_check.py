# plugins/ssl_check.py — Cascavel 2026 Intelligence
import ssl
import socket
import datetime


WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "SEED", "IDEA", "CAMELLIA128",
]

KNOWN_BAD_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
]


def _check_certificate(target, port):
    """Analisa certificado SSL/TLS do alvo."""
    vulns = []
    cert_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cert_info["emissor"] = cert.get("issuer")
                cert_info["assunto"] = cert.get("subject")
                cert_info["validade_de"] = cert.get("notBefore")
                cert_info["validade_ate"] = cert.get("notAfter")
                cert_info["serial"] = cert.get("serialNumber", "N/A")
                cert_info["versao"] = cert.get("version", "N/A")
                cert_info["protocolo"] = ssock.version()
                cert_info["cipher"] = ssock.cipher()

                # SAN extraction
                san = cert.get("subjectAltName", [])
                cert_info["san_total"] = len(san)
                cert_info["san_amostra"] = [s[1] for s in san[:15]]

                # Expiry check
                try:
                    not_after = cert.get("notAfter", "")
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    cert_info["dias_ate_expirar"] = days_left
                    if days_left < 0:
                        vulns.append({
                            "tipo": "SSL_CERT_EXPIRED", "severidade": "CRITICO",
                            "descricao": f"Certificado expirado há {abs(days_left)} dias!",
                        })
                    elif days_left < 30:
                        vulns.append({
                            "tipo": "SSL_CERT_EXPIRING", "severidade": "ALTO",
                            "descricao": f"Certificado expira em {days_left} dias!",
                        })
                except Exception:
                    pass

                # Protocol check
                protocol = ssock.version()
                if protocol in WEAK_PROTOCOLS:
                    vulns.append({
                        "tipo": "SSL_WEAK_PROTOCOL", "protocolo": protocol,
                        "severidade": "CRITICO",
                        "descricao": f"Protocolo {protocol} — downgrade attack possível!",
                    })

                # Cipher check
                cipher_name = ssock.cipher()[0] if ssock.cipher() else ""
                for weak in WEAK_CIPHERS:
                    if weak.lower() in cipher_name.lower():
                        vulns.append({
                            "tipo": "SSL_WEAK_CIPHER", "cipher": cipher_name,
                            "severidade": "ALTO",
                            "descricao": f"Cipher fraco: {cipher_name}",
                        })
                        break

                # Key size check
                cipher_bits = ssock.cipher()[2] if ssock.cipher() and len(ssock.cipher()) > 2 else 0
                if cipher_bits and cipher_bits < 128:
                    vulns.append({
                        "tipo": "SSL_WEAK_KEY", "bits": cipher_bits,
                        "severidade": "CRITICO",
                        "descricao": f"Key size {cipher_bits} bits — muito fraco!",
                    })

                # Wildcard check
                cn = ""
                for field in cert.get("subject", ()):
                    for k, v in field:
                        if k == "commonName":
                            cn = v
                if cn.startswith("*."):
                    cert_info["wildcard"] = True

    except ssl.SSLCertVerificationError as e:
        err_str = str(e)
        cert_info["erro_verificacao"] = err_str
        if "self-signed" in err_str.lower() or "self signed" in err_str.lower():
            vulns.append({
                "tipo": "SSL_SELF_SIGNED", "severidade": "ALTO",
                "descricao": "Certificado auto-assinado — MITM possível!",
            })
        elif "hostname mismatch" in err_str.lower():
            vulns.append({
                "tipo": "SSL_HOSTNAME_MISMATCH", "severidade": "ALTO",
                "descricao": "Hostname não confere com CN/SAN!",
            })
        else:
            vulns.append({
                "tipo": "SSL_CERT_INVALID", "severidade": "ALTO",
                "descricao": f"Certificado inválido: {err_str[:100]}",
            })
    except ConnectionRefusedError:
        cert_info["erro"] = f"Conexão recusada na porta {port}"
    except Exception as e:
        cert_info["erro"] = str(e)[:100]

    return cert_info, vulns


def _check_hsts(target):
    """Verifica HSTS (HTTP Strict Transport Security)."""
    vulns = []
    try:
        resp = __import__("requests").get(f"https://{target}", timeout=5, verify=False)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            vulns.append({
                "tipo": "HSTS_AUSENTE", "severidade": "MEDIO",
                "descricao": "HSTS não configurado — downgrade HTTP possível!",
            })
        else:
            if "includeSubDomains" not in hsts:
                vulns.append({
                    "tipo": "HSTS_NO_SUBDOMAINS", "severidade": "BAIXO",
                    "descricao": "HSTS sem includeSubDomains",
                })
            if "preload" not in hsts:
                vulns.append({
                    "tipo": "HSTS_NO_PRELOAD", "severidade": "BAIXO",
                    "descricao": "HSTS sem preload — não está na preload list",
                })
            # Max-Age check
            import re
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age and int(max_age.group(1)) < 31536000:
                vulns.append({
                    "tipo": "HSTS_LOW_MAX_AGE", "severidade": "BAIXO",
                    "descricao": f"HSTS max-age={max_age.group(1)} — recomendado >= 31536000",
                })
    except Exception:
        pass
    return vulns


def _check_http_redirect(target):
    """Verifica se HTTP redireciona para HTTPS."""
    vulns = []
    try:
        resp = __import__("requests").get(f"http://{target}", timeout=5,
                                           allow_redirects=False)
        if resp.status_code in [301, 302, 307, 308]:
            location = resp.headers.get("Location", "")
            if "https://" in location:
                pass  # OK
            else:
                vulns.append({
                    "tipo": "HTTP_NO_HTTPS_REDIRECT", "severidade": "MEDIO",
                    "descricao": "HTTP redireciona mas não para HTTPS!",
                })
        elif resp.status_code == 200:
            vulns.append({
                "tipo": "HTTP_NO_REDIRECT", "severidade": "ALTO",
                "descricao": "HTTP serve conteúdo sem redirecionar para HTTPS — MITM!",
            })
    except Exception:
        pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner SSL/TLS 2026-Grade — Certificate, Protocol, Cipher, HSTS.

    Técnicas: Certificate analysis (expiry/self-signed/hostname mismatch/
    wildcard/SAN extraction), protocol check (TLSv1/SSLv3),
    cipher analysis (RC4/DES/3DES/NULL/EXPORT), key size validation,
    HSTS analysis (includeSubDomains/preload/max-age),
    HTTP→HTTPS redirect verification.
    """
    _ = (ip, banners)
    ssl_port = 443
    ssl_ports = [p for p in open_ports if p in [443, 8443]]
    if ssl_ports:
        ssl_port = ssl_ports[0]

    cert_info, vulns = _check_certificate(target, ssl_port)
    vulns.extend(_check_hsts(target))
    vulns.extend(_check_http_redirect(target))

    return {
        "plugin": "ssl_check", "versao": "2026.1",
        "tecnicas": ["cert_analysis", "protocol_check", "cipher_check",
                      "hsts_analysis", "http_redirect", "key_size"],
        "certificado": cert_info,
        "resultados": vulns if vulns else "SSL/TLS sem vulnerabilidades críticas",
    }
