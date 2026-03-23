# plugins/ssl_check.py
def run(target, ip, open_ports, banners):
    """
    Checa o certificado SSL/TLS de um alvo na porta 443.
    Mostra emissor, assunto, validade e algoritmo do certificado.
    """
    import ssl
    import socket

    resultado = {}
    ssl_port = 443

    # Usar porta SSL do core se disponível
    ssl_ports = [p for p in open_ports if p in [443, 8443]]
    if ssl_ports:
        ssl_port = ssl_ports[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, ssl_port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                resultado["emissor"] = cert.get("issuer")
                resultado["assunto"] = cert.get("subject")
                resultado["validade_de"] = cert.get("notBefore")
                resultado["validade_ate"] = cert.get("notAfter")
                resultado["versao"] = cert.get("version", "N/A")
                resultado["serial"] = cert.get("serialNumber", "N/A")
                resultado["san"] = cert.get("subjectAltName", [])
                resultado["protocolo"] = ssock.version()
    except ssl.SSLCertVerificationError as e:
        resultado["aviso"] = "Certificado SSL inválido ou auto-assinado"
        resultado["detalhes"] = str(e)
    except ConnectionRefusedError:
        resultado["erro"] = f"Conexão recusada na porta {ssl_port}"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "ssl_check", "resultados": resultado}
