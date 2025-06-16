# plugins/ssl_check.py
def run(target, results):
    """
    Checa o certificado SSL/TLS de um alvo na porta 443.
    Mostra emissor, assunto, validade e algoritmo do certificado.
    """
    import ssl, socket
    out = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                out['emissor'] = cert.get('issuer')
                out['assunto'] = cert.get('subject')
                out['validade_ate'] = cert.get('notAfter')
                out['versao'] = cert.get('version', 'N/A')
                out['algoritmo'] = cert.get('signatureAlgorithm', 'N/A')
        results["ssl_check"] = out
    except Exception as e:
        results["ssl_check"] = {"erro": str(e)}
