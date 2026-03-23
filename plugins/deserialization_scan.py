# plugins/deserialization_scan.py
def run(target, ip, open_ports, banners):
    """
    Scanner de Insecure Deserialization (Java, PHP, Python, .NET).
    Detecta endpoints que aceitam objetos serializados e testa gadget chains.
    """
    import requests
    import base64

    endpoints = ["/", "/api/", "/api/v1/", "/import", "/upload",
                 "/deserialize", "/object", "/data"]
    vulns = []

    # Payloads de deserialization por tecnologia
    test_payloads = [
        {
            "nome": "JAVA_SERIAL",
            "data": base64.b64decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="),
            "content_type": "application/x-java-serialized-object",
            "indicadores": ["java.", "ClassNotFoundException", "ObjectInputStream", "serialVersionUID"],
        },
        {
            "nome": "PHP_SERIAL",
            "data": 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            "content_type": "application/x-php-serialized",
            "indicadores": ["unserialize", "stdClass", "__wakeup", "__destruct"],
        },
        {
            "nome": "PYTHON_PICKLE",
            "data": base64.b64encode(b'\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01X\x94.').decode(),
            "content_type": "application/octet-stream",
            "indicadores": ["pickle", "unpickle", "cPickle", "Unpickler"],
        },
    ]

    for ep in endpoints:
        url = f"http://{target}{ep}"

        for payload in test_payloads:
            try:
                data = payload["data"]
                if isinstance(data, bytes):
                    resp = requests.post(url, data=data, timeout=5,
                                         headers={"Content-Type": payload["content_type"]})
                else:
                    resp = requests.post(url, data=str(data), timeout=5,
                                         headers={"Content-Type": payload["content_type"]})

                # Verificar indicadores de parsing de serialized data
                for indicator in payload["indicadores"]:
                    if indicator.lower() in resp.text.lower():
                        vulns.append({
                            "tipo": "INSECURE_DESERIALIZATION",
                            "tecnologia": payload["nome"],
                            "endpoint": ep,
                            "indicador": indicator,
                            "severidade": "CRITICO",
                            "status": resp.status_code,
                        })
                        break

            except Exception:
                continue

        # Testar ViewState (.NET)
        try:
            resp = requests.get(url, timeout=5)
            if "__VIEWSTATE" in resp.text:
                import re
                viewstate = re.search(r'__VIEWSTATE[^>]*value="([^"]+)"', resp.text)
                vulns.append({
                    "tipo": "VIEWSTATE_DETECTADO",
                    "endpoint": ep,
                    "severidade": "MEDIO",
                    "tamanho": len(viewstate.group(1)) if viewstate else 0,
                    "descricao": "ASP.NET ViewState presente — possível deserialization",
                })
        except Exception:
            pass

    return {"plugin": "deserialization_scan", "resultados": vulns if vulns else "Nenhum endpoint de deserialization detectado"}
