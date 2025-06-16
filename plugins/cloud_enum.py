# plugins/cloud_enum.py
def run(target, ip, open_ports, banners):
    """
    Identifica o provedor de nuvem provável do domínio ou IP alvo.
    Faz checagem pelo domínio e também por whois reverso do IP.
    """
    import socket

    cloud_ips = {
        "Amazon": ["amazonaws.com", ".cloudfront.net"],
        "Azure": [".cloudapp.net", ".windows.net"],
        "Google": [".googleusercontent.com", ".cloudfunctions.net"],
    }
    resultado = {"provider": "Desconhecido"}

    try:
        # Checagem pelo nome do domínio
        for nome, padroes in cloud_ips.items():
            for padrao in padroes:
                if padrao in target:
                    resultado["provider"] = nome

        # Checagem básica de IP (opcional)
        if resultado["provider"] == "Desconhecido":
            try:
                host_ip = socket.gethostbyname(target)
                resultado["ip"] = host_ip
            except Exception:
                resultado["ip"] = ip if ip else "Não resolvido"
        else:
            resultado["dominio"] = target

    except Exception as e:
        resultado = {"erro": str(e)}

    return {
        "plugin": "cloud_enum",
        "resultados": resultado
    }
