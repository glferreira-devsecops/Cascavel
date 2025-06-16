# plugins/directory_bruteforce.py
def run(target, ip, open_ports, banners):
    """
    Faz brute-force de diretórios usando feroxbuster, salva resultados em JSON.
    """
    import subprocess, os, json

    wordlist = os.path.expanduser("~/common.txt")
    ferox_cmd = f"feroxbuster -u http://{target} -w {wordlist} --depth 1 --json -q"

    resultado = []
    try:
        output = subprocess.check_output(ferox_cmd, shell=True, timeout=60)
        lines = [l for l in output.decode().split("\n") if l.strip()]
        for l in lines:
            try:
                obj = json.loads(l)
                resultado.append({"url": obj.get("url"), "status": obj.get("status")})
            except Exception:
                pass
    except Exception as e:
        return {"plugin": "directory_bruteforce", "resultados": f"Erro no feroxbuster: {e}"}

    return {"plugin": "directory_bruteforce", "resultados": resultado if resultado else "Nenhum diretório encontrado"}
