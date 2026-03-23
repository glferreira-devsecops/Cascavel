# plugins/dir_bruteforce.py
import os

def run(target, ip, open_ports, banners):
    """
    Faz brute-force de diretórios usando feroxbuster, salva resultados em JSON.
    Usa wordlist do framework (não mais hardcoded).
    """
    import subprocess
    import json
    import shutil

    # Usar wordlist do framework
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wordlist_candidates = [
        os.path.join(base_path, "wordlists", "common.txt"),
        os.path.join(base_path, "wordlists", "dirb_common.txt"),
    ]
    wordlist = None
    for wl in wordlist_candidates:
        if os.path.isfile(wl):
            wordlist = wl
            break

    if not wordlist:
        return {"plugin": "dir_bruteforce", "resultados": {"erro": "Nenhuma wordlist encontrada em wordlists/"}}

    if not shutil.which("feroxbuster"):
        return {"plugin": "dir_bruteforce", "resultados": {"erro": "feroxbuster não encontrado no PATH"}}

    ferox_cmd = f"feroxbuster -u http://{target} -w {wordlist} --depth 1 --json -q"
    resultado = []
    try:
        proc = subprocess.run(
            ferox_cmd, shell=True, capture_output=True,
            timeout=60, encoding="utf-8"
        )
        lines = [l for l in proc.stdout.split("\n") if l.strip()]
        for l in lines:
            try:
                obj = json.loads(l)
                if "url" in obj:
                    resultado.append({"url": obj.get("url"), "status": obj.get("status")})
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        return {"plugin": "dir_bruteforce", "resultados": "Timeout no feroxbuster (limite: 60s)"}
    except Exception as e:
        return {"plugin": "dir_bruteforce", "resultados": f"Erro no feroxbuster: {e}"}

    return {
        "plugin": "dir_bruteforce",
        "resultados": resultado if resultado else "Nenhum diretório encontrado"
    }
