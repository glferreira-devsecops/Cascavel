# plugins/smb_ad.py
import subprocess
import re
import shutil
import shlex


def run(target, ip, open_ports, banners):
    """
    Enumera compartilhamentos SMB abertos no alvo usando smbclient.
    Retorna lista de shares ou erro no formato estruturado.
    """
    _ = (ip, open_ports, banners)

    if not shutil.which("smbclient"):
        return {"plugin": "smb_ad", "resultados": {"erro": "smbclient não encontrado no PATH"}}

    safe_target = shlex.quote(target)
    resultado = {}
    try:
        cmd = f"smbclient -L //{safe_target} -N"
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=20, encoding="utf-8")
        saida = proc.stdout
        compartilhamentos = re.findall(r'^\s*([A-Za-z0-9\$\-_]+)\s+Disk', saida, re.MULTILINE)
        resultado["compartilhamentos"] = compartilhamentos if compartilhamentos else "Nenhum compartilhamento encontrado"
        if proc.stderr:
            resultado["stderr"] = proc.stderr[:500]
    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout ao enumerar SMB"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "smb_ad", "resultados": resultado}
