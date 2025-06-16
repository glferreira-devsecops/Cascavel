# plugins/smb_enum.py
def run(target, results):
    """
    Enumera compartilhamentos SMB abertos no alvo usando smbclient.
    Retorna lista de shares ou erro no formato estruturado.
    """
    import subprocess, re
    resultado = {}
    try:
        cmd = f"smbclient -L //{target} -N"
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=20)
        saida = proc.stdout.decode(errors="ignore")
        # Captura apenas os nomes dos compartilhamentos (Disk)
        compartilhamentos = re.findall(r'^\s*([A-Za-z0-9\$\-_]+)\s+Disk', saida, re.MULTILINE)
        resultado["compartilhamentos"] = compartilhamentos if compartilhamentos else "Nenhum compartilhamento encontrado"
    except Exception as e:
        resultado["erro"] = str(e)
    results["smb_enum"] = resultado
