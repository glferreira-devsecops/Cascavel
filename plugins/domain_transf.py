# plugins/domain_transf.py
import subprocess
import shlex


def run(target, ip, open_ports, banners):
    """
    Tenta realizar transferência de zona DNS AXFR (zone transfer) no domínio alvo.
    Retorna resultado estruturado para o core do Cascavel.
    """
    _ = (ip, open_ports, banners)

    safe_target = shlex.quote(target)
    resultado = {}
    cmd = f"dig axfr {safe_target} @{safe_target}"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=20)
        decoded = output.decode()
        if "Transfer failed" not in decoded and "connection timed out" not in decoded:
            resultado["transferencia"] = decoded
        else:
            resultado["transferencia"] = "Zone transfer não permitido ou falhou."
    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout ao tentar zone transfer"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "domain_transf", "resultados": resultado}
