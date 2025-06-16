# plugins/domain_transfers.py
def run(target, results):
    """
    Tenta realizar transferência de zona DNS AXFR (zone transfer) no domínio alvo.
    """
    import subprocess

    cmd = f"dig axfr {target} @{target}"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=20)
        decoded = output.decode()
        if "Transfer failed" not in decoded and "connection timed out" not in decoded:
            results["domain_transfers"] = decoded
        else:
            results["domain_transfers"] = "Zone transfer não permitido ou falhou."
    except Exception as e:
        results["domain_transfers"] = {"error": str(e)}
