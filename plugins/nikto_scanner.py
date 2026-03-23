# plugins/nikto_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner de vulnerabilidades web via Nikto.
    Executa scan completo nos serviços HTTP/HTTPS do alvo.
    Requer: nikto instalado no PATH.
    """
    import subprocess
    import shutil

    if not shutil.which("nikto"):
        return {"plugin": "nikto_scanner", "resultados": {"erro": "nikto não encontrado no PATH"}}

    # Detectar portas HTTP do core
    http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 8888]] or [80]
    resultados = []

    for port in http_ports[:2]:  # Limitar a 2 portas para não demorar demais
        scheme = "https" if port in [443, 8443] else "http"
        cmd = f"nikto -h {scheme}://{target}:{port} -Tuning 1234567890abc -maxtime 120s -nointeractive"
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True,
                timeout=150, encoding="utf-8"
            )
            output = proc.stdout
            # Extrair vulnerabilidades
            vulns = [line.strip() for line in output.splitlines() if line.strip().startswith("+")]
            resultados.append({
                "porta": port,
                "scheme": scheme,
                "vulnerabilidades": vulns[:50] if vulns else "Nenhuma vulnerabilidade detectada",
                "total_achados": len(vulns),
            })
        except subprocess.TimeoutExpired:
            resultados.append({"porta": port, "erro": "Timeout (limite: 150s)"})
        except Exception as e:
            resultados.append({"porta": port, "erro": str(e)})

    return {"plugin": "nikto_scanner", "resultados": resultados}
