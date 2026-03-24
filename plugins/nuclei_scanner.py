# plugins/nuclei_scanner.py
import subprocess
import shutil
import shlex
import json


def run(target, ip, open_ports, banners):
    """
    Scanner de vulnerabilidades via ProjectDiscovery Nuclei com templates.
    Executa varredura categorizada por severidade (critical, high, medium).
    Requer: nuclei instalado no PATH.
    """
    _ = (ip, open_ports, banners)

    if not shutil.which("nuclei"):
        return {"plugin": "nuclei_scanner", "resultados": {"erro": "nuclei não encontrado no PATH"}}

    safe_target = shlex.quote(target)
    resultado = {}
    severidades = ["critical", "high", "medium"]

    for sev in severidades:
        try:
            cmd = f"echo http://{safe_target} | nuclei -silent -severity {sev} -jsonl -rate-limit 50 -timeout 5 -retries 1"
            proc = subprocess.run(
                cmd, shell=True, capture_output=True,
                timeout=180, encoding="utf-8",
            )
            achados = []
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        obj = json.loads(line)
                        achados.append({
                            "template_id": obj.get("template-id", ""),
                            "nome": obj.get("info", {}).get("name", ""),
                            "severidade": obj.get("info", {}).get("severity", sev),
                            "matched_at": obj.get("matched-at", ""),
                            "tipo": obj.get("type", ""),
                            "descricao": obj.get("info", {}).get("description", "")[:200],
                        })
                    except json.JSONDecodeError:
                        continue
            resultado[sev] = achados if achados else f"Nenhuma vuln {sev} detectada"
        except subprocess.TimeoutExpired:
            resultado[sev] = "Timeout (180s)"
        except Exception as e:
            resultado[sev] = f"Erro: {e}"

    return {"plugin": "nuclei_scanner", "resultados": resultado}
