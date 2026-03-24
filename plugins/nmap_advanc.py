# plugins/nmap_advanc.py
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET


def _parse_nmap_xml(xml_output):
    """Parseia output XML do nmap e retorna lista de hosts."""
    root = ET.fromstring(xml_output)
    hosts = []
    for host in root.findall(".//host"):
        host_info = {"address": "", "ports": []}
        addr = host.find("address")
        if addr is not None:
            host_info["address"] = addr.get("addr", "")
        for port in host.findall(".//port"):
            port_data = {
                "portid": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
            }
            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "")
            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["product"] = service.get("product", "")
                port_data["version"] = service.get("version", "")
            host_info["ports"].append(port_data)
        hosts.append(host_info)
    return hosts


def run(target, ip, open_ports, banners):
    """
    Varredura Nmap avançada: all ports, scripts NSE, detecção de versão.
    Usa saída XML parseada. Requer nmap 7.80+.
    """
    _ = (ip, open_ports, banners)

    if not shutil.which("nmap"):
        return {"plugin": "nmap_advanc", "resultados": {"erro": "nmap não encontrado no PATH"}}

    safe_target = shlex.quote(target)
    nmap_cmd = f"nmap -sC -sV -p- --min-rate 5000 -T4 {safe_target} -oX -"
    resultado = {}
    try:
        proc = subprocess.run(
            nmap_cmd,
            shell=True,
            capture_output=True,
            timeout=300,
            encoding="utf-8",
        )
        try:
            resultado["hosts"] = _parse_nmap_xml(proc.stdout)
        except ET.ParseError:
            resultado["raw_output"] = proc.stdout[:3000]
    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout na varredura nmap (limite: 5min)"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "nmap_advanc", "resultados": resultado}
