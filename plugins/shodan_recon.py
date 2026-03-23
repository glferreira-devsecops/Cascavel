# plugins/shodan_recon.py
def run(target, ip, open_ports, banners):
    """
    Reconnaissance via Shodan API.
    Busca informações públicas sobre o IP do alvo: portas, serviços, vulns, geo.
    Requer: pip install shodan + SHODAN_API_KEY no ambiente.
    """
    import os

    try:
        import shodan
    except ImportError:
        return {"plugin": "shodan_recon", "resultados": {"erro": "shodan não instalado (pip install shodan)"}}

    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        return {
            "plugin": "shodan_recon",
            "resultados": {"aviso": "SHODAN_API_KEY não definida no ambiente. Defina com: export SHODAN_API_KEY=sua_chave"}
        }

    resultado = {}
    try:
        api = shodan.Shodan(api_key)
        host_ip = ip if ip and ip != "?" else target

        host = api.host(host_ip)
        resultado["ip"] = host.get("ip_str", host_ip)
        resultado["org"] = host.get("org", "N/A")
        resultado["os"] = host.get("os", "N/A")
        resultado["pais"] = host.get("country_name", "N/A")
        resultado["cidade"] = host.get("city", "N/A")
        resultado["isp"] = host.get("isp", "N/A")
        resultado["portas"] = host.get("ports", [])
        resultado["vulns"] = host.get("vulns", [])
        resultado["hostnames"] = host.get("hostnames", [])

        # Serviços detalhados (top 10)
        servicos = []
        for item in host.get("data", [])[:10]:
            servicos.append({
                "porta": item.get("port"),
                "protocolo": item.get("transport", "tcp"),
                "produto": item.get("product", "N/A"),
                "versao": item.get("version", "N/A"),
                "banner": item.get("data", "")[:200],
            })
        resultado["servicos"] = servicos

    except shodan.APIError as e:
        resultado["erro"] = f"Shodan API: {str(e)}"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "shodan_recon", "resultados": resultado}
