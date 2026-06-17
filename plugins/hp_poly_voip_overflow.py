# plugins/hp_poly_voip_overflow.py


def run(target, ip, open_ports, banners, context=None):
    """
    Verificador para HP Poly VoIP Phones (CVE-2026-0826).
    Checa portas associadas a VoIP SIP e web de gerenciamento.
    """
    _ = (ip, banners)

    voip_ports = [5060, 5061, 80, 443]
    portas_alvo = [p for p in open_ports if p in voip_ports]

    if not portas_alvo:
        return {
            "plugin": "hp_poly_voip_overflow",
            "resultados": "Portas VoIP ou Web não detectadas",
        }

    resultados = []

    for porta in portas_alvo:
        # Analise de banner para Polycom/HP Poly
        banner = str(banners.get(porta, "")).lower()
        if "polycom" in banner or "poly " in banner or "hp poly" in banner:
            resultados.append(
                {
                    "porta": porta,
                    "status": "Aparelho HP Poly VoIP Detectado",
                    "aviso": "Dispositivo VoIP Poly detectado via banner. Possível vulnerabilidade de Stack Overflow crítico (CVE-2026-0826).",
                }
            )
            continue

        # Simples verificação SIP se for porta SIP
        if porta in (5060, 5061):
            resultados.append(
                {
                    "porta": porta,
                    "status": "Serviço SIP Exposto",
                    "aviso": "Se este SIP pertencer a um HP Poly VoIP, investigue CVE-2026-0826 imediatamente.",
                }
            )

    if not resultados:
        return {
            "plugin": "hp_poly_voip_overflow",
            "resultados": "Nenhum aparelho VoIP HP Poly detectado.",
        }

    return {"plugin": "hp_poly_voip_overflow", "resultados": resultados}
