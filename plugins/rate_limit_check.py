# plugins/rate_limit_check.py
import time

import requests


def run(target, ip, open_ports, banners):
    """
    Testa ausência de rate limiting em endpoints sensíveis.
    Importante para brute-force, credential stuffing e DoS.
    """
    _ = (ip, open_ports, banners)

    endpoints = [
        "/login",
        "/api/login",
        "/api/auth",
        "/register",
        "/api/v1/login",
        "/forgot-password",
        "/api/reset-password",
    ]
    resultado = {}

    for ep in endpoints:
        url = f"http://{target}{ep}"
        statuses = []
        times = []
        blocked = False

        for i in range(30):
            try:
                start = time.time()
                resp = requests.post(
                    url,
                    json={"username": f"test{i}", "password": "test"},
                    timeout=5,
                )
                elapsed = time.time() - start
                statuses.append(resp.status_code)
                times.append(elapsed)

                if resp.status_code == 429:
                    blocked = True
                    resultado[ep] = {
                        "rate_limit": True,
                        "bloqueado_em": i + 1,
                        "severidade": "INFO",
                        "descricao": f"Rate limit ativo — bloqueou na request #{i + 1}",
                    }
                    break
                if resp.status_code in [403, 503]:
                    blocked = True
                    resultado[ep] = {
                        "rate_limit": True,
                        "bloqueado_em": i + 1,
                        "status": resp.status_code,
                        "severidade": "INFO",
                    }
                    break
            except Exception:
                break

        if not blocked and len(statuses) >= 25:
            avg_time = round(sum(times) / len(times), 3) if times else 0
            resultado[ep] = {
                "rate_limit": False,
                "requests_sem_bloqueio": len(statuses),
                "severidade": "ALTO",
                "descricao": f"Endpoint aceita {len(statuses)}+ requests sem rate limiting",
                "tempo_medio": avg_time,
            }

    return {
        "plugin": "rate_limit_check",
        "resultados": resultado if resultado else "Nenhum endpoint de auth encontrado",
    }
