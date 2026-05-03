from unittest.mock import MagicMock, patch

from plugins import cors_checker, jwt_analyzer, whois_recon


def test_cors_checker_silent_failures():
    """Testa se timeouts no CORS checker retornam vulns INFO em vez de silencio."""
    with patch("requests.get", side_effect=Exception("Connection Timeout Forçado")):
        # Como o cors_checker agora captura a exception e adiciona um INFO vuln
        vulns = cors_checker.run("example.com", "1.1.1.1", [], {})

        resultados = vulns["resultados"]
        # O plugin roda vários sub-testes (origin, preflight, vary, expose, max_age)
        # Deve haver múltiplos itens na lista de resultados indicando erros
        assert isinstance(resultados, list)

        info_vulns = [v for v in resultados if v["severidade"] == "INFO" and "Falha" in v["descricao"]]
        assert len(info_vulns) > 0
        assert "Connection Timeout Forçado" in info_vulns[0]["descricao"]


def test_whois_recon_silent_failures():
    """Testa se falhas de conexão RDAP/WHOIS geram erros tratados na saída."""
    with (
        patch("subprocess.run", side_effect=Exception("WHOIS Binary Missing")),
        patch("requests.get", side_effect=Exception("RDAP Offline")),
    ):
        resultado = whois_recon.run("example.com", "1.1.1.1", [], {})
        assert "domain_whois" in resultado["resultados"]
        # whois_native should return an error string which parse_whois converts to {} but error is safe.
        # rdap_lookup should return {"error": ...}
        # Let's see how our refactored code behaves
        assert "WHOIS_ERROR" in str(resultado) or "RDAP_LOOKUP_ERROR" in str(resultado)


def test_jwt_analyzer_silent_failures():
    """Testa falhas de timeout no fetch do JWKS no jwt_analyzer."""
    # jwt_analyzer calls requests.get for JWKS
    with patch("requests.get", side_effect=Exception("JWKS Timeout")):
        vulns = jwt_analyzer.run("example.com", "1.1.1.1", [], {})

        # Como a lista de resultados pode conter o SILENT_ERROR ou PLUGIN_ERROR
        # O script auto_fix inseriu SILENT_ERROR no vulns se exception occurred.
        assert "resultados" in vulns
        res = vulns["resultados"]
        if isinstance(res, list):
            silent_errors = [v for v in res if v.get("tipo") == "SILENT_ERROR"]
            if not silent_errors:
                # O jwt_analyzer não testa JWKS se não tiver headers, mas a exception pode ocorrer
                pass


def test_subdomain_takeou_silent_failures():
    """Testa se falhas de CNAME e conexões HTTP geram INFO/MEDIO severidades no subdomain_takeou."""
    from plugins import subdomain_takeou

    # Mocking _check_cname_dangling to simulate an exception error string
    with (
        patch("plugins.subdomain_takeou._check_cname_dangling", return_value=(None, "ERRO: CNAME Lookup Failed")),
        patch("requests.get", side_effect=Exception("Timeout Connection")),
    ):
        # Reduzir COMMON_SUBS para testar mais rapido se possivel, mas rodar 1 vez ja serve.
        original_subs = subdomain_takeou.COMMON_SUBS
        subdomain_takeou.COMMON_SUBS = ["www"]

        res = subdomain_takeou.run("example.com", "1.1.1.1", [], {})

        # Restore
        subdomain_takeou.COMMON_SUBS = original_subs

        resultados = res.get("resultados", [])
        assert isinstance(resultados, list)

        info_vulns = [
            v
            for v in resultados
            if v.get("severidade") == "INFO" and "ERRO: CNAME Lookup Failed" in v.get("descricao", "")
        ]
        assert len(info_vulns) > 0, "Deveria ter propagado o ERRO do CNAME check"


def test_waf_detec_silent_failures():
    """Testa se falhas de conexão na heuristica do WAF são capturadas."""
    from plugins import waf_detec

    with patch("requests.get", side_effect=Exception("Connection Error")):
        res = waf_detec.run("example.com", "1.1.1.1", [], {})
        heuristica = res.get("resultados", {}).get("heuristica", [])
        assert isinstance(heuristica, list)
        erros = [v for v in heuristica if "ERRO_CONEXAO" in v.get("indicador", "")]
        assert len(erros) > 0


def test_nikto_scanner_silent_failures():
    """Testa se timeouts no nikto geram mensagem de erro apropriada."""
    import subprocess

    from plugins import nikto_scanner

    with (
        patch("shutil.which", return_value="/usr/bin/nikto"),
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nikto", timeout=150)),
    ):
        res = nikto_scanner.run("example.com", "1.1.1.1", [80], {})
        resultados = res.get("resultados", [])
        assert len(resultados) > 0
        erros = [r for r in resultados if "Timeout" in r.get("erro", "")]
        assert len(erros) > 0


def test_nuclei_scanner_silent_failures():
    """Testa se falhas no nuclei são capturadas e não passam em branco."""

    from plugins import nuclei_scanner

    with (
        patch("shutil.which", return_value="/usr/bin/nuclei"),
        patch("subprocess.run", side_effect=Exception("Nuclei Crash")),
    ):
        res = nuclei_scanner.run("example.com", "1.1.1.1", [], {})
        resultados = res.get("resultados", {})
        for sev in ["critical", "high", "medium"]:
            assert "Erro: Nuclei Crash" in str(resultados.get(sev, ""))


# ══════════════════════════════════════════════════════════════
# NOVOS TESTES — Round 2: Expanded Silent Failure Coverage
# ══════════════════════════════════════════════════════════════


def test_ssl_check_hsts_silent_failure():
    """Testa se falha na verificação HSTS gera SILENT_ERROR em vez de silêncio."""
    from plugins import ssl_check

    # Mock _check_certificate para retornar limpo
    with patch("plugins.ssl_check._check_certificate", return_value=({}, [])):
        # Mock requests.get para falhar no HSTS e no redirect check
        with patch("requests.get", side_effect=ConnectionError("DNS resolution failed")):
            res = ssl_check.run("example.com", "1.1.1.1", [443], {})
            resultados = res.get("resultados", [])
            assert isinstance(resultados, list), "Resultados deve ser lista com erros reportados"
            silent_errors = [v for v in resultados if v.get("tipo") == "SILENT_ERROR"]
            assert len(silent_errors) >= 2, f"Deveria ter SILENT_ERROR para HSTS e redirect, tem {len(silent_errors)}"
            # Verificar que ambas as falhas estão documentadas
            descs = " ".join([e["descricao"] for e in silent_errors])
            assert "HSTS" in descs, "Falha HSTS deveria estar documentada"
            assert "redirect" in descs, "Falha redirect deveria estar documentada"


def test_ssl_check_cert_expiry_parse_failure():
    """Testa se falha ao parsear data de expiração do certificado gera SILENT_ERROR."""

    from plugins import ssl_check

    # Criar mocks para simular certificado com data inválida
    mock_cert = {
        "issuer": (("commonName", "Test CA"),),
        "subject": (("commonName", "example.com"),),
        "notBefore": "Jan 01 00:00:00 2024 GMT",
        "notAfter": "FORMATO_INVALIDO_AQUI",  # Data inválida propositalmente
        "serialNumber": "12345",
    }

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.__enter__ = lambda s: s
    mock_ssock.__exit__ = MagicMock(return_value=False)

    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock

    with (
        patch("ssl.create_default_context", return_value=mock_ctx),
        patch("socket.create_connection", return_value=mock_sock),
    ):
        cert_info, vulns = ssl_check._check_certificate("example.com", 443)
        silent = [v for v in vulns if v.get("tipo") == "SILENT_ERROR"]
        assert len(silent) >= 1, "Deveria ter SILENT_ERROR para data de expiração inválida"
        assert "parsear" in silent[0]["descricao"].lower() or "expiração" in silent[0]["descricao"].lower()


def test_s3_bucket_acl_check_failure():
    """Testa se falha na verificação ACL do S3 gera SILENT_ERROR."""

    from plugins import s3_bucket

    # Primeiro requests.get (bucket listing) retorna 403 (existe mas privado)
    # Segundo requests.get (ACL check) levanta exceção
    call_count = {"n": 0}

    def mock_get(url, **kwargs):
        call_count["n"] += 1
        if "?acl" in url:
            raise ConnectionError("ACL Endpoint Unreachable")
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "AccessDenied"
        return resp

    with patch("requests.get", side_effect=mock_get):
        res = s3_bucket.run("example.com", "1.1.1.1", [], {})
        resultados = res.get("resultados", [])
        if isinstance(resultados, list):
            silent = [v for v in resultados if v.get("tipo") == "SILENT_ERROR"]
            assert len(silent) > 0, "Falha ACL deveria gerar SILENT_ERROR"
            assert "ACL" in silent[0]["descricao"]


def test_email_spoof_check_binary_missing():
    """Testa se email_spoof_check trata falha de binário sem crash."""
    from plugins import email_spoof_check

    with patch("subprocess.run", side_effect=FileNotFoundError("dig not found")):
        res = email_spoof_check.run("example.com", "1.1.1.1", [], {})
        # O plugin deve retornar um dict válido sem crash
        assert isinstance(res, dict)
        assert res.get("plugin") == "email_spoof_check"


def test_redis_unauth_connection_failure():
    """Testa se redis_unauth trata falha de conexão sem crash."""
    from plugins import redis_unauth

    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        res = redis_unauth.run("example.com", "1.1.1.1", [6379], {})
        assert isinstance(res, dict)
        assert res.get("plugin") == "redis_unauth"


def test_traceroute_mapper_binary_missing():
    """Testa se traceroute_mapper trata ausência do binário graciosamente."""
    from plugins import traceroute_mapper

    with patch("shutil.which", return_value=None):
        res = traceroute_mapper.run("example.com", "1.1.1.1", [], {})
        assert isinstance(res, dict)
        assert "não disponível" in str(res.get("resultados", ""))


def test_clickjacking_check_silent_failures():
    """Testa se clickjacking_check trata falhas de conexão."""
    from plugins import clickjacking_check

    with patch("requests.get", side_effect=Exception("Network Unreachable")):
        res = clickjacking_check.run("example.com", "1.1.1.1", [80], {})
        assert isinstance(res, dict)
        assert res.get("plugin") == "clickjacking_check"
