import json
from rich.console import Console
from threat_intel import enrich_results
from ai_remediation import generate_ai_fixes
from ocsf_exporter import export_ocsf

console = Console()

# Simulando um resultado do scan
plugin_results = [
    {
        "plugin": "cve_2021_44228_log4j",
        "resultados": [
            {
                "nome": "Log4Shell Vulnerability",
                "descricao": "Detectado Apache Log4j RCE CVE-2021-44228.",
                "severidade": "ALTO",
                "correcao": "Atualize o Log4j para >= 2.17.0"
            }
        ]
    }
]

print("\n--- 1. Testando Threat Intel (EPSS/KEV) ---")
enriched = enrich_results(plugin_results, console)

print("\n--- 2. Testando AI Remediation ---")
ai_fixed = generate_ai_fixes(enriched, console)

print("\n--- 3. Testando OCSF Exporter ---")
import os
os.makedirs("reports", exist_ok=True)
ocsf_file = export_ocsf("127.0.0.1", "127.0.0.1", ai_fixed, 1.5, "reports")
print(f"Exportado para: {ocsf_file}")

with open(ocsf_file, 'r') as f:
    print(json.dumps(json.load(f), indent=2))

