"""
╔══════════════════════════════════════════════════════════════════╗
║  CASCAVEL v3.0.0 — SARIF Exporter                               ║
║  Static Analysis Results Interchange Format v2.1.0               ║
║  Product of RET Tecnologia (https://rettecnologia.org)          ║
╚══════════════════════════════════════════════════════════════════╝

Exports Cascavel scan results to SARIF format for integration with:
  • GitHub Code Scanning (Advanced Security)
  • Azure DevOps Security Center
  • VSCode SARIF Viewer extension
  • JetBrains Qodana

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

# Version aligned with cascavel core
__version__ = "3.0.0"

# SARIF severity mapping (Cascavel → SARIF level)
_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    # Legacy PT-BR keys
    "CRITICO": "error",
    "ALTO": "error",
    "MEDIO": "warning",
    "BAIXO": "note",
}


def _build_tool_component() -> dict[str, Any]:
    """Build the SARIF tool component for Cascavel."""
    return {
        "driver": {
            "name": "Cascavel",
            "semanticVersion": __version__,
            "informationUri": "https://github.com/glferreira-devsecops/Cascavel",
            "organization": "RET Tecnologia",
            "rules": [],  # Populated dynamically from results
        }
    }


def _result_to_sarif(result: dict[str, Any], rule_index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert a single plugin result to a SARIF result + rule pair.

    Returns:
        Tuple of (sarif_result, sarif_rule).
    """
    plugin_name = result.get("plugin", "unknown")
    severity = result.get("severity", result.get("severidade", "INFO"))
    level = _SARIF_LEVEL.get(str(severity).upper(), "note")

    # Rule definition
    rule = {
        "id": f"cascavel/{plugin_name}",
        "name": plugin_name.replace("_", " ").title(),
        "shortDescription": {
            "text": result.get("title", f"Finding from {plugin_name}"),
        },
        "fullDescription": {
            "text": result.get("description", result.get("title", f"Security finding detected by {plugin_name}")),
        },
        "helpUri": f"https://github.com/glferreira-devsecops/Cascavel/blob/main/PLUGINS.md#{plugin_name}",
        "properties": {},
    }

    # Add CWE tag if available
    cwe = result.get("cwe", "")
    if cwe:
        rule["properties"]["tags"] = [cwe]

    # Add OWASP mapping
    owasp = result.get("owasp", "")
    if owasp:
        rule["properties"]["owasp"] = owasp

    # CVSS metadata
    cvss_score = result.get("cvss_score", 0.0)
    if cvss_score > 0:
        rule["properties"]["security-severity"] = str(cvss_score)
        cvss_vector = result.get("cvss_vector", "")
        if cvss_vector:
            rule["properties"]["cvss-vector"] = cvss_vector

    # SARIF result
    sarif_result: dict[str, Any] = {
        "ruleId": f"cascavel/{plugin_name}",
        "ruleIndex": rule_index,
        "level": level,
        "message": {
            "text": result.get("title", result.get("description", f"Issue detected by {plugin_name}")),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.get("target", "unknown"),
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
        ],
    }

    # Evidence as attachment
    evidence = result.get("evidence", "")
    if evidence:
        sarif_result["attachments"] = [
            {
                "description": {"text": "Raw evidence captured during scan"},
                "contents": {"text": str(evidence)[:4096]},
            }
        ]

    # Findings as related locations
    findings = result.get("findings", [])
    if findings and isinstance(findings, list):
        related = []
        for i, finding in enumerate(findings[:20]):  # Cap at 20
            if isinstance(finding, dict):
                detail = finding.get("detail", finding.get("payload", str(finding)))
            else:
                detail = str(finding)
            related.append(
                {
                    "id": i,
                    "message": {"text": str(detail)[:1024]},
                }
            )
        if related:
            sarif_result["relatedLocations"] = related

    # Remediation as fix
    remediation = result.get("remediation", result.get("correcao", ""))
    if remediation:
        sarif_result["fixes"] = [
            {
                "description": {"text": str(remediation)},
            }
        ]

    return sarif_result, rule


def export_sarif(
    target: str,
    ip: str,
    results: list[dict[str, Any]],
    elapsed: float,
    output_dir: str = "reports",
) -> str:
    """Export scan results to SARIF v2.1.0 format.

    Args:
        target: Scanned target (domain/IP).
        ip: Resolved IP address.
        results: List of plugin result dicts.
        elapsed: Total scan duration in seconds.
        output_dir: Directory to write the .sarif file.

    Returns:
        Absolute path to the generated .sarif file.
    """
    tool = _build_tool_component()
    sarif_results: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    for idx, result in enumerate(results):
        # Skip error-only results with no findings
        if "erro" in result and not result.get("findings"):
            continue

        sarif_result, rule = _result_to_sarif(result, idx)
        sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = target
        sarif_results.append(sarif_result)
        rules.append(rule)

    tool["driver"]["rules"] = rules

    sarif_doc: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": tool,
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"cascavel -t {target} --sarif",
                        "startTimeUtc": (
                            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=elapsed)
                        ).isoformat(),
                        "endTimeUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "target": target,
                    "ip": ip,
                    "cascavel_version": __version__,
                    "total_plugins": len(results),
                    "total_findings": len(sarif_results),
                    "elapsed_seconds": round(elapsed, 2),
                },
            }
        ],
    }

    # Write to disk
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace("/", "_").replace(":", "_").replace(".", "-")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cascavel_{safe_target}_{ts}.sarif"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2, ensure_ascii=False)

    return os.path.abspath(filepath)
