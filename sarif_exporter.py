"""
Cascavel SARIF Exporter (2026 Standards)
Generates SARIF 2.1.0 compliant JSON logs for integration with GitHub Code Scanning, GitLab Security, and DefectDojo.
"""

import datetime
import json
import os
from typing import Any

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "CRITICO": "error",
    "ALTO": "error",
    "MEDIUM": "warning",
    "MEDIO": "warning",
    "LOW": "note",
    "BAIXO": "note",
    "INFO": "note",
}


def _result_to_sarif(
    result: dict[str, Any], index: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    plugin = result.get("plugin", "unknown")
    severity = str(result.get("severity", "INFO")).upper()
    title = str(result.get("title", f"Finding from {plugin}"))
    evidence = str(result.get("evidence", ""))

    rule_id = f"cascavel/{plugin}"
    sarif_level = _SARIF_LEVEL.get(severity, "note")

    rule = {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": title},
        "properties": {"tags": [severity], "precision": "high"},
    }

    sarif_result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": sarif_level,
        "message": {"text": title},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.get("target", "target_environment")
                    }
                }
            }
        ],
    }

    if evidence:
        sarif_result["attachments"] = [
            {"description": {"text": "Evidence"}, "contents": {"text": evidence}}
        ]

    return sarif_result, rule


def export_sarif(
    target: str,
    ip: str,
    results: list[dict[str, Any]],
    duration: float,
    output_dir: str,
) -> str:
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for i, res in enumerate(results):
        if "erro" in res and not res.get("findings"):
            continue
        sarif_res, rule = _result_to_sarif(res, i)
        sarif_results.append(sarif_res)
        rules_dict[rule["id"]] = rule

    sarif_log: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cascavel",
                        "version": "3.0.1",
                        "informationUri": "https://rettecnologia.org",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"cascavel_{target}_{timestamp}.sarif")

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sarif_log, f, indent=2)

    return filepath
