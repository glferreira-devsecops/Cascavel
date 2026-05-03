"""
╔══════════════════════════════════════════════════════════════════╗
║  CASCAVEL v3.0.0 — Plugin API v2 Schema                         ║
║  Standardized return schema with CVSS v4.0 scoring              ║
║  Product of RET Tecnologia (https://rettecnologia.org)          ║
╚══════════════════════════════════════════════════════════════════╝

Every plugin SHOULD return a dict compatible with PluginResult.
Legacy plugins (returning arbitrary dicts) are still supported
via PluginResult.from_legacy() adapter for backward compatibility.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY ENUM (string-based for JSON serialization)
# ═══════════════════════════════════════════════════════════════════════════════
VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

# Maps Portuguese severity keys (legacy) to standardized English keys
_SEVERITY_MAP: dict[str, str] = {
    "CRITICO": "CRITICAL",
    "ALTO": "HIGH",
    "MEDIO": "MEDIUM",
    "BAIXO": "LOW",
    "INFO": "INFO",
    # Already English — pass through
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# CVSS v4.0 score ranges → severity
_CVSS_SEVERITY: list[tuple[float, float, str]] = [
    (9.0, 10.0, "CRITICAL"),
    (7.0, 8.9, "HIGH"),
    (4.0, 6.9, "MEDIUM"),
    (0.1, 3.9, "LOW"),
    (0.0, 0.0, "INFO"),
]


def severity_from_cvss(score: float) -> str:
    """Derive severity label from CVSS v4.0 score."""
    for low, high, label in _CVSS_SEVERITY:
        if low <= score <= high:
            return label
    return "INFO"


def normalize_severity(raw: str) -> str:
    """Normalize severity string (PT-BR or EN) to standardized English."""
    return _SEVERITY_MAP.get(raw.upper().strip(), "INFO")


# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN RESULT DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class PluginResult:
    """Standardized return schema for Cascavel plugins (API v2).

    Attributes:
        plugin: Plugin module name (e.g., 'xss_scanner').
        version: Plugin version string.
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        cvss_score: CVSS v4.0 base score (0.0–10.0).
        cvss_vector: Full CVSS v4.0 vector string.
        cwe: CWE identifier (e.g., 'CWE-79').
        owasp: OWASP Top 10 2021 mapping (e.g., 'A03:2021').
        title: One-line finding title.
        description: Detailed finding description.
        evidence: Raw evidence (HTTP response, payload, etc.).
        remediation: Recommended fix.
        references: URLs to advisories, documentation.
        findings: List of individual findings (backward compat with v1 API).
    """

    plugin: str
    version: str = "2.0.0"
    severity: str = "INFO"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe: str = ""
    owasp: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate and normalize fields after init."""
        self.severity = normalize_severity(self.severity)
        if self.severity not in VALID_SEVERITIES:
            self.severity = "INFO"
        self.cvss_score = max(0.0, min(10.0, self.cvss_score))
        # Auto-derive severity from CVSS if severity wasn't explicitly set
        if self.cvss_score > 0 and self.severity == "INFO":
            self.severity = severity_from_cvss(self.cvss_score)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output / SARIF conversion."""
        return asdict(self)

    @classmethod
    def from_legacy(cls, data: dict[str, Any]) -> PluginResult:
        """Adapt a legacy plugin return dict to PluginResult.

        Handles v1 API keys like 'resultados', 'severidade', 'correcao',
        'tecnicas', 'versao', etc.
        """
        plugin_name = data.get("plugin", "unknown")
        version = data.get("versao", data.get("version", "1.0.0"))

        # Extract severity
        raw_sev = data.get("severity", data.get("severidade", "INFO"))
        resultados = data.get("resultados", data.get("findings", ""))

        # If resultados is a dict with 'severidade' at root
        if isinstance(resultados, dict):
            raw_sev = resultados.get("severidade", raw_sev)

        # Extract findings list
        findings: list[dict[str, Any]] = []
        if isinstance(resultados, list):
            for item in resultados:
                if isinstance(item, dict):
                    findings.append(item)
                elif item:
                    findings.append({"detail": str(item)})
        elif isinstance(resultados, dict):
            vulns = resultados.get("vulns", [])
            if isinstance(vulns, list):
                findings = [v for v in vulns if isinstance(v, dict)]
            elif resultados.get("status") == "vulneravel":
                findings = [resultados]
        elif resultados and str(resultados).strip():
            findings = [{"detail": str(resultados)}]

        # Determine highest severity from findings
        highest_sev = raw_sev
        for f in findings:
            f_sev = f.get("severidade", f.get("severity", "INFO"))
            if _severity_rank(normalize_severity(str(f_sev))) > _severity_rank(normalize_severity(str(highest_sev))):
                highest_sev = f_sev

        # Error handling
        if "erro" in data:
            return cls(
                plugin=plugin_name,
                version=str(version),
                severity="INFO",
                title=f"Plugin error: {data['erro']}",
                description=str(data["erro"]),
            )

        return cls(
            plugin=plugin_name,
            version=str(version),
            severity=str(highest_sev),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cvss_vector=str(data.get("cvss_vector", "")),
            cwe=str(data.get("cwe", "")),
            owasp=str(data.get("owasp", "")),
            title=str(data.get("title", f"Finding from {plugin_name}")),
            description=str(data.get("description", "")),
            evidence=str(data.get("evidence", "")),
            remediation=str(data.get("correcao", data.get("remediation", ""))),
            references=data.get("references", []),
            findings=findings,
        )


def _severity_rank(sev: str) -> int:
    """Numeric rank for severity comparison (higher = worse)."""
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(sev, 0)
