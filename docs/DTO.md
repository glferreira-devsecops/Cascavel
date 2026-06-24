# 📋 Data Transfer Objects (DTOs)

## Plugin Result DTO

```python
@dataclass
class PluginResult:
    plugin: str                    # Plugin name
    resultados: list[Finding] | str | dict  # Findings
    erro: str | None               # Error message (if failed)
    severidade: str | None         # Max severity
    epss_score: str | None         # EPSS probability
    cisa_kev: bool | None          # In CISA KEV catalog
    ai_remediation_script: str | None  # AI-generated fix
```

## Finding DTO

```python
@dataclass
class Finding:
    nome: str                      # Vulnerability name
    descricao: str                 # Description
    severidade: str                # CRITICO|ALTO|MEDIO|BAIXO|INFO
    evidencia: str                 # Evidence/proof
    correcao: str                  # Remediation advice
    cve: str | None                # CVE identifier
    epss_score: str | None         # EPSS probability
    cisa_kev: bool | None          # In CISA KEV
    severidade_original: str | None  # Original severity before elevation
```

## Scan Context DTO

```python
@dataclass
class ScanContext:
    baseline_latency: float        # Average response time (seconds)
    baseline_404_len: int          # Average 404 response length (bytes)
    discovered_params: list[str]   # Discovered parameters
    oob_server: str                # Out-of-band interaction server
```

## Scan Result DTO

```python
@dataclass
class ScanResult:
    cascavel_version: str          # Framework version
    target: str                    # Target hostname
    ip: str                        # Resolved IP
    timestamp: str                 # ISO 8601 timestamp
    duration_seconds: float        # Total scan duration
    plugin_results: list[PluginResult]  # All plugin results
    tools_used: dict[str, bool]    # External tools availability
    open_ports: list[int]          # Discovered open ports
    banners: dict[int, str]        # Port banners
```

## Report DTO

```python
@dataclass
class Report:
    format: str                    # md|json|pdf|sarif|ocsf
    path: str                      # File path
    target: str                    # Target
    total_findings: int            # Total findings count
    severity_breakdown: dict[str, int]  # {CRITICO: n, ALTO: n, ...}
    duration: float                # Scan duration
```

## Profile DTO

```python
@dataclass
class ScanProfile:
    name: str                      # Profile name
    description: str               # Description
    plugins: list[str]             # Plugin names to run
    all_plugins: bool              # Run all plugins
```

## Tool Status DTO

```python
@dataclass
class ToolStatus:
    name: str                      # Tool name
    available: bool                # Is installed
    version: str                   # Version string
```

## Threat Intel DTO

```python
@dataclass
class ThreatIntel:
    cve: str                       # CVE identifier
    epss_score: float              # EPSS probability (0.0-1.0)
    cisa_kev: bool                 # In CISA KEV catalog
    severity_elevated: bool        # Was severity elevated
    original_severity: str         # Original severity
    elevated_severity: str         # Elevated severity
    reason: str                    # Reason for elevation
```

## JSON Report Schema

```json
{
  "cascavel_version": "3.0.1",
  "target": "example.com",
  "ip": "93.184.216.34",
  "timestamp": "2026-06-24T14:30:00.000Z",
  "duration_seconds": 127.5,
  "plugin_results": [
    {
      "plugin": "sqli_scanner",
      "resultados": [
        {
          "nome": "SQL Injection in /api/users",
          "descricao": "Parameter 'id' is vulnerable to time-based blind SQL injection",
          "severidade": "CRITICO",
          "evidencia": "Response delayed by 5.2s with payload: 1' AND SLEEP(5)--",
          "correcao": "Use parameterized queries. Never concatenate user input into SQL.",
          "cve": "CWE-89",
          "epss_score": "94.2%",
          "cisa_kev": true
        }
      ]
    }
  ]
}
```

## SARIF v2.1.0 Schema

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Cascavel",
          "version": "3.0.1",
          "informationUri": "https://github.com/glferreira-devsecops/Cascavel"
        }
      },
      "results": [
        {
          "ruleId": "SQLI-001",
          "level": "error",
          "message": { "text": "SQL Injection in /api/users" },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "http://example.com/api/users" },
              "region": { "startLine": 1 }
            }
          }]
        }
      ]
    }
  ]
}
```

## OCSF v1.1.0 Schema

```json
{
  "activity_id": 1,
  "category_uid": 2,
  "class_uid": 2001,
  "severity": "High",
  "severity_id": 4,
  "status": "New",
  "time": 1719243000000,
  "message": "SQL Injection in /api/users",
  "observables": [{
    "type": "URL",
    "value": "http://example.com/api/users"
  }],
  "unmapped": {
    "plugin": "sqli_scanner",
    "cve": "CWE-89",
    "epss_score": "94.2%"
  }
}
```
