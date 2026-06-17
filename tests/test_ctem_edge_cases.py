import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import requests

import ai_remediation
import ocsf_exporter

# Import the core CTEM modules
import threat_intel


class MockConsole:
    def print(self, *args, **kwargs):
        pass


def generate_edge_case_results():
    """Generates 100+ different edge cases for plugin_results."""
    cases = []

    # Base payloads
    valid_cve = "CVE-2023-1234"
    valid_cve_kev = "CVE-2021-44228"  # Log4j (known)
    invalid_cve = "CVE-999-999999"
    unicode_payload = "Exploited 💣 💀 \\x1b[31mTerminal Injection\\x1b[0m"
    long_payload = "A" * 10000

    severities = ["BAIXO", "MEDIO", "ALTO", "CRITICO", "INFO", None, 123]
    descriptions = [
        f"Found {valid_cve}",
        f"Found {valid_cve_kev}",
        f"Found {invalid_cve}",
        unicode_payload,
        long_payload,
        None,
        "",
    ]

    # Construct permutations (7 severities * 7 descriptions * 2 structural variants = 98 cases)
    # Plus edge cases

    for sev in severities:
        for desc in descriptions:
            cases.append([{"plugin": "test", "resultados": [{"nome": "vuln1", "severidade": sev, "descricao": desc}]}])
            cases.append([{"plugin": "test2", "resultados": [{"nome": None, "severidade": sev, "descricao": desc}]}])

    # Structural edge cases
    cases.extend(
        [
            [],  # empty
            [{}],  # empty dict
            [{"plugin": "test", "resultados": []}],  # empty results
            [{"plugin": "test", "resultados": None}],  # None results
            [{"plugin": "test", "resultados": "Not a list"}],  # String results
            [{"plugin": "test", "resultados": [1, 2, 3]}],  # Ints in results
        ]
    )

    return cases


EDGE_CASES = generate_edge_case_results()


@pytest.mark.parametrize("plugin_results", EDGE_CASES)
def test_threat_intel_edge_cases(plugin_results):
    console = MockConsole()
    # Execute enrich_results and ensure no crashes occur (resilience)
    # The requirement is NOT TO MASK ERRORS but rather handle them natively in the function.
    try:
        enriched = threat_intel.enrich_results(plugin_results, console)
        assert isinstance(enriched, list)
    except Exception as e:
        pytest.fail(f"threat_intel crashed on edge case: {plugin_results}. Error: {e}")


@pytest.mark.parametrize("plugin_results", EDGE_CASES)
def test_ai_remediation_edge_cases(plugin_results):
    console = MockConsole()
    try:
        remediated = ai_remediation.generate_ai_fixes(plugin_results, console)
        assert isinstance(remediated, list)
    except Exception as e:
        pytest.fail(f"ai_remediation crashed on edge case: {plugin_results}. Error: {e}")


@pytest.mark.parametrize("plugin_results", EDGE_CASES)
def test_ocsf_exporter_edge_cases(plugin_results):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = ocsf_exporter.export_ocsf("target.com", "1.1.1.1", plugin_results, 5.0, tmpdir)
            if file_path:
                assert os.path.exists(file_path)
                with open(file_path) as f:
                    # Should be valid JSONL
                    for line in f:
                        json.loads(line)
    except Exception as e:
        pytest.fail(f"ocsf_exporter crashed on edge case: {plugin_results}. Error: {e}")


@patch("requests.get")
def test_threat_intel_network_failures(mock_get):
    """Test combined advanced techniques: network timeouts, 503s, malformed responses."""
    console = MockConsole()
    results = [
        {"plugin": "test", "resultados": [{"nome": "test", "severidade": "BAIXO", "descricao": "CVE-2021-44228"}]}
    ]

    # Timeout
    mock_get.side_effect = requests.exceptions.Timeout("Timeout")
    try:
        enriched = threat_intel.enrich_results(results, console)
        assert len(enriched) > 0
    except Exception as e:
        pytest.fail(f"Failed to handle timeout: {e}")

    # Malformed JSON
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
    mock_get.side_effect = None
    mock_get.return_value = mock_response

    try:
        enriched = threat_intel.enrich_results(results, console)
        assert len(enriched) > 0
    except Exception as e:
        pytest.fail(f"Failed to handle malformed JSON: {e}")
