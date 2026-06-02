import json
import os
import tempfile

from hypothesis import given
from hypothesis import strategies as st

from sarif_exporter import _SARIF_LEVEL, _result_to_sarif, export_sarif


def test_result_to_sarif_basic():
    result = {
        "plugin": "test_plugin",
        "severity": "CRITICAL",
        "title": "SQL Injection",
        "evidence": "SELECT * FROM users",
        "target": "http://example.com",
    }
    sarif_result, rule = _result_to_sarif(result, 0)
    assert sarif_result["level"] == "error"
    assert sarif_result["ruleId"] == "cascavel/test_plugin"
    assert rule["id"] == "cascavel/test_plugin"
    assert sarif_result["attachments"][0]["contents"]["text"] == "SELECT * FROM users"


@given(
    st.text(),
    st.sampled_from(
        [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "CRITICO",
            "ALTO",
            "MEDIO",
            "BAIXO",
            "UNKNOWN",
        ]
    ),
)
def test_result_to_sarif_fuzz(plugin_name, severity):
    result = {
        "plugin": plugin_name,
        "severity": severity,
        "title": "A random finding",
        "evidence": "Some evidence",
    }
    sarif_result, rule = _result_to_sarif(result, 1)

    expected_level = _SARIF_LEVEL.get(severity.upper(), "note")
    assert sarif_result["level"] == expected_level
    assert "cascavel/" in sarif_result["ruleId"]


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "plugin": st.text(),
                "severity": st.sampled_from(["HIGH", "LOW"]),
                "findings": st.lists(st.text(), max_size=3),
                "remediation": st.text(),
            }
        ),
        max_size=5,
    )
)
def test_export_sarif_fuzz(results):
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = export_sarif("example.com", "1.2.3.4", results, 10.5, tmpdir)
        assert os.path.exists(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

        # Verify findings count matches (except empty errors which are skipped)
        run = data["runs"][0]
        # Our export skips errors without findings, but in our fuzz we didn't specify 'erro'
        assert len(run["results"]) == len(results)
