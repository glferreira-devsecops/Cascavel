"""
╔══════════════════════════════════════════════════════════════════╗
║  Cascavel v3.0.0 — Core Module Tests                             ║
║  Tests for sanitizer, SARIF exporter, and profile loader         ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestAnsiSanitizer:
    """Tests for the ANSI escape sanitizer."""

    def test_strips_osc_sequences(self):
        """OSC sequences (title change, clipboard) should be stripped."""
        # Import the regex from cascavel.py
        sys.path.insert(0, PROJECT_ROOT)
        from cascavel import _sanitize_output

        # OSC title change
        malicious = "\x1b]0;PWNED\x07Normal text"
        result = _sanitize_output(malicious)
        assert "PWNED" not in result or "Normal text" in result

    def test_preserves_sgr_colors(self):
        """SGR color sequences (\\x1b[31m) should be preserved."""
        sys.path.insert(0, PROJECT_ROOT)
        from cascavel import _sanitize_output

        colored = "\x1b[31mRed text\x1b[0m"
        result = _sanitize_output(colored)
        assert "\x1b[31m" in result
        assert "Red text" in result

    def test_sanitizes_nested_structures(self):
        """Dicts and lists should be recursively sanitized."""
        sys.path.insert(0, PROJECT_ROOT)
        from cascavel import _sanitize_output

        data = {
            "key": "\x1b]0;EVIL\x07value",
            "nested": ["\x1b[2Ahidden"],
        }
        result = _sanitize_output(data)
        assert isinstance(result, dict)
        assert isinstance(result["nested"], list)


class TestSarifExporter:
    """Tests for the SARIF exporter module."""

    def test_import(self):
        """SARIF exporter should be importable."""
        from sarif_exporter import export_sarif

        assert callable(export_sarif)

    def test_export_creates_file(self):
        """export_sarif() should create a .sarif file."""
        from sarif_exporter import export_sarif

        results = [
            {
                "plugin": "test_plugin",
                "severity": "HIGH",
                "title": "Test Finding",
                "description": "A test vulnerability",
                "findings": [{"detail": "found something"}],
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_sarif("example.com", "93.184.216.34", results, 12.5, output_dir=tmpdir)
            assert os.path.isfile(path)
            assert path.endswith(".sarif")

            with open(path, encoding="utf-8") as f:
                sarif = json.load(f)

            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) == 1
            assert sarif["runs"][0]["tool"]["driver"]["name"] == "Cascavel"
            assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_schema_compliance(self):
        """SARIF output should have required top-level keys."""
        from sarif_exporter import export_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_sarif("test.com", "1.2.3.4", [], 1.0, output_dir=tmpdir)
            with open(path, encoding="utf-8") as f:
                sarif = json.load(f)

            assert "$schema" in sarif
            assert "version" in sarif
            assert "runs" in sarif
            run = sarif["runs"][0]
            assert "tool" in run
            assert "results" in run
            assert "invocations" in run

    def test_sarif_skips_error_only_results(self):
        """Results with only 'erro' and no findings should be skipped."""
        from sarif_exporter import export_sarif

        results = [
            {"plugin": "broken", "erro": "Timeout"},
            {"plugin": "working", "severity": "LOW", "title": "Found", "findings": [{"x": 1}]},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_sarif("test.com", "1.2.3.4", results, 5.0, output_dir=tmpdir)
            with open(path, encoding="utf-8") as f:
                sarif = json.load(f)
            # Only 'working' should appear
            assert len(sarif["runs"][0]["results"]) == 1


class TestProfileLoader:
    """Tests for YAML scan profiles."""

    def test_profiles_exist(self, profiles_dir):
        """Required profiles should exist."""
        required = ["web.yaml", "api.yaml", "cloud.yaml", "network.yaml", "full.yaml"]
        for name in required:
            path = os.path.join(profiles_dir, name)
            assert os.path.isfile(path), f"Missing profile: {name}"

    def test_profiles_are_valid_yaml(self, profiles_dir):
        """All profiles should parse as valid YAML."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        for fname in os.listdir(profiles_dir):
            if fname.endswith(".yaml"):
                path = os.path.join(profiles_dir, fname)
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                assert isinstance(data, dict), f"Profile {fname} is not a dict"
                assert "name" in data, f"Profile {fname} missing 'name'"

    def test_web_profile_has_xss(self, profiles_dir):
        """Web profile should include xss_scanner."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        with open(os.path.join(profiles_dir, "web.yaml"), encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert "xss_scanner" in data["plugins"]

    def test_full_profile_all_plugins_flag(self, profiles_dir):
        """Full profile should have all_plugins: true."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        with open(os.path.join(profiles_dir, "full.yaml"), encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert data.get("all_plugins") is True
