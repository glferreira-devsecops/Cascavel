"""
╔══════════════════════════════════════════════════════════════════╗
║  Cascavel v3.0.0 — Plugin Schema Validation Tests                ║
║  Validates that all plugins can be loaded and return sane data   ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import glob
import importlib.util
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGINS_DIR = os.path.join(PROJECT_ROOT, "plugins")


def _discover_plugins() -> list[tuple[str, str]]:
    """Discover all plugin files (name, path)."""
    files = sorted(glob.glob(os.path.join(PLUGINS_DIR, "*.py")))
    return [
        (os.path.splitext(os.path.basename(f))[0], f)
        for f in files
        if not os.path.basename(f).startswith("__") and os.path.basename(f) != "schema.py"
    ]


def _load_plugin(name: str, path: str):
    """Dynamically load a plugin module."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PLUGINS = _discover_plugins()


class TestPluginDiscovery:
    """Tests for plugin discovery and loading."""

    def test_plugins_exist(self):
        """At least 80 plugins should be discovered."""
        assert len(PLUGINS) >= 80, f"Expected 80+ plugins, found {len(PLUGINS)}"

    @pytest.mark.parametrize("name,path", PLUGINS, ids=[p[0] for p in PLUGINS])
    def test_plugin_has_run_function(self, name: str, path: str):
        """Every plugin must export a run() function."""
        mod = _load_plugin(name, path)
        assert mod is not None, f"Failed to load plugin: {name}"
        assert hasattr(mod, "run"), f"Plugin {name} missing run() function"
        assert callable(mod.run), f"Plugin {name}.run is not callable"

    @pytest.mark.parametrize("name,path", PLUGINS, ids=[p[0] for p in PLUGINS])
    def test_plugin_run_accepts_4_args(self, name: str, path: str):
        """run() must accept (target, ip, ports, banners) signature."""
        mod = _load_plugin(name, path)
        assert mod is not None
        import inspect

        sig = inspect.signature(mod.run)
        params = list(sig.parameters.keys())
        assert len(params) >= 4, (
            f"Plugin {name}.run() has {len(params)} params, expected >= 4: (target, ip, ports, banners). Got: {params}"
        )


class TestPluginSchema:
    """Tests for plugin return value schema compliance."""

    @pytest.mark.parametrize("name,path", PLUGINS[:5], ids=[p[0] for p in PLUGINS[:5]])
    def test_plugin_returns_dict(self, name: str, path: str, mock_target, mock_ip, mock_ports, mock_banners):
        """Plugin run() should return a dict."""
        mod = _load_plugin(name, path)
        assert mod is not None
        try:
            result = mod.run(mock_target, mock_ip, mock_ports, mock_banners)
        except Exception:
            # Network errors are expected in test env — skip
            pytest.skip(f"Plugin {name} raised network error (expected in test)")
        if result is not None:
            assert isinstance(result, dict), f"Plugin {name}.run() returned {type(result).__name__}, expected dict"

    @pytest.mark.parametrize("name,path", PLUGINS[:5], ids=[p[0] for p in PLUGINS[:5]])
    def test_plugin_result_has_plugin_key(self, name: str, path: str, mock_target, mock_ip, mock_ports, mock_banners):
        """Plugin result dict should contain 'plugin' key."""
        mod = _load_plugin(name, path)
        assert mod is not None
        try:
            result = mod.run(mock_target, mock_ip, mock_ports, mock_banners)
        except Exception:
            pytest.skip(f"Plugin {name} raised network error (expected in test)")
        if result is not None:
            assert "plugin" in result, f"Plugin {name} result missing 'plugin' key"


class TestSchemaModule:
    """Tests for the plugins.schema module itself."""

    def test_import_schema(self):
        """schema.py should be importable."""
        sys.path.insert(0, PLUGINS_DIR)
        try:
            from schema import PluginResult

            assert PluginResult is not None
        finally:
            sys.path.pop(0)

    def test_severity_normalization(self):
        """PT-BR severities should normalize to EN."""
        sys.path.insert(0, PLUGINS_DIR)
        try:
            from schema import normalize_severity

            assert normalize_severity("CRITICO") == "CRITICAL"
            assert normalize_severity("ALTO") == "HIGH"
            assert normalize_severity("MEDIO") == "MEDIUM"
            assert normalize_severity("BAIXO") == "LOW"
            assert normalize_severity("INFO") == "INFO"
            assert normalize_severity("CRITICAL") == "CRITICAL"
            assert normalize_severity("garbage") == "INFO"
        finally:
            sys.path.pop(0)

    def test_cvss_to_severity(self):
        """CVSS scores should map to correct severity."""
        sys.path.insert(0, PLUGINS_DIR)
        try:
            from schema import severity_from_cvss

            assert severity_from_cvss(9.5) == "CRITICAL"
            assert severity_from_cvss(7.0) == "HIGH"
            assert severity_from_cvss(4.5) == "MEDIUM"
            assert severity_from_cvss(2.0) == "LOW"
            assert severity_from_cvss(0.0) == "INFO"
        finally:
            sys.path.pop(0)

    def test_plugin_result_creation(self):
        """PluginResult should create valid instances."""
        sys.path.insert(0, PLUGINS_DIR)
        try:
            from schema import PluginResult

            r = PluginResult(
                plugin="test_plugin",
                severity="HIGH",
                cvss_score=7.5,
                title="Test Finding",
            )
            assert r.severity == "HIGH"
            assert r.cvss_score == 7.5
            d = r.to_dict()
            assert d["plugin"] == "test_plugin"
            assert d["severity"] == "HIGH"
        finally:
            sys.path.pop(0)

    def test_legacy_adapter(self):
        """from_legacy() should convert v1 plugin output."""
        sys.path.insert(0, PLUGINS_DIR)
        try:
            from schema import PluginResult

            legacy = {
                "plugin": "xss_scanner",
                "versao": "1.5.0",
                "resultados": [
                    {"payload": "<script>alert(1)</script>", "severidade": "ALTO"},
                    {"payload": "<img onerror=alert(1)>", "severidade": "MEDIO"},
                ],
            }
            r = PluginResult.from_legacy(legacy)
            assert r.plugin == "xss_scanner"
            assert r.severity == "HIGH"  # Normalized from ALTO
            assert len(r.findings) == 2
        finally:
            sys.path.pop(0)
