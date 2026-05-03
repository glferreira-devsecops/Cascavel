import subprocess
from unittest.mock import MagicMock, patch

import pytest

import cascavel


def test_engine_handles_plugin_crash():
    """Testa se a engine (cascavel.py) sobrevive se um plugin lançar exception critica"""

    def fake_run(target, ip, ports, banners):
        raise RuntimeError("CRASH FATAL DO PLUGIN")

    mock_mod = MagicMock()
    mock_mod.run = fake_run

    with (
        patch("importlib.util.module_from_spec", return_value=mock_mod),
        patch("importlib.util.spec_from_file_location") as mock_spec,
    ):
        mock_loader = MagicMock()
        mock_spec.return_value.loader = mock_loader

        try:
            res = cascavel._exec_plugin(
                path="/fake/path.py", name="fake_plugin", target="example.com", ip="1.1.1.1", ports=[], banners={}
            )
            assert "erro" in res
            assert "CRASH FATAL DO PLUGIN" in res["erro"]
        except Exception as e:
            pytest.fail(f"Engine não tratou crash do plugin, levantou exception: {e}")


def test_engine_handles_tool_timeout():
    """Testa o comportamento da engine ao receber um timeout em ferramentas externas"""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="fake", timeout=1)):
        try:
            res = cascavel.run_cmd("fake_tool --target example.com", timeout=1)
            assert "TIMEOUT" in res or res == ""
        except Exception as e:
            pytest.fail(f"Engine não tratou timeout da tool: {e}")
