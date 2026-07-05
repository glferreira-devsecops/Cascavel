import subprocess
from unittest.mock import MagicMock, patch

import pytest

from cascavel import engine, tools


def test_engine_handles_plugin_crash():
    """Testa se a engine sobrevive se um plugin lançar exception crítica."""

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
            res = engine._exec_plugin(
                path="/fake/path.py",
                name="fake_plugin",
                target="example.com",
                ip="1.1.1.1",
                ports=[],
                banners={},
            )
            assert "erro" in res
            assert "CRASH FATAL DO PLUGIN" in res["erro"]
        except Exception as e:
            pytest.fail(f"Engine não tratou crash do plugin, levantou exception: {e}")


def test_engine_handles_tool_timeout():
    """Testa o comportamento da engine ao receber um timeout em ferramentas externas."""
    mock_proc = MagicMock()
    mock_proc.pid = 2**31 - 1  # PID inexistente → killpg levanta ProcessLookupError (tratado)
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="fake", timeout=1)

    with patch("cascavel.tools.subprocess.Popen", return_value=mock_proc):
        try:
            res = tools.run_cmd("fake_tool --target example.com", timeout=1)
            assert "TIMEOUT" in res or res == ""
        except Exception as e:
            pytest.fail(f"Engine não tratou timeout da tool: {e}")
