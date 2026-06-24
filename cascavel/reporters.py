"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Report Generators                                ║
║  MD, JSON, PDF, SARIF, OCSF export                           ║
╚═══════════════════════════════════════════════════════════════╝
"""

import datetime
import json
import os
from pathlib import Path
from typing import Any

from .constants import REPORTS_PATH, __version__


def _safe_join(base_path: str | Path, *paths: str) -> str:
    """Join paths with traversal protection (CWE-22)."""
    base = Path(base_path).resolve()
    joined = base.joinpath(*paths).resolve()
    if not str(joined).startswith(str(base)):
        raise ValueError(f"Path traversal detected: {joined}")
    return str(joined)


def _sanitize_for_json(obj: Any) -> Any:
    """Sanitiza objeto para serialização JSON segura."""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_json(i) for i in obj]
    return obj


def save_report(content: str) -> str:
    """Salva relatório Markdown."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cascavel_report_{ts}.md"
    path = os.path.join(REPORTS_PATH, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def save_json_report(
    target: str, ip: str, plugin_results: list[dict], elapsed: float,
) -> str:
    """Salva relatório JSON estruturado."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cascavel_report_{ts}.json"
    path = os.path.join(REPORTS_PATH, filename)
    report = _sanitize_for_json({
        "cascavel_version": __version__,
        "target": target,
        "ip": ip,
        "timestamp": datetime.datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 2),
        "plugin_results": plugin_results,
    })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path
