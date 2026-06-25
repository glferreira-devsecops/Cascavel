"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Security Module                                  ║
║  ANSI sanitizer, signal handling, output hardening           ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import re
import signal
import sys
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI ESCAPE SANITIZER — Anti-Terminal Injection (2026 Vector)
# ═══════════════════════════════════════════════════════════════════════════════
_ANSI_DANGEROUS_RE = re.compile(
    r"\x1b"
    r"(?:"
    r"\].*?(?:\x07|\x1b\\)"  # OSC sequences (title change, clipboard)
    r"|P.*?\x1b\\"  # DCS sequences
    r"|\[(?:"
    r"\d*[ABCDEFGHJKST]"  # Cursor movement
    r"|\d*;?\d*[Hf]"  # Cursor positioning
    r"|[su]"  # Cursor save/restore
    r"|\?\d+[hl]"  # Private mode set/reset
    r"|\d*[JK]"  # Erase in display/line
    r")"
    r")",
    re.DOTALL,
)


def _sanitize_output(data: Any) -> Any:
    """Sanitiza saída de plugin contra ANSI escape injection e CRLF Log Injection.

    Remove sequências perigosas (cursor movement, OSC, DCS) mas preserva
    cores SGR básicas (\\x1b[...m) para manter formatação visual.
    Também remove \\r para prevenir Log Forging (CWE-117).
    """
    if isinstance(data, str):
        if len(data) > 100000:
            data = data[:100000] + "... [TRUNCATED BY SECURITY LIMIT]"
        s = _ANSI_DANGEROUS_RE.sub("", data)
        return s.replace("\r", "")
    if isinstance(data, dict):
        return {k: _sanitize_output(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_output(item) for item in data]
    return data


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLING
# ═══════════════════════════════════════════════════════════════════════════════
_shutdown_requested = False


def _signal_handler(sig, frame):
    """Graceful shutdown handler — signal-safe (no print/logging to avoid deadlock)."""
    global _shutdown_requested
    _shutdown_requested = True
    sig_name = "SIGTERM" if sig == signal.SIGTERM else "SIGINT"
    exit_code = 128 + sig
    try:
        os.write(
            sys.stderr.fileno(),
            f"\n  \x1b[91m✗ {sig_name} recebido — encerrando...\x1b[0m\n".encode(),
        )
    except OSError:
        pass
    os._exit(exit_code)


def setup_signals():
    """Registra handlers de sinal (SIGINT, SIGTERM, SIGPIPE)."""
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
