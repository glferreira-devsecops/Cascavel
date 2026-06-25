"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Constants & Style                                ║
╚═══════════════════════════════════════════════════════════════╝
"""

from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════════
BASE_PATH = Path(__file__).resolve().parent.parent
EXPORTS_PATH = BASE_PATH / "exports"
REPORTS_PATH = BASE_PATH / "reports"
PLUGINS_PATH = BASE_PATH / "plugins"
WORDLISTS_PATH = BASE_PATH / "wordlists"
NUCLEI_TEMPLATES_PATH = BASE_PATH / "nuclei-templates"
PROFILES_PATH = BASE_PATH / "profiles"

for _p in [EXPORTS_PATH, REPORTS_PATH, PLUGINS_PATH, WORDLISTS_PATH, NUCLEI_TEMPLATES_PATH]:
    _p.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
# STYLE CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
S_GREEN = "bold bright_green"
S_RED = "bold red"
S_CYAN = "bold cyan"
S_WHITE = "bold white"
S_DIM = "dim"
S_YELLOW = "bold yellow"

SEV_MAP = {
    "CRITICO": (S_RED, "💀"),
    "ALTO": ("red", "🔴"),
    "MEDIO": ("yellow", "🟡"),
    "BAIXO": ("cyan", "🔵"),
    "INFO": (S_DIM, "⚪"),
}

__version__ = "3.0.1"
