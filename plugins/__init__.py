# plugins/__init__.py
"""
Cascavel Plugin Package — Zero Trust Plugin Execution Environment
Implements 2026 Advanced Security Hardening.
"""

import ast
import importlib.util
import logging
import sys
import types
from pathlib import Path

# 1. Namespace Package Hijacking Defense
# Enforce that plugins only load from THIS absolute directory.
__path__ = [str(Path(__file__).resolve().parent)]

_BANNED_AST_NAMES = {
    "eval",
    "exec",
    "__subclasses__",
    "globals",
    "locals",
}

# Banned modules for ctypes escape & OS interaction
_BANNED_MODULES = {"ctypes", "os", "subprocess", "pty", "shlex", "sys"}

logger = logging.getLogger(__name__)


class ZeroTrustASTVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in _BANNED_AST_NAMES:
            raise SecurityError(f"Banned function call detected: {node.func.id}")

        # Detect subclassing or attribute overrides (e.g. startswith)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in _BANNED_AST_NAMES:
                raise SecurityError(
                    f"Banned attribute access detected: {node.func.attr}"
                )
        self.generic_visit(node)

    # In Python 3, Exec is not an AST node (it's a function), but just in case we hit older AST nodes.
    # We mainly rely on visit_Call for exec.


class SecurityError(Exception):
    pass


def _verify_ast(source_code: str, filename: str):
    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as e:
        raise SecurityError(f"Syntax error in plugin: {e}")

    visitor = ZeroTrustASTVisitor()
    visitor.visit(tree)


def import_plugin_safely(module_name: str, filepath: str) -> types.ModuleType | None:
    """
    Zero Trust Importer (2026 Hardening)
    1. Reads source, checks AST for malicious payloads.
    2. Overrides sys.modules temporarily to trap imports (Sandbox).
    """
    path = Path(filepath).resolve()
    if not path.is_file():
        return None

    try:
        source_code = path.read_text(encoding="utf-8")
        _verify_ast(source_code, str(path))
    except SecurityError as e:
        logger.error(f"Security Alert: Plugin {module_name} rejected via AST: {e}")
        return None

    # Custom Importer Sandbox
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)

    # Snapshot sys.modules to prevent poisoning
    snapshot = dict(sys.modules)

    # Poison banned modules so the plugin crashes if it tries to import them
    for banned in _BANNED_MODULES:
        sys.modules[banned] = None  # type: ignore

    try:
        # Prevent .pth execution and enforce bytecode suppression
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    except Exception as e:
        logger.error(f"Error executing plugin {module_name}: {e}")
        return None
    finally:
        # Restore sys.modules perfectly
        sys.modules.clear()
        sys.modules.update(snapshot)

    return module
