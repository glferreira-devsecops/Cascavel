"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Self-Updater & Global Installer                  ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from .constants import S_CYAN, S_DIM, S_GREEN, S_RED, S_YELLOW, __version__

console = Console()

GITHUB_REPO = "glferreira-devsecops/Cascavel"


def _parse_semver(v: str) -> tuple[int, ...]:
    """Parse semver string to tuple for comparison."""
    clean = v.lstrip("v").split("-")[0]
    return tuple(int(x) for x in clean.split("."))


def check_for_update(quiet: bool = False) -> str | None:
    """Verifica se há atualizações disponíveis no GitHub."""
    try:
        import requests

        r = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout=5)
        if r.status_code != 200:
            return None
        data = r.json()
        remote_tag = data.get("tag_name", "")
        if not remote_tag:
            return None
        remote_ver = remote_tag.lstrip("v")
        local_ver = __version__

        if _parse_semver(remote_ver) > _parse_semver(local_ver):
            if not quiet:
                console.print(f"  [{S_YELLOW}]⬆ Nova versão disponível: v{remote_ver} (atual: v{local_ver})[/]")
                console.print(f"  [{S_DIM}]Execute: cascavel --update[/]")
            return remote_ver
        else:
            if not quiet:
                console.print(f"  [{S_GREEN}]✓ Cascavel v{local_ver} está atualizado.[/]")
            return None
    except Exception as _exc:
        return None


def self_update() -> None:
    """Atualiza o Cascavel para a versão mais recente."""
    console.print(f"  [{S_CYAN}]🔄 Verificando atualizações...[/]")

    try:
        import requests

        r = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout=10)
        if r.status_code != 200:
            console.print(f"  [{S_RED}]✗ Não foi possível verificar atualizações.[/]")
            return
        data = r.json()
        remote_tag = data.get("tag_name", "")
        remote_ver = remote_tag.lstrip("v")

        if _parse_semver(remote_ver) <= _parse_semver(__version__):
            console.print(f"  [{S_GREEN}]✓ Já está na versão mais recente (v{__version__}).[/]")
            return

        console.print(f"  [{S_YELLOW}]⬆ Atualizando v{__version__} → v{remote_ver}...[/]")

        # Try git pull first
        base_path = Path(__file__).resolve().parent.parent
        if (base_path / ".git").is_dir():
            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                capture_output=True,
                text=True,
                cwd=str(base_path),
            )
            if result.returncode == 0:
                console.print(f"  [{S_GREEN}]✓ Atualizado via git.[/]")
                return

        # Fallback: download zip
        zip_url = f"https://github.com/{GITHUB_REPO}/archive/refs/tags/{remote_tag}.zip"
        console.print(f"  [{S_DIM}]Baixando de {zip_url}...[/]")

        import tempfile
        import zipfile

        r = requests.get(zip_url, timeout=30)
        if r.status_code != 200:
            console.print(f"  [{S_RED}]✗ Download falhou.[/]")
            return

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(r.content)
            tmp_path = tmp.name

        with zipfile.ZipFile(tmp_path) as zf:
            zf.extractall(str(base_path.parent))

        os.unlink(tmp_path)
        console.print(f"  [{S_GREEN}]✓ Atualizado para v{remote_ver}. Reinicie o Cascavel.[/]")

    except Exception as e:
        console.print(f"  [{S_RED}]✗ Erro na atualização: {e}[/]")


def _install_global() -> None:
    """Instala o Cascavel como comando global no sistema."""
    console.print(f"  [{S_CYAN}]📦 Instalando Cascavel globalmente...[/]")

    base_path = Path(__file__).resolve().parent.parent
    cascavel_py = base_path / "cascavel.py"

    if not cascavel_py.exists():
        console.print(f"  [{S_RED}]✗ cascavel.py não encontrado em {base_path}[/]")
        return

    # Determine install location
    if sys.platform == "darwin" or sys.platform.startswith("linux"):
        scripts_dir = Path.home() / ".local" / "bin"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        target_path = scripts_dir / "cascavel"

        # Create wrapper script
        wrapper = f"""#!/usr/bin/env python3
import sys
sys.path.insert(0, "{base_path}")
from cascavel.cascavel import main
main()
"""
        with open(target_path, "w") as f:
            f.write(wrapper)
        os.chmod(str(target_path), 0o644)

        console.print(f"  [{S_GREEN}]✓ Instalado em: {target_path}[/]")
        _configure_path_export(str(scripts_dir))
    else:
        console.print(f"  [{S_YELLOW}]⚠ Instalação manual no Windows. Adicione {base_path} ao PATH.[/]")


def _configure_path_export(scripts_dir: str) -> None:
    """Configura export PATH se necessário."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rc_file = Path.home() / ".zshrc"
    elif "bash" in shell:
        rc_file = Path.home() / ".bashrc"
    else:
        return

    path_export = 'export PATH="$HOME/.local/bin:$PATH"'
    try:
        if rc_file.exists():
            content = rc_file.read_text()
            if ".local/bin" in content:
                return
        with open(rc_file, "a") as f:
            f.write(f"\n# Cascavel global install\n{path_export}\n")
        console.print(f"  [{S_DIM}]Adicionado PATH em {rc_file}. Execute: source {rc_file}[/]")
    except Exception as _exc:
        console.print(f"  [{S_YELLOW}]⚠ Adicione manualmente: {path_export}[/]")
