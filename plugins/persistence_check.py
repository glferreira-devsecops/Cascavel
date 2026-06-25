# plugins/persistence_check.py — Cascavel 2026 Intelligence
import os
import subprocess

# Systemd service directories
SYSTEMD_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/etc/systemd/user",
    "/usr/lib/systemd/user",
]

# Shell profile files
SHELL_PROFILES = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshrc",
    "/etc/zshenv",
    "/etc/csh.cshrc",
    "/etc/csh.login",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.zshrc",
    "/root/.zshenv",
    "/root/.bash_login",
    "/root/.bash_logout",
    "/home/*/.bashrc",
    "/home/*/.bash_profile",
    "/home/*/.profile",
    "/home/*/.zshrc",
    "/home/*/.zshenv",
]

# SSH-related paths
SSH_PATHS = [
    "/root/.ssh/authorized_keys",
    "/root/.ssh/authorized_keys2",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_dsa",
    "/root/.ssh/id_ecdsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/config",
    "/etc/ssh/sshd_config",
    "/home/*/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys2",
]

# LD_PRELOAD related
LD_PRELOAD_PATHS = [
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/",
]

# Startup/init directories
STARTUP_DIRS = [
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/rc.d",
    "/etc/init",
    "/etc/init/",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
]

# Persistence-related patterns in configs
SUSPICIOUS_PATTERNS = [
    "nc -e",
    "ncat -e",
    "bash -i",
    "/dev/tcp",
    "python -c",
    "perl -e",
    "ruby -e",
    "lua -e",
    "wget http",
    "curl http",
    "fetch http",
    "base64 -d",
    "eval(",
    "exec(",
    "chmod +s",
    "chmod 4755",
    "setuid",
    "reverse",
    "shell",
    "backdoor",
    "connect",
    "payload",
    "exploit",
    "tunnel",
]


def _check_crontab_entries():
    """Check for crontab entries (persistence mechanism)."""
    findings = []

    # System crontabs
    cron_files = ["/etc/crontab", "/etc/anacrontab"]
    cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    for cron_file in cron_files:
        try:
            with open(cron_file) as f:
                content = f.read().strip()
                if content:
                    entries = [line for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    findings.append(
                        {
                            "tipo": "CRONTAB_SYSTEM",
                            "arquivo": cron_file,
                            "entradas": len(entries),
                            "severidade": "INFO",
                            "descricao": f"Sistema crontab com {len(entries)} entradas em {cron_file}",
                            "preview": entries[:10] if entries else [],
                        }
                    )

                    # Check for suspicious entries
                    for entry in entries:
                        lower = entry.lower()
                        for pattern in SUSPICIOUS_PATTERNS:
                            if pattern in lower:
                                findings.append(
                                    {
                                        "tipo": "CRONTAB_SUSPICIOUS",
                                        "arquivo": cron_file,
                                        "entrada": entry,
                                        "padrao": pattern,
                                        "severidade": "CRITICO",
                                        "descricao": f"Crontab suspeita em {cron_file}: contém '{pattern}'",
                                        "remediacao": "Investigar entrada. Remover se não for legítima.",
                                    }
                                )
                                break
        except PermissionError:
            continue
        except FileNotFoundError:
            continue
        except Exception:
            continue

    for cron_dir in cron_dirs:
        try:
            if os.path.isdir(cron_dir):
                for filename in os.listdir(cron_dir):
                    if filename.startswith("."):
                        continue
                    filepath = os.path.join(cron_dir, filename)
                    try:
                        with open(filepath) as f:
                            content = f.read().strip()
                            entries = [
                                line for line in content.splitlines() if line.strip() and not line.startswith("#")
                            ]
                            if entries:
                                findings.append(
                                    {
                                        "tipo": "CRON_DIR_ENTRY",
                                        "diretorio": cron_dir,
                                        "arquivo": filename,
                                        "entradas": len(entries),
                                        "severidade": "INFO",
                                        "descricao": f"Cron entry: {cron_dir}/{filename}",
                                        "preview": entries[:5],
                                    }
                                )

                                # Check for suspicious patterns
                                for entry in entries:
                                    lower = entry.lower()
                                    for pattern in SUSPICIOUS_PATTERNS:
                                        if pattern in lower:
                                            findings.append(
                                                {
                                                    "tipo": "CRON_SUSPICIOUS",
                                                    "arquivo": filepath,
                                                    "entrada": entry,
                                                    "padrao": pattern,
                                                    "severidade": "CRITICO",
                                                    "descricao": f"Cron suspeito em {filepath}: contém '{pattern}'",
                                                    "remediacao": f"Investigar e remover {filepath} se malicioso.",
                                                }
                                            )
                                            break
                    except PermissionError:
                        continue
                    except Exception:
                        continue
        except Exception:
            continue

    # User crontabs
    try:
        result = subprocess.run(
            ["ls", "/var/spool/cron/crontabs/"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            users = result.stdout.strip().split()
            findings.append(
                {
                    "tipo": "USER_CRONTABS_FOUND",
                    "usuarios": users,
                    "severidade": "INFO",
                    "descricao": f"User crontabs: {', '.join(users)}",
                }
            )

            for user in users:
                try:
                    with open(f"/var/spool/cron/crontabs/{user}") as f:
                        content = f.read().strip()
                        entries = [line for line in content.splitlines() if line.strip() and not line.startswith("#")]
                        if entries:
                            findings.append(
                                {
                                    "tipo": "USER_CRONTAB",
                                    "usuario": user,
                                    "entradas": len(entries),
                                    "severidade": "MEDIO",
                                    "descricao": f"Crontab do usuário {user} com {len(entries)} entradas",
                                    "preview": entries[:5],
                                }
                            )
                except Exception:
                    continue
    except Exception:  # noqa: S110
        pass

    return findings


def _check_systemd_services():
    """Check for systemd service persistence."""
    findings = []

    for systemd_dir in SYSTEMD_DIRS:
        try:
            if not os.path.isdir(systemd_dir):
                continue

            for filename in os.listdir(systemd_dir):
                if not filename.endswith(".service"):
                    continue
                filepath = os.path.join(systemd_dir, filename)
                try:
                    with open(filepath) as f:
                        content = f.read()

                    finding = {
                        "tipo": "SYSTEMD_SERVICE",
                        "arquivo": filepath,
                        "nome": filename,
                        "severidade": "INFO",
                    }

                    # Parse service type
                    for line in content.splitlines():
                        if line.startswith("ExecStart="):
                            finding["exec_start"] = line.split("=", 1)[1].strip()
                        elif line.startswith("Type="):
                            finding["service_type"] = line.split("=", 1)[1].strip()
                        elif line.startswith("User="):
                            finding["user"] = line.split("=", 1)[1].strip()

                    finding["descricao"] = f"Systemd service: {filename}"

                    # Check for suspicious patterns
                    lower = content.lower()
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern in lower:
                            finding["severidade"] = "CRITICO"
                            finding["descricao"] = f"Systemd service suspeito: {filename} — contém '{pattern}'"
                            finding["remediacao"] = f"Investigar e desabilitar: systemctl disable {filename}"
                            break

                    # Check if recently modified (possible persistence)
                    try:
                        stat = os.stat(filepath)
                        finding["modificado"] = stat.st_mtime
                    except Exception:  # noqa: S110
                        pass

                    findings.append(finding)
                except PermissionError:
                    continue
                except Exception:
                    continue

            # Check for enabled services
            try:
                result = subprocess.run(
                    ["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    enabled = []
                    for line in result.stdout.splitlines():
                        if "enabled" in line and ".service" in line:
                            svc = line.split()[0]
                            enabled.append(svc)

                    findings.append(
                        {
                            "tipo": "ENABLED_SERVICES",
                            "quantidade": len(enabled),
                            "servicos": enabled,
                            "severidade": "INFO",
                            "descricao": f"{len(enabled)} serviços habilitados no boot",
                        }
                    )
            except FileNotFoundError:
                pass
            except Exception:  # noqa: S110
                pass

        except Exception:
            continue

    return findings


def _check_shell_profiles():
    """Check for shell profile modifications (persistence)."""
    findings = []

    for profile_path in SHELL_PROFILES:
        # Handle glob patterns
        if "*" in profile_path:
            import glob

            paths = glob.glob(profile_path)
        else:
            paths = [profile_path]

        for path in paths:
            try:
                if not os.path.isfile(path):
                    continue

                with open(path) as f:
                    content = f.read()

                if not content.strip():
                    continue

                # Check for suspicious patterns
                lower = content.lower()
                suspicious_found = []
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in lower:
                        suspicious_found.append(pattern)

                if suspicious_found:
                    findings.append(
                        {
                            "tipo": "PROFILE_SUSPICIOUS",
                            "arquivo": path,
                            "padroes": suspicious_found,
                            "severidade": "CRITICO",
                            "descricao": f"Shell profile contém padrões suspeitos: {', '.join(suspicious_found)}",
                            "remediacao": f"Revisar {path}. Remover entradas maliciosas.",
                            "preview": content[:300],
                        }
                    )
                else:
                    # Check for non-standard entries
                    lines = [
                        line.strip()
                        for line in content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    findings.append(
                        {
                            "tipo": "PROFILE_ENTRIES",
                            "arquivo": path,
                            "entradas": len(lines),
                            "severidade": "INFO",
                            "descricao": f"Shell profile com {len(lines)} entradas: {path}",
                        }
                    )
            except PermissionError:
                continue
            except Exception:
                continue

    return findings


def _check_ssh_authorized_keys():
    """Check for SSH authorized_keys manipulation."""
    findings = []

    for ssh_path in SSH_PATHS:
        if "*" in ssh_path:
            import glob

            paths = glob.glob(ssh_path)
        else:
            paths = [ssh_path]

        for path in paths:
            try:
                if not os.path.isfile(path):
                    continue

                with open(path) as f:
                    content = f.read()

                if "authorized_keys" in path:
                    keys = [line.strip() for line in content.splitlines() if line.strip()]
                    findings.append(
                        {
                            "tipo": "SSH_AUTHORIZED_KEYS",
                            "arquivo": path,
                            "chaves": len(keys),
                            "severidade": "MEDIO" if len(keys) > 0 else "INFO",
                            "descricao": f"{len(keys)} chaves SSH em {path}",
                        }
                    )

                    # Check for suspicious key options
                    for key in keys:
                        if key.startswith("#"):
                            continue
                        options = []
                        if "command=" in key:
                            options.append("command-restricted")
                        if "from=" in key:
                            options.append("ip-restricted")
                        if "no-" in key:
                            options.append("restricted")
                        if not options and not key.startswith("ssh-"):
                            # Might be a suspicious entry
                            findings.append(
                                {
                                    "tipo": "SSH_KEY_SUSPICIOUS",
                                    "arquivo": path,
                                    "entrada": key[:100],
                                    "severidade": "ALTO",
                                    "descricao": "Entrada suspeita em authorized_keys: formato inválido",
                                    "remediacao": "Verificar se a entrada é legítima. Remover se não reconhecida.",
                                }
                            )

                elif "id_rsa" in path or "id_dsa" in path or "id_ecdsa" in path or "id_ed25515" in path:
                    findings.append(
                        {
                            "tipo": "SSH_PRIVATE_KEY",
                            "arquivo": path,
                            "severidade": "ALTO",
                            "descricao": f"Chave privada SSH encontrada: {path}",
                            "remediacao": "Proteger chave privada com passphrase. Restringir permissões (600).",
                        }
                    )

                elif path.endswith("sshd_config"):
                    # Check for risky sshd_config settings
                    risky_settings = {
                        "PermitRootLogin yes": "CRITICO",
                        "PasswordAuthentication yes": "ALTO",
                        "PermitEmptyPasswords yes": "CRITICO",
                        "X11Forwarding yes": "MEDIO",
                        "AllowTcpForwarding yes": "MEDIO",
                        "PermitTunnel yes": "MEDIO",
                    }
                    for setting, severity in risky_settings.items():
                        if setting in content:
                            findings.append(
                                {
                                    "tipo": "SSHD_CONFIG_RISKY",
                                    "arquivo": path,
                                    "configuracao": setting,
                                    "severidade": severity,
                                    "descricao": f"sshd_config: {setting}",
                                    "remediacao": f"Alterar para: {setting.replace('yes', 'no')}",
                                }
                            )

            except PermissionError:
                continue
            except Exception:
                continue

    return findings


def _check_ld_preload():
    """Check for LD_PRELOAD injection."""
    findings = []

    for ld_path in LD_PRELOAD_PATHS:
        try:
            if os.path.isfile(ld_path):
                with open(ld_path) as f:
                    content = f.read().strip()
                if content:
                    libraries = [line.strip() for line in content.splitlines() if line.strip()]
                    findings.append(
                        {
                            "tipo": "LD_PRELOAD_ACTIVE",
                            "arquivo": ld_path,
                            "bibliotecas": libraries,
                            "severidade": "CRITICO",
                            "descricao": f"LD_PRELOAD ativo em {ld_path} — possible rootkit/library injection",
                            "remediacao": "Investigar bibliotecas listadas. Verificar integridade com rpm -V ou dpkg.",
                        }
                    )

                    # Check if libraries exist and are legit
                    for lib in libraries:
                        if os.path.exists(lib):
                            findings.append(
                                {
                                    "tipo": "LD_PRELOAD_LIBRARY",
                                    "biblioteca": lib,
                                    "severidade": "ALTO",
                                    "descricao": f"Biblioteca pré-carregada existe: {lib}",
                                }
                            )
                        else:
                            findings.append(
                                {
                                    "tipo": "LD_PRELOAD_MISSING",
                                    "biblioteca": lib,
                                    "severidade": "MEDIO",
                                    "descricao": f"Biblioteca pré-carregada não encontrada: {lib}",
                                }
                            )
            elif os.path.isdir(ld_path):
                # Check .conf files in directory
                for filename in os.listdir(ld_path):
                    if filename.endswith(".conf"):
                        filepath = os.path.join(ld_path, filename)
                        try:
                            with open(filepath) as f:
                                content = f.read().strip()
                            if content:
                                findings.append(
                                    {
                                        "tipo": "LD_SO_CONF",
                                        "arquivo": filepath,
                                        "severidade": "MEDIO",
                                        "descricao": f"ld.so.conf entry: {filename}",
                                        "conteudo": content[:200],
                                    }
                                )
                        except Exception:
                            continue
        except PermissionError:
            continue
        except FileNotFoundError:
            continue
        except Exception:
            continue

    # Check environment variable
    ld_preload_env = os.environ.get("LD_PRELOAD", "")
    if ld_preload_env:
        findings.append(
            {
                "tipo": "LD_PRELOAD_ENV",
                "valor": ld_preload_env,
                "severidade": "CRITICO",
                "descricao": f"LD_PRELOAD definido via variável de ambiente: {ld_preload_env}",
                "remediacao": "Investigar origem. Remover LD_PRELOAD se não legítimo.",
            }
        )

    return findings


def _check_startup_scripts():
    """Check for startup script modifications."""
    findings = []

    for startup_path in STARTUP_DIRS:
        try:
            if os.path.isfile(startup_path):
                # rc.local
                with open(startup_path) as f:
                    content = f.read().strip()
                if (
                    content
                    and not content.startswith("#!/")
                    or (content.startswith("#!/") and len(content.splitlines()) > 2)
                ):
                    # Has actual commands
                    lines = [
                        line.strip()
                        for line in content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    if lines:
                        findings.append(
                            {
                                "tipo": "STARTUP_SCRIPT",
                                "arquivo": startup_path,
                                "comandos": len(lines),
                                "severidade": "MEDIO",
                                "descricao": f"Startup script com {len(lines)} comandos: {startup_path}",
                                "preview": lines[:5],
                            }
                        )

                        # Check for suspicious patterns
                        for line in lines:
                            lower = line.lower()
                            for pattern in SUSPICIOUS_PATTERNS:
                                if pattern in lower:
                                    findings.append(
                                        {
                                            "tipo": "STARTUP_SUSPICIOUS",
                                            "arquivo": startup_path,
                                            "comando": line,
                                            "padrao": pattern,
                                            "severidade": "CRITICO",
                                            "descricao": f"Startup script suspeito em {startup_path}: contém '{pattern}'",
                                            "remediacao": f"Investigar e remover comando de {startup_path}",
                                        }
                                    )
                                    break

            elif os.path.isdir(startup_path):
                for filename in os.listdir(startup_path):
                    filepath = os.path.join(startup_path, filename)
                    if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                        try:
                            stat = os.stat(filepath)
                            findings.append(
                                {
                                    "tipo": "STARTUP_EXECUTABLE",
                                    "diretorio": startup_path,
                                    "arquivo": filename,
                                    "modificado": stat.st_mtime,
                                    "severidade": "INFO",
                                    "descricao": f"Executável em diretório de startup: {startup_path}/{filename}",
                                }
                            )
                        except Exception:
                            continue

        except PermissionError:
            continue
        except FileNotFoundError:
            continue
        except Exception:
            continue

    # Check for init.d services
    init_d = "/etc/init.d"
    try:
        if os.path.isdir(init_d):
            for filename in os.listdir(init_d):
                filepath = os.path.join(init_d, filename)
                if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                    try:
                        with open(filepath) as f:
                            content = f.read().lower()
                        for pattern in SUSPICIOUS_PATTERNS:
                            if pattern in content:
                                findings.append(
                                    {
                                        "tipo": "INIT_D_SUSPICIOUS",
                                        "arquivo": filepath,
                                        "padrao": pattern,
                                        "severidade": "CRITICO",
                                        "descricao": f"init.d script suspeito: {filename} — contém '{pattern}'",
                                        "remediacao": f"Investigar e remover {filepath}",
                                    }
                                )
                                break
                    except Exception:
                        continue
    except Exception:  # noqa: S110
        pass

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    Persistence Check 2026-Grade — Crontab, Systemd, Shell Profiles, SSH, LD_PRELOAD, Startup.

    Técnicas: crontab entries (system/user/cron.d), systemd service scanning,
    shell profile modification detection, SSH authorized_keys manipulation,
    LD_PRELOAD injection detection (/etc/ld.so.preload + env var),
    startup script analysis (rc.local/init.d/systemd).
    """
    _ = (target, ip, open_ports, banners)
    resultado = {
        "crontab": [],
        "systemd_services": [],
        "shell_profiles": [],
        "ssh_keys": [],
        "ld_preload": [],
        "startup_scripts": [],
    }

    resultado["crontab"] = _check_crontab_entries()
    resultado["systemd_services"] = _check_systemd_services()
    resultado["shell_profiles"] = _check_shell_profiles()
    resultado["ssh_keys"] = _check_ssh_authorized_keys()
    resultado["ld_preload"] = _check_ld_preload()
    resultado["startup_scripts"] = _check_startup_scripts()

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )
    alto = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "ALTO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "altos": alto,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if alto > 0 else "LIMPO"),
    }

    return {
        "plugin": "persistence_check",
        "versao": "2026.1",
        "tecnicas": [
            "crontab_analysis",
            "systemd_service_scan",
            "shell_profile_check",
            "ssh_key_audit",
            "ld_preload_detection",
            "startup_script_check",
        ],
        "resultados": resultado,
    }
