# plugins/privilege_escalation.py — Cascavel 2026 Intelligence
import logging
import os
import subprocess

logger = logging.getLogger(__name__)
# SUID/SGID binaries commonly exploitable
SUID_EXPLOITABLE = [
    "/usr/bin/find",
    "/usr/bin/vim",
    "/usr/bin/vi",
    "/usr/bin/nmap",
    "/usr/bin/less",
    "/usr/bin/more",
    "/usr/bin/man",
    "/usr/bin/pico",
    "/usr/bin/nano",
    "/usr/bin/wget",
    "/usr/bin/curl",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/dash",
    "/usr/bin/zsh",
    "/usr/bin/env",
    "/usr/bin/awk",
    "/usr/bin/gawk",
    "/usr/bin/perl",
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/ruby",
    "/usr/bin/lua",
    "/usr/bin/tclsh",
    "/usr/bin/rsync",
    "/usr/bin/strace",
    "/usr/bin/ltrace",
    "/usr/bin/gdb",
    "/usr/bin/ftp",
    "/usr/bin/socat",
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/tee",
    "/usr/bin/xargs",
    "/usr/bin/ar",
    "/usr/bin/base64",
    "/usr/bin/busybox",
    "/usr/bin/cp",
    "/usr/bin/dd",
    "/usr/bin/mv",
    "/usr/bin/docker",
    "/usr/bin/kubectl",
    "/usr/bin/apt-get",
    "/usr/bin/yum",
    "/usr/bin/pip",
    "/usr/bin/gem",
    "/usr/bin/systemctl",
    "/usr/sbin/exim4",
    "/usr/sbin/sendmail",
]

# Sensitive files that should not be world-writable
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ld.so.preload",
    "/etc/environment",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
]

# Known kernel vulnerability patterns
KERNEL_VULNS = [
    ("4.4", "Dirty COW (CVE-2016-5195)", "CRITICO"),
    ("4.8", "Dirty COW (CVE-2016-5195)", "CRITICO"),
    ("3.13", "Overlayfs (CVE-2015-1328)", "CRITICO"),
    ("4.13", "Exploitable kernel", "ALTO"),
    ("5.8", "Dirty Pipe (CVE-2022-0847)", "CRITICO"),
    ("5.16", "Dirty Pipe (CVE-2022-0847)", "CRITICO"),
]

# Container escape indicators
CONTAINER_INDICATORS = [
    "/.dockerenv",
    "/run/.containerenv",
    "/proc/1/cgroup",
]

# Sudo misconfiguration patterns
SUDO_VULN_PATTERNS = [
    "NOPASSWD",
    "!authenticate",
    "!requiretty",
    "env_keep+=LD_PRELOAD",
    "env_keep+=LD_LIBRARY_PATH",
    "env_keep+=PYTHONPATH",
    "env_keep+=PERL5OPT",
    "ALL=(ALL)",
]


def _check_suid_sgid():
    """Check for exploitable SUID/SGID binaries."""
    findings = []
    try:
        # Find SUID binaries
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f", "-ls"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        suid_files = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                filepath = parts[-1]
                suid_files.append(filepath)

                # Check if known exploitable
                if filepath in SUID_EXPLOITABLE:
                    findings.append(
                        {
                            "tipo": "SUID_EXPLOITABLE",
                            "arquivo": filepath,
                            "severidade": "CRITICO",
                            "descricao": f"SUID binário explorável: {filepath} — privilege escalation trivial",
                            "remediacao": f"Remover SUID bit: chmod u-s {filepath}. Alternativas: usar capabilities.",
                            "exploit_ref": f"GTFOBins: https://gtfobins.github.io/gtfobins/{filepath.split('/')[-1]}/",
                        }
                    )
                else:
                    findings.append(
                        {
                            "tipo": "SUID_BINARY",
                            "arquivo": filepath,
                            "severidade": "INFO",
                            "descricao": f"SUID binário encontrado: {filepath}",
                        }
                    )

        # Find SGID binaries
        result = subprocess.run(
            ["find", "/", "-perm", "-2000", "-type", "f", "-ls"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                filepath = parts[-1]
                if filepath in SUID_EXPLOITABLE:
                    findings.append(
                        {
                            "tipo": "SGID_EXPLOITABLE",
                            "arquivo": filepath,
                            "severidade": "CRITICO",
                            "descricao": f"SGID binário explorável: {filepath}",
                            "remediacao": f"Remover SGID bit: chmod g-s {filepath}.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "tipo": "SGID_BINARY",
                            "arquivo": filepath,
                            "severidade": "INFO",
                            "descricao": f"SGID binário encontrado: {filepath}",
                        }
                    )

    except subprocess.TimeoutExpired:
        findings.append(
            {
                "tipo": "SUID_CHECK_TIMEOUT",
                "severidade": "INFO",
                "descricao": "SUID scan timeout — sistema pode ter muitos arquivos",
            }
        )
    except Exception as e:
        findings.append(
            {
                "tipo": "SUID_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar SUID/SGID: {str(e)}",
            }
        )
    return findings


def _check_sudo_misconfig():
    """Check for sudo misconfigurations."""
    findings = []
    try:
        # Check sudo -l (if we have sudo access)
        result = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr

        if "not allowed to execute" not in output and "sorry" not in output.lower():
            for pattern in SUDO_VULN_PATTERNS:
                if pattern in output:
                    findings.append(
                        {
                            "tipo": "SUDO_MISCONFIG",
                            "pattern": pattern,
                            "severidade": "CRITICO",
                            "descricao": f"Sudo misconfiguração: {pattern} — privilege escalation possível",
                            "remediacao": f"Remover '{pattern}' do sudoers. Usar visudo para edições seguras.",
                            "sudo_output": output[:500],
                        }
                    )

    except FileNotFoundError:
        findings.append(
            {
                "tipo": "SUDO_NOT_AVAILABLE",
                "severidade": "INFO",
                "descricao": "sudo não disponível no sistema",
            }
        )
    except Exception as e:
        findings.append(
            {
                "tipo": "SUDO_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar sudo: {str(e)}",
            }
        )

    # Check /etc/sudoers directly (if readable)
    try:
        with open("/etc/sudoers") as f:
            content = f.read()
            for pattern in SUDO_VULN_PATTERNS:
                if pattern in content:
                    findings.append(
                        {
                            "tipo": "SUDOERS_MISCONFIG",
                            "pattern": pattern,
                            "severidade": "CRITICO",
                            "descricao": f"Sudoers contém: {pattern}",
                            "remediacao": "Editar /etc/sudoers com visudo. Remover configurações perigosas.",
                        }
                    )
    except PermissionError as _exc:
        logger.debug("Non-critical error: %s", _exc)
    except FileNotFoundError as _exc:
        logger.debug("Non-critical error: %s", _exc)
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # Check sudoers.d directory
    try:
        sudoers_d = "/etc/sudoers.d"
        if os.path.isdir(sudoers_d):
            for filename in os.listdir(sudoers_d):
                filepath = os.path.join(sudoers_d, filename)
                try:
                    with open(filepath) as f:
                        content = f.read()
                        for pattern in SUDO_VULN_PATTERNS:
                            if pattern in content:
                                findings.append(
                                    {
                                        "tipo": "SUDOERS_D_MISCONFIG",
                                        "arquivo": filepath,
                                        "pattern": pattern,
                                        "severidade": "CRITICO",
                                        "descricao": f"{filepath} contém: {pattern}",
                                        "remediacao": f"Revisar e corrigir {filepath}.",
                                    }
                                )
                except PermissionError:
                    continue
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def _check_writable_sensitive_files():
    """Check for writable sensitive files."""
    findings = []
    for filepath in SENSITIVE_FILES:
        try:
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    # Check if world-writable
                    stat = os.stat(filepath)
                    if stat.st_mode & 0o002:
                        findings.append(
                            {
                                "tipo": "WORLD_WRITABLE_FILE",
                                "arquivo": filepath,
                                "severidade": "CRITICO",
                                "descricao": f"Arquivo sensível world-writable: {filepath}",
                                "remediacao": f"Corrigir permissões: chmod o-w {filepath}",
                            }
                        )
                    elif stat.st_mode & 0o020:
                        findings.append(
                            {
                                "tipo": "GROUP_WRITABLE_FILE",
                                "arquivo": filepath,
                                "severidade": "ALTO",
                                "descricao": f"Arquivo sensível group-writable: {filepath}",
                                "remediacao": f"Corrigir permissões: chmod g-w {filepath}",
                            }
                        )
                elif os.path.isdir(filepath):
                    stat = os.stat(filepath)
                    if stat.st_mode & 0o002:
                        findings.append(
                            {
                                "tipo": "WORLD_WRITABLE_DIR",
                                "diretorio": filepath,
                                "severidade": "CRITICO",
                                "descricao": f"Diretório sensível world-writable: {filepath}",
                                "remediacao": f"Corrigir permissões: chmod o-w {filepath}",
                            }
                        )
        except PermissionError:
            continue
        except Exception as _exc:
            continue

    # Check for writable PATH directories
    try:
        path_dirs = os.environ.get("PATH", "").split(":")
        for pdir in path_dirs:
            if os.path.isdir(pdir):
                stat = os.stat(pdir)
                if stat.st_mode & 0o002:
                    findings.append(
                        {
                            "tipo": "WRITABLE_PATH_DIR",
                            "diretorio": pdir,
                            "severidade": "CRITICO",
                            "descricao": f"Diretório no PATH é world-writable: {pdir} — binary hijacking trivial",
                            "remediacao": f"Corrigir permissões: chmod o-w {pdir}",
                        }
                    )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def _check_kernel_vulnerabilities():
    """Check for known kernel vulnerabilities."""
    findings = []
    try:
        result = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        kernel_version = result.stdout.strip()
        if kernel_version:
            findings.append(
                {
                    "tipo": "KERNEL_VERSION",
                    "versao": kernel_version,
                    "severidade": "INFO",
                    "descricao": f"Kernel: {kernel_version}",
                }
            )

            # Check against known vulnerable versions
            major_minor = ".".join(kernel_version.split(".")[:2])
            for vuln_version, vuln_name, severity in KERNEL_VULNS:
                if major_minor == vuln_version:
                    findings.append(
                        {
                            "tipo": "KERNEL_VULNERABLE",
                            "versao": kernel_version,
                            "vulnerabilidade": vuln_name,
                            "severidade": severity,
                            "descricao": f"Kernel {kernel_version} potencialmente vulnerável a {vuln_name}",
                            "remediacao": "Atualizar kernel para versão mais recente. Verificar patches de segurança.",
                        }
                    )

            # Check for kernel hardening
            sysctl_params = {
                "kernel.randomize_va_space": ("2", "ASLR"),
                "kernel.kptr_restrict": ("1", "KPTR restrict"),
                "kernel.dmesg_restrict": ("1", "dmesg restrict"),
                "kernel.yama.ptrace_scope": ("1", "Yama ptrace"),
                "kernel.unprivileged_bpf_disabled": ("1", "BPF restrict"),
            }
            for param, (expected, name) in sysctl_params.items():
                try:
                    result = subprocess.run(
                        ["sysctl", "-n", param],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    value = result.stdout.strip()
                    if value != expected:
                        findings.append(
                            {
                                "tipo": "KERNEL_HARDENING_MISSING",
                                "parametro": param,
                                "valor_atual": value,
                                "valor_esperado": expected,
                                "severidade": "MEDIO",
                                "descricao": f"Kernel hardening ausente: {name} ({param}={value}, esperado={expected})",
                                "remediacao": f"Configurar sysctl {param}={expected} em /etc/sysctl.d/",
                            }
                        )
                except Exception as _exc:
                    continue

    except Exception as e:
        findings.append(
            {
                "tipo": "KERNEL_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar kernel: {str(e)}",
            }
        )
    return findings


def _check_container_escape():
    """Check for container escape vectors."""
    findings = []
    is_container = False

    # Check if running in container
    for indicator in CONTAINER_INDICATORS:
        if os.path.exists(indicator):
            is_container = True
            findings.append(
                {
                    "tipo": "CONTAINER_DETECTED",
                    "indicador": indicator,
                    "severidade": "INFO",
                    "descricao": f"Executando dentro de container ({indicator} existe)",
                }
            )
            break

    if not is_container:
        # Also check cgroup
        try:
            with open("/proc/1/cgroup") as f:
                content = f.read()
                if "docker" in content or "kubepods" in content or "containerd" in content:
                    is_container = True
                    findings.append(
                        {
                            "tipo": "CONTAINER_DETECTED",
                            "indicador": "/proc/1/cgroup",
                            "severidade": "INFO",
                            "descricao": "Executando dentro de container (cgroup indica Docker/K8s)",
                        }
                    )
        except Exception as _exc:
            logger.debug("Non-critical error: %s", _exc)

    if is_container:
        # Check for privileged mode
        try:
            result = subprocess.run(
                ["cat", "/proc/1/status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "CapEff:\t0000003fffffffff" in result.stdout or "CapEff:\tffffffffffffffff" in result.stdout:
                findings.append(
                    {
                        "tipo": "PRIVILEGED_CONTAINER",
                        "severidade": "CRITICO",
                        "descricao": "Container rodando em modo privilegiado — escape trivial",
                        "remeciacao": "Remover --privileged. Usar capabilities específicas. Implementar seccomp/AppArmor.",
                    }
                )
        except Exception as _exc:
            logger.debug("Non-critical error: %s", _exc)

        # Check for mounted Docker socket
        if os.path.exists("/var/run/docker.sock"):
            findings.append(
                {
                    "tipo": "DOCKER_SOCKET_MOUNTED",
                    "severidade": "CRITICO",
                    "descricao": "Docker socket montado no container — escape via docker API",
                    "remediacao": "Nunca montar /var/run/docker.sock em containers. Usar Docker-in-Docker com cautela.",
                }
            )

        # Check for sensitive mounts
        sensitive_mounts = [
            "/proc/sysrq-trigger",
            "/sys/kernel",
            "/dev/sd",
            "/etc/crontab",
            "/var/spool/cron",
        ]
        for mount in sensitive_mounts:
            if os.path.exists(mount):
                findings.append(
                    {
                        "tipo": "SENSITIVE_MOUNT",
                        "path": mount,
                        "severidade": "ALTO",
                        "descricao": f"Path sensível acessível: {mount} — possível escape vector",
                        "remediacao": f"Remover mount de {mount} ou usar read-only.",
                    }
                )

        # Check available capabilities
        try:
            result = subprocess.run(
                ["cat", "/proc/self/status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if line.startswith("CapEff:"):
                    caps = line.split(":")[1].strip()
                    if caps != "0000000000000000":
                        findings.append(
                            {
                                "tipo": "CONTAINER_CAPABILITIES",
                                "capabilities": caps,
                                "severidade": "ALTO",
                                "descricao": f"Container com capabilities: {caps} — verificar se são necessárias",
                                "remediacao": "Usar --cap-drop ALL e adicionar apenas capabilities necessárias.",
                            }
                        )
        except Exception as _exc:
            logger.debug("Non-critical error: %s", _exc)

    return findings


def _check_cron_exploitation():
    """Check for cron job exploitation vectors."""
    findings = []

    # System crontab
    cron_files = [
        "/etc/crontab",
        "/etc/anacrontab",
    ]
    cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    # Check system crontab
    for cron_file in cron_files:
        try:
            with open(cron_file) as f:
                content = f.read()
                if content.strip():
                    findings.append(
                        {
                            "tipo": "CRONTAB_ENTRIES",
                            "arquivo": cron_file,
                            "severidade": "INFO",
                            "descricao": f"Crontab com entradas: {cron_file}",
                            "preview": content[:300],
                        }
                    )

                    # Check for writable scripts referenced in crontab
                    for line in content.splitlines():
                        if line.strip() and not line.startswith("#"):
                            parts = line.split()
                            if parts:
                                cmd = parts[-1]
                                if os.path.isfile(cmd):
                                    try:
                                        stat = os.stat(cmd)
                                        if stat.st_mode & 0o002:
                                            findings.append(
                                                {
                                                    "tipo": "CRON_WRITABLE_SCRIPT",
                                                    "arquivo": cmd,
                                                    "crontab": cron_file,
                                                    "severidade": "CRITICO",
                                                    "descricao": f"Script referenciado no cron é world-writable: {cmd}",
                                                    "remediacao": f"Corrigir permissões: chmod 755 {cmd}",
                                                }
                                            )
                                    except Exception as _exc:
                                        logger.debug("Non-critical error: %s", _exc)
        except PermissionError:
            continue
        except FileNotFoundError:
            continue
        except Exception as _exc:
            continue

    # Check cron directories
    for cron_dir in cron_dirs:
        try:
            if os.path.isdir(cron_dir):
                for filename in os.listdir(cron_dir):
                    filepath = os.path.join(cron_dir, filename)
                    try:
                        stat = os.stat(filepath)
                        if stat.st_mode & 0o002:
                            findings.append(
                                {
                                    "tipo": "CRON_WRITABLE_ENTRY",
                                    "arquivo": filepath,
                                    "severidade": "CRITICO",
                                    "descricao": f"Entrada cron world-writable: {filepath}",
                                    "remediacao": f"Corrigir permissões: chmod 644 {filepath}",
                                }
                            )
                    except Exception as _exc:
                        continue
        except PermissionError:
            continue
        except Exception as _exc:
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
            findings.append(
                {
                    "tipo": "USER_CRONTABS",
                    "usuarios": result.stdout.strip().split(),
                    "severidade": "INFO",
                    "descricao": f"User crontabs encontrados: {result.stdout.strip()}",
                }
            )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    Privilege Escalation 2026-Grade — SUID/SGID, Sudo, Kernel, Container, Cron.

    Técnicas: SUID/SGID binary scanning (40+ exploitable), sudo misconfiguration
    (NOPASSWD, env_keep, !authenticate), writable sensitive files (passwd/shadow/
    sudoers/PATH), kernel vulnerability fingerprinting (Dirty COW/Dirty Pipe),
    container escape detection (privileged mode, Docker socket, capabilities),
    cron job exploitation (writable scripts, world-writable entries).
    """
    _ = (target, ip, open_ports, banners)
    resultado = {
        "suid_sgid": [],
        "sudo_misconfig": [],
        "writable_files": [],
        "kernel_vulns": [],
        "container_escape": [],
        "cron_exploitation": [],
    }

    resultado["suid_sgid"] = _check_suid_sgid()
    resultado["sudo_misconfig"] = _check_sudo_misconfig()
    resultado["writable_files"] = _check_writable_sensitive_files()
    resultado["kernel_vulns"] = _check_kernel_vulnerabilities()
    resultado["container_escape"] = _check_container_escape()
    resultado["cron_exploitation"] = _check_cron_exploitation()

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total > 0 else "LIMPO"),
    }

    return {
        "plugin": "privilege_escalation",
        "versao": "2026.1",
        "tecnicas": [
            "suid_sgid_scan",
            "sudo_misconfig",
            "writable_files",
            "kernel_vulnerability",
            "container_escape",
            "cron_exploitation",
        ],
        "resultados": resultado,
    }
