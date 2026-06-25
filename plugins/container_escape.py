# plugins/container_escape.py — Cascavel 2026 Intelligence
import os
import re
import subprocess

import requests

# ──────────── CONTAINER DETECTION INDICATORS ────────────
CONTAINER_INDICATORS = {
    "/.dockerenv": "Docker container flag file",
    "/run/.containerenv": "Podman container flag file",
    "/proc/1/cgroup": "Cgroup namespace (container indicator)",
    "/proc/1/environ": "Process environment variables",
    "/proc/self/cgroup": "Self cgroup info",
    "/proc/self/mountinfo": "Mount namespace info",
}

# ──────────── ESCAPE VECTORS ────────────
PRIVILEGED_INDICATORS = [
    "/dev/sda",
    "/dev/xvda",
    "/dev/vda",  # Host disk access
    "/proc/sysrq-trigger",
    "/sys/firmware",
    "/proc/1/ns/pid",  # Host PID namespace
]

DOCKER_SOCK_PATHS = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/docker/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
]


def run(target, ip, ports, banners, context=None):
    """
    Scanner Container Escape 2026-Grade — Detection, Privilege Check,
    Docker Socket Exposure, CVE-2024-21626, Namespace Access, Cgroup Escape.

    Técnicas: container detection (cgroup/dockerenv/podman), privileged
    container test (host disk access), docker.sock exposure (6 paths),
    CVE-2024-21626 (runc fd leak), host namespace access (pid/net/mnt),
    cgroup release_agent escape, AppArmor/SELinux/seccomp status,
    capability analysis.
    """
    _ = (ip, ports, banners)
    vulns = []

    # Container detection
    container_info = _detect_container()
    if container_info:
        vulns.append(
            {
                "tipo": "CONTAINER_DETECTED",
                "evidence": container_info,
                "severidade": "INFO",
                "descricao": "Executando dentro de container.",
                "remediao": "Se não esperado, investigar origem do container.",
            }
        )

    # Privileged container check
    vulns.extend(_check_privileged())

    # Docker socket exposure
    vulns.extend(_check_docker_sock())

    # CVE-2024-21626 (runc escape)
    vulns.extend(_check_cve_2024_21626())

    # Host namespace access
    vulns.extend(_check_namespace_access())

    # Cgroup release_agent escape
    vulns.extend(_check_cgroup_escape())

    # Security context analysis
    vulns.extend(_check_security_context())

    # Capability analysis
    vulns.extend(_check_capabilities())

    # Network-based escape checks (against target)
    vulns.extend(_check_remote_container_escape(target))

    return {
        "plugin": "container_escape",
        "versao": "2026.1",
        "tecnicas": [
            "container_detection",
            "privileged_check",
            "docker_sock_exposure",
            "cve_2024_21626",
            "namespace_access",
            "cgroup_escape",
            "security_context",
            "capability_analysis",
        ],
        "resultados": vulns if vulns else "Nenhum vetor de container escape detectado",
    }


def _detect_container():
    """Detecta se está rodando dentro de um container."""
    evidence = []

    # Check /.dockerenv
    if os.path.exists("/.dockerenv"):
        evidence.append("/.dockerenv existe — Docker container")

    # Check /run/.containerenv (Podman)
    if os.path.exists("/run/.containerenv"):
        evidence.append("/run/.containerenv existe — Podman container")

    # Check cgroup for container indicators
    try:
        with open("/proc/1/cgroup") as f:
            cgroup_content = f.read()
            if "docker" in cgroup_content or "kubepods" in cgroup_content:
                evidence.append("cgroup indica container Docker/K8s")
            if "containerd" in cgroup_content:
                evidence.append("cgroup indica containerd")
            if "lxc" in cgroup_content:
                evidence.append("cgroup indica LXC")
    except (FileNotFoundError, PermissionError):
        pass

    # Check /proc/1/environ for container env vars
    try:
        with open("/proc/1/environ") as f:
            environ = f.read()
            container_env_vars = [
                "container=",
                "KUBERNETES_SERVICE_HOST",
                "DOCKER_CONTAINER",
                "container=docker",
            ]
            for var in container_env_vars:
                if var in environ:
                    evidence.append(f"Env var '{var}' detectada em PID 1")
    except (FileNotFoundError, PermissionError):
        pass

    # Check hostname pattern (containers often have random hex hostnames)
    hostname = subprocess.run(["hostname"], capture_output=True, text=True, timeout=5).stdout.strip()
    if hostname and len(hostname) == 12 and all(c in "0123456789abcdef" for c in hostname):
        evidence.append(f"Hostname '{hostname}' parece container ID")

    return evidence if evidence else None


def _check_privileged():
    """Verifica se container roda em modo privilegiado."""
    vulns = []

    # Check for host device access
    for device in PRIVILEGED_INDICATORS:
        try:
            if os.path.exists(device):
                vulns.append(
                    {
                        "tipo": "PRIVILEGED_DEVICE_ACCESS",
                        "device": device,
                        "severidade": "CRITICO",
                        "descricao": f"Container tem acesso a {device} — modo privilegiado!",
                        "remediao": "Remover --privileged e usar capabilities granulares.",
                    }
                )
        except Exception:
            continue

    # Check for all capabilities
    try:
        with open("/proc/1/status") as f:
            status = f.read()
            cap_match = re.search(r"CapEff:\s*(\w+)", status)
            if cap_match:
                cap_hex = cap_match.group(1)
                cap_val = int(cap_hex, 16)
                # 0xffffffffffffffff = all capabilities
                if cap_val >= 0x3FFFFFFFFF:
                    vulns.append(
                        {
                            "tipo": "ALL_CAPABILITIES",
                            "cap_effective": cap_hex,
                            "severidade": "CRITICO",
                            "descricao": f"Todas as capabilities ativas (0x{cap_hex}) — container privilegiado!",
                            "remediao": "Dropear capabilities desnecessárias. Usar --cap-drop=ALL e adicionar só as necessárias.",
                        }
                    )
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Check /proc/sysrq-trigger (writable = privileged)
    try:
        if os.path.exists("/proc/sysrq-trigger"):
            with open("/proc/sysrq-trigger") as f:
                f.read(1)
            vulns.append(
                {
                    "tipo": "SYSRQ_ACCESSIBLE",
                    "severidade": "CRITICO",
                    "descricao": "/proc/sysrq-trigger acessível — container privilegiado!",
                    "remediao": "Dropear SYS_RAWIO capability ou remover --privileged.",
                }
            )
    except (PermissionError, OSError):
        pass

    return vulns


def _check_docker_sock():
    """Verifica exposição do Docker socket."""
    vulns = []
    for sock_path in DOCKER_SOCK_PATHS:
        try:
            if os.path.exists(sock_path):
                # Check if writable
                writable = os.access(sock_path, os.W_OK)
                sev = "CRITICO" if writable else "ALTO"
                vulns.append(
                    {
                        "tipo": "DOCKER_SOCK_EXPOSED",
                        "path": sock_path,
                        "writable": writable,
                        "severidade": sev,
                        "descricao": f"Docker socket exposto em {sock_path}" + (" (gravável!)" if writable else ""),
                        "remediao": "Nunca montar docker.sock em containers. Usar socket proxies.",
                    }
                )

                # Try to interact with socket via HTTP
                if sock_path.endswith("docker.sock"):
                    try:
                        resp = requests.get(
                            "http://localhost/info",
                            timeout=3,
                            proxies={"http": f"unix://{sock_path}"},
                        )
                        if resp.status_code == 200:
                            vulns.append(
                                {
                                    "tipo": "DOCKER_API_VIA_SOCKET",
                                    "severidade": "CRITICO",
                                    "descricao": "Docker API acessível via socket — full container escape!",
                                    "remediao": "Remover montagem do docker.sock imediatamente.",
                                }
                            )
                    except Exception as _exc:
                        pass

        except Exception:
            continue
    return vulns


def _check_cve_2024_21626():
    """Verifica CVE-2024-21626 — runc fd leak escape."""
    vulns = []

    # CVE-2024-21626: runc process.cwd() can be set to /proc/self/fd/7/
    # which leaks the host filesystem
    try:
        cwd = os.getcwd()
        if "/proc/self/fd/" in cwd:
            vulns.append(
                {
                    "tipo": "CVE_2024_21626_ACTIVE",
                    "cwd": cwd,
                    "severidade": "CRITICO",
                    "descricao": f"CVE-2024-21626 ativo! CWD={cwd} — runc fd leak!",
                    "remediao": "Atualizar runc >= 1.1.12 e container runtimes.",
                }
            )
    except Exception as _exc:
        pass

    # Check runc version
    try:
        runc_version = subprocess.run(["runc", "--version"], capture_output=True, text=True, timeout=5).stdout.strip()
        if runc_version:
            version_match = re.search(r"version\s+(\d+\.\d+\.\d+)", runc_version)
            if version_match:
                ver = version_match.group(1)
                parts = [int(x) for x in ver.split(".")]
                # Vulnerable: < 1.1.12 or < 1.0.3
                if (
                    (parts[0] == 1 and parts[1] == 1 and parts[2] < 12)
                    or (parts[0] == 1 and parts[1] == 0 and parts[2] < 3)
                    or parts[0] == 0
                ):
                    vulns.append(
                        {
                            "tipo": "CVE_2024_21626_VULNERABLE",
                            "runc_version": ver,
                            "severidade": "CRITICO",
                            "descricao": f"runc {ver} vulnerável ao CVE-2024-21626!",
                            "remediao": "Atualizar runc para >= 1.1.12.",
                        }
                    )
    except Exception as _exc:
        pass

    # Check for /proc/self/fd directory access
    try:
        fd_dir = "/proc/self/fd"
        if os.path.isdir(fd_dir):
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link.startswith("/") and not link.startswith("/proc") and not link.startswith("/dev"):
                        # Check if it's a host path
                        if os.path.isdir(link) and link not in ["/", "/dev", "/proc", "/sys"]:
                            vulns.append(
                                {
                                    "tipo": "HOST_FD_LEAK",
                                    "fd": fd,
                                    "target": link,
                                    "severidade": "ALTO",
                                    "descricao": f"FD {fd} aponta para path do host: {link}",
                                    "remediao": "Investigar configuração de --work-dir do runc.",
                                }
                            )
                            break
                except (OSError, PermissionError):
                    continue
    except Exception as _exc:
        pass

    return vulns


def _check_namespace_access():
    """Verifica acesso a namespaces do host."""
    vulns = []
    ns_types = ["pid", "net", "mnt", "uts", "ipc", "user", "cgroup"]

    for ns in ns_types:
        ns_path = f"/proc/1/ns/{ns}"
        try:
            if os.path.exists(ns_path):
                # Read the namespace inode
                host_inode = os.readlink(ns_path)

                # Compare with self namespace
                self_ns_path = f"/proc/self/ns/{ns}"
                if os.path.exists(self_ns_path):
                    self_inode = os.readlink(self_ns_path)
                    if host_inode != self_inode:
                        vulns.append(
                            {
                                "tipo": "HOST_NAMESPACE_ACCESS",
                                "namespace": ns,
                                "host_inode": host_inode,
                                "self_inode": self_inode,
                                "severidade": "CRITICO",
                                "descricao": f"Acesso a namespace {ns} do host detectado!",
                                "remediao": "Usar --pid=host e --net=host apenas quando necessário.",
                            }
                        )
        except (OSError, PermissionError):
            continue

    # Check if running with --pid=host
    try:
        host_pids = os.listdir("/proc")
        container_pids = [p for p in host_pids if p.isdigit() and int(p) > 2]
        if len(container_pids) > 500:
            vulns.append(
                {
                    "tipo": "PID_HOST_NAMESPACE",
                    "process_count": len(container_pids),
                    "severidade": "ALTO",
                    "descricao": f"Muitos processos ({len(container_pids)}) — possível --pid=host!",
                    "remediao": "Remover --pid=host e usar PID namespace isolado.",
                }
            )
    except Exception as _exc:
        pass

    return vulns


def _check_cgroup_escape():
    """Verifica escape via cgroup release_agent."""
    vulns = []

    # Check if cgroup is writable
    cgroup_paths = [
        "/sys/fs/cgroup/release_agent",
        "/sys/fs/cgroup/device/release_agent",
        "/sys/fs/cgroup/memory/release_agent",
        "/sys/fs/cgroup/cpu/release_agent",
    ]

    for cgroup_path in cgroup_paths:
        try:
            if os.path.exists(cgroup_path):
                writable = os.access(cgroup_path, os.W_OK)
                if writable:
                    vulns.append(
                        {
                            "tipo": "CGROUP_RELEASE_AGENT_WRITABLE",
                            "path": cgroup_path,
                            "severidade": "CRITICO",
                            "descricao": "Cgroup release_agent gravável — escape via cgroup possível!",
                            "remediao": "Montar cgroup como read-only ou remover --privileged.",
                        }
                    )

                    # Read current value
                    try:
                        with open(cgroup_path) as f:
                            current = f.read().strip()
                        if current:
                            vulns[-1]["valor_atual"] = current
                    except Exception as _exc:
                        pass

        except Exception:
            continue

    # Check /proc/sysrq-trigger
    try:
        if os.access("/proc/sysrq-trigger", os.W_OK):
            vulns.append(
                {
                    "tipo": "SYSRQ_TRIGGER_WRITABLE",
                    "severidade": "CRITICO",
                    "descricao": "/proc/sysrq-trigger gravável — pode causar panic/reboot do host!",
                    "remediao": "Remover --privileged ou dropar SYS_RAWIO capability.",
                }
            )
    except Exception as _exc:
        pass

    # Check /proc/sys writability
    writable_sysctl = []
    sysctl_paths = [
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
        "/proc/sys/vm/panic_on_oom",
    ]
    for path in sysctl_paths:
        try:
            if os.access(path, os.W_OK):
                writable_sysctl.append(path)
        except Exception:
            continue

    if writable_sysctl:
        vulns.append(
            {
                "tipo": "HOST_SYSCTL_WRITABLE",
                "paths": writable_sysctl,
                "severidade": "CRITICO",
                "descricao": "Sysctl do host gravável — escape via core_pattern/modprobe!",
                "remediao": "Montar /proc/sys como read-only.",
            }
        )

    return vulns


def _check_security_context():
    """Verifica AppArmor, SELinux, seccomp."""
    vulns = []

    # AppArmor
    try:
        with open("/proc/self/attr/current") as f:
            apparmor = f.read().strip()
            if apparmor and apparmor != "unconfined":
                vulns.append(
                    {
                        "tipo": "APPARMOR_ACTIVE",
                        "profile": apparmor,
                        "severidade": "INFO",
                        "descricao": f"AppArmor ativo: {apparmor}",
                        "remediao": "Manter AppArmor habilitado.",
                    }
                )
            elif apparmor == "unconfined":
                vulns.append(
                    {
                        "tipo": "APPARMOR_UNCONFINED",
                        "severidade": "ALTO",
                        "descricao": "Container sem restrição AppArmor!",
                        "remediao": "Aplicar profile AppArmor ao container.",
                    }
                )
    except (FileNotFoundError, PermissionError):
        pass

    # Seccomp
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    seccomp_mode = line.split(":")[1].strip()
                    if seccomp_mode == "0":
                        vulns.append(
                            {
                                "tipo": "SECCOMP_DISABLED",
                                "severidade": "ALTO",
                                "descricao": "Seccomp desabilitado — syscalls irrestritos!",
                                "remediao": "Usar seccomp profile (pelo menos o default do Docker).",
                            }
                        )
                    elif seccomp_mode == "2":
                        vulns.append(
                            {
                                "tipo": "SECCOMP_FILTER_ACTIVE",
                                "severidade": "INFO",
                                "descricao": "Seccomp filter ativo.",
                                "remediao": "Manter seccomp habilitado.",
                            }
                        )
                    break
    except (FileNotFoundError, PermissionError):
        pass

    # SELinux
    try:
        selinux_status = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=5).stdout.strip()
        if selinux_status == "Disabled":
            vulns.append(
                {
                    "tipo": "SELINUX_DISABLED",
                    "severidade": "MEDIO",
                    "descricao": "SELinux desabilitado no host.",
                    "remediao": "Habilitar SELinux em enforcing mode.",
                }
            )
    except Exception as _exc:
        pass

    return vulns


def _check_capabilities():
    """Analisa capabilities do container."""
    vulns = []
    dangerous_caps = [
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_CHOWN",
        "CAP_SETUID",
        "CAP_SETGID",
    ]

    try:
        with open("/proc/1/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = line.split(":")[1].strip()
                    cap_val = int(cap_hex, 16)

                    # Map capability bits
                    cap_names = {
                        0: "CAP_CHOWN",
                        1: "CAP_DAC_OVERRIDE",
                        2: "CAP_DAC_READ_SEARCH",
                        3: "CAP_FOWNER",
                        4: "CAP_FSETID",
                        5: "CAP_KILL",
                        6: "CAP_SETGID",
                        7: "CAP_SETUID",
                        8: "CAP_SETPCAP",
                        9: "CAP_LINUX_IMMUTABLE",
                        10: "CAP_NET_BIND_SERVICE",
                        11: "CAP_NET_BROADCAST",
                        12: "CAP_NET_ADMIN",
                        13: "CAP_NET_RAW",
                        14: "CAP_IPC_LOCK",
                        15: "CAP_IPC_OWNER",
                        16: "CAP_SYS_MODULE",
                        17: "CAP_SYS_RAWIO",
                        18: "CAP_SYS_CHROOT",
                        19: "CAP_SYS_PTRACE",
                        20: "CAP_SYS_PACCT",
                        21: "CAP_SYS_ADMIN",
                        22: "CAP_SYS_BOOT",
                        23: "CAP_SYS_NICE",
                        24: "CAP_SYS_RESOURCE",
                        25: "CAP_SYS_TIME",
                        26: "CAP_SYS_TTY_CONFIG",
                        27: "CAP_MKNOD",
                        28: "CAP_LEASE",
                        29: "CAP_AUDIT_WRITE",
                        30: "CAP_AUDIT_CONTROL",
                        31: "CAP_SETFCAP",
                    }

                    active_dangerous = []
                    for bit, name in cap_names.items():
                        if cap_val & (1 << bit) and name in dangerous_caps:
                            active_dangerous.append(name)

                    if active_dangerous:
                        vulns.append(
                            {
                                "tipo": "DANGEROUS_CAPABILITIES",
                                "capabilities": active_dangerous,
                                "severidade": "ALTO",
                                "descricao": f"Capabilities perigosas ativas: {', '.join(active_dangerous)}",
                                "remediao": "Usar --cap-drop=ALL e adicionar apenas as necessárias.",
                            }
                        )
                    break
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return vulns


def _check_remote_container_escape(target):
    """Verifica vetores de escape via rede contra o target."""
    vulns = []

    # Check for exposed container APIs on common ports
    container_api_ports = [
        (2375, "Docker API (HTTP)"),
        (2376, "Docker API (HTTPS)"),
        (10250, "Kubelet API"),
        (10255, "Kubelet read-only"),
        (6443, "Kubernetes API"),
        (8443, "Kubernetes API (alt)"),
        (9090, "Kubernetes API (minikube)"),
    ]

    for port, service in container_api_ports:
        try:
            resp = requests.get(f"http://{target}:{port}/version", timeout=3)
            if resp.status_code == 200:
                vulns.append(
                    {
                        "tipo": "CONTAINER_API_EXPOSED",
                        "porta": port,
                        "service": service,
                        "severidade": "CRITICO",
                        "descricao": f"{service} exposto em :{port} — container escape possível!",
                        "remediao": "Restringir acesso à API do container runtime.",
                    }
                )
        except Exception:
            continue

    # Check for kubelet anonymous auth
    try:
        resp = requests.get(f"http://{target}:10255/pods", timeout=3)
        if resp.status_code == 200 and "items" in resp.text:
            vulns.append(
                {
                    "tipo": "KUBELET_ANONYMOUS_ACCESS",
                    "severidade": "CRITICO",
                    "descricao": "Kubelet aceita auth anônima — pods listáveis!",
                    "remediao": "Habilitar --anonymous-auth=false no kubelet.",
                }
            )
    except Exception as _exc:
        pass

    return vulns
