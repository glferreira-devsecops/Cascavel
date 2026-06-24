"""
╔═══════════════════════════════════════════════════════════════╗
║  CASCAVEL — Target Validators                                ║
║  SSRF blocklist, IP normalization, IDNA homograph detection  ║
╚═══════════════════════════════════════════════════════════════╝
"""

import ipaddress
import re
import socket
import unicodedata
from typing import Any

from rich.console import Console

from .constants import S_CYAN, S_DIM, S_RED, S_YELLOW

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD METADATA SSRF BLOCKLIST (2026 Expanded)
# ═══════════════════════════════════════════════════════════════════════════════
_CLOUD_METADATA_HOSTS = {
    "169.254.169.254", "fd00:ec2::254", "169.254.169.123",
    "metadata.google.internal", "metadata.google.com",
    "100.100.100.200",
    "localhost", "0.0.0.0", "::1", "0177.0.0.1", "ip6-localhost", "ip6-loopback",
}


def _normalize_ip_representation(host: str) -> str | None:
    """Normaliza representações alternativas de IP para detecção de bypass."""
    if host.startswith("[") and host.endswith("]"):
        host = host.removeprefix("[").removesuffix("]")

    if host.isdigit():
        try:
            val = int(host)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, ipaddress.AddressValueError):
            pass

    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, ipaddress.AddressValueError):
            pass

    if "." in host:
        parts = host.split(".")
        if all(p.startswith("0") and len(p) > 1 and p.isdigit() for p in parts if p):
            try:
                decimal_parts: list[str] = []
                for p in parts:
                    octal_val = int(p, 8)
                    decimal_parts.append(str(octal_val))
                normalized = ".".join(decimal_parts)
                ipaddress.IPv4Address(normalized)
                return normalized
            except (ValueError, ipaddress.AddressValueError):
                pass

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    return None


def _is_blocked_ip(ip_str: str) -> tuple[bool, str]:
    """Verifica se um IP é privado/reservado/loopback/link-local/multicast."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, ""

    if addr.is_loopback:
        return True, "loopback (127.0.0.0/8)"
    if addr.is_private:
        return True, "rede privada (RFC 1918/6598)"
    if addr.is_reserved:
        return True, "IP reservado IETF"
    if addr.is_multicast:
        return True, "multicast (224.0.0.0/4)"
    if addr.is_link_local:
        return True, "link-local (169.254.0.0/16 — cloud metadata)"
    if addr.is_unspecified:
        return True, "IP não especificado (0.0.0.0)"

    if isinstance(addr, ipaddress.IPv6Address):
        mapped: ipaddress.IPv4Address | None = addr.ipv4_mapped
        if mapped is not None:
            if mapped.is_loopback or mapped.is_private or mapped.is_link_local:
                return True, f"IPv4-mapped IPv6 → {mapped}"

    return False, ""


def _detect_idna_homograph(host: str) -> str | None:
    """Detecta domínios com Punycode que podem ser homograph attacks."""
    labels = host.lower().split(".")
    for label in labels:
        if label.startswith("xn--"):
            return f"Punycode detectado: '{label}' — possível homograph attack"

    if any(ord(c) > 127 for c in host):
        scripts = set()
        for c in host:
            if c in ".-":
                continue
            try:
                script = unicodedata.name(c, "").split()[0]
                scripts.add(script)
            except (ValueError, IndexError):
                pass
        if len(scripts) > 2:
            return f"Scripts misturados detectados: {scripts} — possível homograph"

    return None


def validate_target(target: str, allow_self: bool = False) -> str:
    """Valida e normaliza o target com 50+ edge cases.

    SEGURANÇA 2026 — Proteções:
    1. Strip protocolo, path, query, fragment
    2. Regex de formato (domínio/IP/host:porta)
    3. Normalização de IPs alternativos (octal, hex, decimal)
    4. ipaddress.is_private/is_loopback/is_reserved/is_link_local nativo
    5. Cloud metadata SSRF blocklist expandida
    6. IDNA/Punycode homograph attack detection
    7. DNS rebinding guard (resolve e re-verifica o IP)
    8. Port range validation (1-65535)
    """
    if not target or not target.strip():
        console.print(f"  [{S_RED}]✗ Target vazio.[/]")
        console.print(f"  [{S_DIM}]Exemplo: cascavel -t example.com[/]")
        return ""

    target = target.strip()

    # Phase 1: Strip protocol
    target_lower: str = target.lower()
    for prefix in ("https://", "http://", "ftp://", "ftps://"):
        if target_lower.startswith(prefix):
            clean_target: str = target.replace(prefix, "", 1) if target.lower().startswith(prefix) else target
            target = clean_target
            break

    if "@" in target:
        at_parts: list[str] = target.split("@")
        target = at_parts[-1]

    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]
    target = target.strip()

    # Phase 2: Format validation
    if not target:
        console.print(f"  [{S_RED}]✗ Target vazio após normalização.[/]")
        return ""

    _control_chars: str = "\t\n\r"
    if any(ord(c) < 32 or c in _control_chars for c in target):
        console.print(f"  [{S_RED}]✗ Target contém caracteres de controle.[/]")
        return ""

    host_part = target
    port_part = None
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host_part = parts[0]
            port_part = int(parts[1])

    if port_part is not None:
        if port_part < 1 or port_part > 65535:
            console.print(f"  [{S_RED}]✗ Porta fora do range (1-65535): {port_part}[/]")
            return ""

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]*(:\d{1,5})?$", target):
        has_unicode = any(ord(c) > 127 for c in target)
        has_punycode = any(label.startswith("xn--") for label in host_part.split("."))
        if not has_unicode and not has_punycode:
            console.print(f"  [{S_RED}]✗ Target inválido: {target}[/]")
            console.print(f"  [{S_DIM}]Formatos aceitos: dominio.com │ 1.2.3.4 │ host:porta[/]")
            return ""

    # Phase 3: IDNA/Homograph detection
    homograph = _detect_idna_homograph(host_part)
    if homograph:
        console.print(f"  [{S_YELLOW}]⚠ ALERTA: {homograph}[/]")

    # Phase 4: IP normalization + private/reserved check
    if not allow_self:
        normalized_ip = _normalize_ip_representation(host_part)
        if normalized_ip:
            blocked, reason = _is_blocked_ip(normalized_ip)
            if blocked:
                console.print(f"  [{S_RED}]✗ Target bloqueado: {host_part} → {normalized_ip}[/]")
                console.print(f"  [{S_DIM}]Motivo: {reason}[/]")
                console.print(f"  [{S_DIM}]Use --allow-localhost para red-teaming consentido.[/]")
                return ""

        if host_part.lower() in _CLOUD_METADATA_HOSTS:
            console.print(f"  [{S_RED}]✗ Target bloqueado: {host_part}[/]")
            console.print(f"  [{S_DIM}]Motivo: cloud metadata / SSRF vector[/]")
            return ""

    # Phase 5: DNS rebinding guard
    if not allow_self and not _normalize_ip_representation(host_part):
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5)
            try:
                addrs = socket.getaddrinfo(host_part, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for _family, _, _, _, sockaddr in addrs:
                    resolved_ip: str = str(sockaddr[0])
                    blocked, reason = _is_blocked_ip(resolved_ip)
                    if blocked:
                        console.print(f"  [{S_RED}]✗ DNS rebinding detectado![/]")
                        console.print(f"  [{S_DIM}]{host_part} resolve para {resolved_ip} ({reason})[/]")
                        return ""
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (TimeoutError, socket.gaierror, OSError):
            console.print(f"  [{S_YELLOW}]⚠ DNS não resolveu {host_part} — continuando.[/]")

    return target


def inputx(prompt: str, max_retries: int = 3, validator=None) -> str:
    """Prompt interativo com retry loop, EOF protection e validação opcional."""
    for attempt in range(1, max_retries + 1):
        try:
            value = console.input(f"  [{S_CYAN}]❯ {prompt}[/]")
            value = value.strip()
            if not value:
                remaining = max_retries - attempt
                if remaining > 0:
                    console.print(f"  [{S_YELLOW}]⚠ Entrada vazia. {remaining} tentativa(s) restante(s).[/]")
                    continue
                else:
                    console.print(f"  [{S_RED}]✗ Máximo de tentativas atingido. Abortando.[/]")
                    import sys
                    sys.exit(1)
            if validator:
                error = validator(value)
                if error:
                    remaining = max_retries - attempt
                    if remaining > 0:
                        console.print(f"  [{S_RED}]✗ {error}[/]")
                        continue
                    else:
                        console.print(f"  [{S_RED}]✗ {error} — máximo de tentativas.[/]")
                        import sys
                        sys.exit(1)
            return value
        except EOFError:
            console.print(f"\n  [{S_RED}]✗ EOF — entrada não disponível.[/]")
            import sys
            sys.exit(1)
        except KeyboardInterrupt:
            console.print(f"\n  [{S_RED}]✗ Interrompido.[/]\n")
            import sys
            sys.exit(0)
    console.print(f"  [{S_RED}]✗ Sem input válido. Abortando.[/]")
    import sys
    sys.exit(1)
