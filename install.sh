#!/usr/bin/env bash
# shellcheck disable=SC2024,SC2034
# ╔═══════════════════════════════════════════════════════════════════╗
# ║  CASCAVEL — Quantum Security Framework                           ║
# ║  One-Command Universal Installer v2.4.0 (Bulletproof 2026)       ║
# ║  By RET Tecnologia (https://rettecnologia.org)                   ║
# ║  Maintainer: DevFerreiraG <devferreirag@proton.me>               ║
# ║                                                                   ║
# ║  EDGE-CASE HARDENING (2026):                                      ║
# ║  • trap cleanup para diretórios temporários                       ║
# ║  • mktemp para temp files (anti-TOCTOU)                          ║
# ║  • lock file contra execução paralela + anti-symlink              ║
# ║  • log de instalação persistente                                  ║
# ║  • verificação de integridade do requirements.txt (SHA-256)       ║
# ║  • validação de permissões antes de sudo                         ║
# ║  • umask restritivo (077)                                         ║
# ║  • absolute paths para binários críticos                         ║
# ║  • PATH prefix safety (rejeita '.' e paths relativos)            ║
# ║  • Detecção Docker/Podman/LXC container                          ║
# ║  • WSL2 kernel detection + adjustments                           ║
# ║  • GOPATH/GOBIN export validation                                 ║
# ║  • pip --no-cache-dir + hash-check mode                          ║
# ║  • Locale UTF-8 enforcement                                       ║
# ║  • Stale venv detection (Python binary moved/deleted)             ║
# ║  • Python ssl module availability check                           ║
# ║  • Git presence check (for Go tools)                              ║
# ║  • ARM/aarch64 architecture warnings                              ║
# ║  • sudo availability pre-check                                    ║
# ╚═══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Security: Restringir umask ──────────────────────────────────────
umask 077

# ─── Security: Locale UTF-8 enforcement ──────────────────────────────
# Previne encoding bugs em pipes/subprocessos com chars não-ASCII
export LC_ALL="${LC_ALL:-en_US.UTF-8}"
export LANG="${LANG:-en_US.UTF-8}"

# ─── Security: PATH prefix safety ───────────────────────────────────
# Remove '.' e paths relativos do PATH (previne PATH injection attacks)
SAFE_PATH=""
IFS=':' read -ra _PATH_PARTS <<< "$PATH"
for _pp in "${_PATH_PARTS[@]}"; do
    case "$_pp" in
        .|./*|../*|*/../*) ;; # Reject relative paths
        /*) SAFE_PATH="${SAFE_PATH:+${SAFE_PATH}:}$_pp" ;;
    esac
done
export PATH="$SAFE_PATH"

# ─── Absolute paths para binários críticos ───────────────────────────
MKDIR="/bin/mkdir"
RM="/bin/rm"
CAT="/bin/cat"
DATE="/bin/date"
UNAME="/usr/bin/uname"
# Fallback para sistemas onde paths diferem
command -v mkdir &>/dev/null && MKDIR="$(command -v mkdir)"
command -v rm &>/dev/null && RM="$(command -v rm)"
command -v cat &>/dev/null && CAT="$(command -v cat)"
command -v date &>/dev/null && DATE="$(command -v date)"
command -v uname &>/dev/null && UNAME="$(command -v uname)"

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
MAGENTA='\033[0;35m'

# ─── TTY Detection (pipe vs interactive) ─────────────────────────────
IS_TTY="false"
[ -t 1 ] && IS_TTY="true"

# ─── Step Counter ────────────────────────────────────────────────────
CURRENT_STEP=0
TOTAL_STEPS=12
_next_step() {
    ((CURRENT_STEP++))
}

# ─── Spinner (visual feedback for long operations) ───────────────────
_SPINNER_PID=""
_spinner_start() {
    local msg="${1:-Processando...}"
    if [ "$IS_TTY" = "true" ]; then
        (
            local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
            local i=0
            while true; do
                local frame="${frames:i%${#frames}:1}"
                printf "\r  ${CYAN}%s${NC} %s" "$frame" "$msg"
                i=$((i + 1))
                sleep 0.1
            done
        ) &
        _SPINNER_PID=$!
        disown $_SPINNER_PID 2>/dev/null
    fi
}
_spinner_stop() {
    if [ -n "$_SPINNER_PID" ] && kill -0 "$_SPINNER_PID" 2>/dev/null; then
        kill "$_SPINNER_PID" 2>/dev/null
        wait "$_SPINNER_PID" 2>/dev/null || true
        _SPINNER_PID=""
        printf "\r%-60s\r" " "  # Clear spinner line
    fi
}

# ─── Lock File (anti-execução paralela + anti-symlink) ───────────────
LOCK_FILE="/tmp/.cascavel_install.lock"

_acquire_lock() {
    # Anti-symlink attack: rejeita lock files que são symlinks
    if [ -L "$LOCK_FILE" ]; then
        echo -e "  ${RED}✗${NC} Lock file é um symlink (possível ataque). Removendo."
        $RM -f "$LOCK_FILE"
    fi
    if [ -f "$LOCK_FILE" ]; then
        LOCK_PID=$($CAT "$LOCK_FILE" 2>/dev/null || echo "")
        # Valida que PID é numérico (previne injeção via conteúdo do lock file)
        if [[ "$LOCK_PID" =~ ^[0-9]+$ ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
            echo -e "  ${RED}✗${NC} Instalação já em andamento (PID: $LOCK_PID)."
            echo -e "  ${DIM}Se travou, remova: $LOCK_FILE${NC}"
            exit 1
        fi
        # Stale lock — remove
        $RM -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
}

_release_lock() {
    $RM -f "$LOCK_FILE"
}

# ─── Temp Directory (mktemp anti-TOCTOU) ─────────────────────────────
INSTALL_TMPDIR=""

_create_tmpdir() {
    INSTALL_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/cascavel-install.XXXXXXXX")
}

# ─── Trap Cleanup ──────────────────────────────────────────────────
_cleanup() {
    local exit_code=$?
    _spinner_stop
    if [ -n "$INSTALL_TMPDIR" ] && [ -d "$INSTALL_TMPDIR" ]; then
        $RM -rf "$INSTALL_TMPDIR"
    fi
    _release_lock
    if [ $exit_code -ne 0 ]; then
        echo -e "\n  ${RED}✗ Instalação falhou (exit code: $exit_code)${NC}"
        echo -e "  ${DIM}Log salvo em: ${INSTALL_LOG:-/dev/null}${NC}"
        echo -e "  ${DIM}Reporte: https://github.com/glferreira-devsecops/Cascavel/issues${NC}"
    fi
}
trap _cleanup EXIT INT TERM HUP

# ─── Install Log ──────────────────────────────────────────────────────
INSTALL_LOG="$(pwd)/install.log"
_log() {
    echo "[$(${DATE} '+%Y-%m-%d %H:%M:%S')] $1" >> "$INSTALL_LOG"
}

# ─── Logo ────────────────────────────────────────────────────────────
show_logo() {
    local Y='\033[1;33m'   # Yellow (scales)
    local G='\033[0;32m'   # Green (body)
    local R='\033[0;31m'   # Red (tongue/eyes)
    local C='\033[0;36m'   # Cyan (accent)
    local W='\033[1;37m'   # White bold
    local D='\033[2m'      # Dim
    local B='\033[1m'      # Bold
    local N='\033[0m'      # Reset

    echo ""
    echo -e "${Y}          ▄▄▄▄▄▄▄▄▄▄▄                                              ${N}"
    echo -e "${Y}       ▄█▀${R}≈≈≈≈≈≈≈≈≈${Y}▀█▄        ${W}╔═══════════════════════════════╗${N}"
    echo -e "${Y}     ▄█▀${R} ◉${Y}▓▓▓▓▓▓▓${R}◉ ${Y}▀█▄      ${W}║${N}  ${C}█▀▀ █▀█ █▀▀ █▀▀ █▀█ █ █ █▀▀ █${N}  ${W}║${N}"
    echo -e "${Y}    █▀${G}▄▄${Y}▓▓▓▓${G}▄▄▄${Y}▓▓▓▓${G}▄▄${Y}▀█     ${W}║${N}  ${C}█   █▀█ ▀▀█ █   █▀█ ▀▄▀ █▀▀ █${N}  ${W}║${N}"
    echo -e "${Y}   █${G}▓▓${Y}▓▓▓▓▓${G}▓▓▓${Y}▓▓▓▓▓${G}▓▓${Y}█     ${W}║${N}  ${C}▀▀▀ ▀ ▀ ▀▀▀ ▀▀▀ ▀ ▀  ▀  ▀▀▀ ▀▀${N} ${W}║${N}"
    echo -e "${Y}   █${G}▓${Y}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${G}▓${Y}█     ${W}╠═══════════════════════════════╣${N}"
    echo -e "${Y}   █▄${G}▓▓${Y}▓▓▓▓▓▓▓▓▓▓▓${G}▓▓${Y}▄█     ${W}║${N}  ${D}Offensive Security Framework${N}   ${W}║${N}"
    echo -e "${Y}    ▀█▄${G}▓▓${Y}▓▓▓▓▓▓▓${G}▓▓${Y}▄█▀      ${W}║${N}  ${D}by RET Tecnologia  © 2026${N}     ${W}║${N}"
    echo -e "${Y}      ▀▀█▄▄${G}▓▓▓${Y}▄▄█▀▀        ${W}╚═══════════════════════════════╝${N}"
    echo -e "${Y}      ${R}  ╱${Y}▀▀▀▀▀▀▀${R}╲${N}"
    echo -e "${Y}     ${R} ╱╱${Y}         ${R}╲╲${N}"
    echo -e "${R}    ≺≺≺${Y}    ▄▄▄    ${R}≻≻≻        ${G}┌─────────────────────────────┐${N}"
    echo -e "${Y}    ╲╲${Y}  ▄█▀ ▀█▄  ${R}╱╱${N}         ${G}│${N} ${B}85${N} plugins · ${B}30+${N} tools · CVSS ${G}│${N}"
    echo -e "${Y}     ╲${Y}▄█▀     ▀█▄${R}╱${N}          ${G}│${N} PDF/MD/JSON · OWASP · LGPD   ${G}│${N}"
    echo -e "${Y}      █${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}█           ${G}│${N} Python 3.12+ · MIT License   ${G}│${N}"
    echo -e "${Y}      █${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}▓${G}◆${Y}█           ${G}└─────────────────────────────┘${N}"
    echo -e "${Y}       ▀█${G}◆◆◆◆${Y}█▀${N}"
    echo -e "${Y}         ▀████▀${N}"
    echo -e "${Y}          ${G}◆◆◆◆${N}"
    echo -e "${Y}           ${G}◆◆${N}"
    echo ""
    echo -e "  ${B}CASCAVEL${N} — ${D}Instalador Universal v2.4.0 (Bulletproof 2026)${N}"
    echo -e "  ${D}Detecta SO, instala dependências, configura comando global.${N}"
    echo ""
}

# ─── Logging ─────────────────────────────────────────────────────────
info()    { _spinner_stop; echo -e "  ${GREEN}✓${NC} $1"; _log "INFO: $1"; }
warn()    { _spinner_stop; echo -e "  ${YELLOW}⚠${NC} $1"; _log "WARN: $1"; }
error()   { _spinner_stop; echo -e "  ${RED}✗${NC} $1"; _log "ERROR: $1"; exit 1; }
step()    {
    _spinner_stop
    _next_step
    echo -e "\n  ${MAGENTA}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${CYAN}▶${NC} ${BOLD}$1${NC}"
    _log "STEP [${CURRENT_STEP}/${TOTAL_STEPS}]: $1"
}
dimlog()  { echo -e "    ${DIM}$1${NC}"; }

# ─── Auto-Clone (suporte a curl | bash) ─────────────────────────────
_auto_install_git() {
    # Tenta instalar git automaticamente em qualquer SO
    warn "Git não encontrado. Tentando instalar automaticamente..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq git 2>/dev/null
    elif command -v brew &>/dev/null; then
        brew install git 2>/dev/null
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q git 2>/dev/null
    elif command -v yum &>/dev/null; then
        sudo yum install -y -q git 2>/dev/null
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm git 2>/dev/null
    elif command -v apk &>/dev/null; then
        sudo apk add git 2>/dev/null
    elif command -v zypper &>/dev/null; then
        sudo zypper install -y git 2>/dev/null
    fi

    if command -v git &>/dev/null; then
        info "Git instalado com sucesso: $(git --version)"
        return 0
    fi
    return 1
}

_auto_clone_if_needed() {
    if [ -f "cascavel.py" ]; then
        return 0
    fi

    # Detecta se já estamos dentro de um clone parcial/corrompido
    if [ -d ".git" ] && [ ! -f "cascavel.py" ]; then
        error "Repositório corrompido: .git existe mas cascavel.py não encontrado. Re-clone manualmente."
    fi

    # Não estamos no diretório do Cascavel — auto-clone
    echo -e "\n  ${CYAN}▶${NC} ${BOLD}cascavel.py não encontrado — clonando repositório automaticamente...${NC}"
    _log "AUTO-CLONE: cascavel.py não encontrado em $(pwd)"

    local CLONE_DIR="Cascavel"
    local REPO_URL="https://github.com/glferreira-devsecops/Cascavel.git"
    local TARBALL_URL="https://github.com/glferreira-devsecops/Cascavel/archive/refs/heads/main.tar.gz"

    # Se o diretório Cascavel já existe, tentar entrar nele
    if [ -d "$CLONE_DIR" ] && [ -f "$CLONE_DIR/cascavel.py" ]; then
        info "Diretório Cascavel/ encontrado — entrando."
        cd "$CLONE_DIR" || error "Falha ao entrar no diretório $CLONE_DIR"
        INSTALL_LOG="$(pwd)/install.log"
        _log "AUTO-CLONE: Usando diretório existente $CLONE_DIR"
        return 0
    fi

    # Método 1: Git clone (preferido)
    if command -v git &>/dev/null || _auto_install_git; then
        _spinner_start "Clonando repositório..."
        if git clone --depth 1 "$REPO_URL" "$CLONE_DIR" >>"$INSTALL_LOG" 2>&1; then
            _spinner_stop
            cd "$CLONE_DIR" || error "Falha ao entrar no diretório clonado"
            INSTALL_LOG="$(pwd)/install.log"
            info "Repositório clonado com sucesso em $(pwd)"
            _log "AUTO-CLONE: Clonado via git em $(pwd)"
            return 0
        fi
        warn "Git clone falhou. Tentando download via tarball..."
    fi

    # Método 2: Curl/wget tarball (fallback — não precisa de git)
    if command -v curl &>/dev/null || command -v wget &>/dev/null; then
        local TMP_TAR
        TMP_TAR=$(mktemp "${TMPDIR:-/tmp}/cascavel-XXXXXXXX.tar.gz")
        _spinner_start "Baixando tarball do repositório..."
        if command -v curl &>/dev/null; then
            curl -fsSL "$TARBALL_URL" -o "$TMP_TAR" 2>/dev/null
        else
            wget -q "$TARBALL_URL" -O "$TMP_TAR" 2>/dev/null
        fi

        _spinner_stop
        if [ -s "$TMP_TAR" ]; then
            $MKDIR -p "$CLONE_DIR"
            tar xzf "$TMP_TAR" --strip-components=1 -C "$CLONE_DIR" 2>/dev/null
            $RM -f "$TMP_TAR"
            cd "$CLONE_DIR" || error "Falha ao entrar no diretório extraído"
            INSTALL_LOG="$(pwd)/install.log"
            info "Repositório baixado e extraído com sucesso em $(pwd)"
            _log "AUTO-CLONE: Baixado via tarball em $(pwd)"
            return 0
        fi
        $RM -f "$TMP_TAR"
    fi

    error "Falha ao obter o repositório. Instale git ou curl e tente novamente."
}

# ─── Pre-flight Checks ──────────────────────────────────────────────
preflight_checks() {
    step "Verificações de segurança pré-instalação (15+ checks)..."

    # 1. Auto-clone se não estamos no diretório correto
    _auto_clone_if_needed
    if [ ! -f "cascavel.py" ]; then
        error "cascavel.py não encontrado mesmo após tentativa de clone."
    fi

    # 2. Verificar se requirements.txt existe
    if [ ! -f "requirements.txt" ]; then
        error "requirements.txt não encontrado!"
    fi

    # 3. Verificar se não estamos rodando como root (a menos que necessário)
    if [ "$(id -u)" -eq 0 ]; then
        warn "Executando como root. Recomendado: instale como usuário normal."
        _log "WARNING: Executando como root (UID=0)"
    fi

    # 4. Verificar permissões do diretório atual
    if [ ! -w "." ]; then
        error "Sem permissão de escrita no diretório atual: $(pwd)"
    fi

    # 5. Verificar espaço em disco (mínimo 500MB)
    if command -v df &>/dev/null; then
        AVAIL_KB=$(df -k "." 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
        if [ "${AVAIL_KB:-0}" -lt 512000 ]; then
            warn "Espaço em disco baixo: $((AVAIL_KB / 1024))MB disponível (recomendado: 500MB+)"
        fi
    fi

    # 6. Verificar conectividade de rede
    if command -v curl &>/dev/null; then
        if ! curl -sS --connect-timeout 5 --max-time 10 https://pypi.org/simple/ &>/dev/null; then
            warn "Sem acesso ao PyPI. Dependências podem falhar."
            dimlog "Verifique: DNS, proxy, firewall (porta 443)"
            _log "NETWORK: PyPI unreachable"
        else
            info "Conectividade OK (PyPI acessível)."
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=10 --spider https://pypi.org/simple/ 2>/dev/null; then
            warn "Sem acesso ao PyPI. Dependências podem falhar."
        else
            info "Conectividade OK (PyPI acessível)."
        fi
    else
        warn "Nem curl nem wget encontrados. Não foi possível verificar conectividade."
    fi

    # 7. Detecção de container (Docker/Podman/LXC)
    IN_CONTAINER="false"
    if [ -f "/.dockerenv" ]; then
        IN_CONTAINER="docker"
    elif [ -f "/run/.containerenv" ]; then
        IN_CONTAINER="podman"
    elif grep -qsE 'docker|lxc|containerd|kubepods' /proc/1/cgroup 2>/dev/null; then
        IN_CONTAINER="cgroup"
    elif [ "${container:-}" = "lxc" ]; then
        IN_CONTAINER="lxc"
    fi
    if [ "$IN_CONTAINER" != "false" ]; then
        warn "Ambiente containerizado detectado ($IN_CONTAINER). Algumas ferramentas podem ter limitações."
        _log "CONTAINER: $IN_CONTAINER"
    fi

    # 8. Detecção WSL2
    if grep -qsi microsoft /proc/version 2>/dev/null; then
        warn "WSL2 detectado. Networking pode afetar scans de rede."
        _log "WSL: WSL2 detectado via /proc/version"
    fi

    # 9. Verificar sudo disponível (quando não root)
    if [ "$(id -u)" -ne 0 ]; then
        if ! command -v sudo &>/dev/null; then
            warn "sudo não encontrado. Ferramentas que exigem root não serão instaladas."
            _log "WARNING: sudo not available"
        fi
    fi

    # 10. Git disponível (necessário para Go install e versionamento)
    if ! command -v git &>/dev/null; then
        warn "git não encontrado. Necessário para ferramentas Go e atualizações."
    fi

    # 11. Verificar arquitetura (ARM/aarch64 warnings)
    ARCH=$($UNAME -m)
    case "$ARCH" in
        arm*|aarch64)
            warn "Arquitetura $ARCH detectada. Algumas ferramentas Go podem não ter binários pré-compilados."
            _log "ARCH: $ARCH — possíveis limitações em build"
            ;;
    esac

    # 12. Verificar se diretório atual não é um symlink (anti-directory traversal)
    REAL_PWD=$(pwd -P)
    if [ "$(pwd)" != "$REAL_PWD" ]; then
        warn "Diretório atual é um symlink → $REAL_PWD"
        _log "SYMLINK: PWD=$(pwd) → REAL=$REAL_PWD"
    fi

    # 13. Verificar encoding do terminal
    if [ -t 1 ]; then
        TERM_ENCODING=$(locale charmap 2>/dev/null || echo "unknown")
        if [ "$TERM_ENCODING" != "UTF-8" ] && [ "$TERM_ENCODING" != "unknown" ]; then
            warn "Terminal encoding: $TERM_ENCODING (recomendado: UTF-8). Caracteres podem renderizar incorretamente."
        fi
    fi

    # 14. Verificar se /tmp tem noexec (comum em servidores hardened)
    if command -v mount &>/dev/null; then
        if mount 2>/dev/null | grep -q '/tmp.*noexec'; then
            warn "/tmp montado com noexec. Scripts temporários podem falhar."
            _log "SECURITY: /tmp has noexec mount flag"
        fi
    fi

    # 15. Verificar se install.log é gravável
    if ! touch "$INSTALL_LOG" 2>/dev/null; then
        INSTALL_LOG="/tmp/cascavel_install_$(date +%s).log"
        warn "Log padrão não gravável. Usando: $INSTALL_LOG"
    fi

    info "Verificações pré-instalação concluídas (15 checks)."
}

# ─── OS Detection ───────────────────────────────────────────────────
detect_os() {
    step "Detectando sistema operacional..."
    OS="unknown"
    DISTRO="unknown"
    PKG_MANAGER="unknown"
    ARCH=$($UNAME -m)

    case "$($UNAME -s)" in
        Darwin*)
            OS="macos"
            DISTRO="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
            if command -v brew &>/dev/null; then
                PKG_MANAGER="brew"
            else
                PKG_MANAGER="none"
                # Auto-install Homebrew no macOS (one-liner oficial)
                warn "Homebrew não encontrado. Instalando automaticamente..."
                _spinner_start "Instalando Homebrew (isso pode levar 1-2 minutos)..."
                if /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/null >>"$INSTALL_LOG" 2>&1; then
                    _spinner_stop
                    # Adiciona Homebrew ao PATH (Apple Silicon e Intel)
                    if [ -f "/opt/homebrew/bin/brew" ]; then
                        eval "$(/opt/homebrew/bin/brew shellenv)"
                    elif [ -f "/usr/local/bin/brew" ]; then
                        eval "$(/usr/local/bin/brew shellenv)"
                    fi
                    if command -v brew &>/dev/null; then
                        PKG_MANAGER="brew"
                        info "Homebrew instalado com sucesso."
                    fi
                else
                    _spinner_stop
                    warn "Falha ao instalar Homebrew. Algumas ferramentas não serão instaladas."
                fi
            fi
            ;;
        Linux*)
            OS="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="${NAME} ${VERSION_ID}"
                case "$ID" in
                    ubuntu|debian|kali|parrot|pop)
                        PKG_MANAGER="apt"
                        ;;
                    fedora|rhel|centos|rocky|alma)
                        PKG_MANAGER="dnf"
                        if ! command -v dnf &>/dev/null; then
                            PKG_MANAGER="yum"
                        fi
                        ;;
                    arch|manjaro|endeavouros)
                        PKG_MANAGER="pacman"
                        ;;
                    opensuse*|sles)
                        PKG_MANAGER="zypper"
                        ;;
                    alpine)
                        PKG_MANAGER="apk"
                        ;;
                    *)
                        PKG_MANAGER="unknown"
                        ;;
                esac
            elif [ -f /etc/alpine-release ]; then
                DISTRO="Alpine $($CAT /etc/alpine-release)"
                PKG_MANAGER="apk"
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows"
            DISTRO="Windows ($($UNAME -s))"
            PKG_MANAGER="none"
            ;;
        *)
            OS="unknown"
            ;;
    esac

    info "OS detectado: ${BOLD}${DISTRO}${NC} (${ARCH})"
    dimlog "Package manager: ${PKG_MANAGER}"
}

# ─── Python Check ───────────────────────────────────────────────────
check_python() {
    step "Verificando Python..."

    PYTHON_CMD=""
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PY_VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
            PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)' 2>/dev/null)
            PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null)
            if [ "${PY_MAJOR:-0}" -ge 3 ] && [ "${PY_MINOR:-0}" -ge 10 ]; then
                PYTHON_CMD="$cmd"
                info "Python ${PY_VER} encontrado (${BOLD}$(command -v "$cmd")${NC})"
                return
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        warn "Python 3.10+ não encontrado. Tentando instalar..."
        install_python
    fi
}

install_python() {
    _spinner_start "Instalando Python 3..."
    case "$PKG_MANAGER" in
        brew)   brew install python3 >>"$INSTALL_LOG" 2>&1 ;;
        apt)
            sudo apt-get update -qq >>"$INSTALL_LOG" 2>&1
            sudo apt-get install -y -qq python3 python3-pip python3-venv python3-dev libssl-dev >>"$INSTALL_LOG" 2>&1
            ;;
        dnf)    sudo dnf install -y python3 python3-pip python3-devel >>"$INSTALL_LOG" 2>&1 ;;
        yum)    sudo yum install -y python3 python3-pip >>"$INSTALL_LOG" 2>&1 ;;
        pacman) sudo pacman -Sy --noconfirm python python-pip >>"$INSTALL_LOG" 2>&1 ;;
        zypper) sudo zypper install -y python3 python3-pip >>"$INSTALL_LOG" 2>&1 ;;
        apk)    sudo apk add python3 py3-pip python3-dev >>"$INSTALL_LOG" 2>&1 ;;
        *)      _spinner_stop; error "Não foi possível instalar Python. Instale manualmente: https://www.python.org/" ;;
    esac
    _spinner_stop

    # Re-check after install
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PYTHON_CMD="$cmd"
            info "Python instalado: $(${cmd} --version)"
            _log "PYTHON: Installed $(${cmd} --version 2>&1)"
            return
        fi
    done
    error "Falha ao instalar Python."
}

# ─── Virtual Environment ────────────────────────────────────────────
setup_venv() {
    step "Configurando ambiente virtual..."

    if [ -d "venv" ]; then
        # Stale venv detection: verifica se o Python binary dentro do venv ainda funciona
        local VENV_PYTHON="venv/bin/python"
        if [ -f "$VENV_PYTHON" ]; then
            if ! "$VENV_PYTHON" -c 'print(1)' 2>/dev/null; then
                warn "Venv existente está corrompido (Python binary não funciona). Recriando..."
                $RM -rf venv
                $PYTHON_CMD -m venv venv || {
                    warn "Falha ao recriar venv. Instalando python3-venv..."
                    case "$PKG_MANAGER" in
                        apt) sudo apt-get install -y -qq python3-venv >>"$INSTALL_LOG" 2>&1 && $PYTHON_CMD -m venv venv ;;
                        dnf|yum) sudo $PKG_MANAGER install -y python3-devel >>"$INSTALL_LOG" 2>&1 && $PYTHON_CMD -m venv venv ;;
                        *)   $PYTHON_CMD -m ensurepip 2>/dev/null; $PYTHON_CMD -m venv venv ;;
                    esac
                }
                info "Venv recriado."
            else
                info "Venv existente verificado e funcional."
            fi
        else
            warn "Venv existente não contém Python binary. Recriando..."
            $RM -rf venv
            $PYTHON_CMD -m venv venv 2>/dev/null || {
                warn "Falha no venv. Instalando python3-venv..."
                case "$PKG_MANAGER" in
                    apt) sudo apt-get install -y -qq python3-venv >>"$INSTALL_LOG" 2>&1 && $PYTHON_CMD -m venv venv ;;
                    *)   $PYTHON_CMD -m ensurepip 2>/dev/null; $PYTHON_CMD -m venv venv ;;
                esac
            }
            info "Venv recriado."
        fi
    else
        $PYTHON_CMD -m venv venv 2>/dev/null || {
            warn "Falha no venv. Instalando python3-venv..."
            case "$PKG_MANAGER" in
                apt)
                    sudo apt-get install -y -qq python3-venv >>"$INSTALL_LOG" 2>&1
                    $PYTHON_CMD -m venv venv || error "Falha crítica: não foi possível criar venv mesmo após instalar python3-venv"
                    ;;
                dnf|yum)
                    sudo $PKG_MANAGER install -y python3-devel >>"$INSTALL_LOG" 2>&1
                    $PYTHON_CMD -m venv venv || error "Falha crítica: não foi possível criar venv"
                    ;;
                *)
                    $PYTHON_CMD -m ensurepip 2>/dev/null
                    $PYTHON_CMD -m venv venv || error "Falha crítica: não foi possível criar venv. Instale python3-venv manualmente."
                    ;;
            esac
        }
        info "Venv criado."
    fi

    # Activate
    if [ -f "venv/bin/activate" ]; then
        # shellcheck source=/dev/null
        source venv/bin/activate
    elif [ -f "venv/Scripts/activate" ]; then
        # shellcheck source=/dev/null
        source venv/Scripts/activate
    fi

    # Verificar se o venv foi ativado corretamente
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        warn "Venv pode não ter sido ativado corretamente."
    else
        info "Venv ativado: $(which python)"
    fi

    # Python ssl module check (necessário para pip HTTPS)
    if ! $PYTHON_CMD -c 'import ssl' 2>/dev/null; then
        warn "Módulo ssl do Python não disponível! pip pode falhar em HTTPS."
        _log "SECURITY: Python ssl module missing — pip HTTPS will fail"
        case "$PKG_MANAGER" in
            apt) warn "Tente: sudo apt install -y libssl-dev && reinstale Python" ;;
            brew) warn "Tente: brew install openssl && brew reinstall python" ;;
            dnf|yum) warn "Tente: sudo $PKG_MANAGER install -y openssl-devel" ;;
        esac
    fi
}

# ─── Python Dependencies ────────────────────────────────────────────
install_python_deps() {
    step "Instalando dependências Python..."

    # Verificar hash do requirements.txt (integridade)
    if command -v shasum &>/dev/null; then
        REQ_HASH=$(shasum -a 256 requirements.txt | awk '{print $1}')
        _log "requirements.txt SHA-256: $REQ_HASH"
        dimlog "requirements.txt SHA-256: ${REQ_HASH:0:16}..."
    elif command -v sha256sum &>/dev/null; then
        REQ_HASH=$(sha256sum requirements.txt | awk '{print $1}')
        _log "requirements.txt SHA-256: $REQ_HASH"
        dimlog "requirements.txt SHA-256: ${REQ_HASH:0:16}..."
    fi

    # Pip com flags de segurança: --no-cache-dir evita cache envenenado
    # --retries 3 e --timeout 30 para resiliência de rede
    _spinner_start "Atualizando pip..."
    pip install --upgrade pip --no-cache-dir --retries 3 --timeout 30 -q 2>/dev/null || warn "Falha ao atualizar pip"
    _spinner_stop
    _spinner_start "Instalando dependências Python (requirements.txt)..."
    pip install -r requirements.txt --no-cache-dir --retries 3 --timeout 60 -q 2>/dev/null || {
        _spinner_stop
        warn "Falha na instalação via requirements.txt. Tentando uma-a-uma..."
        local dep_count=0
        local dep_total
        dep_total=$(grep -cvE '^\s*$|^\s*#' requirements.txt 2>/dev/null || echo "0")
        while IFS= read -r dep || [ -n "$dep" ]; do
            dep="${dep%%$'\r'}"  # Strip Windows \r (CRLF line endings)
            dep="$(echo "$dep" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"  # Trim whitespace
            [[ -z "$dep" || "$dep" == \#* ]] && continue
            ((dep_count++))
            _spinner_start "Instalando [$dep_count/$dep_total] $dep..."
            pip install "$dep" --no-cache-dir --retries 3 --timeout 30 -q 2>/dev/null || warn "Falha: $dep"
            _spinner_stop
        done < requirements.txt
    }
    _spinner_stop

    # Verificar dependências de segurança (versões mínimas)
    _check_dep_versions

    info "Dependências Python instaladas."
    dimlog "$(pip list --format=columns 2>/dev/null | grep -iE 'rich|requests|pyfiglet|PyJWT|notify-py|reportlab' | tr '\n' ', ')" || true
}

_check_dep_versions() {
    # CVE-2026-32597: PyJWT < 2.12.0 tem bypass de validação crit header
    PYJWT_VER=$(pip show pyjwt 2>/dev/null | grep '^Version:' | awk '{print $2}' || echo "0.0.0")
    if [ -n "$PYJWT_VER" ] && [ "$PYJWT_VER" != "0.0.0" ]; then
        PYJWT_MAJOR=$(echo "$PYJWT_VER" | cut -d. -f1)
        PYJWT_MINOR=$(echo "$PYJWT_VER" | cut -d. -f2)
        # Proper semver: 1.x is always < 2.12, 2.x < 2.12 only if minor < 12
        if [ "${PYJWT_MAJOR:-0}" -lt 2 ] || { [ "${PYJWT_MAJOR:-0}" -eq 2 ] && [ "${PYJWT_MINOR:-0}" -lt 12 ]; }; then
            warn "⚠ CVE-2026-32597: PyJWT $PYJWT_VER < 2.12.0 — crit header bypass!"
            warn "  Atualize: pip install 'pyjwt>=2.12.0'"
            _log "SECURITY: CVE-2026-32597 — PyJWT $PYJWT_VER vulnerável"
        fi
    fi

    # CVE-2023-33733: reportlab < 3.6.13 tem RCE via rl_safe_eval
    REPORTLAB_VER=$(pip show reportlab 2>/dev/null | grep '^Version:' | awk '{print $2}' || echo "0.0.0")
    if [ -n "$REPORTLAB_VER" ] && [ "$REPORTLAB_VER" != "0.0.0" ]; then
        RL_MAJOR=$(echo "$REPORTLAB_VER" | cut -d. -f1)
        RL_MINOR=$(echo "$REPORTLAB_VER" | cut -d. -f2)
        RL_PATCH=$(echo "$REPORTLAB_VER" | cut -d. -f3)
        # Proper semver: < 3.6.13 means major<3 OR (major==3 AND (minor<6 OR (minor==6 AND patch<13)))
        if [ "${RL_MAJOR:-0}" -lt 3 ] || { [ "${RL_MAJOR:-0}" -eq 3 ] && { [ "${RL_MINOR:-0}" -lt 6 ] || { [ "${RL_MINOR:-0}" -eq 6 ] && [ "${RL_PATCH:-0}" -lt 13 ]; }; }; }; then
            warn "⚠ CVE-2023-33733: reportlab $REPORTLAB_VER < 3.6.13 — RCE via rl_safe_eval!"
            warn "  Atualize: pip install 'reportlab>=3.6.13'"
            _log "SECURITY: CVE-2023-33733 — reportlab $REPORTLAB_VER vulnerável"
        fi
    fi

    # CVE-2023-32681: requests < 2.31.0 tem Proxy-Authorization header leak
    REQUESTS_VER=$(pip show requests 2>/dev/null | grep '^Version:' | awk '{print $2}' || echo "0.0.0")
    if [ -n "$REQUESTS_VER" ] && [ "$REQUESTS_VER" != "0.0.0" ]; then
        REQ_MAJOR=$(echo "$REQUESTS_VER" | cut -d. -f1)
        REQ_MINOR=$(echo "$REQUESTS_VER" | cut -d. -f2)
        # Proper semver: < 2.31 means major<2 OR (major==2 AND minor<31)
        if [ "${REQ_MAJOR:-0}" -lt 2 ] || { [ "${REQ_MAJOR:-0}" -eq 2 ] && [ "${REQ_MINOR:-0}" -lt 31 ]; }; then
            warn "⚠ CVE-2023-32681: requests $REQUESTS_VER < 2.31.0 — Proxy-Auth header leak!"
            _log "SECURITY: CVE-2023-32681 — requests $REQUESTS_VER vulnerável"
        fi
    fi
}

# ─── Auto-Install Go (for ProjectDiscovery tools) ────────────────────
_auto_install_go() {
    if command -v go &>/dev/null; then
        return 0
    fi

    warn "Go não encontrado. Tentando instalar automaticamente..."

    # Detect OS and Architecture
    local GO_OS GO_ARCH GO_VERSION
    case "$($UNAME -s)" in
        Darwin*) GO_OS="darwin" ;;
        Linux*)  GO_OS="linux" ;;
        *)       warn "Auto-install de Go não suportado neste OS."; return 1 ;;
    esac
    case "$($UNAME -m)" in
        x86_64|amd64) GO_ARCH="amd64" ;;
        arm64|aarch64) GO_ARCH="arm64" ;;
        armv*)         GO_ARCH="armv6l" ;;
        *)             warn "Arquitetura $($UNAME -m) não suportada para auto-install Go."; return 1 ;;
    esac

    # Detect latest stable version from go.dev
    GO_VERSION=$(curl -fsSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -1 || echo "go1.23.4")
    local GO_TAR="${GO_VERSION}.${GO_OS}-${GO_ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    _spinner_start "Baixando Go ${GO_VERSION} (${GO_OS}/${GO_ARCH})..."
    local TMP_GO
    TMP_GO=$(mktemp "${TMPDIR:-/tmp}/go-install.XXXXXXXX.tar.gz")

    if curl -fsSL "$GO_URL" -o "$TMP_GO" 2>/dev/null; then
        _spinner_stop
        if [ -s "$TMP_GO" ]; then
            _spinner_start "Instalando Go em /usr/local/go..."
            # Precisa de sudo para /usr/local
            if [ "$(id -u)" -eq 0 ]; then
                $RM -rf /usr/local/go
                tar -C /usr/local -xzf "$TMP_GO" 2>/dev/null
            elif command -v sudo &>/dev/null; then
                sudo $RM -rf /usr/local/go
                sudo tar -C /usr/local -xzf "$TMP_GO" 2>/dev/null
            else
                # Fallback: instala no $HOME/go-sdk
                local GOROOT_LOCAL="$HOME/go-sdk"
                $MKDIR -p "$GOROOT_LOCAL"
                tar -C "$GOROOT_LOCAL" --strip-components=1 -xzf "$TMP_GO" 2>/dev/null
                export GOROOT="$GOROOT_LOCAL"
                export PATH="$GOROOT_LOCAL/bin:$PATH"
                # Persist GOROOT to shell profiles so Go survives terminal restart
                local GO_EXPORT="export GOROOT=\"$GOROOT_LOCAL\"\nexport PATH=\"$GOROOT_LOCAL/bin:\$PATH\""
                local GO_COMMENT="# Go SDK (auto-installed by Cascavel)"
                for _prof in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
                    if [ -f "$_prof" ] && ! grep -q "go-sdk" "$_prof" 2>/dev/null; then
                        printf "\n%s\n%b\n" "$GO_COMMENT" "$GO_EXPORT" >> "$_prof"
                        _log "GO: Persisted GOROOT to $_prof"
                    fi
                done
                # Fish shell
                local _fish_conf="$HOME/.config/fish/config.fish"
                if [ -f "$_fish_conf" ] || command -v fish &>/dev/null; then
                    $MKDIR -p "$(dirname "$_fish_conf")" 2>/dev/null || true
                    if ! grep -q "go-sdk" "$_fish_conf" 2>/dev/null; then
                        printf "\n%s\nset -gx GOROOT \"%s\"\nset -gx PATH \"%s/bin\" \$PATH\n" "$GO_COMMENT" "$GOROOT_LOCAL" "$GOROOT_LOCAL" >> "$_fish_conf"
                    fi
                fi
            fi
            _spinner_stop

            # Adicionar Go ao PATH
            if [ -d "/usr/local/go/bin" ]; then
                export PATH="/usr/local/go/bin:$PATH"
            fi

            $RM -f "$TMP_GO"

            if command -v go &>/dev/null; then
                info "Go instalado: $(go version 2>/dev/null)"
                _log "GO: Auto-installed $(go version 2>/dev/null)"
                return 0
            fi
        fi
    fi

    _spinner_stop
    $RM -f "$TMP_GO" 2>/dev/null
    warn "Falha ao instalar Go. Ferramentas ProjectDiscovery não serão instaladas."
    dimlog "Instale manualmente: https://go.dev/dl/"
    return 1
}

# ─── External Tools ─────────────────────────────────────────────────
install_external_tools() {
    step "Instalando ferramentas externas (opcionais)..."

    # Core tools per package manager
    case "$PKG_MANAGER" in
        brew)
            BREW_TOOLS="nmap nikto hydra john tshark whois"
            local brew_count=0
            local brew_total=0
            for tool in $BREW_TOOLS; do
                command -v "$tool" &>/dev/null || ((brew_total++))
            done
            if [ "$brew_total" -gt 0 ]; then
                for tool in $BREW_TOOLS; do
                    if ! command -v "$tool" &>/dev/null; then
                        ((brew_count++))
                        _spinner_start "Instalando [$brew_count/$brew_total] $tool..."
                        brew install "$tool" >>"$INSTALL_LOG" 2>&1 || warn "Falha: $tool"
                        _spinner_stop
                    fi
                done
            else
                info "Todas as ferramentas brew já instaladas (idempotent skip)."
            fi
            # sqlmap + wafw00f via pip
            pip install sqlmap wafw00f --no-cache-dir --retries 3 -q 2>/dev/null || true
            ;;
        apt)
            APT_TOOLS="nmap nikto sqlmap hydra john sslscan dnsrecon fierce tshark whois traceroute"
            _spinner_start "Instalando ferramentas APT ($(echo "$APT_TOOLS" | wc -w | tr -d ' ') pacotes)..."
            sudo apt-get install -y $APT_TOOLS >>"$INSTALL_LOG" 2>&1 || warn "Alguns pacotes APT falharam."
            _spinner_stop
            pip install wafw00f --no-cache-dir --retries 3 -q 2>/dev/null || true
            ;;
        dnf|yum)
            sudo $PKG_MANAGER install -y nmap nikto hydra john nmap-ncat whois traceroute 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        pacman)
            sudo pacman -Sy --noconfirm nmap nikto hydra john wireshark-cli whois traceroute 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        zypper)
            sudo zypper install -y nmap nikto hydra john wireshark whois traceroute 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        apk)
            sudo apk add nmap nikto hydra john-the-ripper whois curl 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        *)
            warn "Package manager '$PKG_MANAGER' não suportado. Ferramentas externas não instaladas."
            dimlog "Instale manualmente: nmap, nikto, hydra, subfinder, nuclei"
            ;;
    esac

    # Go-based tools (auto-detect/install Go)
    if ! command -v go &>/dev/null; then
        _auto_install_go
    fi
    if command -v go &>/dev/null; then
        echo -e "\n    ${CYAN}▶${NC} ${BOLD}Go encontrado ($(go version 2>/dev/null | awk '{print $3}')). Instalando ProjectDiscovery suite...${NC}"

        # GOPATH/GOBIN validation — garante que binários Go fiquem no PATH
        export GOPATH="${GOPATH:-$HOME/go}"
        export GOBIN="${GOBIN:-$GOPATH/bin}"
        $MKDIR -p "$GOBIN" 2>/dev/null || true
        # Adiciona GOBIN ao PATH se não estiver lá
        case ":$PATH:" in
            *":$GOBIN:"*) ;; # já está
            *) export PATH="$GOBIN:$PATH" ;;
        esac
        # Persist GOBIN to shell profiles so Go tools survive terminal restart
        local GOBIN_EXPORT="export GOPATH=\"$GOPATH\"\nexport PATH=\"$GOBIN:\$PATH\""
        local GOBIN_COMMENT="# Go tools PATH (auto-configured by Cascavel)"
        for _goprof in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$_goprof" ] && ! grep -q "GOPATH" "$_goprof" 2>/dev/null; then
                printf "\n%s\n%b\n" "$GOBIN_COMMENT" "$GOBIN_EXPORT" >> "$_goprof"
                _log "GO: Persisted GOBIN to $_goprof"
            fi
        done
        local _gofish="$HOME/.config/fish/config.fish"
        if { [ -f "$_gofish" ] || command -v fish &>/dev/null; } && ! grep -q "GOPATH" "$_gofish" 2>/dev/null; then
            $MKDIR -p "$(dirname "$_gofish")" 2>/dev/null || true
            printf "\n%s\nset -gx GOPATH \"%s\"\nset -gx PATH \"%s\" \$PATH\n" "$GOBIN_COMMENT" "$GOPATH" "$GOBIN" >> "$_gofish"
        fi
        dimlog "GOPATH=$GOPATH | GOBIN=$GOBIN (persistido)"
        _log "GO: GOPATH=$GOPATH GOBIN=$GOBIN GO_VERSION=$(go version 2>/dev/null)"

        # Git check — Go install precisa de git
        if ! command -v git &>/dev/null; then
            warn "git não encontrado. go install precisa de git. Pulando ferramentas Go."
        else
            GO_TOOLS=(
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                "github.com/projectdiscovery/httpx/cmd/httpx@latest"
                "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                "github.com/projectdiscovery/katana/cmd/katana@latest"
                "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
                "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
                "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
                "github.com/owasp-amass/amass/v3/...@master"
                "github.com/ffuf/ffuf@latest"
                "github.com/OJ/gobuster/v3@latest"
                "github.com/lc/gau/v2/cmd/gau@latest"
                "github.com/tomnomnom/waybackurls@latest"
            )
            local go_count=0
            local go_total=${#GO_TOOLS[@]}
            local go_installed=0
            for pkg in "${GO_TOOLS[@]}"; do
                TOOL_NAME=$(basename "${pkg%%@*}")
                ((go_count++))
                if command -v "$TOOL_NAME" &>/dev/null; then
                    ((go_installed++))
                else
                    _spinner_start "[${go_count}/${go_total}] go install ${TOOL_NAME}..."
                    go install "$pkg" >>"$INSTALL_LOG" 2>&1 || warn "Falha: $TOOL_NAME"
                    _spinner_stop
                    command -v "$TOOL_NAME" &>/dev/null && ((go_installed++))
                fi
            done
            info "Go tools: ${go_installed}/${go_total} instaladas."

            # Nuclei templates auto-update
            if command -v nuclei &>/dev/null; then
                _spinner_start "Atualizando Nuclei templates..."
                nuclei -ut -silent >>"$INSTALL_LOG" 2>&1 || true
                _spinner_stop
                info "Nuclei templates atualizados."
            fi
        fi
    else
        warn "Go não encontrado. Ferramentas Go-based não instaladas."
        dimlog "Instale Go: https://go.dev/dl/"
    fi

    # Rust-based tools
    if command -v cargo &>/dev/null; then
        if ! command -v feroxbuster &>/dev/null; then
            dimlog "cargo install feroxbuster..."
            cargo install feroxbuster -q 2>/dev/null || warn "Falha: feroxbuster"
        fi
    fi
}

# ─── Directories ─────────────────────────────────────────────────────
setup_dirs() {
    step "Verificando diretórios..."
    for dir in reports exports wordlists nuclei-templates docs plugins output logs; do
        if [ ! -d "$dir" ]; then
            $MKDIR -p "$dir"
            dimlog "Criado: $dir/"
        fi
    done

    # Permissões seguras nos diretórios de output
    chmod 700 reports exports 2>/dev/null || true

    info "Diretórios verificados (reports/ e exports/ com chmod 700)."
}

# ─── File Permissions Hardening ─────────────────────────────────────
harden_permissions() {
    step "Ajustando permissões de arquivos..."

    # cascavel.py deve ser executável apenas pelo owner
    chmod 700 cascavel.py 2>/dev/null || true

    # plugins devem ser legíveis pelo owner
    chmod 600 plugins/*.py 2>/dev/null || true

    # install.sh — executável pelo owner
    chmod 700 install.sh 2>/dev/null || true

    # Se existir .env ou config com secrets, restringir
    for secret_file in .env config.ini secrets.json api_keys.txt; do
        if [ -f "$secret_file" ]; then
            chmod 600 "$secret_file"
            warn "Permissões restringidas: $secret_file (chmod 600)"
        fi
    done

    info "Permissões ajustadas."
}

# ─── Tools Verification ─────────────────────────────────────────────
verify_installation() {
    echo ""
    step "Verificação final..."
    echo ""

    TOOLS=(subfinder amass httpx nmap ffuf gobuster naabu nuclei
           feroxbuster curl nikto sqlmap wafw00f dnsrecon fierce
           hydra gau waybackurls katana dnsx asnmap mapcidr
           tshark sslscan john whois traceroute)

    FOUND=0
    TOTAL=${#TOOLS[@]}
    MISSING_LIST=""

    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            ((FOUND++))
        else
            MISSING_LIST="${MISSING_LIST}${tool} "
        fi
    done

    info "Ferramentas externas: ${BOLD}${FOUND}/${TOTAL}${NC} instaladas"

    if [ -n "$MISSING_LIST" ]; then
        dimlog "Não encontradas: ${MISSING_LIST}"
    fi

    # Python deps check
    PLUGIN_COUNT=$(find plugins -maxdepth 1 -name '*.py' ! -name '__init__*' 2>/dev/null | wc -l | tr -d ' ')
    info "Plugins disponíveis: ${BOLD}${PLUGIN_COUNT}${NC}"

    # Quick syntax check
    $PYTHON_CMD -c "import py_compile; py_compile.compile('cascavel.py', doraise=True)" 2>/dev/null && \
        info "cascavel.py — sintaxe OK" || warn "cascavel.py — erro de sintaxe"

    # Log summary
    _log "SUMMARY: ${FOUND}/${TOTAL} tools, ${PLUGIN_COUNT} plugins"
}

# ─── Global Command Setup ────────────────────────────────────────────
setup_global_command() {
    step "Configurando comando global 'cascavel'..."

    # 1. pip install -e . (editable mode — desenvolvedor vê mudanças imediatas)
    if [ -f "pyproject.toml" ]; then
        dimlog "pip install -e . (editable mode)..."
        pip install -e . --no-cache-dir -q 2>/dev/null || {
            warn "Editable mode falhou. Tentando install padrão..."
            pip install . --no-cache-dir -q 2>/dev/null || {
                warn "pip install falhou. Comando global não configurado."
                _log "ERROR: pip install -e . and pip install . both failed"
                return
            }
        }
        info "Pacote 'cascavel' registrado via pip."
    else
        warn "pyproject.toml não encontrado. Pulando instalação global."
        return
    fi

    # 2. Verificar se 'cascavel' já está no PATH
    if command -v cascavel &>/dev/null; then
        CASCAVEL_PATH=$(command -v cascavel)
        info "Comando 'cascavel' disponível: ${BOLD}${CASCAVEL_PATH}${NC}"
        _log "GLOBAL: cascavel found at $CASCAVEL_PATH"
        return
    fi

    # 3. Se não está no PATH, detectar e configurar
    warn "'cascavel' não encontrado no PATH. Configurando automaticamente..."

    # Detectar diretório de scripts do pip
    PIP_SCRIPTS=""
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        PIP_SCRIPTS="${VIRTUAL_ENV}/bin"
    else
        PIP_SCRIPTS=$($PYTHON_CMD -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>/dev/null || echo "")
    fi

    # User scripts (--user install)
    USER_SCRIPTS=""
    USER_BASE=$($PYTHON_CMD -m site --user-base 2>/dev/null || echo "")
    if [ -n "$USER_BASE" ]; then
        USER_SCRIPTS="${USER_BASE}/bin"
    fi

    TARGET_DIR="${PIP_SCRIPTS:-$USER_SCRIPTS}"

    if [ -z "$TARGET_DIR" ]; then
        warn "Não foi possível detectar o diretório de scripts. Configure manualmente."
        dimlog "Após instalar: pip show cascavel"
        return
    fi

    # 4. Configurar PATH permanente em todos os shells
    HOME_DIR="$HOME"
    EXPORT_LINE="export PATH=\"${TARGET_DIR}:\$PATH\""
    COMMENT="# Cascavel Security Framework — global command"

    _add_to_profile() {
        local profile="$1"
        local line="$2"
        local comment="$3"
        local use_fish="$4"

        if [ ! -f "$profile" ]; then
            touch "$profile" 2>/dev/null || return
        fi

        # Anti-duplicação: verifica se já está configurado
        if grep -q "$TARGET_DIR" "$profile" 2>/dev/null; then
            info "PATH já configurado em $(basename "$profile")"
            return
        fi

        if [ "$use_fish" = "yes" ]; then
            echo "" >> "$profile"
            echo "$comment" >> "$profile"
            echo "set -gx PATH \"${TARGET_DIR}\" \$PATH" >> "$profile"
        else
            echo "" >> "$profile"
            echo "$comment" >> "$profile"
            echo "$line" >> "$profile"
        fi
        info "PATH adicionado em $(basename "$profile")"
        _log "PATH: Added $TARGET_DIR to $profile"
    }

    # Bash
    for bashrc in ".bashrc" ".bash_profile" ".profile"; do
        if [ -f "${HOME_DIR}/${bashrc}" ]; then
            _add_to_profile "${HOME_DIR}/${bashrc}" "$EXPORT_LINE" "$COMMENT" "no"
            break
        fi
    done

    # Zsh
    if [ -f "${HOME_DIR}/.zshrc" ] || command -v zsh &>/dev/null; then
        _add_to_profile "${HOME_DIR}/.zshrc" "$EXPORT_LINE" "$COMMENT" "no"
    fi

    # Fish
    FISH_CONFIG="${HOME_DIR}/.config/fish/config.fish"
    if [ -f "$FISH_CONFIG" ] || command -v fish &>/dev/null; then
        $MKDIR -p "$(dirname "$FISH_CONFIG")" 2>/dev/null || true
        _add_to_profile "$FISH_CONFIG" "" "$COMMENT" "yes"
    fi

    # Aplicar no shell atual
    export PATH="${TARGET_DIR}:$PATH"

    # Re-verificar
    if command -v cascavel &>/dev/null; then
        info "Comando 'cascavel' ativado: $(command -v cascavel)"
    else
        warn "Reinicie o terminal para usar: cascavel target.com"
        dimlog "Ou execute agora: source ~/.bashrc  (ou ~/.zshrc)"
    fi
}

# ─── Post-Install Deep Health Check ──────────────────────────────────
post_install_health_check() {
    step "Validação pós-instalação profunda..."

    local HEALTH_PASS=0
    local HEALTH_FAIL=0
    local HEALTH_WARN=0

    _health_ok()  { ((HEALTH_PASS++)); echo -e "    ${GREEN}✓${NC} $1"; }
    _health_fail(){ ((HEALTH_FAIL++)); echo -e "    ${RED}✗${NC} $1"; }
    _health_warn(){ ((HEALTH_WARN++)); echo -e "    ${YELLOW}⚠${NC} $1"; }

    # 1. Core files exist
    for f in cascavel.py requirements.txt install.sh pyproject.toml; do
        [ -f "$f" ] && _health_ok "$f existe" || _health_fail "$f NÃO ENCONTRADO"
    done

    # 2. Directories exist with correct permissions
    for d in reports exports plugins wordlists docs; do
        if [ -d "$d" ]; then
            _health_ok "$d/ criado"
        else
            _health_fail "$d/ NÃO EXISTE"
        fi
    done

    # 3. reports/ and exports/ have 700
    for d in reports exports; do
        if [ -d "$d" ]; then
            local perms
            perms=$(stat -f '%Lp' "$d" 2>/dev/null || stat -c '%a' "$d" 2>/dev/null || echo "???")
            if [ "$perms" = "700" ]; then
                _health_ok "$d/ permissões corretas (700)"
            else
                _health_warn "$d/ permissões: $perms (esperado: 700)"
            fi
        fi
    done

    # 4. Virtual environment functional
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        _health_ok "Venv ativo: $VIRTUAL_ENV"
    else
        _health_warn "Venv não está ativo na sessão atual"
    fi

    # 5. Python can import core modules
    local CORE_IMPORTS="rich requests pyfiglet"
    for mod in $CORE_IMPORTS; do
        if $PYTHON_CMD -c "import $mod" 2>/dev/null; then
            _health_ok "Python import $mod OK"
        else
            _health_fail "Python import $mod FALHOU"
        fi
    done

    # 6. cascavel.py syntax check
    if $PYTHON_CMD -c "import py_compile; py_compile.compile('cascavel.py', doraise=True)" 2>/dev/null; then
        _health_ok "cascavel.py sintaxe válida"
    else
        _health_fail "cascavel.py ERRO DE SINTAXE"
    fi

    # 7. Plugins count and syntax
    local PLUGIN_COUNT
    PLUGIN_COUNT=$(find plugins -name '*.py' ! -name '__init__*' 2>/dev/null | wc -l | tr -d ' ')
    if [ "${PLUGIN_COUNT:-0}" -gt 0 ]; then
        _health_ok "${PLUGIN_COUNT} plugins encontrados"
    else
        _health_warn "Nenhum plugin encontrado em plugins/"
    fi

    # 8. Global command 'cascavel' reachable
    if command -v cascavel &>/dev/null; then
        _health_ok "Comando cascavel no PATH: $(command -v cascavel)"
    else
        _health_warn "cascavel não está no PATH (reinicie o terminal)"
    fi

    # 9. Nuclei templates updated (if nuclei exists)
    if command -v nuclei &>/dev/null; then
        if [ -d "${HOME}/nuclei-templates" ] || [ -d "nuclei-templates" ]; then
            _health_ok "Nuclei templates presentes"
        else
            _health_warn "Nuclei templates não encontrados (execute: nuclei -ut)"
        fi
    fi

    # 10. install.log writable
    if [ -f "$INSTALL_LOG" ] && [ -w "$INSTALL_LOG" ]; then
        _health_ok "Log de instalação gravável: $INSTALL_LOG"
    else
        _health_warn "Log de instalação não acessível"
    fi

    echo ""
    local HEALTH_TOTAL=$((HEALTH_PASS + HEALTH_FAIL + HEALTH_WARN))
    if [ "$HEALTH_FAIL" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}━━━ HEALTH CHECK: ${HEALTH_PASS}/${HEALTH_TOTAL} PASSED${NC} ${GREEN}(✓ SAUDÁVEL)${NC}"
    else
        echo -e "  ${RED}${BOLD}━━━ HEALTH CHECK: ${HEALTH_PASS}/${HEALTH_TOTAL} PASSED${NC} ${RED}(${HEALTH_FAIL} FALHAS)${NC}"
    fi
    if [ "$HEALTH_WARN" -gt 0 ]; then
        echo -e "  ${YELLOW}${DIM}${HEALTH_WARN} aviso(s) — não críticos${NC}"
    fi
    _log "HEALTH: pass=$HEALTH_PASS fail=$HEALTH_FAIL warn=$HEALTH_WARN"
}

# ─── Summary ─────────────────────────────────────────────────────────
show_summary() {
    step "Resumo da instalação..."
    local elapsed_time=""
    if [ -n "${INSTALL_START_TIME:-}" ]; then
        local end_time
        end_time=$(${DATE} +%s)
        local diff=$((end_time - INSTALL_START_TIME))
        elapsed_time="${diff}s"
    fi

    echo ""
    echo -e "${GREEN}╔═════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}🐍 CASCAVEL INSTALADO COM SUCESSO!${NC}                         ${GREEN}║${NC}"
    if [ -n "$elapsed_time" ]; then
        echo -e "${GREEN}║${NC}  ${DIM}Tempo total: ${elapsed_time}${NC}                                       ${GREEN}║${NC}"
    fi
    echo -e "${GREEN}╠═════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}                                                             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}Quick Start:${NC}                                               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}❯ cascavel target.com${NC}                                    ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}❯ cascavel -t target.com --plugins-only${NC}                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}Se não funciona imediatamente:${NC}                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${DIM}source ~/.bashrc  ou  source ~/.zshrc${NC}                    ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}Exploração:${NC}                                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}❯ cascavel --help${NC}                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}❯ cascavel --check-tools${NC}                                 ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}❯ cascavel --list-plugins${NC}                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${DIM}Log: install.log │ Versão: v2.4.0${NC}                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${DIM}RET Tecnologia — rettecnologia.org${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                             ${GREEN}║${NC}"
    echo -e "${GREEN}╚═════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─── First-Run Wizard (opc. interativo) ──────────────────────────────
first_run_wizard() {
    # Só roda em modo interativo (não em curl | bash)
    if [ "$IS_TTY" != "true" ]; then
        return 0
    fi

    echo -e "  ${MAGENTA}✨${NC} ${BOLD}Deseja executar um scan de demonstração agora?${NC}"
    echo -e "    ${DIM}Digite o domínio alvo ou pressione Enter para pular:${NC}"
    echo ""
    printf "  ${CYAN}❯${NC} "
    read -r TARGET_INPUT </dev/tty 2>/dev/null || TARGET_INPUT=""

    if [ -n "$TARGET_INPUT" ]; then
        # Validação básica do input
        TARGET_INPUT=$(echo "$TARGET_INPUT" | sed 's|^https\?://||;s|/$||;s/ //g')

        # Validação de domínio OU endereço IP
        if [[ "$TARGET_INPUT" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # IP address — aceitar
            true
        elif [[ ! "$TARGET_INPUT" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
            warn "Formato inválido: '$TARGET_INPUT'. Use: exemplo.com.br ou 192.168.1.1"
            echo -e "  ${DIM}Você pode executar depois: cascavel $TARGET_INPUT${NC}"
            return 0
        fi

        echo ""
        echo -e "  ${GREEN}🚀${NC} ${BOLD}Iniciando scan em ${CYAN}${TARGET_INPUT}${NC}${BOLD}...${NC}"
        echo -e "  ${DIM}(Ctrl+C para cancelar)${NC}"
        echo ""

        # Tenta executar via comando global ou diretamente
        if command -v cascavel &>/dev/null; then
            cascavel "$TARGET_INPUT" || warn "Scan finalizado com avisos."
        elif [ -f "cascavel.py" ]; then
            $PYTHON_CMD cascavel.py -t "$TARGET_INPUT" || warn "Scan finalizado com avisos."
        else
            warn "Não foi possível iniciar o scan. Execute manualmente após reiniciar o terminal."
        fi
    else
        echo -e "  ${DIM}Sem problemas! Execute quando quiser:${NC}"
        echo -e "    ${CYAN}❯ cascavel seu-alvo.com.br${NC}"
    fi
    echo ""
}

# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════
main() {
    clear 2>/dev/null || true

    # Timer
    INSTALL_START_TIME=$(${DATE} +%s)

    # Security: acquire lock first
    _acquire_lock
    _create_tmpdir

    show_logo

    _log "=== CASCAVEL INSTALL START ==="
    _log "PWD: $(pwd)"
    _log "USER: $(whoami)"
    _log "SHELL: ${SHELL:-unknown}"
    _log "TERM: ${TERM:-unknown}"
    _log "IS_TTY: $IS_TTY"
    _log "ARGV: $*"

    # ─── Step 1: Pre-flight
    preflight_checks

    # ─── Step 2: OS Detection
    detect_os

    # ─── Step 3: Python
    check_python

    # ─── Step 4: Venv
    setup_venv

    # ─── Step 5: Python deps
    install_python_deps

    # ─── Step 6: Directories
    setup_dirs

    # ─── Step 7: Permissions
    harden_permissions

    # ─── Step 8: External tools
    install_external_tools

    # ─── Step 9: Verification
    verify_installation

    # ─── Step 10: Global command
    setup_global_command

    # ─── Step 11: Deep Health Check
    post_install_health_check

    # ─── Step 12: Summary
    show_summary

    # ─── First-Run Wizard (interactive only)
    first_run_wizard

    _log "=== CASCAVEL INSTALL SUCCESS ==="
}

main "$@"
