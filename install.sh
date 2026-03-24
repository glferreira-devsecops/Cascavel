#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════╗
# ║  CASCAVEL — Quantum Security Framework                           ║
# ║  One-Command Universal Installer                                  ║
# ║  Detects OS, installs deps, configures everything.                ║
# ╚═══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Logo ────────────────────────────────────────────────────────────
show_logo() {
    echo ""
    echo -e "${GREEN}"
    echo "        ____"
    echo "       / . .\\"
    echo "       \\  ---<<<    ${BOLD}CASCAVEL${NC}${GREEN}"
    echo "        \\  /        ${DIM}Quantum Security Framework${NC}${GREEN}"
    echo "      __/ /"
    echo "     /.  /"
    echo "     \\__/"
    echo -e "${NC}"
}

# ─── Logging ─────────────────────────────────────────────────────────
info()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
error()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }
step()    { echo -e "  ${CYAN}▶${NC} ${BOLD}$1${NC}"; }
dimlog()  { echo -e "    ${DIM}$1${NC}"; }

# ─── OS Detection ───────────────────────────────────────────────────
detect_os() {
    OS="unknown"
    DISTRO="unknown"
    PKG_MANAGER="unknown"
    ARCH=$(uname -m)

    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            DISTRO="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
            if command -v brew &>/dev/null; then
                PKG_MANAGER="brew"
            else
                PKG_MANAGER="none"
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
                DISTRO="Alpine $(cat /etc/alpine-release)"
                PKG_MANAGER="apk"
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows"
            DISTRO="Windows ($(uname -s))"
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
            if [ "${PY_MAJOR:-0}" -ge 3 ] && [ "${PY_MINOR:-0}" -ge 8 ]; then
                PYTHON_CMD="$cmd"
                info "Python ${PY_VER} encontrado (${BOLD}$(command -v "$cmd")${NC})"
                return
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        warn "Python 3.8+ não encontrado. Tentando instalar..."
        install_python
    fi
}

install_python() {
    case "$PKG_MANAGER" in
        brew)   brew install python3 ;;
        apt)    sudo apt update && sudo apt install -y python3 python3-pip python3-venv ;;
        dnf)    sudo dnf install -y python3 python3-pip ;;
        yum)    sudo yum install -y python3 python3-pip ;;
        pacman) sudo pacman -Sy --noconfirm python python-pip ;;
        zypper) sudo zypper install -y python3 python3-pip ;;
        apk)    sudo apk add python3 py3-pip ;;
        *)      error "Não foi possível instalar Python. Instale manualmente: https://www.python.org/" ;;
    esac

    # Re-check after install
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PYTHON_CMD="$cmd"
            info "Python instalado: $(${cmd} --version)"
            return
        fi
    done
    error "Falha ao instalar Python."
}

# ─── Virtual Environment ────────────────────────────────────────────
setup_venv() {
    step "Configurando ambiente virtual..."

    if [ -d "venv" ]; then
        info "Venv existente detectado."
    else
        $PYTHON_CMD -m venv venv || {
            warn "Falha no venv. Instalando python3-venv..."
            case "$PKG_MANAGER" in
                apt) sudo apt install -y python3-venv && $PYTHON_CMD -m venv venv ;;
                *)   $PYTHON_CMD -m ensurepip && $PYTHON_CMD -m venv venv ;;
            esac
        }
        info "Venv criado."
    fi

    # Activate
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    elif [ -f "venv/Scripts/activate" ]; then
        source venv/Scripts/activate
    fi
    info "Venv ativado: $(which python)"
}

# ─── Python Dependencies ────────────────────────────────────────────
install_python_deps() {
    step "Instalando dependências Python..."

    pip install --upgrade pip -q 2>/dev/null
    pip install -r requirements.txt -q 2>/dev/null

    info "Dependências Python instaladas."
    dimlog "$(pip list --format=columns 2>/dev/null | grep -E 'rich|requests|pyfiglet|PyJWT|notify-py' | tr '\n' ', ')"
}

# ─── External Tools ─────────────────────────────────────────────────
install_external_tools() {
    step "Instalando ferramentas externas (opcionais)..."

    # Core tools per package manager
    case "$PKG_MANAGER" in
        brew)
            BREW_TOOLS="nmap nikto hydra john tshark whois"
            for tool in $BREW_TOOLS; do
                if ! command -v "$tool" &>/dev/null; then
                    dimlog "Instalando $tool..."
                    brew install "$tool" 2>/dev/null || warn "Falha: $tool"
                fi
            done
            # sqlmap via pip
            pip install sqlmap -q 2>/dev/null || true
            # wafw00f via pip
            pip install wafw00f -q 2>/dev/null || true
            ;;
        apt)
            APT_TOOLS="nmap nikto sqlmap hydra john sslscan dnsrecon fierce tshark whois traceroute"
            sudo apt install -y $APT_TOOLS 2>/dev/null || warn "Alguns pacotes APT falharam."
            pip install wafw00f -q 2>/dev/null || true
            ;;
        dnf|yum)
            sudo $PKG_MANAGER install -y nmap nikto hydra john nmap-ncat whois traceroute 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        pacman)
            sudo pacman -Sy --noconfirm nmap nikto hydra john wireshark-cli whois traceroute 2>/dev/null || true
            pip install wafw00f sqlmap -q 2>/dev/null || true
            ;;
        *)
            warn "Package manager não suportado. Ferramentas externas não instaladas."
            ;;
    esac

    # Go-based tools (auto-detect Go)
    if command -v go &>/dev/null; then
        step "Go encontrado. Instalando ProjectDiscovery suite..."
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
        for pkg in "${GO_TOOLS[@]}"; do
            TOOL_NAME=$(basename "${pkg%%@*}")
            if ! command -v "$TOOL_NAME" &>/dev/null; then
                dimlog "go install $TOOL_NAME..."
                go install -v "$pkg" 2>/dev/null || warn "Falha: $TOOL_NAME"
            fi
        done
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
    for dir in reports exports wordlists nuclei-templates docs plugins; do
        mkdir -p "$dir"
    done
    info "Diretórios verificados."
}

# ─── Tools Verification ─────────────────────────────────────────────
verify_installation() {
    echo ""
    step "Verificação final..."
    echo ""

    TOOLS=(subfinder amass httpx nmap ffuf gobuster naabu nuclei
           feroxbuster curl nikto sqlmap wafw00f dnsrecon fierce
           hydra gau waybackurls katana dnsx asnmap mapcidr
           tshark sslscan whatweb wpscan john whois traceroute dig)

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
    PLUGIN_COUNT=$(ls plugins/*.py 2>/dev/null | grep -v __init__ | wc -l | tr -d ' ')
    info "Plugins disponíveis: ${BOLD}${PLUGIN_COUNT}${NC}"

    # Quick syntax check
    $PYTHON_CMD -c "import py_compile; py_compile.compile('cascavel.py', doraise=True)" 2>/dev/null && \
        info "cascavel.py — sintaxe OK" || warn "cascavel.py — erro de sintaxe"
}

# ─── Summary ─────────────────────────────────────────────────────────
show_summary() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${BOLD}🐍 CASCAVEL INSTALADO COM SUCESSO!${NC}                           ${GREEN}║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}                                                               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Para ativar o ambiente:                                      ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}source venv/bin/activate${NC}                                    ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Para iniciar um scan:                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}python3 cascavel.py -t alvo.com${NC}                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Mais opções:                                                 ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}python3 cascavel.py --help${NC}                                   ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}python3 cascavel.py --check-tools${NC}                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    ${CYAN}python3 cascavel.py --list-plugins${NC}                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                               ${GREEN}║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════
main() {
    clear 2>/dev/null || true
    show_logo
    echo -e "  ${BOLD}Instalador Universal — v2.1.0${NC}"
    echo -e "  ${DIM}Detecta SO, instala dependências, configura tudo.${NC}"
    echo ""

    detect_os
    echo ""
    check_python
    echo ""
    setup_venv
    echo ""
    install_python_deps
    echo ""
    setup_dirs
    echo ""
    install_external_tools
    echo ""
    verify_installation
    show_summary
}

main "$@"
