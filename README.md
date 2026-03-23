# 🐍 Cascavel — Quantum Security Framework

<p align="center">
  <img src="cascavel_logo.png" alt="Cascavel Logo" width="400" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python 3.8+" /></a>
  <img src="https://img.shields.io/badge/tool-CLI-orange.svg" alt="CLI Tool" />
  <img src="https://img.shields.io/badge/plugins-60-purple.svg" alt="60 Plugins" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg" alt="Platform" />
</p>

## 📝 Visão Geral

O **Cascavel** é um **Quantum Security Framework** modular, extensível e multiplataforma (Linux/macOS) projetado para automatizar e otimizar processos de testes de penetração (pentest). Ele integra ferramentas de segurança líderes de mercado com um sistema robusto de **60 plugins** customizáveis, permitindo varreduras abrangentes de subdomínios, portas, diretórios, banners, OSINT e identificação de vulnerabilidades.

O framework gera relatórios detalhados em Markdown, facilitando a análise e o compartilhamento dos resultados de segurança.

Desenvolvido por [DevFerreiraG](https://github.com/glferreira-devsecops).

## ✨ Funcionalidades Destacadas

- **Automação de Pentest Inteligente**: Automatiza tarefas repetitivas e complexas
- **60 Plugins de Segurança**: Cobertura completa de rede, web, cloud, OSINT, auth, wireless, OWASP Top 10, API Security e Cloud Security
- **Integração OSINT Avançada**: Shodan, Katana, GAU, Waybackurls, DNSx, ASNmap
- **CLI Completa**: Modo interativo e não-interativo com argparse (`--target`, `--list-plugins`, etc.)
- **Detecção Automática de Ferramentas**: Verifica o `$PATH` e pula graciosamente as ausentes
- **Validação de Segurança**: Input sanitizado contra injeção de comandos
- **Multi-Plataforma**: macOS e Linux com detecção automática de OS
- **Relatórios Detalhados em Markdown**: Auto-gerados com timestamp e versionamento

## 🛠️ Ferramentas Integradas

| Categoria | Ferramentas |
|-----------|-----------|
| **Reconhecimento** | Subfinder, Amass, DNSx, Fierce, DnsRecon |
| **Web Scanning** | Httpx, Nikto, Katana, Feroxbuster, Ffuf, Gobuster |
| **Port Scanning** | Nmap, Naabu |
| **Vulnerability** | Nuclei, SQLMap |
| **OSINT** | Shodan, GAU, Waybackurls, ASNmap, MapCIDR |
| **WAF Detection** | Wafw00f |
| **Brute Force** | Hydra, John |

## 🚀 Instalação

### ⚙️ Pré-requisitos

- Python **3.8+**
- Sistema: macOS ou Linux

### 1. Clonar o Repositório

```bash
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel
```

### 2. Criar Ambiente Virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar Dependências

```bash
pip install -r requirements.txt
```

### 4. Instalar Ferramentas Externas (Recomendado)

Ferramentas Go (adicione `$(go env GOPATH)/bin` ao `$PATH`):

```bash
# ProjectDiscovery Suite
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# Outras ferramentas Go
go install -v github.com/owasp-amass/amass/v3/...@master
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

Ferramentas via package manager:

```bash
# macOS (Homebrew)
brew install nmap nikto sqlmap feroxbuster hydra john-jumbo wafw00f dnsrecon fierce tshark

# Linux (Debian/Ubuntu)
sudo apt install nmap nikto sqlmap hydra john sslscan dnsrecon fierce tshark
cargo install feroxbuster  # requer Rust
pip install wafw00f
```

## 💡 Uso

### Modo Interativo

```bash
python3 cascavel.py
```

### Modo CLI (Não-Interativo)

```bash
# Scan completo
python3 cascavel.py -t exemplo.com

# Apenas plugins (sem ferramentas externas)
python3 cascavel.py -t exemplo.com --plugins-only

# Listar plugins disponíveis
python3 cascavel.py --list-plugins

# Verificar ferramentas instaladas
python3 cascavel.py --check-tools
```

### Fluxo de Execução

1. **Enumeração de Subdomínios**: Subfinder, Amass
2. **Sondagem HTTP/S**: Httpx, Curl
3. **Varredura de Portas**: Naabu, Nmap
4. **Web Crawling**: Katana, GAU, Waybackurls
5. **Descoberta de Conteúdo**: Ffuf, Gobuster, Feroxbuster
6. **DNS Profundo**: DNSx, DnsRecon, Fierce
7. **Detecção de WAF**: Wafw00f
8. **Testes de Vulnerabilidade**: Nuclei, Nikto
9. **Coleta de Banners**: TCP handshake em portas abertas
10. **Execução de 60 Plugins**: Módulos de teste Red Team completos
11. **Relatório Final**: Markdown completo em `reports/`

## 🧩 Plugins

O Cascavel inclui **60 plugins** cobrindo diversas áreas de segurança. Consulte [PLUGINS.md](PLUGINS.md) para documentação completa.

| Categoria | Plugins |
|-----------|---------|
| Rede | `admin_finder`, `heartbleed_scanner`, `nmap_advanc`, `domain_transf` |
| Web | `wps_scanmini`, `tech_fingerprint`, `sqli_scanner`, `dir_bruteforce`, `nikto_scanner`, `katana_crawler`, `http_methods` |
| OWASP Top 10 | `xss_scanner`, `cors_checker`, `open_redirect`, `js_analyzer`, `crlf_scanner`, `ssrf_scanner`, `idor_scanner`, `prototype_pollution` |
| Red Team Injection | `lfi_scanner`, `rce_scanner`, `xxe_scanner`, `nosql_scanner`, `ssti_scanner` |
| Red Team Recon | `param_miner`, `api_enum`, `info_disclosure`, `dns_rebinding` |
| Red Team Defense Bypass | `csrf_detector`, `clickjacking_check`, `rate_limit_check`, `host_header_injection`, `web_cache_poison` |
| Red Team Auth | `jwt_analyzer`, `deserialization_scan` |
| API Security | `graphql_probe` |
| Autenticação | `ssh_brute`, `ftp_brute`, `smb_ad`, `smpt_enum` |
| Cloud Security | `s3_bucket`, `cloud_enum`, `cloud_metadata` |
| OSINT | `shodan_recon`, `wayback_enum`, `dns_deep`, `network_mapper`, `subdomain_hunter`, `email_harvester` |
| Análise | `profiler_bundpent`, `ssl_check`, `waf_detec`, `secrets_scraper`, `subdomain_takeou` |
| Vulnerability | `auto_exploit`, `cve_2021_44228_scanner`, `nuclei_scanner`, `fast_webshell`*, `aws_keyhunter`* |
| Wireless | `wifi_attac` |

*\*`aws_keyhunter` é wrapper deprecated. `fast_webshell` é PoC educacional.*

## 🗂️ Estrutura do Projeto

```
.
├── cascavel.py           # Core engine do framework
├── plugins/              # 60 plugins de segurança
│   ├── __init__.py       # Package init
│   ├── admin_finder.py   # Localizador de painéis admin
│   ├── shodan_recon.py   # Shodan OSINT
│   ├── katana_crawler.py # Web crawler
│   ├── dns_deep.py       # DNS profundo
│   └── ...               # +55 plugins adicionais
├── wordlists/            # Wordlists para enumeração
├── nuclei-templates/     # Templates de vulnerabilidade
├── exports/              # Saídas de ferramentas
├── reports/              # Relatórios gerados
├── index.html            # Landing page (PT-BR)
├── en/index.html         # Landing page (EN)
├── requirements.txt      # Dependências Python
├── PLUGINS.md            # Documentação de plugins
├── CONTRIBUTING.md       # Guia de contribuição
├── CODE_OF_CONDUCT.md    # Código de conduta
├── SECURITY.md           # Política de segurança
└── LICENSE               # MIT License
```

## 📄 Geração de Relatórios

Relatórios em Markdown em `reports/`, nomeados `cascavel_YYYYMMDD_HHMMSS.md`, incluindo:

- Informações do alvo (Target, IP, Timestamp, versão do framework)
- Ferramentas disponíveis vs total
- Saídas de todas as ferramentas de reconhecimento
- Resultados JSON de ferramentas estruturadas
- Portas abertas e banners coletados
- Resultados de todos os 60 plugins executados

## 🤝 Contribuição

Consulte [CONTRIBUTING.md](CONTRIBUTING.md) para o guia completo.

## 📝 Código de Conduta

Consulte [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## 📄 Licença

Distribuído sob a [MIT License](LICENSE).

## ❤️ Agradecimentos

À comunidade de segurança cibernética e aos desenvolvedores das ferramentas open-source que tornam este projeto possível.

---

*Desenvolvido com 🐍 por [DevFerreiraG](https://github.com/glferreira-devsecops)*