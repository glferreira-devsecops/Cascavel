<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>🐍 CASCAVEL</code>
</h1>

<h3 align="center">Uma engine unificada de segurança ofensiva que automatiza assessments de Red Team e relatórios de conformidade em um único comando.</h3>

<p align="center">
  <strong>O Cascavel é uma plataforma CTEM de atrito zero para times de DevSecOps validarem continuamente a exposição de segurança e gerarem relatórios executivos em PDF sem malabarismos com múltiplas ferramentas open-source.</strong>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev"><strong>🌐 cascavel.pages.dev</strong></a> ·
  <a href="#-idioma--language">🇺🇸 English</a> ·
  <a href="#-instala%C3%A7%C3%A3o">Instalação</a> ·
  <a href="#-por-que-o-cascavel">Por que Cascavel</a> ·
  <a href="#-arquitetura">Arquitetura</a> ·
  <a href="#-arsenal-de-plugins-85">Plugins</a> ·
  <a href="#-refer%C3%AAncia-cli">CLI</a> ·
  <a href="#-relat%C3%B3rios-pdf">Relatórios</a> ·
  <a href="#-seguran%C3%A7a">Segurança</a> ·
  <a href="#-contribuindo">Contribuindo</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/Licen%C3%A7a-MIT-00D4FF.svg?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat-square&logo=python&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Plugins-108-blueviolet.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Plataforma-macOS%20|%20Linux%20|%20WSL-0D1B2A.svg?style=flat-square" />
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/v3.0.1-C89F5D.svg?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Relat%C3%B3rios-PDF%20|%20MD%20|%20JSON-28A745.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Seguran%C3%A7a-Hardened%202026-critical?style=flat-square" />
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Open%20Source-00D4FF.svg?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01ek0yIDE3bDEwIDUgMTAtNS0xMC01LTEwIDV6TTIgMTJsMTAgNSAxMC01LTEwLTUtMTAgNXoiLz48L3N2Zz4=" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/security.yml?style=flat-square&label=CI%20Security&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/ci.yml?style=flat-square&label=CI&logo=github" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/glferreira-devsecops/Cascavel"><img src="https://img.shields.io/ossf-scorecard/github.com/glferreira-devsecops/Cascavel?style=flat-square&label=OpenSSF%20Scorecard" /></a>
  <a href="https://www.bestpractices.dev/projects/12255"><img src="https://www.bestpractices.dev/projects/12255/badge" alt="OpenSSF Best Practices" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/codeql.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/codeql.yml?style=flat-square&label=CodeQL&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/stargazers"><img src="https://img.shields.io/github/stars/glferreira-devsecops/Cascavel?style=flat-square&color=FFD700" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/network/members"><img src="https://img.shields.io/github/forks/glferreira-devsecops/Cascavel?style=flat-square&color=00D4FF" /></a>
</p>

---

## 🌐 Idioma / Language

> 🇧🇷 **Você está lendo a versão em Português.** Este README foi escrito para representar a comunidade brasileira de segurança ofensiva.
>
> 🇺🇸 [Click here for the **English** version →](README.md)

---

## 🎬 Demonstração

<p align="center">
  <img src="docs/cascavel_scan.png" width="700" />
</p>

<p align="center">
  <sub><strong>Sequência de boot cinematográfica</strong> · Detecta automaticamente 30+ ferramentas · Preloader com dicas de inteligência de segurança</sub>
</p>

<p align="center">
  <img src="docs/cascavel_results.png" width="700" />
</p>

<p align="center">
  <sub><strong>Dashboard split-screen em tempo real</strong> · Tracking de severidade · Inteligência de segurança rotativa</sub>
</p>

---

## 💡 Por que o Cascavel?

A maioria dos workflows de pentest envolve **mais de 20 ferramentas separadas**, cada uma com sua própria sintaxe, formato de saída e estilo de relatório. Você mescla resultados manualmente, formata relatórios e perde horas com context-switching.

**O Cascavel substitui todo o workflow:**

```
┌─────────────────────────────────────────────────────────┐
│  $ python3 cascavel.py -t target.com --pdf              │
│                                                         │
│  ┌──────────┐  ┌────────┐  ┌──────────┐  ┌──────────┐  │
│  │DESCOBERTA│→ │ SONDA  │→ │  ATAQUE  │→ │ ANÁLISE  │  │
│  └──────────┘  └────────┘  └──────────┘  └──────────┘  │
│   Subdomínios   Portas      XSS,SQLi      JWT,CORS     │
│   DNS,WHOIS     Banners     SSRF,RCE      CSP,CSRF     │
│   Cloud enum    Headers     SSTI,XXE      OAuth,IDOR    │
│                                                         │
│  ┌──────────┐  ┌──────────────────────────────────────┐ │
│  │ DETECÇÃO │→ │       RELATÓRIO (PDF/MD/JSON)        │ │
│  └──────────┘  └──────────────────────────────────────┘ │
│   Docker,K8s    CVSS v4.0 · OWASP · PTES · LGPD        │
│   Redis,S3      Disclaimers legais · Hash SHA-256       │
│   CI/CD         Mapeamento de compliance · Risk matrix  │
└─────────────────────────────────────────────────────────┘
```

| Capacidade | Cascavel | Outras Ferramentas |
|:---|:---|:---|
| **Pipeline unificado** | 108 plugins + 30 ferramentas em um comando | Scripts fragmentados |
| **Dashboard ao vivo** | Split-screen com stats em tempo real + intel | Sem feedback ao vivo |
| **Relatórios PDF** | 12 disclaimers legais, CVSS v4.0, PTES | Formatação manual |
| **UX Terminal** | Preloader cinematográfico, animações fade | Plain stdout |
| **Hardening de segurança** | Sanitizador ANSI, sandbox de plugins | Confia em toda saída |
| **Zero configuração** | `install.sh` cuida de tudo | Dependency hell manual |

---

## ⚡ Instalação

### Pré-requisitos

| Requisito | Mínimo | Por quê |
|:---|:---|:---|
| **Python** | 3.12+ | LTS até 2028 · `importlib.metadata`, typed generics |
| **PyJWT** | 2.12.0 | CVE-2022-29217 — ataque de confusão de algoritmo |
| **ReportLab** | 3.6.13 | CVE-2023-33733 — execução de código via PDF crafted |
| **Requests** | 2.31.0 | CVE-2023-32681 — vazamento de header em redirect |

> [!NOTE]
> O instalador automaticamente aplica essas versões mínimas. Instalações manuais devem verificar com `pip list`.

**Um comando — funciona no macOS, Linux (Debian/Ubuntu/Kali/Parrot/Fedora/Arch/Alpine/SUSE) e WSL:**

```bash
curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/Cascavel/main/install.sh | bash
```

O instalador v2.4.0 inclui **15 hardenings de segurança**: limpeza via `trap`, isolamento `mktemp -d` (anti-TOCTOU), lock anti-symlink, verificação de hash SHA-256, enforcement de versão para 6 pacotes (PyJWT, ReportLab, requests, pyOpenSSL, dnspython), `umask 077`, sanitização de PATH (rejeita `.` e caminhos relativos), detecção de container (Docker/Podman/LXC), detecção WSL2, verificação do módulo `ssl` do Python, recuperação de venv corrompido, `chmod 700/600` em caminhos sensíveis, validação GOPATH/GOBIN, enforcement de locale UTF-8, e caminhos absolutos para binários críticos.

<details>
<summary><strong>Instalação manual</strong></summary>

```bash
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 cascavel.py -t target.com
```

</details>

---

## 🏗️ Arquitetura

```
cascavel.py (3000+ linhas)
├── Sanitizador ANSI Escape ── Bloqueia injeção CSI/OSC/DCS de plugins
├── Motor de Preloader ──────── Boot cinematográfico de 5 fases (logo fade → boot seq → progress → online)
├── Orquestrador de Plugins ── Carga dinâmica, timeout (SIGALRM), sanitização de saída
├── Dashboard Split-Screen ─── Rich Live layout (tabela de scan + painel de intel)
├── Pipeline de Ferramentas ── 30+ ferramentas com segurança shlex.quote()
├── Motor de Relatórios ────── PDF (ReportLab Platypus), Markdown, JSON
└── Signal Handler ─────────── SIGINT async-signal-safe (os.write, sem deadlocks)
```

### Motor de UX Terminal (21 Hardenings)

| Proteção | O que faz |
|:---|:---|
| `_get_terminal_height()` | Fallback POSIX para terminais headless/pipe |
| Detecção de terminal `_fade_in_logo` | Pula manipulação de cursor em terminais < 20 linhas |
| Clamp de segurança `_clear_block` | Nunca move cursor além dos limites do terminal |
| Wrapper try/except `run_preloader` | Fallback gracioso para CI/pipe/dumb terminals |
| KeyboardInterrupt `_typewriter` | Garante newline antes da propagação SIGINT |
| stdout unificado `_boot_line` | Elimina race condition entre buffer Rich/stdout |
| Paleta `green_ramp` da Cobra | Gradiente 256-cores verde real (22→46) |
| Progress bar velocidade variável | Ritmo confortável de 2s com `TimeElapsedColumn` |
| `_build_table` pct máx 100 | Previne display >100% na última iteração |
| Sanitizador ANSI escape | Bloqueia injeção de terminal CSI/OSC/DCS de plugins |
| Tracking de stats fallback | Dashboard preciso mesmo quando Rich Live falha |

---

## 📄 Relatórios PDF

Relatórios de nível enterprise assinados pela **RET Tecnologia**, conformes com frameworks brasileiros e internacionais:

- **Capa** — logo, alvo, ID do relatório, classificação de confidencialidade
- **12 disclaimers legais** — NDA, LGPD, Marco Civil da Internet, Art. 154-A do CP, PL 4752/2025, ISO 27001, PCI DSS v4.0, NIST SP 800-115, OWASP Testing Guide, CVSS v4.0
- **Sumário executivo** — badge dinâmico de postura de severidade
- **Scoring CVSS v4.0** — tabela de severidade com código de cores e risk matrix
- **Achados detalhados** — mapeamento OWASP, evidências, passos de remediação
- **Mapeamento de compliance** — 9 frameworks internacionais
- **Metodologia PTES** — documentação de pentest em 5 fases
- **Página de assinatura** — hash de integridade SHA-256

```bash
python3 cascavel.py -t target.com --pdf    # Gerar PDF
python3 cascavel.py -t target.com -o json  # JSON para CI/CD
```

---

## 🔌 Arsenal de Plugins (108)

Zero tolerância a falsos positivos. Interface `run()` padronizada. Cada plugin retorna resultados estruturados com classificação de severidade.

### 💉 Injeção & Execução de Código (7)

`xss_scanner` · `sqli_scanner` · `ssti_scanner` · `rce_scanner` · `blind_rce` · `nosql_scanner` · `cve_2021_44228_scanner`

### 🌐 Ataques Server-Side (4)

`ssrf_scanner` · `xxe_scanner` · `lfi_scanner` · `path_traversal`

### 🔐 Autenticação & Autorização (6)

`jwt_analyzer` · `oauth_scanner` · `csrf_detector` · `idor_scanner` · `session_fixation` · `password_policy`

### 🔄 Nível de Protocolo (4)

`http_smuggling` · `http2_smuggle` · `websocket_scanner` · `grpc_scanner`

### 🛡️ Bypass de Defesa (7)

`cors_checker` · `csp_bypass` · `clickjacking_check` · `host_header_injection` · `web_cache_poison` · `rate_limit_check` · `waf_bypass`

### 🎯 Segurança de API (4)

`graphql_probe` · `graphql_injection` · `api_enum` · `api_versioning`

### 💣 Web Avançado (6)

`mass_assignment` · `race_condition` · `prototype_pollution` · `deserialization_scan` · `open_redirect` · `crlf_scanner`

### 🏗️ Infraestrutura (8)

`docker_exposure` · `k8s_exposure` · `redis_unauth` · `mongodb_unauth` · `elastic_exposure` · `cicd_exposure` · `cloud_metadata` · `cloud_enum`

### 🔍 Recon & OSINT (11)

`subdomain_hunter` · `subdomain_takeou` · `dns_deep` · `dns_rebinding` · `network_mapper` · `email_harvester` · `email_spoof_check` · `shodan_recon` · `wayback_enum` · `whois_recon` · `traceroute_mapper`

### 🕵️ Coleta de Informações (7)

`tech_fingerprint` · `js_analyzer` · `param_miner` · `info_disclosure` · `secrets_scraper` · `git_dumper` · `admin_finder`

### 🌐 Web Scanning (7)

`dir_bruteforce` · `nikto_scanner` · `katana_crawler` · `http_methods` · `wps_scanmini` · `nuclei_scanner` · `fast_webshell`

### ☁️ Cloud (2)

`s3_bucket` · `saml_scanner`

### 📊 Análise (6)

`ssl_check` · `security_headers` · `waf_detec` · `profiler_bundpent` · `nmap_advanc` · `auto_exploit`

### 🔐 Força Bruta (6)

`ssh_brute` · `ftp_brute` · `smb_ad` · `smpt_enum` · `heartbleed_scanner` · `domain_transf`

> 📖 Documentação completa: [PLUGINS.md](PLUGINS.md)

---

## 💻 Referência CLI

```bash
python3 cascavel.py -t example.com           # Scan completo (todos os plugins + ferramentas)
python3 cascavel.py                           # Modo interativo
python3 cascavel.py -t example.com --pdf      # Gerar relatório PDF
python3 cascavel.py -t example.com -o json    # Saída JSON (integração CI/CD)
python3 cascavel.py -t example.com -q         # Modo silencioso (sem animações)
python3 cascavel.py --plugins-only            # Pular ferramentas externas
python3 cascavel.py --list-plugins            # Listar todos os 108 plugins
python3 cascavel.py --check-tools             # Verificar ferramentas instaladas
```

| Flag | Descrição |
|:---|:---|
| `-t ALVO` | Domínio ou IP alvo |
| `-q` | Suprimir animações e preloader |
| `-o FORMATO` | Formato de saída: `md` / `json` / `pdf` |
| `--pdf` | Atalho para `-o pdf` |
| `--timeout N` | Timeout por ferramenta em segundos (padrão: 90) |
| `--plugins-only` | Executar apenas plugins internos, pular ferramentas externas |
| `--check-tools` | Exibir status das 30+ ferramentas externas |
| `--list-plugins` | Listar todos os plugins disponíveis |
| `--no-preloader` | Pular animação de boot cinematográfica |
| `--no-notify` | Desabilitar notificações desktop |
| `-v` | Exibir versão |

---

## 🛠️ Ferramentas Externas (30+)

Todas opcionais — o Cascavel auto-detecta e pula ferramentas ausentes graciosamente.

| Categoria | Ferramentas |
|:---|:---|
| **Recon** | subfinder · amass · dnsx · fierce · dnsrecon · whois |
| **Web Probing** | httpx · nikto · katana · feroxbuster · ffuf · gobuster |
| **Port Scanning** | nmap · naabu |
| **Vulnerabilidade** | nuclei · sqlmap |
| **OSINT** | shodan · gau · waybackurls · asnmap · mapcidr |
| **Detecção WAF** | wafw00f |
| **Rede** | traceroute · dig · tshark |
| **Crypto/TLS** | sslscan |
| **CMS** | wpscan · whatweb |
| **Força Bruta** | hydra · john |

> 💡 O `install.sh` detecta seu SO e instala todas as ferramentas disponíveis automaticamente.

---

## 🔒 Hardening de Segurança

O Cascavel é blindado contra vetores de ataque modernos que miram as próprias ferramentas de segurança:

### Proteções do Motor

| Vetor | Mitigação |
|:---|:---|
| **Injeção de terminal** (CSI/OSC/DCS) | `_sanitize_output()` remove escapes ANSI perigosos de toda saída, preservando apenas códigos de cor SGR |
| **Path Traversal Sandboxing** | Geração de relatórios rigorosamente isolada com `pathlib.resolve().is_relative_to()`, impedindo gravação arbitrária de arquivos |
| **Server-Side Request Forgery (SSRF)** | IPs de metadados da nuvem (`169.254.169.254`) bloqueados e `allow_redirects=False` forçado nas requisições do motor |
| **ReDoS & Log Injection (CRLF)** | Limite de memória pré-processamento de regex e sanitização restrita de quebras de carro (`\r`) para imunidade CWE-117 |
| **Injeção de input** | Todos os alvos de ferramentas externas sanitizados com `shlex.quote()` |
| **Desserialização Segura** | Bloqueio absoluto do módulo `pickle` e enforcing de `yaml.safe_load` para prevenção total contra RCE |

### Proteções do Instalador (v2.4.0 — 15 hardenings)

| # | Vetor | Mitigação |
|:--|:---|:---|
| 1 | **Race condition TOCTOU** | `mktemp -d` para diretórios temporários únicos |
| 2 | **Execução paralela** | Lock file + check anti-symlink previne instalações concorrentes |
| 3 | **Supply chain** | Verificação de hash SHA-256 no `requirements.txt` |
| 4 | **CVEs conhecidos** | Enforcement de versão para 6 pacotes (PyJWT, ReportLab, requests, pyOpenSSL, dnspython) |
| 5 | **Escalação de permissão** | `umask 077`, `chmod 700/600` em caminhos sensíveis |
| 6 | **Falha de limpeza** | `trap` cleanup em EXIT/INT/TERM/HUP garante remoção |
| 7 | **Injeção de PATH** | Remove `.` e caminhos relativos do `$PATH` na inicialização |
| 8 | **Hijacking de binário** | Usa caminhos absolutos para `mkdir`, `rm`, `cat`, `date`, `uname` |
| 9 | **Detecção de container** | Detecta Docker, Podman, LXC, containers baseados em cgroup |
| 10 | **Detecção WSL2** | Identifica kernel WSL para ajustes de scan de rede |
| 11 | **Venv corrompido** | Detecta binário Python corrompido/movido e recria venv |
| 12 | **Check do módulo ssl** | Verifica disponibilidade do módulo `ssl` para pip HTTPS |
| 13 | **Enforcement de locale** | Força `LC_ALL=en_US.UTF-8` para prevenir bugs de encoding |
| 14 | **Validação GOPATH** | Exporta e valida `GOPATH/GOBIN` para instalação de ferramentas Go |
| 15 | **Check de espaço em disco** | Avisa se < 500MB disponível antes de iniciar instalação |

---

## 📁 Estrutura do Projeto

```
Cascavel/
├── cascavel.py           # Motor principal (3000+ linhas)
├── report_generator.py   # Relatórios PDF (ReportLab Platypus)
├── install.sh            # Instalador universal (v2.4.0, 15 hardenings)
├── plugins/              # 108 plugins de segurança
│   ├── xss_scanner.py    #   └── Interface run() padronizada
│   ├── jwt_analyzer.py
│   └── ...
├── docs/                 # Screenshots e assets
├── reports/              # Relatórios gerados (criado automaticamente)
├── exports/              # Dados exportados (criado automaticamente)
├── wordlists/            # Wordlists para fuzzing
├── nuclei-templates/     # Templates Nuclei customizados
├── requirements.txt      # Dependências Python
├── PLUGINS.md            # Documentação completa dos plugins
├── CONTRIBUTING.md       # Guia de contribuição
├── CHANGELOG.md          # Histórico de versões
├── SECURITY.md           # Política de divulgação de vulnerabilidades
└── LICENSE               # MIT
```

---

## 🔄 Pipeline de Segurança CI/CD

O Cascavel é distribuído com [workflows GitHub Actions](.github/workflows/security.yml) que garantem segurança em todo push e PR:

| Job | Ferramenta | Saída |
|:----|:-----------|:------|
| **Verificação de Sintaxe** | `py_compile` | Valida todos os arquivos `.py` |
| **SAST (Bandit)** | [Bandit](https://github.com/PyCQA/bandit) | SARIF → Aba Security do GitHub |
| **SAST (Semgrep)** | [Semgrep](https://semgrep.dev) | Regras: `auto` + `python` + `owasp-top-ten` |
| **Auditoria de CVEs** | `pip-audit` | Aplica mínimos PyJWT/ReportLab/Requests |
| **Detecção de Segredos** | [Gitleaks](https://github.com/gitleaks/gitleaks) | Scan completo do histórico de commits |

> [!TIP]
> Os resultados SARIF aparecem diretamente na aba **Security** do seu repo no GitHub — sem dashboard adicional.

---

## ⚡ Tratamento de Sinais

O Cascavel trata sinais Unix para operação robusta em todos os ambientes:

| Sinal | Comportamento | Caso de Uso |
|:-------|:---------|:---------|
| `SIGINT` (Ctrl+C) | Shutdown async-signal-safe via `os.write()` → exit 130 | Terminal interativo |
| `SIGTERM` | Mesmo handler → exit 143 | Shutdown gracioso Docker/K8s |
| `SIGPIPE` | Restaurado para `SIG_DFL` | Término limpo de pipe (`\| head`) |
| `BrokenPipeError` | Capturado + `os._exit(141)` | Fallback para edge cases SIGPIPE |

---

## 🤝 Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para o guia completo.

**Interface de plugin** — solte um arquivo em `plugins/` e ele é auto-descoberto:

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """
    Args:
        target:     Domínio ou IP sendo escaneado
        ip:         Endereço IPv4/IPv6 resolvido
        open_ports: Lista de números de portas abertas (do naabu)
        banners:    Dict mapeando porta -> string do banner

    Returns:
        {
            "plugin": "meu_plugin",
            "resultados": [...],      # Lista de achados ou string de sumário
            "severidade": "ALTO",     # CRITICO | ALTO | MEDIO | BAIXO | INFO
        }
    """
    return {"plugin": "meu_plugin", "resultados": "Limpo", "severidade": "INFO"}
```

---

## 📋 Links

| Recurso | Descrição |
|:---|:---|
| [CHANGELOG.md](CHANGELOG.md) | Histórico de versões e notas de release |
| [SECURITY.md](SECURITY.md) | Política de divulgação de vulnerabilidades |
| [PLUGINS.md](PLUGINS.md) | Documentação completa dos plugins e técnicas |
| [LICENSE](LICENSE) | Licença MIT |
| [README.md](README.md) | 🇺🇸 Versão em Inglês |

---

<p align="center">
  <strong><code>MÉTODO CASCAVEL™</code></strong><br />
  <sub>
    Um produto da <a href="https://rettecnologia.org"><strong>RET Tecnologia</strong></a> — Engenharia de Software & Cibersegurança Ofensiva<br />
    <a href="https://github.com/glferreira-devsecops">Gabriel L. Ferreira</a> · Fundador & DevSecOps Lead<br />
    <br />
    🇧🇷 Feito no Brasil com orgulho. Protegendo a web, um alvo por vez. 🐍
  </sub>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev"><strong>🌐 cascavel.pages.dev</strong></a> ·
  <a href="https://rettecnologia.org"><strong>🏢 rettecnologia.org</strong></a>
</p>
