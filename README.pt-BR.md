<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>MOTOR CASCAVEL CTEM</code>
</h1>

<h3 align="center">Plataforma autônoma de validação de exposição adversária (AEV) e orquestração de Red Team.</h3>

<p align="center">
  <strong>O Cascavel é um motor de Continuous Threat Exposure Management (CTEM) de atrito zero. Ele orquestra cadeias complexas de ataque, enriquece resultados com Threat Intel (EPSS/CISA KEV), gera remediação com IA, e exporta telemetria nativa (OCSF) em um único comando.</strong>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev"><strong>🌐 cascavel.pages.dev</strong></a> ·
  <a href="README.md">🇺🇸 English</a> ·
  🇧🇷 <strong>Português (Brasil)</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/Licença-MIT-00D4FF.svg?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat-square&logo=python&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Plugins-108-blueviolet.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Plataforma-macOS%20|%20Linux%20|%20WSL-0D1B2A.svg?style=flat-square" />
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/CTEM-v2.0-C89F5D.svg?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Relatórios-OCSF%20|%20PDF%20|%20JSON-28A745.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Segurança-Hardened%202026-critical?style=flat-square" />
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Open%20Source-00D4FF.svg?style=flat-square" /></a>
  <a href="https://github.com/devferreirag/Cascavel/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/devferreirag/Cascavel/security.yml?style=flat-square&label=CI%20Security&logo=github" /></a>
  <a href="https://github.com/devferreirag/Cascavel/stargazers"><img src="https://img.shields.io/github/stars/devferreirag/Cascavel?style=flat-square&color=FFD700" /></a>
</p>

---

## 🎬 Demonstração

<p align="center">
  <img src="docs/cascavel_scan.png" width="700" />
</p>

<p align="center">
  <sub><strong>Sequência de Boot AEV</strong> · Preloader de ameaças em tempo real · Simulação Stealth</sub>
</p>

<p align="center">
  <img src="docs/cascavel_results.png" width="700" />
</p>

<p align="center">
  <sub><strong>Dashboard CTEM Interativo</strong> · Tracking EPSS · Correlação cruzada CISA KEV</sub>
</p>

---

## O Problema vs. A Solução (Modelo CTEM)

A gestão de vulnerabilidades padrão gera fadiga de alertas. Analistas de SOC gastam horas triando achados irrelevantes de dezenas de ferramentas que não se integram e produzem formatos JSON incompatíveis.

O **Cascavel AEV (Adversarial Exposure Validation)** substitui todo esse workflow fragmentado por um motor orquestrado:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  $ python3 cascavel.py -t target.com -o ocsf --ai-fix --stealth-eval   │
│                                                                        │
│  ┌────────────┐  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │ DESCOBERTA │→ │ EXPOSIÇÃO │→ │  ATAQUE    │→ │ ENRIQUECIMENTO    │  │
│  └────────────┘  └───────────┘  └────────────┘  └───────────────────┘  │
│   Recon Stealth   WAF Bypass     Exploitation    CISA KEV Match        │
│   OSINT/WHOIS     Cloud Enum     Injections      FIRST.org EPSS Score  │
│                                                                        │
│  ┌────────────┐  ┌──────────────────────────────────────────────────┐  │
│  │ REMEDIAÇÃO │→ │        TELEMETRIA OCSF & RELATÓRIOS PDF          │  │
│  └────────────┘  └──────────────────────────────────────────────────┘  │
│   Bash Fixes      Esquema Linux Foundation OCSF v1.1.0                 │
│   Python Mitig.   CVSS v4.0 · Mapeamento ISO 27001/LGPD/SOC 2          │
└────────────────────────────────────────────────────────────────────────┘
```

| Capacidade | Engine Cascavel CTEM | Ferramentas Tradicionais |
|:---|:---|:---|
| **Pipeline CTEM** | 108 plugins + 30 binários orquestrados | Scripts dispersos (Nmap + Nuclei + FFuf) |
| **Enriquecimento Intel** | CISA KEV automático e probabilidade EPSS | Exige plataformas de terceiros pagas |
| **Remediação IA** | Gera scripts corretivos locais (Bash/Python) | Nenhum suporte a remediação ativa |
| **Padrão de Telemetria** | Saída OCSF v1.1.0 para Splunk/Elastic | JSONs proprietários incompatíveis |
| **Evasão (Stealth)** | Hooks avançados de `requests` + `X-COST-Simulation` | Enviam User-Agents ruidosos padrão |
| **Segurança Runtime** | Sanitizador ANSI, Prevenção SSRF & TOCTOU | Confia cegamente na saída de binários |

---

## Instalação Determinística

O instalador foi arquitetado sob um rigoroso Threat Model, garantindo total isolamento de dependências e prevenindo RCE de supply chain. **Não requer `git`. Compatível com macOS, Linux, WSL2 e Docker.**

```bash
curl -sL https://github.com/devferreirag/Cascavel/releases/latest/download/cascavel-release.tar.gz | tar xz && cd Cascavel && bash install.sh
```

### Proteções do Instalador (Hardening v2.0)

| Mecanismo | Proteção de Segurança |
|:--|:---|
| **Ambiente Hermético** | Isola via virtualenv (`mktemp -d`) contra conflitos no SO raiz. |
| **Zero Supply Chain** | Integridade forçada via hashes SHA-256 no `requirements.txt`. |
| **Prevenção TOCTOU** | Travas contra escalonamento via lock anti-symlink e permissões `umask 077`. |
| **Clean Exit** | Handlers POSIX `trap` asseguram exclusão segura de `/tmp` pós-instalação. |
| **Isolamento $PATH** | Evita Hijacking Binário limpando entradas `.` relativas. |

---

## Referência CLI: Workflows de Red Team

A API do terminal foi projetada para ser simples e tática.

```bash
# Scan CTEM Completo (Integra binários externos + plugins)
python3 cascavel.py -t target.com

# Modo Stealth: Simulação SOC/WAF bypass (Ignora binários ruidosos)
python3 cascavel.py -t target.com --plugins-only --stealth-eval

# Workflow Automático: CISA KEV + IA Remediation + OCSF Telemetry
python3 cascavel.py -t target.com -o ocsf --ai-fix

# Workflow Executivo: Gerar Relatório PDF Legal (CVSS v4, ISO 27001)
python3 cascavel.py -t target.com --pdf

# Integração CI/CD: Modo Headless Silencioso
python3 cascavel.py -t target.com -q -o json
```

### Orquestração CI/CD (GitHub Actions)
Adicione como security gate bloqueante no seu `.github/workflows/ctem.yml`:

```yaml
name: "Cascavel AEV Pipeline"
on: [push, pull_request]
jobs:
  validate-exposure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: curl -sL https://github.com/devferreirag/Cascavel/releases/latest/download/cascavel-release.tar.gz | tar xz && cd Cascavel && bash install.sh
      - name: Execute CTEM (OCSF + AI Fixes)
        run: cascavel -t staging.internal -q -o ocsf --ai-fix
      - name: Upload Telemetry
        uses: actions/upload-artifact@v4
        with:
          name: ocsf-logs
          path: exports/*.jsonl
```

---

## Arsenal de Plugins (108) e Arquitetura

Nossa arquitetura prioriza a ausência de falsos positivos via parseamento AST e detecção semântica profunda. 

### Engine Core
```text
cascavel.py (3000+ linhas)
├── Engine de Stealth ──────── Hooks Requests, X-COST headers, Bypass WAF Rate-Limit
├── Analisador Threat Intel ── Mapeamento EPSS (FIRST) e CISA KEV Dinâmico
├── Módulo AI Fix ──────────── Geração Sandbox de Scripts (Bash/Python mitigations)
├── Telemetria OCSF ────────── Exportação EventUID 2002 (Linux Foundation Standard)
├── Sanitizador ANSI/Regex ─── Anti-Terminal Injection (CSI/OSC), Anti-ReDoS
└── PDF Engine ─────────────── Relatórios Auditáveis com ReportLab (Hashes SHA-256)
```

### Categorias de Infiltração

1. **Injeção e Code Exec (7):** `xss_scanner`, `sqli_scanner`, `ssti_scanner`, `rce_scanner`, `nosql_scanner`...
2. **Infraestrutura Cloud & K8s (8):** `cloud_metadata` (SSRF via 169.254.x), `docker_exposure`, `s3_bucket_enum`...
3. **Autenticação (6):** `jwt_analyzer` (Bypass Alg, Null Signature), `oauth_scanner`, `idor_scanner`...
4. **Defense Bypass (7):** `cors_checker`, `csp_bypass`, `waf_evasion`, `cache_poisoning`...
5. **Ataques Lógicos API (6):** `graphql_probe`, `mass_assignment`, `api_versioning`...
6. **OSINT e Reconhecimento (11):** `shodan_recon`, `dns_rebinding`, `subdomain_takeover`...

Para a matriz completa de vetores e severidades CVSS precalculadas, consulte nosso [Documento de Plugins](PLUGINS.md).

---

## Modelo de Segurança & Hardening Defensivo

Um motor ofensivo deve ser imune a retaliação. O Cascavel blinda seu hospedeiro de armadilhas preparadas por Blue Teams em HoneyPots.

| Vetor de Retaliação | Mitigação Defensiva no Core |
|:---|:---|
| **Injeção via Terminal (ANSI)** | Filtros Regex estritos removem payloads de Escape (CSI/OSC/DCS), evitando hijacking de clipboard de terminal. |
| **Command Injection (OS)** | Exige delimitador de binário `--` e bloqueia variáveis nativas em `subprocess.run(shell=False)`. |
| **Server-Side Request Forgery** | Trava de IP interna (`169.254.x`) previne que instâncias maliciosas reboteiem ataques via motor. `redirects=False` obrigatório. |
| **Path Traversal Sandboxing** | Utiliza `pathlib.resolve().is_relative_to()` garantindo total contenção da escrita de relatórios/logs OCSF. |
| **Deserialization Arbitrária** | Rejeita funções de `pickle` e uso global de `yaml.safe_load()`. |

---

## Contribuindo

Regras rígidas para assegurar a integridade do Framework:
- Todo código deve passar no pipeline Type Hinting Mypy.
- A conformidade PEP8 (Flake8) não é negociável.
- Nenhum uso de pacotes arbitrários para prevenir contaminação da cadeia de dependências.
- Leia [CONTRIBUTING.md](CONTRIBUTING.md) e a [Política de Segurança](SECURITY.md).

*O Cascavel é classificado como "Dual-Use". O autor repudia seu emprego contra ativos não autorizados.*

---

<p align="center">
  <strong>MÉTODO CASCAVEL</strong><br />
  <sub>
    Desenvolvido e engenheirado por <strong>DevFerreiraG</strong><br />
    <a href="https://github.com/devferreirag">Perfil no GitHub</a>
  </sub>
</p>
