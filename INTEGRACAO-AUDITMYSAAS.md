# Estudo de Integração — Cascavel ↔ AuditMySaaS (Watcher)

> Documento de estudo/arquitetura. Não altera código do Watcher. Objetivo:
> mapear o que do **Cascavel** (CTEM engine, Python, 135 plugins) pode ser
> aproveitado pelo **Watcher** (scanner backend do AuditMySaaS, Rust,
> `static-only`, `RCE-safe`) sem violar a doutrina de segurança do Watcher.

---

## 1. Contexto dos dois sistemas

### Watcher (AuditMySaaS) — doutrina `static-only` / `RCE-safe`
- Scanner backend em **Rust**, orquestra ferramentas **estáticas**:
  `osv-scanner`, `semgrep` (+ vibecoder rules), `gitleaks`, `trufflehog`,
  `trivy`, `grype`, `syft`, `zizmor`.
- Triagem **adversarial via LLM** + enrichment **EPSS/KEV**.
- Regra inviolável: **NUNCA executa código do alvo**. Recon **só passivo**.
  Qualquer ação **ativa** (recon ativo, exploit, fuzzing contra host vivo)
  é responsabilidade da **escada humana** (Risk Review / Pentest), nunca do
  worker automático.

### Cascavel — CTEM engine ofensivo
- Framework Python plugável, **135 plugins**, 5 estágios CTEM
  (Scoping → Discovery → Prioritization → Validation → Mobilization).
- Enrichment **EPSS + CISA KEV**, export **OCSF / SARIF / MITRE ATT&CK / PDF / JSON**,
  remediação assistida.
- Natureza: **ativo por design**. Medição objetiva neste repo:
  - **68/135** plugins enviam payloads / tentam exploração.
  - **35/135** plugins fazem `subprocess`/`shell-out` para ferramentas externas
    (`nmap`, `nuclei`, `nikto`, `ldapsearch`, `smbclient`, `hydra`-like, etc.).
  - A grande maioria dos demais faz **requisições diretas ao alvo vivo**
    (HTTP, sockets, DNS ao host).

---

## 2. A regra de ouro para a integração

> **Qualquer interação direta com o alvo = ATIVO = escada humana.**
> O Watcher automático só recebe o que for **static** (análise de artefatos
> fornecidos) ou **passivo** (fontes terceiras, sem tocar o alvo).

Duas consequências diretas:

1. **O engine do Cascavel e a maioria dos plugins NÃO cabem no Watcher.**
   Eles violam `static-only` (probing ao alvo) e `RCE-safe` (shell-out a
   ferramentas externas é superfície de RCE dentro do worker).
2. **O que é reaproveitável é a LÓGICA PURA de pós-processamento** —
   enrichment, priorização, staging CTEM e export — que opera **sobre findings
   já coletados**, sem nunca tocar o alvo nem executar binários do alvo.

---

## 3. O que APROVEITAR JÁ no Watcher (static/passivo — cabe no automatizado)

Módulos de **lógica pura** do Cascavel, sem interação com alvo:

| Capacidade Cascavel | Arquivo | Natureza | Como reusar no Watcher |
|---|---|---|---|
| **Enrichment EPSS + CISA KEV** | `cascavel/threat_intel.py` | Passivo (APIs `first.org` / `cisa.gov`, cache local) | Já é doutrina do Watcher. Usar como **referência/validação** da implementação Rust; ou rodar como passo de enrichment isolado. Convergente. |
| **Priorização por KEV/EPSS** | `threat_intel.enrich_results` (elevação de severidade quando `EPSS > 0.5` ou CVE ∈ KEV) | Puro (opera sobre findings) | Portar a **regra de elevação** para o scoring do Watcher. Baixo esforço, alto valor. |
| **Export OCSF** | `cascavel/ocsf_exporter.py` (mapeia finding → OCSF `class_uid 2002` Vulnerability Finding) | Puro (serialização) | Reusar o **schema/mapeamento OCSF** para o Watcher emitir OCSF nativo. |
| **Export SARIF** | `cascavel/sarif_exporter.py` (SARIF 2.1.0, filtra erros) | Puro | Reusar o mapeamento SARIF para integração com GitHub code scanning. |
| **MITRE ATT&CK Navigator layer** | `mitre_exporter.py` (orphan no repo) | Puro | Reusar o gerador de layer para visualização ATT&CK dos findings. |
| **Modelo de estágios CTEM** | organização Scoping→Discovery→Prioritization→Validation→Mobilization | Conceitual | Adotar como **modelo de organização** do output do Watcher → escada humana (Validation/Mobilization = handoff para o humano). |

Analisadores **de artefato fornecido** (static de verdade — analisam algo que
você entrega, não o alvo vivo). Cabem no Watcher **se** alimentados com o
artefato em vez de fazerem fetch do alvo:

- `mobile_apk_scan` — análise estática de APK (arquivo local).
- `wasm_reverser` — análise estática de binário WASM.
- `jwt_analyzer` — análise estrutural de um JWT fornecido.
- `supply_chain_scan` / `secrets_deep_scan` / `secrets_scraper` — só se
  alimentados com SBOM/manifest/conteúdo capturado (sobrepõem-se muito ao
  que `osv-scanner`/`syft`/`gitleaks`/`trufflehog` já fazem no Watcher →
  **provável redundância**, avaliar antes de portar).

> ⚠️ Ressalva importante: mesmo plugins "leves" do Cascavel (`security_headers`,
> `ssl_check`, `cors_checker`, `tech_fingerprint`, `waf_detec`) fazem **fetch
> HTTP do alvo vivo**. Pela doutrina do Watcher isso é **recon ativo** → NÃO
> entram no worker automático; entram na escada humana. Só entrariam no Watcher
> se refatorados para operar sobre uma resposta **já capturada passivamente**.

### AI remediation — baixo valor, não portar
`cascavel/ai_remediation.py` é hoje um **stub template-based** (`time.sleep`,
gera um script WAF estático) — **não** chama LLM real. O Watcher já tem
**triagem adversarial LLM** superior. Não há ganho em portar.

---

## 4. O que fica na ESCADA HUMANA (Risk Review / Pentest — NÃO no Watcher)

Tudo que **toca o alvo vivo** ou **executa binários externos**. Ou seja: o
**engine do Cascavel** + a esmagadora maioria dos 135 plugins. Categorias:

- **Exploits / RCE ativos:** `auto_exploit`, `blind_rce`, `rce_scanner`,
  `sspp_rce`, `fast_webshell`, `memshell_injector`, `cve_2021_44228_scanner`
  (dispara Log4Shell), `*_rce`, `wp_rogue_admin_cve_2026_8732`,
  `ghost_cms_sqli`, `airflow_jwt_config_cve`, `hp_poly_voip_overflow`.
- **Injection scanners (enviam payload):** `sqli_scanner`, `xss_scanner`,
  `ssti_scanner`, `xxe_scanner`, `lfi_scanner`, `path_traversal`,
  `nosql_scanner`, `crlf_scanner`, `ssrf_scanner`, `host_header_injection`,
  `open_redirect`, `csrf_detector`, `deserialization_scan`,
  `prototype_pollution`, `mass_assignment`, `graphql_injection`,
  `graphql_ast_bomb`, `graphql_nuclear`, `http_smuggling`, `http2_smuggle`,
  `http2_rapid_reset`, `smtp_smuggling`, `web_cache_poison`, `dns_rebinding`,
  `race_condition`, `param_miner`, `fuzzing_engine`, `api_fuzzing`,
  `waf_bypass`, `csp_bypass`, `serverless_event_injection`,
  `broker_ssrf_relay`, `llm_rag_poisoning`, `oidc_poisoning`, `oauth_scanner`.
- **Brute force / auth:** `ssh_brute`, `ftp_brute`.
- **Scanners ativos / shell-out a ferramentas:** `nmap_advanc`,
  `nuclei_scanner`, `nikto_scanner`, `network_mapper`, `katana_crawler`,
  `dir_bruteforce`, `admin_finder`, `subdomain_hunter`, `heartbleed_scanner`,
  `wps_scanmini`, `ad_detection` (`smbclient`/`ldapsearch`).
- **Red team / pós-exploração / OT / wireless:** `cobalt_strike_c2`,
  `mitm_framework`, `adversary_simulation`, `persistence_check`,
  `privilege_escalation`, `container_escape`, `cloud_exploitation`,
  `printer_exploit`, `wifi_rogue_ap`, `wireless_audit`, `bluetooth_audit`,
  `ics_scada`, `firmware_emulation`, `phishing_simulation`.
- **Recon ativo:** varredura de portas, DNS zone transfer (`domain_transf`),
  `git_dumper` (baixa `.git` exposto), e todo probing HTTP/socket ao alvo.

Nesses casos, **o Cascavel é a ferramenta do pentester humano**: roda durante
Risk Review/Pentest, com autorização e escopo, fora do pipeline automático.

---

## 5. Recomendação arquitetural concreta

### ❌ NÃO fazer: Cascavel-as-a-service chamado pelo worker do Watcher
Rodar o Cascavel (ou plugins dele) como serviço Python invocado pelo worker
**viola as duas doutrinas**:
- `static-only`: os plugins fazem probing ativo do alvo.
- `RCE-safe`: o engine faz `shell-out` para `nmap`/`nuclei`/`ldapsearch`/etc.,
  introduzindo superfície de execução de comando dentro do worker.

### ✅ FAZER: portar/reusar apenas a lógica pura (pós-scan, sem tocar o alvo)

**Opção A (recomendada) — reimplementar em Rust no Watcher:**
- Regra de **priorização KEV/EPSS** (elevação de severidade) — trivial de portar.
- **Mapeamento OCSF / SARIF** dos findings — schema estável, portar direto.
- **Layer MITRE ATT&CK Navigator** — gerador de JSON.
- Custo baixo, mantém o worker 100% Rust, sem dependência Python, sem RCE.

**Opção B — micro-serviço Python de enrichment isolado (sem target):**
- Um serviço `enrichment-only` que recebe **a lista de findings do Watcher**
  (CVEs/severidades) e devolve findings enriquecidos (EPSS/KEV) + export
  OCSF/SARIF/ATT&CK, reusando `threat_intel.py` / `ocsf_exporter.py` /
  `sarif_exporter.py` / `mitre_exporter.py` **as-is**.
- **Sem qualquer plugin**, sem `subprocess`, sem contato com o alvo → respeita
  `static-only` e `RCE-safe`.
- Bom se quiser reaproveitar o código Python já pronto sem reescrever em Rust.

**Cascavel como um todo → escada humana:**
- O engine + plugins ativos entram como **toolkit do Risk Review/Pentest**.
- Fluxo sugerido: Watcher (automático, static/passivo) sinaliza exposição →
  estágios CTEM `Validation`/`Mobilization` = **handoff humano** → pentester
  roda o Cascavel com escopo/autorização para validação ativa e exploração.

### Convergência já existente
O Watcher **já** faz enrichment EPSS/KEV — então o maior valor do Cascavel aqui
é **validar/alinhar a regra de priorização** e **reusar os schemas de export
(OCSF/SARIF/ATT&CK)**, não reintroduzir capacidade de scan.

---

## 6. Resumo executivo (TL;DR)

| Item | Destino | Ação |
|---|---|---|
| Enrichment EPSS/KEV | Watcher | Reusar/validar (convergente) |
| Priorização KEV/EPSS | Watcher | Portar regra de elevação |
| Export OCSF / SARIF / ATT&CK | Watcher | Reusar schema/mapeamento |
| Modelo de estágios CTEM | Watcher (organização) | Adotar como framework de handoff |
| Static-artifact analyzers (APK/WASM/JWT) | Watcher (condicional) | Só se sem fetch do alvo; avaliar redundância |
| AI remediation (stub) | — | Não portar (Watcher já tem LLM real) |
| Engine + 68 plugins de payload + 35 de shell-out | **Escada humana** | Cascavel na mão do pentester (Risk Review/Pentest) |

**Regra final:** o Watcher automatizado recebe só **lógica pura de
pós-processamento** do Cascavel (enrichment, priorização, export). Tudo que
**toca o alvo** ou **executa binário** permanece na **escada humana**, onde o
Cascavel é a ferramenta ofensiva do pentester — nunca o worker automático.
