# 🐍 Cascavel — Documentação de Plugins

## 📋 Visão Geral

O Cascavel utiliza **44 plugins** baseados em **funções Python puras**. Cada plugin é um `.py` em `plugins/` com `run()` padronizado.

### Assinatura

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """Descrição."""
    return {"plugin": "nome", "resultados": {...}}
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `target` | `str` | Hostname ou IP do alvo |
| `ip` | `str` | IP resolvido |
| `open_ports` | `List[int]` | Portas abertas (Naabu) |
| `banners` | `Dict[int, str]` | Banners por porta |

---

## 🔍 Plugins por Categoria (44)

### 🛡️ Rede
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `admin_finder` | Painéis administrativos | requests |
| `heartbleed_scanner` | CVE-2014-0160 via NSE | nmap |
| `nmap_advanc` | Nmap avançado (XML parse) | nmap |
| `domain_transf` | Zone transfer DNS AXFR | dig |

### 🌐 Web
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `wps_scanmini` | Scanner WordPress + REST API | requests |
| `tech_fingerprint` | Fingerprint + security headers | requests |
| `sqli_scanner` | SQL injection via GET | requests |
| `dir_bruteforce` | Brute-force diretórios | feroxbuster |
| `nikto_scanner` | Vulnerabilidades web | nikto |
| `katana_crawler` | Web crawler moderno | katana |
| `http_methods` | Auditoria PUT/DELETE/TRACE | requests |

### 🔓 OWASP Top 10
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `xss_scanner` | XSS Refletido + SSTI | requests |
| `cors_checker` | CORS misconfiguration | requests |
| `open_redirect` | Open Redirect (header + JS) | requests |
| `js_analyzer` | Segredos e endpoints em JS | requests |
| `crlf_scanner` | CRLF injection + response splitting | requests |
| `ssrf_scanner` | SSRF + cloud metadata (AWS/GCP/Azure) | requests |
| `idor_scanner` | IDOR em APIs (Broken Access Control) | requests |
| `prototype_pollution` | Prototype Pollution (Node.js) | requests |

### 🔌 API Security
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `graphql_probe` | GraphQL introspection, batch, alias DoS | requests |

### 🔐 Autenticação
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `ssh_brute` | Brute force SSH | paramiko |
| `ftp_brute` | Brute force FTP | ftplib |
| `smb_ad` | Enumeração SMB | smbclient |
| `smpt_enum` | Enumeração SMTP (VRFY) | smtplib |

### ☁️ Cloud Security
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `s3_bucket` | Buckets S3 públicos | requests |
| `cloud_enum` | Identificação de provedor cloud | socket |
| `cloud_metadata` | Cloud metadata exposure (5 providers) | requests |
| `aws_keyhunter` | [DEPRECATED] → secrets_scraper | importlib |

### 🔍 OSINT
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `shodan_recon` | Reconnaissance via Shodan | shodan |
| `wayback_enum` | URLs históricas (Wayback) | gau, waybackurls |
| `dns_deep` | DNS profundo multi-tool | dnsx, dnsrecon |
| `network_mapper` | Mapeamento ASN/rede | asnmap, mapcidr |
| `subdomain_hunter` | Enum massiva subdomínios | subfinder, amass, httpx |
| `email_harvester` | Coleta emails do domínio | requests, dig |

### 📊 Análise
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `profiler_bundpent` | Profiler + MITRE ATT&CK | nmap, whatweb |
| `ssl_check` | Certificado SSL/TLS | ssl, socket |
| `waf_detec` | Detecção WAF heurística | requests, wafw00f |
| `secrets_scraper` | Segredos (AWS/Stripe/GitHub/Slack) | requests |
| `subdomain_takeou` | Subdomain takeover | requests |

### 🔓 Vulnerability Scanning
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `auto_exploit` | CVEs via API pública | requests |
| `cve_2021_44228_scanner` | Log4Shell | requests |
| `nuclei_scanner` | Nuclei por severidade (JSONL) | nuclei |
| `fast_webshell` | [PoC] Detecção PUT upload | requests |

### 📡 Wireless
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `wifi_attac` | Recon Wi-Fi (macOS/Linux) | root, iw/airport |

---

## 💻 Criando Plugins

```python
# plugins/meu_plugin.py
def run(target, ip, open_ports, banners):
    """Descrição breve."""
    import requests
    resultado = {}
    try:
        resultado["dados"] = "..."
    except Exception as e:
        resultado["erro"] = str(e)
    return {"plugin": "meu_plugin", "resultados": resultado}
```

**Regras**: imports dentro da função • `shutil.which()` para ferramentas externas • timeouts obrigatórios • retorno padronizado

---

[MIT License](LICENSE) — [DevFerreiraG](https://github.com/glferreira-devsecops)