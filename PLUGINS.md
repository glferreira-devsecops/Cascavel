# 🐍 Cascavel — Documentação de Plugins

## 📋 Visão Geral

O Cascavel utiliza **60 plugins** baseados em **funções Python puras**. Cada plugin é um `.py` em `plugins/` com `run()` padronizado.

### Assinatura

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """Descrição."""
    return {"plugin": "nome", "resultados": {...}}
```

---

## 🔍 Plugins por Categoria (60)

### 🛡️ Rede (4)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `admin_finder` | Painéis administrativos | requests |
| `heartbleed_scanner` | CVE-2014-0160 via NSE | nmap |
| `nmap_advanc` | Nmap avançado (XML parse) | nmap |
| `domain_transf` | Zone transfer DNS AXFR | dig |

### 🌐 Web (7)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `wps_scanmini` | Scanner WordPress + REST API | requests |
| `tech_fingerprint` | Fingerprint + security headers | requests |
| `sqli_scanner` | SQL injection via GET | requests |
| `dir_bruteforce` | Brute-force diretórios | feroxbuster |
| `nikto_scanner` | Vulnerabilidades web | nikto |
| `katana_crawler` | Web crawler moderno | katana |
| `http_methods` | Auditoria PUT/DELETE/TRACE | requests |

### 🔓 OWASP Top 10 (8)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `xss_scanner` | XSS Refletido + SSTI | requests |
| `cors_checker` | CORS misconfiguration | requests |
| `open_redirect` | Open Redirect (header + JS) | requests |
| `js_analyzer` | Segredos e endpoints em JS | requests |
| `crlf_scanner` | CRLF injection + response splitting | requests |
| `ssrf_scanner` | SSRF + cloud metadata (AWS/GCP/Azure) | requests |
| `idor_scanner` | IDOR/Broken Access Control | requests |
| `prototype_pollution` | Prototype Pollution (Node.js) | requests |

### 💀 Red Team — Injection (5)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `lfi_scanner` | LFI/Path Traversal (16 params × 8 payloads) | requests |
| `rce_scanner` | RCE/Command Injection time-based + output | requests |
| `xxe_scanner` | XXE file read, SSRF, Content-Type switch | requests |
| `nosql_scanner` | NoSQL injection ($ne, $gt, $regex) | requests |
| `ssti_scanner` | SSTI multi-engine (Jinja2/Twig/ERB/Smarty) | requests |

### 💀 Red Team — Recon (4)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `param_miner` | Hidden parameter discovery (50 params) | requests |
| `api_enum` | API enumeration (Swagger/Actuator/Redoc) | requests |
| `info_disclosure` | Sensitive files (.env, .git, backups, keys) | requests |
| `dns_rebinding` | DNS security (wildcard, DNSSEC, SPF/DMARC) | dig |

### 💀 Red Team — Defense Bypass (5)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `csrf_detector` | CSRF token analysis em forms | requests |
| `clickjacking_check` | X-Frame-Options + CSP frame-ancestors | requests |
| `rate_limit_check` | Rate limiting em endpoints de auth | requests |
| `host_header_injection` | Host/XFF injection + IP bypass | requests |
| `web_cache_poison` | Cache poisoning via unkeyed headers | requests |

### 💀 Red Team — Auth (2)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `jwt_analyzer` | JWT alg:none, HS256 weak, sensitive data | requests |
| `deserialization_scan` | Insecure deserialization (Java/PHP/Python/.NET) | requests |

### 🔌 API Security (1)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `graphql_probe` | GraphQL introspection, batch, alias DoS | requests |

### 🔐 Autenticação (4)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `ssh_brute` | Brute force SSH | paramiko |
| `ftp_brute` | Brute force FTP | ftplib |
| `smb_ad` | Enumeração SMB | smbclient |
| `smpt_enum` | Enumeração SMTP (VRFY) | smtplib |

### ☁️ Cloud Security (4)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `s3_bucket` | Buckets S3 públicos | requests |
| `cloud_enum` | Identificação de provedor cloud | socket |
| `cloud_metadata` | Cloud metadata (AWS/GCP/Azure/DO/Oracle) | requests |
| `aws_keyhunter` | [DEPRECATED] → secrets_scraper | importlib |

### 🔍 OSINT (6)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `shodan_recon` | Reconnaissance via Shodan | shodan |
| `wayback_enum` | URLs históricas (Wayback) | gau, waybackurls |
| `dns_deep` | DNS profundo multi-tool | dnsx, dnsrecon |
| `network_mapper` | Mapeamento ASN/rede | asnmap, mapcidr |
| `subdomain_hunter` | Enum massiva subdomínios | subfinder, amass, httpx |
| `email_harvester` | Coleta emails do domínio | requests, dig |

### 📊 Análise (5)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `profiler_bundpent` | Profiler + MITRE ATT&CK | nmap, whatweb |
| `ssl_check` | Certificado SSL/TLS | ssl, socket |
| `waf_detec` | Detecção WAF heurística | requests, wafw00f |
| `secrets_scraper` | Segredos (AWS/Stripe/GitHub/Slack) | requests |
| `subdomain_takeou` | Subdomain takeover | requests |

### 🔓 Vulnerability Scanning (5)
| Plugin | Descrição | Deps |
|--------|-----------|------|
| `auto_exploit` | CVEs via API pública | requests |
| `cve_2021_44228_scanner` | Log4Shell | requests |
| `nuclei_scanner` | Nuclei por severidade (JSONL) | nuclei |
| `fast_webshell` | [PoC] Detecção PUT upload | requests |

### 📡 Wireless (1)
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