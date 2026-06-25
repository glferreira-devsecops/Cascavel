# 🔌 Plugin Guide

## Plugin Categories

### Injection Testing (12 plugins)
| Plugin | Description |
|---|---|
| `sqli_scanner` | SQL injection detection |
| `xss_scanner` | Cross-site scripting detection |
| `ssrf_scanner` | Server-side request forgery |
| `xxe_scanner` | XML external entity injection |
| `ssti_scanner` | Server-side template injection |
| `lfi_scanner` | Local file inclusion |
| `rce_scanner` | Remote code execution |
| `nosql_scanner` | NoSQL injection |
| `blind_rce` | Blind RCE detection |
| `crlf_scanner` | CRLF injection |
| `host_header_injection` | Host header injection |
| `deserialization_scan` | Insecure deserialization |

### Web Security (12 plugins)
| Plugin | Description |
|---|---|
| `csrf_detector` | CSRF vulnerability detection |
| `cors_checker` | CORS misconfiguration |
| `clickjacking_check` | Clickjacking vulnerability |
| `open_redirect` | Open redirect detection |
| `http_smuggling` | HTTP request smuggling |
| `http2_smuggle` | HTTP/2 smuggling |
| `http2_rapid_reset` | HTTP/2 rapid reset attack |
| `web_cache_poison` | Web cache poisoning |
| `websocket_scanner` | WebSocket security |
| `graphql_probe` | GraphQL endpoint discovery |
| `graphql_injection` | GraphQL injection |
| `graphql_nuclear` | Advanced GraphQL attacks |

### Authentication (7 plugins)
| Plugin | Description |
|---|---|
| `jwt_analyzer` | JWT security analysis |
| `oauth_scanner` | OAuth misconfiguration |
| `saml_scanner` | SAML vulnerability |
| `oidc_poisoning` | OIDC poisoning |
| `session_fixation` | Session fixation |
| `password_policy` | Password policy analysis |
| `idor_scanner` | IDOR vulnerability |

### Reconnaissance (8 plugins)
| Plugin | Description |
|---|---|
| `subdomain_hunter` | Subdomain enumeration |
| `dns_deep` | Advanced DNS analysis |
| `whois_recon` | WHOIS information |
| `wayback_enum` | Wayback Machine URLs |
| `shodan_recon` | Shodan search |
| `email_harvester` | Email address harvesting |
| `email_spoof_check` | Email spoofing check |
| `tech_fingerprint` | Technology fingerprinting |

### Network (5 plugins)
| Plugin | Description |
|---|---|
| `nmap_advanc` | Advanced Nmap scanning |
| `ssl_check` | SSL/TLS analysis |
| `security_headers` | Security headers check |
| `waf_detec` | WAF detection |
| `rate_limit_check` | Rate limiting test |

### Cloud & Container (7 plugins)
| Plugin | Description |
|---|---|
| `k8s_exposure` | Kubernetes exposure |
| `kubelet_anonymous_rce` | Kubelet anonymous RCE |
| `docker_exposure` | Docker exposure |
| `cloud_metadata` | Cloud metadata SSRF |
| `cloud_enum` | Cloud enumeration |
| `cloud_ghosting` | Cloud ghost resources |
| `s3_bucket` | S3 bucket enumeration |

### Infrastructure (7 plugins)
| Plugin | Description |
|---|---|
| `redis_unauth` | Redis unauthorized access |
| `mongodb_unauth` | MongoDB unauthorized access |
| `elastic_exposure` | Elasticsearch exposure |
| `smb_ad` | SMB/Active Directory |
| `ftp_brute` | FTP brute force |
| `ssh_brute` | SSH brute force |
| `smpt_enum` | SMTP enumeration |

### NEW: 2026 Advanced (27 plugins)
| Plugin | Description | Category |
|---|---|---|
| `supply_chain_scan` | Supply chain vulnerabilities | Supply Chain |
| `secrets_deep_scan` | Deep secrets scanning | Supply Chain |
| `container_escape` | Container escape detection | Container |
| `cloud_exploitation` | Cloud exploitation (AWS/GCP/Azure) | Cloud |
| `ad_detection` | Active Directory detection | AD |
| `adversary_simulation` | MITRE ATT&CK simulation | Red Team |
| `mobile_apk_scan` | Mobile app scanning | Mobile |
| `firmware_analysis` | Firmware analysis | IoT |
| `fuzzing_engine` | Advanced fuzzing | Fuzzing |
| `http3_test` | HTTP/3/QUIC testing | Protocol |
| `wireless_audit` | Wireless network auditing | Wireless |
| `mitm_framework` | Man-in-the-Middle testing | Network |
| `printer_exploit` | Printer exploitation | IoT |
| `osint_deep` | Deep OSINT reconnaissance | OSINT |
| `api_fuzzing` | API security testing | API |
| `dns_recon_deep` | Advanced DNS reconnaissance | DNS |
| `subdomain_takeover` | Subdomain takeover detection | Recon |
| `privilege_escalation` | Privilege escalation testing | Post-Exploit |
| `persistence_check` | Persistence mechanism detection | Post-Exploit |
| `cobalt_strike_c2` | C2 framework detection | Defense |
| `phishing_simulation` | Phishing vulnerability testing | Social Eng |
| `wifi_rogue_ap` | Rogue AP detection | Wireless |
| `firmware_emulation` | Firmware emulation testing | IoT |
| `bluetooth_audit` | Bluetooth security testing | IoT |
| `blockchain_audit` | Blockchain/Web3 security | Web3 |
| `ics_scada` | ICS/SCADA security testing | ICS/OT |
| `zero_trust_validate` | Zero Trust validation | Architecture |

## Severity Levels

| Level | Icon | Description |
|---|---|---|
| `CRITICO` | 💀 | Immediate exploitation risk, data breach |
| `ALTO` | 🔴 | High risk, requires immediate attention |
| `MEDIO` | 🟡 | Medium risk, should be addressed |
| `BAIXO` | 🔵 | Low risk, defense in depth |
| `INFO` | ⚪ | Informational finding |

## Plugin Development Checklist

- [ ] Implements `run(target, ip, ports, banners, context)` signature
- [ ] Returns `dict` with `plugin` and `resultados` keys
- [ ] Handles all exceptions gracefully
- [ ] Uses timeouts on all network operations
- [ ] Includes remediation advice in findings
- [ ] Uses context for baseline-aware testing
- [ ] Works with `--plugins-only` mode
- [ ] Works with `--plugin-filter` filtering
- [ ] Compatible with scan profiles (YAML)
