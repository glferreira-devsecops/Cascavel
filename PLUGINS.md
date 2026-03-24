# 🔌 Cascavel — Plugin Documentation

> **84 security plugins** across 14 attack categories. Every plugin follows the standardized `run(target, ip, open_ports, banners) -> dict` interface.

---

## Plugin Categories

| Category | Count | Description |
|----------|-------|-------------|
| [Injection & Code Execution](#-injection--code-execution) | 7 | XSS, SQLi, SSTI, RCE, NoSQL, Log4Shell |
| [Server-Side Attacks](#-server-side-attacks) | 4 | SSRF, XXE, LFI, Path Traversal |
| [Authentication & Authorization](#-authentication--authorization) | 6 | JWT, OAuth, CSRF, IDOR, Session |
| [Protocol-Level Attacks](#-protocol-level-attacks) | 4 | HTTP Smuggling, HTTP/2, WebSocket, gRPC |
| [Defense Analysis & Bypass](#-defense-analysis--bypass) | 7 | CORS, CSP, WAF, Rate Limit, Cache Poison |
| [API Security](#-api-security) | 4 | GraphQL, API Enum, API Versioning |
| [Advanced Web Attacks](#-advanced-web-attacks) | 6 | Mass Assignment, Race Condition, Prototype Pollution |
| [Infrastructure Exposure](#-infrastructure-exposure) | 8 | Docker, K8s, Redis, MongoDB, CI/CD, Cloud |
| [Reconnaissance & OSINT](#-reconnaissance--osint) | 11 | Subdomains, DNS, WHOIS, Shodan, Traceroute |
| [Information Gathering](#-information-gathering) | 7 | Tech Fingerprint, JS, Secrets, Git Dump |
| [Web Scanning](#-web-scanning) | 7 | Dir Brute, Nikto, Nuclei, HTTP Methods |
| [Cloud & Storage](#-cloud--storage) | 2 | S3 Buckets, SAML |
| [Analysis & Profiling](#-analysis--profiling) | 5 | SSL, WAF Detection, Nmap Advanced |
| [Brute Force & Auth Testing](#-brute-force--auth-testing) | 6 | SSH, FTP, SMB, SMTP, Heartbleed |

---

## 💉 Injection & Code Execution

| Plugin | File | Techniques |
|--------|------|------------|
| **XSS Scanner** | `xss_scanner.py` | Polyglot payloads, DOM-based, mutation XSS, WAF bypass, event handlers |
| **SQLi Scanner** | `sqli_scanner.py` | Time-based, error-based, union-based, boolean blind, DBMS fingerprint |
| **SSTI Scanner** | `ssti_scanner.py` | Jinja2, Twig, Mako, Freemarker, multi-engine polyglot payloads |
| **RCE Scanner** | `rce_scanner.py` | Command injection, OS detection, chained commands, encoding bypass |
| **Blind RCE** | `blind_rce.py` | Time-based OOB detection, sleep injection, DNS callback |
| **NoSQL Scanner** | `nosql_scanner.py` | MongoDB injection ($gt, $ne, $regex), JSON body injection |
| **Log4Shell Scanner** | `cve_2021_44228_scanner.py` | 12 headers, 5 WAF bypass payloads, Java fingerprint, OOB tokens |

## 🌐 Server-Side Attacks

| Plugin | File | Techniques |
|--------|------|------------|
| **SSRF Scanner** | `ssrf_scanner.py` | IMDSv2, DNS rebinding, gopher://, redirect chain, cloud metadata |
| **XXE Scanner** | `xxe_scanner.py` | XML entity injection, OOB exfiltration, parameter entities |
| **LFI Scanner** | `lfi_scanner.py` | Path traversal, null byte, double encoding, wrapper protocols |
| **Path Traversal** | `path_traversal.py` | Directory traversal, encoding bypass, OS-specific paths |

## 🔐 Authentication & Authorization

| Plugin | File | Techniques |
|--------|------|------------|
| **JWT Analyzer** | `jwt_analyzer.py` | None algorithm, key confusion (RS→HS), JWKS poisoning, claim analysis |
| **OAuth Scanner** | `oauth_scanner.py` | PKCE enforcement, state validation, token leakage, redirect URI |
| **CSRF Detector** | `csrf_detector.py` | Token validation, SameSite, origin header check |
| **IDOR Scanner** | `idor_scanner.py` | Sequential ID enumeration, UUID prediction, access control bypass |
| **Session Fixation** | `session_fixation.py` | Cookie flags, session regeneration, pre-auth token analysis |
| **Password Policy** | `password_policy.py` | Policy strength analysis, common password testing, lockout detection |

## 🔄 Protocol-Level Attacks

| Plugin | File | Techniques |
|--------|------|------------|
| **HTTP Smuggling** | `http_smuggling.py` | CL-TE, TE-CL, TE-TE, H2.O desync, chunked mutation |
| **HTTP/2 Smuggle** | `http2_smuggle.py` | HTTP/2 downgrade, continuation flood, HPACK injection |
| **WebSocket Scanner** | `websocket_scanner.py` | CSWSH, origin bypass, message injection, upgrade detection |
| **gRPC Scanner** | `grpc_scanner.py` | Reflection enabled, insecure channel, service enumeration |

## 🛡️ Defense Analysis & Bypass

| Plugin | File | Techniques |
|--------|------|------------|
| **CORS Checker** | `cors_checker.py` | Wildcard origin, null origin, subdomain trust, credential exposure |
| **CSP Bypass** | `csp_bypass.py` | Unsafe-inline, unsafe-eval, data: URI, base-uri, *.cdn bypass |
| **Clickjacking** | `clickjacking_check.py` | X-Frame-Options, CSP frame-ancestors, transparent overlay |
| **Host Header Injection** | `host_header_injection.py` | Password reset poisoning, cache deception, SSRF via Host |
| **Cache Poisoning** | `web_cache_poison.py` | Unkeyed headers, cache key normalization, fat GET |
| **Rate Limit Check** | `rate_limit_check.py` | Brute force feasibility, IP rotation bypass, header spoofing |
| **WAF Bypass** | `waf_bypass.py` | Encoding mutation, chunked TE, case alternation, comment injection |

## 🎯 API Security

| Plugin | File | Techniques |
|--------|------|------------|
| **GraphQL Probe** | `graphql_probe.py` | Introspection enabled, field suggestion, type enumeration |
| **GraphQL Injection** | `graphql_injection.py` | Batch query, alias overload, nested depth, SQL in fields |
| **API Enum** | `api_enum.py` | Endpoint discovery, version detection, documentation exposure |
| **API Versioning** | `api_versioning.py` | Deprecated version detection, v1 vs v2 comparison, OpenAPI exposure |

## 💣 Advanced Web Attacks

| Plugin | File | Techniques |
|--------|------|------------|
| **Mass Assignment** | `mass_assignment.py` | Hidden field injection, role escalation, isAdmin bypass |
| **Race Condition** | `race_condition.py` | TOCTOU, parallel request race, last-write-wins detection |
| **Prototype Pollution** | `prototype_pollution.py` | `__proto__`, constructor pollution, JSON merge injection |
| **Deserialization** | `deserialization_scan.py` | Java/PHP/Python/Ruby serialized objects, magic bytes |
| **Open Redirect** | `open_redirect.py` | URL parameter manipulation, encoding bypass, scheme tricks |
| **CRLF Injection** | `crlf_scanner.py` | Header injection, response splitting, log injection |

## 🏗️ Infrastructure Exposure

| Plugin | File | Techniques |
|--------|------|------------|
| **Docker Exposure** | `docker_exposure.py` | Remote API (2375/2376), registry leak, socket exposure |
| **K8s Exposure** | `k8s_exposure.py` | API server, etcd, kubelet, dashboard, service accounts |
| **Redis Unauth** | `redis_unauth.py` | Unauthenticated access, INFO dump, config get |
| **MongoDB Unauth** | `mongodb_unauth.py` | No-auth access, database listing, collection dump |
| **Elastic Exposure** | `elastic_exposure.py` | Cluster health, index listing, Kibana dashboard |
| **CI/CD Exposure** | `cicd_exposure.py` | Jenkins, GitLab CI, GitHub Actions, artifact exposure |
| **Cloud Metadata** | `cloud_metadata.py` | AWS IMDS, GCP metadata, Azure IMDS, link-local bypass |
| **Cloud Enum** | `cloud_enum.py` | S3/GCS/Azure blob enumeration, DNS CNAME analysis |

## 🔍 Reconnaissance & OSINT

| Plugin | File | Techniques |
|--------|------|------------|
| **Subdomain Hunter** | `subdomain_hunter.py` | Certificate Transparency, DNS brute, zone transfer |
| **Subdomain Takeover** | `subdomain_takeou.py` | CNAME dangling, fingerprint matching, service detection |
| **DNS Deep** | `dns_deep.py` | All record types (A/AAAA/MX/TXT/NS/SOA/SRV/CAA/DMARC) |
| **DNS Rebinding** | `dns_rebinding.py` | TTL manipulation, private IP rebind, bypass detection |
| **Network Mapper** | `network_mapper.py` | Live host detection, service enumeration, port profiling |
| **Email Harvester** | `email_harvester.py` | Web scraping, SMTP VRFY, pattern generation |
| **Email Spoof Check** | `email_spoof_check.py` | SPF, DKIM, DMARC validation, spoofability scoring |
| **Shodan Recon** | `shodan_recon.py` | API-based reconnaissance, service fingerprint, CVE mapping |
| **Wayback Enum** | `wayback_enum.py` | Wayback Machine URL extraction, parameter discovery |
| **WHOIS Recon** | `whois_recon.py` | WHOIS/RDAP, domain age, registrar risk, privacy, DNSSEC, expiry |
| **Traceroute Mapper** | `traceroute_mapper.py` | Hop analysis, latency profiling, CDN/ISP detection, firewall filter |

## 🕵️ Information Gathering

| Plugin | File | Techniques |
|--------|------|------------|
| **Tech Fingerprint** | `tech_fingerprint.py` | Wappalyzer-style detection, header/meta/script analysis |
| **JS Analyzer** | `js_analyzer.py` | API key extraction, endpoint discovery, source map detection |
| **Param Miner** | `param_miner.py` | Hidden parameter brute force, reflected parameter discovery |
| **Info Disclosure** | `info_disclosure.py` | .env, .git, backup files, debug endpoints, error messages |
| **Secrets Scraper** | `secrets_scraper.py` | AWS/GCP/Azure keys, JWT, API tokens, passwords (regex-based) |
| **Git Dumper** | `git_dumper.py` | .git directory enumeration, HEAD/config/refs extraction |
| **Admin Finder** | `admin_finder.py` | Common admin paths, CMS-specific panels, status code analysis |

## 🌐 Web Scanning

| Plugin | File | Techniques |
|--------|------|------------|
| **Dir Bruteforce** | `dir_bruteforce.py` | Path enumeration, wordlist-based, status filtering |
| **Nikto Scanner** | `nikto_scanner.py` | Nikto integration (requires nikto binary) |
| **Katana Crawler** | `katana_crawler.py` | Katana integration (automated deep crawling) |
| **HTTP Methods** | `http_methods.py` | OPTIONS, TRACE, PUT, DELETE, PATCH method testing |
| **WPS Scanmini** | `wps_scanmini.py` | WordPress-specific: themes, plugins, user enum |
| **Nuclei Scanner** | `nuclei_scanner.py` | Nuclei integration (template-based vulnerability scanning) |
| **Upload Detection** | `fast_webshell.py` | PUT/PATCH method detection, WebDAV, extension acceptance (passive) |

## ☁️ Cloud & Storage

| Plugin | File | Techniques |
|--------|------|------------|
| **S3 Bucket** | `s3_bucket.py` | Public bucket detection, ACL misconfiguration, listing |
| **SAML Scanner** | `saml_scanner.py` | Signature wrapping, assertion injection, XML canonicalization |

## 📊 Analysis & Profiling

| Plugin | File | Techniques |
|--------|------|------------|
| **SSL Check** | `ssl_check.py` | Certificate validation, TLS version, cipher strength, HSTS |
| **WAF Detection** | `waf_detec.py` | WAF fingerprint (30+ products), bypass recommendations |
| **Profiler** | `profiler_bundpent.py` | Target profiling, technology stack, risk scoring |
| **Nmap Advanced** | `nmap_advanc.py` | Service version detection, script scanning, OS fingerprint |
| **Auto Exploit** | `auto_exploit.py` | CVE matching, exploit suggestion based on detected versions |

## 🔐 Brute Force & Auth Testing

| Plugin | File | Techniques |
|--------|------|------------|
| **SSH Brute** | `ssh_brute.py` | Paramiko-based auth testing, key auth detection |
| **FTP Brute** | `ftp_brute.py` | Anonymous login, credential testing, directory listing |
| **SMB/AD** | `smb_ad.py` | SMB share enumeration, null session, AD recon |
| **SMTP Enum** | `smpt_enum.py` | VRFY/EXPN user enumeration, open relay detection |
| **Heartbleed** | `heartbleed_scanner.py` | CVE-2014-0160, TLS heartbeat memory leak detection |
| **Domain Transfer** | `domain_transf.py` | DNS zone transfer (AXFR) testing |

---

## 🛠️ Creating New Plugins

See [CONTRIBUTING.md](CONTRIBUTING.md) for the standardized interface and coding guidelines.

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """Plugin description."""
    return {
        "plugin": "my_plugin",
        "versao": "2026.1",
        "tecnicas": ["technique_1", "technique_2"],
        "resultados": {"vulns": [], "intel": {}},
    }
```

---

> **Total: 84 plugins** | Last updated: v2.1.0 (2026-03-24)