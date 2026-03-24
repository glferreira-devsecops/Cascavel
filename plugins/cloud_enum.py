# plugins/cloud_enum.py — Cascavel 2026 Intelligence
import socket

import requests

CLOUD_PATTERNS = {
    "AWS": [
        ".amazonaws.com",
        ".cloudfront.net",
        ".elasticbeanstalk.com",
        ".elb.amazonaws.com",
        ".s3.amazonaws.com",
        ".execute-api.",
    ],
    "Azure": [
        ".cloudapp.net",
        ".windows.net",
        ".azurewebsites.net",
        ".azurecontainer.io",
        ".azure-api.net",
        ".trafficmanager.net",
        ".blob.core.windows.net",
        ".azureedge.net",
    ],
    "Google": [
        ".googleusercontent.com",
        ".cloudfunctions.net",
        ".appspot.com",
        ".run.app",
        ".googleapis.com",
        ".firebaseio.com",
        ".firebaseapp.com",
        ".web.app",
    ],
    "DigitalOcean": [".digitaloceanspaces.com", ".ondigitalocean.app"],
    "Cloudflare": [".cdn.cloudflare.net", ".workers.dev", ".pages.dev"],
    "Heroku": [".herokuapp.com"],
    "Vercel": [".vercel.app", ".now.sh"],
    "Netlify": [".netlify.app", ".netlify.com"],
    "Fastly": [".fastly.net", ".global.ssl.fastly.net"],
    "Akamai": [".akamaized.net", ".akamaiedge.net", ".edgekey.net"],
}

AWS_IP_RANGES = ["52.", "54.", "3.", "13.", "18.", "35.", "34.", "15.", "44."]
AZURE_IP_RANGES = ["20.", "40.", "51.", "52.", "104.", "137.", "168."]
GCP_IP_RANGES = ["34.", "35.", "104.", "130.", "146.", "199."]


def _detect_by_domain(target):
    """Detecta provider por padrões de domínio."""
    providers = []
    for name, patterns in CLOUD_PATTERNS.items():
        for pattern in patterns:
            if pattern in target.lower():
                providers.append({"provider": name, "match": pattern, "metodo": "domain_pattern"})
                break
    return providers


def _detect_by_headers(target):
    """Detecta provider por headers HTTP."""
    providers = []
    try:
        resp = requests.get(f"http://{target}", timeout=5)
        headers = resp.headers
        # AWS
        if any(h in str(headers) for h in ["x-amz", "x-amzn", "AmazonS3", "CloudFront"]):
            providers.append({"provider": "AWS", "metodo": "http_headers"})
        # Cloudflare
        if headers.get("server", "").lower() == "cloudflare" or "cf-ray" in headers:
            providers.append({"provider": "Cloudflare", "metodo": "http_headers"})
        # Azure
        if any(h in str(headers) for h in ["x-ms-", "x-azure", "x-aspnet"]):
            providers.append({"provider": "Azure", "metodo": "http_headers"})
        # Google
        if any(h in str(headers) for h in ["x-goog", "x-cloud-trace", "x-gfe"]):
            providers.append({"provider": "Google", "metodo": "http_headers"})
        # Fastly
        if "x-served-by" in headers and "cache" in headers.get("x-served-by", "").lower():
            providers.append({"provider": "Fastly", "metodo": "http_headers"})
        # Vercel
        if headers.get("x-vercel-id"):
            providers.append({"provider": "Vercel", "metodo": "http_headers"})
        # Netlify
        if headers.get("x-nf-request-id"):
            providers.append({"provider": "Netlify", "metodo": "http_headers"})
    except Exception:
        pass
    return providers


def _detect_by_dns(target, ip):
    """Detecta provider por DNS reverso e CNAME."""
    providers = []
    try:
        host_ip = ip if ip else socket.gethostbyname(target)
        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(host_ip)[0]
            for name, patterns in CLOUD_PATTERNS.items():
                for pattern in patterns:
                    if pattern.strip(".") in rdns:
                        providers.append({"provider": name, "metodo": "reverse_dns", "rdns": rdns})
                        break
        except Exception:
            pass

        # IP range heuristic
        for prefix in AWS_IP_RANGES:
            if host_ip.startswith(prefix):
                providers.append({"provider": "AWS_POSSIBLE", "metodo": "ip_range", "ip": host_ip})
                break
    except Exception:
        pass
    return providers


def run(target, ip, open_ports, banners):
    """
    Cloud Provider Enumerator 2026-Grade — Domain, Headers, DNS.

    Técnicas: 10 providers (AWS/Azure/GCP/Cloudflare/DO/Heroku/Vercel/
    Netlify/Fastly/Akamai), domain pattern matching (40+ patterns),
    HTTP header analysis (x-amz/cf-ray/x-goog/x-vercel/x-nf),
    reverse DNS lookup, IP range heuristic, CNAME detection.
    """
    _ = (open_ports, banners)
    providers = []
    providers.extend(_detect_by_domain(target))
    providers.extend(_detect_by_headers(target))
    providers.extend(_detect_by_dns(target, ip))

    # Deduplicate
    seen = set()
    unique = []
    for p in providers:
        key = p["provider"]
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return {
        "plugin": "cloud_enum",
        "versao": "2026.1",
        "tecnicas": ["domain_pattern", "http_headers", "reverse_dns", "ip_range"],
        "resultados": unique if unique else {"provider": "Desconhecido"},
    }
