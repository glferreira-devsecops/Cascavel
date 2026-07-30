# ═══════════════════════════════════════════════════════════════════════════════
# CASCAVEL v3.0.0 — Official Docker Image
# Multi-stage build with external security tools
# Product of RET Tecnologia (https://rettecnologia.org)
# ═══════════════════════════════════════════════════════════════════════════════
# Usage:
#   docker build -t cascavel:3.0.0 .
#   docker run --rm cascavel:3.0.0 -t target.com
#   docker run --rm cascavel:3.0.0 --list-plugins
#   docker run --rm -v $(pwd)/reports:/app/reports cascavel:3.0.0 -t target.com --sarif
# ═══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Go tools builder ────────────────────────────────────────────────
FROM golang:bookworm AS go-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git=1:2.39.5-0+deb12u3 \
    libpcap-dev=1.10.3-1 \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/OJ/gobuster/v3@latest

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.14-slim

LABEL maintainer="DevFerreiraG <devferreirag@proton.me>"
LABEL org.opencontainers.image.source="https://github.com/glferreira-devsecops/Cascavel"
LABEL org.opencontainers.image.description="Cascavel — Advanced Security Framework v3.0.0"
LABEL org.opencontainers.image.version="3.0.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="RET Tecnologia"

# System dependencies for nmap, traceroute, whois + nikto from source
# Versions pinned for reproducibility — captured from python:3.14-slim (Debian trixie)
# To update: docker run --rm python:3.14-slim bash -c "apt-get update -qq && apt-cache show <pkg> | grep ^Version"
# Note: bind9-dnsutils is intentionally unpinned — bind9-libs received a security update
# (1:9.20.23 -> 1:9.20.26) ahead of bind9-dnsutils. Pinning to 1:9.20.23 creates an
# unsatisfiable exact-version dependency on bind9-libs. Restore pin once suite versions align.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap=7.95+dfsg-3 \
        traceroute=1:2.1.6-1 \
        whois=5.6.3 \
        bind9-dnsutils \
        curl=8.14.1-2+deb13u4 \
        git=1:2.47.3-0+deb13u1 \
        perl=5.40.1-6 \
        libnet-ssleay-perl=1.94-3 \
        libpcap-dev=1.10.5-2 \
        ca-certificates=20250419 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Nikto from official source (not available in Debian Trixie repos)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Application setup
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir reportlab qrcode[pil]

# Copy application code
COPY cascavel/ ./cascavel/
COPY plugins/ ./plugins/
COPY profiles/ ./profiles/
COPY wordlists/ ./wordlists/

# Create reports directory
RUN mkdir -p /app/reports

# Update nuclei templates on build
RUN nuclei -update-templates 2>/dev/null || true

# Non-root execution (security hardening)
RUN useradd -r -s /bin/false cascavel && \
    chown -R cascavel:cascavel /app
USER cascavel

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=1 \
    CMD python3 -m cascavel --version || exit 1

ENTRYPOINT ["python3", "-m", "cascavel"]
CMD ["--help"]
