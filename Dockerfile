FROM python:3.11-slim

WORKDIR /app

# Bound DNS resolution so a Redis (or DB) outage fails FAST. socket_connect_timeout does NOT
# cover getaddrinfo, so a dead/removed host can stall name resolution for ~8s per attempt —
# which made every Redis call (login throttle, security monitor, broadcasts) crawl during an
# outage. RES_OPTIONS is honoured by the glibc resolver and is baked into the image (portable
# to every deployment), unlike a docker --dns-option. timeout:1 attempts:1 => ~1s fail.
ENV RES_OPTIONS="timeout:1 attempts:1"

# All Python deps ship manylinux wheels for cp311, so no compiler/apt build
# packages are needed. curl is only here for the container HEALTHCHECK fallback.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Runtime data directories (config.ensure_directories() and the SFTP server also
# create these, but pre-making them keeps volume mounts clean). `brand` holds
# admin-uploaded logo/favicon assets (A4) and is backed by a writable named volume
# so uploads survive a restart even under the read-only root fs; pre-making it here
# (before the chown below) means a fresh volume mounted over it inherits appuser
# ownership, so the non-root process can write uploads into it.
RUN mkdir -p storage logs keys certs brand

# Run as a non-root user (defense-in-depth). This is the per-customer product
# container handling untrusted uploads / SFTP / at-rest crypto, so root-in-container
# is the most valuable to drop. chown /app so the runtime dirs (storage/logs/keys/
# certs) stay writable, and a fresh named volume mounted over them inherits this
# ownership. SFTP binds 2222 (>1024), so no privileged bind is needed.
ENV PYTHONDONTWRITEBYTECODE=1
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

# 8000 - FastAPI web UI / API
# 2222 - SFTP
EXPOSE 8000 2222

# Health check (stdlib only — does not depend on `requests`)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Default: run BOTH the web/API process (8000) and the SFTP server (2222) in one
# container, so a provisioned single-vault deployment exposes SFTP without needing a
# second container or a shared-volume bundle. run_combined.py supervises both and exits
# if either dies, so the container's restart policy recreates the whole thing.
# The dev stack and the bundle composer override this with an explicit
# `command: ["python", "api_server.py"]` / `["python", "sftp_server.py"]`.
CMD ["python", "run_combined.py"]
