FROM python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92

WORKDIR /app

# Bound DNS resolution so a Redis (or DB) outage fails FAST. socket_connect_timeout does NOT
# cover getaddrinfo, so a dead/removed host can stall name resolution for ~8s per attempt —
# which made every Redis call (login throttle, security monitor, broadcasts) crawl during an
# outage. RES_OPTIONS is baked into the image (portable to every deployment), unlike a
# docker --dns-option. timeout:1 attempts:1 => ~1s fail.
ENV RES_OPTIONS="timeout:1 attempts:1"

# Install the fully resolved, hash-locked production dependencies first for layer caching.
# The healthcheck uses Python's standard library, so the runtime needs no apt packages.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip check \
    && python -m pip uninstall --yes pip

# Python 3.14.6 predates three reviewed 3.14-branch security fixes. Vendor the exact upstream
# standard-library snapshot, verify it byte-for-byte before installation, and retain its PSF
# license in the image. Grype still identifies the interpreter as 3.14.6, so release VEX records
# these code-level backports against the immutable image digest.
COPY security/cpython-backports /tmp/cpython-backports
RUN cd /tmp/cpython-backports \
    && echo "3c8d585a77d7d376aea66e5e11a4d53c2605100d4c05a71b5385ed54bc526f51  Lib/tarfile.py" | sha256sum -c - \
    && echo "5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539  Lib/html/parser.py" | sha256sum -c - \
    && echo "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231  PSF-LICENSE.txt" | sha256sum -c - \
    && cp Lib/tarfile.py /usr/local/lib/python3.14/tarfile.py \
    && cp Lib/html/parser.py /usr/local/lib/python3.14/html/parser.py \
    && mkdir -p /usr/share/licenses/cpython-backports \
    && cp PSF-LICENSE.txt /usr/share/licenses/cpython-backports/PSF-LICENSE.txt \
    && rm -rf /tmp/cpython-backports

# Copy application code
COPY . .

# Runtime data directories (config.ensure_directories() and the SFTP server also
# create these, but pre-making them keeps volume mounts clean). `brand` holds
# admin-uploaded logo/favicon assets and is backed by a writable named volume
# so uploads survive a restart even under the read-only root fs; pre-making it here
# (before the chown below) means a fresh volume mounted over it inherits appuser
# ownership, so the non-root process can write uploads into it.
RUN mkdir -p storage logs keys certs brand

# The per-customer product container handling untrusted uploads / SFTP / at-rest crypto, so
# root-in-container is the most valuable to drop. chown /app so the runtime dirs (storage/
# logs/keys/certs) are appuser-owned, and a fresh named volume mounted over them inherits it.
ENV PYTHONDONTWRITEBYTECODE=1
RUN adduser -D -u 10001 appuser && chown -R appuser:appuser /app

# NOTE: we deliberately do NOT `USER appuser`. The container starts as root so the entrypoint
# (docker-entrypoint.py) can chown persistent volumes that an OLDER, root-era image may have
# created root-owned — otherwise an in-place UPGRADE to this non-root image BRICKS the
# container (the non-root app can't read its SSH host key, and worse, the customer's
# /app/storage files). The entrypoint runs as root ONLY for that brief fixup, then DROPS to
# appuser (uid 10001) before exec'ing the command — so the workload never runs as root
# (the postgres/redis official-image pattern). SFTP needs no runtime root (paramiko
# app-level server; no OS chroot/chown; binds 2222 > 1024). Defense-in-depth is preserved:
# the actual web/SFTP processes run as appuser.

# App version. By default the image self-reports the baked VERSION file (copied by `COPY . .`
# above and read by app/config/branding.py). A CI/release build MAY override it with
# `--build-arg APP_VERSION=x.y.z`; an empty value (the default) falls back to the VERSION file.
ARG APP_VERSION=
ENV BRAND_APP_VERSION=${APP_VERSION}

# Standard OCI identity. Release builds replace the development defaults with the exact
# public source URL, semantic version, and tested commit before publication.
ARG OCI_SOURCE=https://github.com/DockVault/vault
ARG OCI_VERSION=development
ARG OCI_REVISION=unknown
LABEL org.opencontainers.image.source=${OCI_SOURCE} \
      org.opencontainers.image.version=${OCI_VERSION} \
      org.opencontainers.image.revision=${OCI_REVISION} \
      org.opencontainers.image.licenses=AGPL-3.0-only

# 8000 - FastAPI web UI / API
# 2222 - SFTP
EXPOSE 8000 2222

# Health check (stdlib only — does not depend on `requests`)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 \
    CMD python -c "import os,ssl,urllib.request; s='https' if os.getenv('API_USE_HTTPS','false').lower()=='true' else 'http'; c=ssl._create_unverified_context() if s=='https' else None; urllib.request.urlopen(s+'://localhost:8000/health', context=c, timeout=8)"

# Root-init entrypoint: fix volume ownership, then drop to appuser and exec the CMD (below)
# or any compose/worker-supplied command. Idempotent + cheap when volumes are already owned.
ENTRYPOINT ["python", "/app/docker-entrypoint.py"]

# Default: run BOTH the web/API process (8000) and the SFTP server (2222) in one
# container, so a provisioned single-vault deployment exposes SFTP without needing a
# second container or a shared-volume bundle. run_combined.py supervises both and exits
# if either dies, so the container's restart policy recreates the whole thing.
# The dev stack and the bundle composer override this with an explicit
# `command: ["python", "-m", "app.api.api_server"]` / `["python", "-m", "app.sftp.sftp_server"]`.
CMD ["python", "run_combined.py"]
