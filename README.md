# DockVault

A self-hostable, end-to-end **encrypted file vault** — a modern web UI **and** an SFTP
server backed by one PostgreSQL + Redis. Store files in encrypted "vaults," share access
with temporary scoped credentials, and (optionally) run **zero-knowledge** vaults where the
server only ever holds ciphertext it cannot read.

Licensed under **AGPL-3.0** — self-host it freely.

## Features

- **Web UI and SFTP** over the same storage — work in the browser or with any SFTP client.
- **Per-vault encryption** (AES-256-GCM) with per-vault keys; file contents, names, and
  metadata are encrypted at rest.
- **Zero-knowledge vaults** (optional) — files are encrypted in the browser, so the server
  stores ciphertext it cannot decrypt.
- **Temporary, scoped credentials** — hand out time-limited, least-privilege access to a
  vault or path.
- **Organizational groups**, per-user storage quotas, role-based access, and an audit log.
- **Login rate-limiting** and durable session revocation.
- **Single standalone image** — needs only its bundled PostgreSQL + Redis; no external
  services required.

## Quick start — production (HTTPS)

DockVault is meant to run in **production**: HTTPS with a real (or self-signed) TLS certificate,
`ENVIRONMENT=production`, and Postgres/Redis kept off the host network. One script does the whole
setup — it writes `.env` with freshly generated secrets, provisions the TLS certificate, and starts
the HTTPS-only stack (web UI/API on port **443**, TLS terminated in-container, no plaintext
listener; optional SFTP).

**Linux** — interactive; collects your domain and TLS choice (Let's Encrypt, self-signed, or
bring-your-own certificate):

```bash
sudo ./deploy/setup-secure.sh
```

**Windows** (Docker Desktop) — self-signed by default, or point it at your own certificate:

```powershell
./deploy/setup-secure.ps1 -ServerName vault.example.com
# ...or bring your own certificate (recommended for anything public):
./deploy/setup-secure.ps1 -ServerName vault.example.com -CertMode byo -CertPath fullchain.pem -KeyPath privkey.pem
```

Both are idempotent — re-run any time to rebuild; they **reuse your existing `.env`** and keep your
data. Both start `deploy/docker-compose.secure.yml`, which you can also run directly (from the repo
root, so `--env-file` finds the root `.env`) once `./.env` and `./certs/{cert.pem,key.pem}` exist:

```bash
docker compose --env-file .env -f deploy/docker-compose.secure.yml up -d --build
```

Then open `https://<your-domain>` and complete the first-run setup wizard to create your admin
account. No license key, no activation.

> Re-running after changing `VAULT_DB_PASSWORD` (or starting fresh by removing `.env`) requires
> resetting the database volume, or Postgres keeps the old password:
> `docker compose --env-file .env -f deploy/docker-compose.secure.yml down -v` then re-run the
> script. This destroys stored data, so only do it before you have real vaults.

### Local trial only (HTTP, no TLS) — not for real use

A throwaway way to click around on your own machine. It serves the product over **plaintext HTTP**
bound to **loopback only** (`127.0.0.1:8200`) and runs in development mode, so it is **not a
supported way to hold real data** — use the production setup above for anything reachable or real.

```bash
cp .env.example .env      # then edit it: set ENCRYPTION_KEY, JWT_SECRET_KEY, VAULT_DB_PASSWORD, and
                          # a strong ADMIN_PASSWORD (boot is refused with the shipped placeholder)
docker compose up -d      # web/API on http://localhost:8200
```

## Repository layout

| Path | What lives there |
|------|------------------|
| `app/` | The Python application — `app/api/` (web/API server + the user-management/dashboard/ECC routers), `app/sftp/` (SFTP server), `app/core/` (config, models, security primitives), `app/services/` (vault/auth/domain services), `app/config/` (branding), `app/routers/` (info endpoints) |
| `deploy/` | Deployment files — `deploy/docker-compose.yml` (local trial), `deploy/docker-compose.secure.yml` + `deploy/setup-secure.sh` / `deploy/setup-secure.ps1` (production HTTPS) |
| `scripts/` | Operator utilities (`scripts/setup_master_password.py`) |
| `static/` | The self-hosted web UI (no CDN assets) |
| `tests/` | pytest + Playwright integration suite (see `tests/README.md`) |
| `run_combined.py`, `docker-entrypoint.py` | Container entrypoints, kept at the root (the image's ENTRYPOINT/CMD contract) |

The root `docker-compose.yml` is a thin `include:` shim over `deploy/docker-compose.yml`, so
`docker compose up -d` keeps working from the repository root (and existing deployments keep their
project and volume names).

## Security model

- **Encryption at rest:** each vault has its own key; contents and file/folder names are
  sealed with authenticated encryption (AES-256-GCM). Standard vaults are decrypted
  server-side per request; **zero-knowledge** vaults keep the key in the browser, so the
  server never sees plaintext.
- **Transport:** run it behind TLS — a reverse proxy, or the included HTTPS deployment
  script. SFTP uses SSH host keys.
- **Container hardening:** runs as a non-root user on a read-only root filesystem with no
  new privileges; login throttling and account lockout are built in.
- **Secrets:** all keys and passwords come from `.env`. Use fresh encryption/JWT keys per deployment.

## Production checklist

If you front the vault yourself (your own reverse proxy, k8s, `docker run`) rather than using
`deploy/setup-secure.sh`, confirm all of these — the setup script handles or prompts you for most of
them, but a README-only reader can miss them (the off-host key backup is always yours to do):

- **Back up `ENCRYPTION_KEY` off the host** (e.g. a password manager). Without it, every stored file — and any
  backup of the storage volume — is **permanently unrecoverable**.
- **Change the seeded admin password.** Boot is refused with the shipped placeholder, but pick a strong one.
- **Terminate TLS** in front of the app (or run it with `API_USE_HTTPS=true` + certs). Never expose plaintext.
- **Restrict network exposure:** publish only the web/API (and SFTP if used) ports; keep Postgres/Redis on the
  internal network. Set `REDIS_PASSWORD` and `ALLOWED_HOSTS` for defense-in-depth.
- **Use fresh `ENCRYPTION_KEY` / `JWT_SECRET_KEY` per deployment.** You can rotate `JWT_SECRET_KEY` (it just
  forces re-login) and passwords on a schedule, but **NEVER rotate `ENCRYPTION_KEY` on a vault that already
  holds data** — it makes every stored file permanently undecryptable.

## Configuration

Every setting lives in `.env`. Copy `.env.example`, which documents each key — database,
Redis, encryption/JWT secrets, SFTP, rate limits, and more. (Email/SMTP is configured in the
admin UI → Settings, not in `.env`.)

## License

[AGPL-3.0](LICENSE). If you run a modified version as a network service, you must make the
modified source available to that service's users.
