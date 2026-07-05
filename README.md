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
- **2FA (TOTP)**, login rate-limiting, and durable session revocation.
- **Single standalone image** — needs only its bundled PostgreSQL + Redis; no external
  services required.

## Quick start — production (HTTPS)

On a Linux host with Docker, one script sets up everything for production:

```bash
sudo ./setup-secure.sh
```

It is interactive and idempotent: it collects your domain and TLS choice (Let's Encrypt,
self-signed, or bring-your-own certificate), writes `.env` with freshly generated secrets,
provisions the certificates, and starts the HTTPS-only stack — the web UI/API on port **443**
(TLS terminated in-container, no plaintext listener) plus optional SFTP. Re-run it any time to
rebuild; it **reuses your existing `.env`** and keeps your data.

Then open `https://<your-domain>` and complete the first-run setup wizard to create your admin
account. No license key, no activation.

> Re-running after changing `VAULT_DB_PASSWORD` (or starting fresh by removing `.env`) requires
> resetting the database volume, or Postgres keeps the old password:
> `docker compose -f docker-compose.secure.yml down -v` then re-run the script. This destroys
> stored data, so only do it before you have real vaults.

### Local trial (HTTP, no TLS)

For a quick test on your machine without certificates:

```bash
cp .env.example .env      # fill in the secrets
docker compose up -d      # web/API on http://localhost:8200
```

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

## Configuration

Every setting lives in `.env`. Copy `.env.example`, which documents each key — database,
Redis, encryption/JWT secrets, SFTP, rate limits, SMTP, and more.

## License

[AGPL-3.0](LICENSE). If you run a modified version as a network service, you must make the
modified source available to that service's users.
