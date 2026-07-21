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
the HTTPS-only stack (web UI/API on port **443** by default, TLS terminated in-container, no
plaintext listener; optional SFTP). The published host ports are configurable in `.env` —
`WEB_HOST_PORT` (default 443) and `SFTP_HOST_PORT` (default 2322); the container ports stay
8000/2222. The setup tooling checks a port is free before using it.

The two setup scripts live at the repo **root** — run either from there.

**Linux** — interactive; collects your domain and TLS choice (Let's Encrypt, self-signed, or
bring-your-own certificate):

```bash
sudo ./setup-secure.sh
```

**Windows** (Docker Desktop) — self-signed by default, or point it at your own certificate:

```powershell
./setup-secure.ps1 -ServerName vault.example.com
# ...or bring your own certificate (recommended for anything public):
./setup-secure.ps1 -ServerName vault.example.com -CertMode byo -CertPath fullchain.pem -KeyPath privkey.pem
```

Both are idempotent — re-run any time to rebuild; they **reuse your existing `.env`** and keep your
data.

The setup script creates the first admin account from the `ADMIN_USERNAME` / `ADMIN_PASSWORD` it
writes to `.env` (the Windows script prints a generated password once; the Linux script prompts you
for one). Then open `https://<your-domain>` and log in with those credentials — change the password
from Settings after the first login. No license key, no activation.

### Production without the script (advanced)

If you'd rather manage `.env` and TLS yourself, provide `./.env` (start from `.env.example`) and
`./certs/{cert.pem,key.pem}`, then start the production stack straight from the repo root:

```bash
cp .env.example .env      # then edit it: set ENCRYPTION_KEY, JWT_SECRET_KEY, VAULT_DB_PASSWORD,
                          # and a strong ADMIN_PASSWORD (boot is refused with the shipped placeholder)
# ...put your TLS cert + key at ./certs/cert.pem and ./certs/key.pem...
docker compose -f docker-compose.secure.yml up -d --build
```

> **`.env` is found automatically — never move it.** The root `docker-compose.secure.yml` (and the
> `docker-compose.yml` below) are thin `include:` shims over the real files in `deploy/`. Running
> `docker compose` against a **root** file makes the repo root the Compose project directory, so
> `./.env` loads on its own — no `--env-file`, and you never copy `.env` into `deploy/`.

> Re-running after changing `VAULT_DB_PASSWORD` (or starting fresh by removing `.env`) requires
> resetting the database volume, or Postgres keeps the old password:
> `docker compose -f docker-compose.secure.yml down -v` then re-run the setup script. This destroys
> stored data, so only do it before you have real vaults.

### Local trial only (HTTP, no TLS) — not for real use

A throwaway way to click around on your own machine. It serves the product over **plaintext HTTP**
bound to **loopback only** (`127.0.0.1:8200`) and runs in development mode, so it is **not a
supported way to hold real data** — use the production setup above for anything reachable or real.

```bash
cp .env.example .env      # edit the same secrets as above
docker compose up -d      # root dev shim; ./.env auto-loads; web/API on http://localhost:8200
```

## Deployment modes: combined vs split

For the **production (HTTPS)** stack, `COMPOSE_PROFILES` in `.env` chooses how the web app and SFTP
run. `./setup-secure.sh` writes it (default **combined**) and `.env.example` ships it.

- **`combined` (default, recommended):** a **single container** runs both the web/API and — when
  `RUN_SFTP=1` — the SFTP server, supervised by `run_combined.py`. Simplest to operate: one
  container, one shared storage/keys volume, one restart policy. SFTP is **opt-in** (`RUN_SFTP=1`),
  so a base install is web-only.
- **`split`:** the web app and SFTP run as **two containers** (`vault-api` + `vault-sftp`) over the
  same volumes. Choose this if you want to scale, restart, or resource-limit them independently, or
  run SFTP on a different host.

Switching between the two never moves or loses data — both mount the same named volumes. Set
`COMPOSE_PROFILES=split` in `.env` (and re-run `./setup-secure.sh`, or recreate the stack) to switch.

**Know the trade-offs of combined mode:**

- The container **healthcheck only probes the web app** (`/health`). An SFTP-only *hang* isn't caught
  by the healthcheck — though `run_combined.py` still exits (and the restart policy recreates the
  container) if **either** process dies.
- Web and SFTP **share one restart policy and resource limit** — an SFTP crash restarts the whole
  container (dropping active web sessions), and you can't size them separately. Both log to one
  stream (each line tagged `[web]` / `[sftp]`).
- **`split` mode** buys independent scaling / restart / blast-radius / resource limits, at the cost
  of two containers that **must share** the storage + keys volume.

The **local HTTP trial** (`docker compose up`) always runs the simple two-container dev stack; the
combined/split choice applies to the production `docker compose.secure.yml` stack.

## Update notifications (opt-in)

DockVault can tell an admin when a newer release is available. It is **off by default**; set
`UPDATE_CHECK_ENABLED=true` in `.env` to turn it on. The running container then checks GitHub at
most **once a day** and shows a dismissible banner in **Settings → General** when a newer version
exists (see [Upgrading](#upgrading) for how to apply it).

The check is privacy-preserving: it sends **no** identifier, account data, version, or telemetry —
just an unauthenticated request to GitHub's public release API (the only thing GitHub sees is your
server's egress IP, as with any outbound request), and it **fails silently**, so an air-gapped or
firewalled install is never affected. Leave it off for offline deployments.

## Upgrading

Upgrading means replacing the container with a newer image — your data lives in named volumes and is
untouched. The entrypoint automatically fixes volume ownership on the way up, so upgrading from an
older (root-era) image "just works".

**From source** (works today, no prebuilt image needed):

```bash
git pull
docker compose -f docker-compose.secure.yml up -d --build   # or `docker compose up -d --build` for the local trial
```

**From a prebuilt image** (once a release is published to GHCR) — set `DOCKVAULT_IMAGE` in `.env` to
the release tag, then pull + restart with no local build:

```bash
# in .env:  DOCKVAULT_IMAGE=ghcr.io/dockvault/vault:v0.6.0
docker compose -f docker-compose.secure.yml pull
docker compose -f docker-compose.secure.yml up -d
```

Either way, re-running `./setup-secure.sh` also upgrades (it rebuilds, recreates the containers, and
keeps your `.env` and data). The `build:` path stays in the compose files, so you can always build
your own (modified) image — which the AGPL license requires you be able to do.

> **Database migrations:** the app creates any missing tables on boot but does **not** yet alter
> existing columns automatically. A release that changes the schema will call out the migration step
> in its notes — read the release notes before upgrading across a schema change, and back up the
> database volume first.

## Repository layout

| Path | What lives there |
|------|------------------|
| `app/` | The Python application — `app/api/` (web/API server + the user-management/dashboard/ECC routers), `app/sftp/` (SFTP server), `app/core/` (config, models, security primitives), `app/services/` (vault/auth/domain services), `app/config/` (branding), `app/routers/` (info endpoints) |
| `setup-secure.sh`, `setup-secure.ps1` | Production setup scripts (Linux / Windows) — run from the repo root |
| `.env.example` | Config template — copy to `.env` and fill in (documents every key) |
| `deploy/` | The real Compose stacks — `deploy/docker-compose.yml` (local trial), `deploy/docker-compose.secure.yml` (production HTTPS) |
| `scripts/` | Operator utilities (`scripts/setup_master_password.py`) |
| `static/` | The self-hosted web UI (no CDN assets) |
| `tests/` | pytest + Playwright integration suite (see `tests/README.md`) |
| `run_combined.py`, `docker-entrypoint.py` | Container entrypoints, kept at the root (the image's ENTRYPOINT/CMD contract) |

The root `docker-compose.yml` and `docker-compose.secure.yml` are thin `include:` shims over the
matching files in `deploy/`, so `docker compose [-f docker-compose.secure.yml] up -d` works from the
repository root and auto-loads the root `.env` (existing deployments keep their project and volume
names). The three files a self-hoster touches — the two `setup-secure.*` scripts and `.env.example` —
all live at the root.

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
`./setup-secure.sh`, confirm all of these — the setup script handles or prompts you for most of
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
