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
`ENVIRONMENT=production`, and Postgres/Redis kept off the host network. One tool does the whole
setup — it writes `.env` with freshly generated secrets, provisions the TLS certificate, and starts
the HTTPS-only stack (web UI/API on port **443** by default, TLS terminated in-container, no
plaintext listener; optional SFTP). The published host ports are configurable in `.env` —
`WEB_HOST_PORT` (default 443) and `SFTP_HOST_PORT` (default 2322); the container ports stay
8000/2222. Setup checks a port is free before using it.

Everything is driven by **`dockvault.py`** — an interactive management tool at the repo root
(stdlib-only; needs **Python 3** on the host). Run it with no arguments for the full menu (Setup,
Backup & Restore, Volumes, Reset, Update, Logs), or go straight to setup:

**Linux** — interactive; collects your domain and TLS choice (Let's Encrypt, self-signed, or
bring-your-own certificate):

```bash
sudo python3 dockvault.py setup
```

**Windows** (Docker Desktop):

```powershell
python dockvault.py setup
# ...bring your own certificate (recommended for anything public):
python dockvault.py setup --server-name vault.example.com --cert-mode byo --cert-path fullchain.pem --key-path privkey.pem
```

Setup is idempotent — re-run any time to rebuild; it **reuses your existing `.env`** and keeps your
data. (The old `./setup-secure.sh` / `./setup-secure.ps1` scripts still work — they are now thin
shims that launch `dockvault.py setup`.)

Setup creates the first admin account from the `ADMIN_USERNAME` / `ADMIN_PASSWORD` it writes to
`.env` (a blank password auto-generates a strong one, printed once). Then open
`https://<your-domain>` and log in with those credentials — change the password from Settings after
the first login. No license key, no activation.

### Production without the script (advanced)

If you'd rather manage `.env` and TLS yourself, provide `./.env` (start from `.env.example`) and
`./certs/{cert.pem,key.pem}`, then start the production stack straight from the repo root:

```bash
cp .env.example .env      # then edit it: set ENCRYPTION_KEY, JWT_SECRET_KEY, VAULT_DB_PASSWORD,
                          # and a strong ADMIN_PASSWORD (boot is refused with the shipped placeholder)
# ...put your TLS cert + key at ./certs/cert.pem and ./certs/key.pem...
docker compose -f docker-compose.secure.yml up -d --build
```

> **The TLS key must be readable by the container's app user (uid `10001`).** `/app/certs` is a
> read-only bind mount of `./certs`, and the app runs unprivileged — a key that is mode `600` owned
> by `root` makes uvicorn exit with `PermissionError: [Errno 13]` in a restart loop. Check and fix
> it from inside a container (this also works on Docker Desktop, where a host `chown` cannot):
>
> ```bash
> docker run --rm --user 10001:10001 -v "$PWD/certs:/certs:ro" busybox head -c1 /certs/key.pem >/dev/null && echo readable
> docker run --rm -v "$PWD/certs:/certs" busybox sh -c 'chown 10001:10001 /certs/*.pem && chmod 600 /certs/key.pem && chmod 644 /certs/cert.pem'
> ```
>
> `dockvault.py setup` does this for you and refuses to start if the key is still unreadable.

> **`.env` is found automatically — never move it.** The root `docker-compose.secure.yml` (and the
> `docker-compose.yml` below) are thin `include:` shims over the real files in `deploy/`. Running
> `docker compose` against a **root** file makes the repo root the Compose project directory, so
> `./.env` loads on its own — no `--env-file`, and you never copy `.env` into `deploy/`.

> Re-running after changing `VAULT_DB_PASSWORD` (or starting fresh by removing `.env`) requires
> resetting the database volume, or Postgres keeps the old password:
> `docker compose -f docker-compose.secure.yml down -v` then re-run `dockvault.py setup` (or use its
> Reset menu). This destroys stored data, so only do it before you have real vaults.

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
run. `dockvault.py setup` writes it (default **combined**) and `.env.example` ships it.

- **`combined` (default, recommended):** a **single container** runs both the web/API and — when
  `RUN_SFTP=1` — the SFTP server, supervised by `run_combined.py`. Simplest to operate: one
  container, one shared storage/keys volume, one restart policy. SFTP is **opt-in** (`RUN_SFTP=1`),
  so a base install is web-only.
- **`split`:** the web app and SFTP run as **two containers** (`vault-api` + `vault-sftp`) over the
  same volumes. Choose this if you want to scale, restart, or resource-limit them independently, or
  run SFTP on a different host.

Switching between the two never moves or loses data — both mount the same named volumes. Set
`COMPOSE_PROFILES=split` in `.env` (and re-run `dockvault.py setup`, or recreate the stack) to switch.

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
`UPDATE_CHECK_ENABLED=true` in `.env` to turn it on. The running container then checks GitHub on a
configurable interval (`UPDATE_CHECK_INTERVAL_MINUTES`, default 360) — or on demand via a **Check for
updates** button — and shows a dismissible banner in **Settings → General** to every admin when a
newer version exists (see [Upgrading](#upgrading) for how to apply it).

The check is privacy-preserving: it sends **no** identifier, account data, version, or telemetry —
just an unauthenticated request to GitHub's public release API (the only thing GitHub sees is your
server's egress IP, as with any outbound request), and it **fails silently**, so an air-gapped or
firewalled install is never affected. Leave it off for offline deployments.

## Upgrading

Upgrading means replacing the container with a newer image — your data lives in named volumes and is
untouched. The entrypoint automatically fixes volume ownership on the way up, so upgrading from an
older (root-era) image "just works".

**The guided way** — `dockvault.py`'s **Update** menu lists the published releases newest-first,
marks the one you're on, and lets you pick a version to **upgrade or downgrade** to. It sets
`DOCKVAULT_IMAGE` (or, with `--source`, does a `git checkout` + build), recreates, and waits for
health. Because the database has no down-migrations, it **warns before any version change** and
recommends a Backup first (Backup & Restore menu). The manual steps below do the same thing by hand:

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

Either way, re-running `dockvault.py setup` also upgrades (it rebuilds, recreates the containers, and
keeps your `.env` and data). The `build:` path stays in the compose files, so you can always build
your own (modified) image — which the AGPL license requires you be able to do.

> **Database migrations:** the app creates any missing tables on boot but does **not** yet alter
> existing columns automatically. A release that changes the schema will call out the migration step
> in its notes — read the release notes before upgrading across a schema change, and back up the
> database volume first.

## Data volumes

A deployment keeps its data in five named volumes — `vault_pg_data` (database), `vault_storage`
(files), `vault_keys` (per-vault key material), `vault_logs`, and `vault_brand`. These volumes **and
the `.env` that holds their secrets** are one atomic set: `.env` carries `ENCRYPTION_KEY` (which the
stored files are encrypted under) and `VAULT_DB_PASSWORD` (which is baked into `vault_pg_data` on
first init), so a fresh `.env` against existing volumes fails to start — keep them together, and back
them up together.

The compose files label every volume so tooling can find a deployment's set at a glance:

| Label | Value |
|-------|-------|
| `com.dockvault.managed` | `true` on every DockVault volume |
| `com.dockvault.role` | `pg` / `storage` / `keys` / `logs` / `brand` |
| `com.dockvault.bundle` | the deployment's `DEPLOYMENT_ID` (or `default` when unset) |

List a host's managed volumes with
`docker volume ls --filter label=com.dockvault.managed=true`. Labels are applied when a volume is
first created, so a deployment made before this release keeps its (unlabelled) volumes and is treated
as the `default` bundle — no data is moved.

The volume **names** carry a `VAULT_VOLUME_PREFIX` (default `dockvault-vault`, which reproduces the
historical names). Changing the prefix points the stack at a **different set of volumes**, so several
sets can sit side by side on one host — each paired with its own `.env` (which holds that set's
secrets). Don't edit the prefix by hand; the management tool's **Volumes** menu manages sets safely:

- **Reuse** — keep the current set (the default).
- **Create new** — author a fresh set (new volume names) *and* a fresh paired `.env`, born together;
  your current set is kept, its `.env` saved aside.
- **Repoint** — point the deployment at another set; you must supply that set's matching `.env`, and
  the tool verifies it against the set's data (the same secret check as on start) before switching.

The **Reset** menu tears the current set down with `docker compose down -v` (a strong, typed
confirmation — this destroys the data) and moves the `.env` aside so a later setup starts fresh.

### Backup & restore

The **Backup & Restore** menu treats a set as one atomic bundle. **Backup** writes a timestamped
directory containing a `tar.gz` of each data volume (`vault_pg_data`, `vault_storage`, `vault_keys`,
and `vault_brand` if present), a copy of the paired **`.env`**, and a `manifest.json`. The manifest
holds **no secret** — only a salted one-way fingerprint that lets restore confirm the `.env` in the
bundle really is the one those volumes were created with. **Restore** verifies that fingerprint,
recreates the volumes, and installs the paired `.env`; it refuses a bundle whose `.env` doesn't match
its volumes, and won't overwrite existing volumes unless you pass `--force`.

> **The `env` file in a backup holds `ENCRYPTION_KEY`.** Treat the whole bundle as a secret — store it
> off-host, encrypted or access-controlled. Anyone with the bundle can read the vault's data.

## Repository layout

| Path | What lives there |
|------|------------------|
| `app/` | The Python application — `app/api/` (web/API server + the user-management/dashboard/ECC routers), `app/sftp/` (SFTP server), `app/core/` (config, models, security primitives), `app/services/` (vault/auth/domain services), `app/config/` (branding), `app/routers/` (info endpoints) |
| `dockvault.py` | The management tool (Setup / Backup & Restore / Volumes / Reset / Update / Logs) — run from the repo root |
| `setup-secure.sh`, `setup-secure.ps1` | Retired shims that launch `dockvault.py setup` (kept for compatibility) |
| `.env.example` | Config template — copy to `.env` and fill in (documents every key) |
| `deploy/` | The real Compose stacks — `deploy/docker-compose.yml` (local trial), `deploy/docker-compose.secure.yml` (production HTTPS) |
| `scripts/` | Operator utilities (`scripts/setup_master_password.py`) |
| `static/` | The self-hosted web UI (no CDN assets) |
| `tests/` | pytest offline + deployed integration suite (see `tests/README.md`) |
| `run_combined.py`, `docker-entrypoint.py` | Container entrypoints, kept at the root (the image's ENTRYPOINT/CMD contract) |

The root `docker-compose.yml` and `docker-compose.secure.yml` are thin `include:` shims over the
matching files in `deploy/`, so `docker compose [-f docker-compose.secure.yml] up -d` works from the
repository root and auto-loads the root `.env` (existing deployments keep their project and volume
names). The files a self-hoster touches — `dockvault.py` and `.env.example` —
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
`dockvault.py setup`, confirm all of these — the tool handles or prompts you for most of
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
