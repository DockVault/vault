# DockVault Vault

A self-hostable, encrypted file vault — a web UI **and** an SFTP server over one Postgres +
Redis, with per-vault encryption, an optional **zero-knowledge** mode (the server stores
ciphertext it cannot read), temporary scoped credentials, and organizational groups.

Licensed under **AGPL-3.0** — you can self-host it for free; a network service built on a
modified version must publish its source.

## Quick start

```bash
cp .env.example .env      # then edit the secrets in .env
docker compose up -d      # web/API on :8200 (host), SFTP on :2322 (host)
```

Open <http://localhost:8200> and complete the first-run setup wizard (create the admin
account). No product key is required — the build is unrestricted.

The image is standalone: it needs only its bundled Postgres + Redis (started by the compose
file) and has no dependency on any external control plane.

## Branding & customization

The vault ships **DockVault-branded** by default (name, logo, favicon, theme colors). Every
brand value is configurable, so an operator can put their own brand on an instance:

- **At deploy** — set `BRAND_*` env vars (see the `.env.example` branding block), e.g.
  `BRAND_APP_NAME`, `BRAND_PRIMARY_COLOR`, `BRAND_SUPPORT_EMAIL`.
- **At runtime** — the admin **Settings → Branding** tab edits the name, tagline, company,
  support email, key URLs, and the 8 theme colors live (no restart), and uploads a logo +
  favicon. These override the env defaults.

A small **"powered by DockVault"** attribution shows on the login page. It is intentionally
not part of the editable brand set; a deployment can hide it with `BRAND_SHOW_POWERED_BY=false`.

The public `GET /branding` endpoint returns the effective brand the UI renders from.

## Configuration

All settings live in `.env` (copy from `.env.example`, which documents every key). Key groups:
database (`DATABASE_URL`), cache (`REDIS_HOST`), crypto/secret keys, SFTP, rate limits, and the
`BRAND_*` branding block.

## Development & tests

Source is baked into the image, so after editing app code rebuild:
`docker compose build vault-api && docker compose up -d vault-api`. The integration test suite
(pytest + Playwright, run on the host against the live container) lives in `tests/` — see
`tests/README.md`.

## License

AGPL-3.0 — see `LICENSE`.
