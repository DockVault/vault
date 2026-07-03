# CLAUDE.md — DockVault vault working instructions

This repo is the DockVault vault service: a self-hostable encrypted file vault
(FastAPI web/API on 8000 + SFTP on 2222, single image, `run_combined.py` runs both).
Deploy paths: `setup-secure.sh` + `docker-compose.secure.yml` (production HTTPS),
`docker-compose.yml` (local trial). The image is also consumed downstream as a
per-customer container, so **treat `main` as production**: everything tracked here
ships inside the built image (`Dockerfile` does `COPY . .`, filtered only by
`.dockerignore`).

## Rules

- **If the current branch is not `main`: commit AND push your completed work**
  (branch to `origin`) before ending the session. Never leave finished work
  uncommitted or local-only. Direct pushes to `main` require explicit owner approval.
- Don't add dev/one-off scripts to the repo root — they end up in every shipped
  image. Ad-hoc verification scripts don't belong in git; the permanent pytest
  suite under `tests/` is the only test surface.
- Never commit secrets: no hardcoded passwords/tokens anywhere, including test
  fallback defaults (`os.environ.get("X", "realpassword")` is a leak). `.env` stays
  untracked; `.env.example` is the only template.
- All web assets are self-hosted under `static/` — no CDN references
  (`tests/test_static_selfhosted_assets.py` guards this).
- `BRAND_*` env vars (see `app/config/branding.py`) are a public contract consumed
  by downstream provisioning — don't rename or remove them without a deprecation path.

## Tests

`tests/` is a pytest + Playwright integration suite run against a live instance
(skips cleanly if none is up). See `tests/README.md`. Quick start:

```
cd tests && python -m venv .venv && .venv/Scripts/pip install -r requirements-test.txt
.venv/Scripts/python -m pytest              # API tests (needs the vault running)
.venv/Scripts/python -m pytest -m "not ui"  # skip browser tests
```
