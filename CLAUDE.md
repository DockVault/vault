# CLAUDE.md — DockVault vault working instructions

This repo is the DockVault vault service: a self-hostable encrypted file vault
(FastAPI web/API on 8000 + SFTP on 2222, single image, `run_combined.py` runs both).
Deploy paths: the host-side management tool `dockvault.py` lives at the repo ROOT (stdlib-only,
needs host `python3`; menu: Setup / Backup & Restore / Volumes / Storage limit / Reset / Update / Logs) and drives
`deploy/docker-compose.secure.yml` (production HTTPS). The `setup-secure.sh` / `setup-secure.ps1`
scripts are retired thin shims that exec `dockvault.py setup`. Root `docker-compose.yml` +
`docker-compose.secure.yml` are thin `include:` shims over the real files in `deploy/` so
`docker compose [-f docker-compose.secure.yml] up` works from the root and auto-loads root `.env`. The image is also consumed downstream as a
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
- **No AI attribution in commits (owner, 2026-07-04).** Never add
  `Co-Authored-By: Claude`, "Generated with Claude Code", or any Claude/AI
  co-author or generated-by trailer to commit messages or PR bodies.
- `BRAND_*` env vars (see `app/config/branding.py`) are a public contract consumed
  by downstream provisioning — don't rename or remove them without a deprecation path.
- **⛔ Do NOT bump Postgres past the 15 major** (`deploy/docker-compose.yml` +
  `deploy/docker-compose.secure.yml`). This was tried on 2026-08-07 and broke CI's
  real-Docker job: the 18+ images moved the data layout to a single mount at
  `/var/lib/postgresql` (major-version subdirectory inside) instead of
  `/var/lib/postgresql/data`, so the container refuses to start. Independently, every
  existing `vault_pg_data` volume holds 15 data files that a newer server cannot read
  without `pg_upgrade` — a tag-only bump ships a dead database to every self-hoster who
  runs `dockvault.py update`. It is not a security fix either: 15-alpine's only findings
  are 3 Mediums from one unfixable BusyBox CVE in the Alpine base, and 18-alpine carries
  those *plus* two more. 15 is supported to Nov 2027. Dependabot now ignores postgres
  semver-majors (`.github/dependabot.yml`). Lift this only as a deliberate migration that
  moves the mount AND gives `dockvault.py` a real `pg_upgrade` path.
  Redis majors are fine — its `/data` is tmpfs (ephemeral cache), so there is no migration.
- **Changing a pinned action SHA or image digest? Update the contract tests in the same
  change.** `tests/test_supply_chain_contract.py` hardcodes an allowlist of reviewed
  action pins and the python/postgres/redis digests, and
  `tests/test_setup_workflow_contract.py` pins the checkout SHA. CI runs
  `pytest --maxfail=1`, so it reveals only ONE stale pin per run — grep for the old value
  across `tests/` and fix them all at once. Verify locally before pushing with
  `python -m pytest -m "unit and not docker" -q` (no `--maxfail`).
- **Keep config, `.env.example`, and the management tool in sync.** When you add or change an
  env/config field in `app/core/config.py`, update `.env.example` **and** `dockvault.py` (the setup
  flow / any menu that writes it) in the SAME change — a new flag with no `.env.example` entry or
  setup prompt is an incomplete change.
- **A schema change declares itself.** When you change `app/core/models.py` or the boot DDL list in
  `app/api/api_server.py`, add the matching entry to `docs/upgrade-matrix.json` in the SAME change:
  whether the hop is reversible, whether it needs a backup, and any condition an operator should
  know about. The release gate refuses to cut a tag whose version is undeclared, so this is not
  optional — but discovering it at release time means writing the description weeks after making
  the change, from memory.
- **Adding a column to an existing table takes two statements, not one.** `create_all` only ever
  creates missing TABLES, so a new column reaches an existing deployment through the DDL list. An
  `ADD COLUMN` that omits a constraint the model declares leaves fresh and upgraded installs with
  different physical schemas: `ADD COLUMN IF NOT EXISTS` is a no-op where the column already
  exists, so tightening it there needs its own `ALTER COLUMN ... SET NOT NULL`, preceded by a
  backfill for the rows written before the column existed. Two columns diverged this way for
  several releases before anything compared the two shapes.

## Tests

`tests/` is a pytest + Playwright integration suite run against a live instance
(skips cleanly if none is up). See `tests/README.md`. Quick start:

```
python -m venv tests/.venv
tests/.venv/Scripts/python -m pip install -r tests/requirements-test.lock
tests/.venv/Scripts/python -m pip check
tests/.venv/Scripts/python -m pytest              # API tests (needs the vault running)
tests/.venv/Scripts/python -m pytest -m "not ui"  # skip browser tests
```
