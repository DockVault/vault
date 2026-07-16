# Vault-service integration tests

End-to-end tests that run on the **host** and exercise the live container at
`http://localhost:8200` over HTTP (API) and a real browser (UI). Apart from two
pure-helper unit files (one imports `app.services.log_pull`, one imports the
`run_combined` entrypoint), nothing here imports the app — it tests the deployed
surface.

## Layout

| File | Covers |
|------|--------|
| `conftest.py` | Shared fixtures: admin login, throwaway vaults/users, `ApiClient` |
| `test_api_health.py` | `/health`, `/api`, `/`, `/setup`, static assets |
| `test_api_auth.py` | login (ok/fail), `/users/me`, logout, temp-cred login |
| `test_api_users.py` | `/users` CRUD + `/api/user-management/*` |
| `test_api_vaults.py` | vault CRUD, settings, password, sharing, key rotation |
| `test_api_files.py` | upload / list / download / rename / delete / folders |
| `test_api_tempcreds.py` | temp-cred lifecycle + **validity/expiry override** |
| `test_api_permissions.py` | permission groups, per-user grant/revoke |
| `test_api_dashboard.py` | dashboard, monitoring, security (admin) |
| `test_api_ecc.py` | `/ecc/*` crypto endpoints |
| `test_api_websocket.py` | `/ws/monitor` auth handshake |
| `test_ui_e2e.py` | Playwright: login, temp-cred validity, create vault/user, logout |

…plus further per-feature suites (branding, lockout, ZK, SFTP round-trip, infra
hardening, and more) — the table lists the core surfaces; see the file names.

## Setup (once)

```powershell
cd tests   # from the repository root
python -m venv .venv
.venv\Scripts\pip install -r requirements-test.txt
.venv\Scripts\playwright install chromium
```

## Run

Make sure the stack is up first (`docker compose up -d`), then:

```powershell
# everything
.venv\Scripts\python -m pytest

# API only (skip the browser tests)
.venv\Scripts\python -m pytest -m "not ui"

# UI only, headed (watch it click)
.venv\Scripts\python -m pytest -m ui --headed
```

## Config (env vars, all optional)

| Var | Default |
|-----|---------|
| `VAULT_BASE_URL` | `http://localhost:8200` |
| `VAULT_ADMIN_USER` / `VAULT_ADMIN_PASS` | read from `../.env` (`ADMIN_USERNAME` / `ADMIN_PASSWORD`) |

If the container isn't reachable the whole suite **skips** (it won't error).
