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

## Prerequisite: raise the rate limits

**The suite cannot pass at the shipped rate-limit defaults.** Every test arrives from one address
(127.0.0.1), and the throttles are per-username *and* per-IP over a 300s window:

| Setting | Default | Effect on a full run |
|---------|---------|----------------------|
| `RATE_LIMIT_LOGIN_ATTEMPTS` | `5` (IP limit is 2x = 10 / 5 min) | login 429s; most tests error at fixture setup |
| `RATE_LIMIT_VAULT_ATTEMPTS` / `_ADMIN` | `5` / `20` per 5 min | vault-open 429s across the file + vault suites |
| `RATE_LIMIT_API_DEFAULT` / `_AUTH` / `_UPLOAD` / `_DOWNLOAD` | `100` / `10` / `20` / `50` per min | the general middleware 429s almost everything |

Put these in the stack's `.env` before running (this is what a dev stack does):

```
RATE_LIMIT_LOGIN_ATTEMPTS=2000
RATE_LIMIT_VAULT_ATTEMPTS=2000
RATE_LIMIT_VAULT_ATTEMPTS_ADMIN=2000
RATE_LIMIT_API_DEFAULT=100000
RATE_LIMIT_API_AUTH=100000
RATE_LIMIT_API_UPLOAD=100000
RATE_LIMIT_API_DOWNLOAD=100000
```

Leave `RATE_LIMIT_API_ENABLED` at `true` — raising the budget keeps the middleware on the request
path, whereas disabling it stops exercising that code entirely.

Two more session-state traps worth knowing:

* **Never kill a run mid-flight.** `test_api_auth_settings.py` writes `max_login_attempts` and
  restores it in a `finally`. Interrupt it and the value stays in the database, where it
  *overrides* the env limits above for every later login — so the next run 429s from wherever
  that setting landed, and so does every run after it, because the value is persisted in the
  Postgres volume. If a run was interrupted, reset it before the next one:
  `UPDATE system_settings SET value = jsonb_set(value::jsonb,'{max_login_attempts}','0') WHERE key='global';`
* **The test venv's paramiko must match the image's.** The SFTP suite is a paramiko client
  talking to the vault's paramiko server, and the two negotiate algorithms. A paramiko 5 client
  against a paramiko 3 server fails every SFTP test with `AuthenticationException` while the
  server logs `Incompatible ssh server (no acceptable ciphers)` — a version skew, not a bug.
  `requirements-test.txt` deliberately floors paramiko at the version `requirements.txt` pins;
  bump them together.

`test_login_throttle.py` detects the raised limit and **skips itself**, by design — CI puts the
shipped defaults back and runs that file on its own so the throttle still gets covered. The ECC
key-management throttle is hardcoded, not env-driven, so `test_zk_ecc_hardening.py` is unaffected.

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
