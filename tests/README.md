# Vault-service test suite

Tests are split by execution environment. The offline fast lane runs pure policy, helper, static,
and management-tool tests without a DockVault deployment. Integration tests exercise a healthy
stack over HTTP, WebSocket, SFTP, or a real browser. Tests that create isolated Docker resources
carry an additional `docker` marker.

## Test taxonomy

| Marker | Contract |
|--------|----------|
| `unit` | Does not require a running DockVault deployment |
| `integration` | Requires a healthy deployed stack (the default for otherwise-unclassified tests) |
| `docker` | Creates throwaway Docker containers or volumes; excluded from the offline fast lane |
| `ui` | Uses Playwright and Chromium against the deployed web UI |
| `websocket` | Opens the deployed `/ws/monitor` WebSocket |
| `sftp` | Connects to the deployed SFTP service |

Every collected test receives exactly one of `unit` or `integration`. Strict marker and config
validation are enabled from the repository-root `pytest.ini`.

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
# from the repository root
python -m venv tests/.venv
tests\.venv\Scripts\python -m pip install -r tests/requirements-test.lock
tests\.venv\Scripts\python -m pip check
tests\.venv\Scripts\playwright install chromium
```

The test lock includes the cross-platform application imports required by host-side tests.
Linux preflight and full-suite CI additionally install the hash-locked production environment;
the Fast workflow uses only the test lock so the same lane works on Linux and Windows.

## Prerequisite: raise the rate limits

**The suite cannot pass at the shipped rate-limit defaults.** Every test arrives from one address
(127.0.0.1), and the throttles are per-username *and* per-IP over a 300s window:

| Setting | Default | Effect on a full run |
|---------|---------|----------------------|
| `RATE_LIMIT_LOGIN_ATTEMPTS` | `5` (IP limit is 2x = 10 / 5 min) | login 429s; most tests error at fixture setup |
| `RATE_LIMIT_VAULT_ATTEMPTS` / `_ADMIN` | `5` / `20` per 5 min | vault-open 429s across the file + vault suites |
| `RATE_LIMIT_API_DEFAULT` / `_AUTH` / `_UPLOAD` / `_DOWNLOAD` | `100` / `10` / `20` / `50` per min | the general middleware 429s almost everything |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | the admin logs in ONCE (session fixture) and the run takes ~35 min, so the token expires ~two thirds through and everything after it 401s |

Put these in the stack's `.env` before running (this is what a dev stack does):

```
RATE_LIMIT_LOGIN_ATTEMPTS=2000
RATE_LIMIT_VAULT_ATTEMPTS=2000
RATE_LIMIT_VAULT_ATTEMPTS_ADMIN=2000
RATE_LIMIT_API_DEFAULT=100000
RATE_LIMIT_API_AUTH=100000
RATE_LIMIT_API_UPLOAD=100000
RATE_LIMIT_API_DOWNLOAD=100000
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=240
```

### The env values are a fallback the stored settings can override

`_global_setting()` prefers a *positive* value stored in the admin settings blob over the env var;
a stored `0` means "use the env value". Leave those settings unset and the env block above is what
is in force — the Settings page renders such fields blank and saves `0`, so the browser tests that
click **Save All Changes** (`test_ui_branding.py` and friends) leave the limits alone.

If you *do* store a limit — by hand, or by typing one into Settings — it wins over the env for
every later run, because it lives in the Postgres volume. To hand the deployment back to its env:

```
curl -X PUT http://localhost:8200/settings -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"max_login_attempts": 0, "session_timeout": 0, "lockout_duration": 0}'
```

Also check `ADMIN_EMAIL`: pydantic's `EmailStr` rejects special-use TLDs, so an address at
`.local`, `.invalid`, `.test` or `.example` makes every endpoint that validates the admin's own
email return 422 (`test_api_self_account.py` is the one that notices). Deliverability is not
checked, so the domain need not resolve — it just must not be reserved.

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
  The test and production inputs pin Paramiko to the same exact version, and the supply-chain
  contract rejects lock drift. Update both inputs and regenerate both locks together.

`test_login_throttle.py` detects the raised limit and **skips itself**, by design — CI puts the
shipped defaults back and runs that file on its own so the throttle still gets covered. The ECC
key-management throttle is hardcoded, not env-driven, so `test_zk_ecc_hardening.py` is unaffected.

## Run

Run the offline lane from the repository root. It does not probe localhost and does not need
Docker:

```powershell
tests\.venv\Scripts\python -m pytest -m "unit and not docker" --maxfail=1
```

For integration tests, start the stack first (`docker compose up -d`) and install Chromium, then:

```powershell
# everything, including UI and SFTP
tests\.venv\Scripts\python -m pytest

# deployed API tests only
tests\.venv\Scripts\python -m pytest -m "integration and not ui and not sftp"

# UI only, headed (watch it click)
tests\.venv\Scripts\python -m pytest -m ui --headed
```

The real-Docker management-tool tests are opt-in locally:

```powershell
tests\.venv\Scripts\python -m pytest -m docker
```

## How CI runs the suite

CI runs every collected test once, split into lanes. Each lane writes a JUnit report.

| Lane | Where | What it runs |
|------|-------|--------------|
| Offline | `preflight.yml`, on Linux with the production lock | `-m "unit and not docker"`, stopping at the first failure |
| Fast | `fast-tests.yml`, on Linux and on Windows with the test lock only | the same expression |
| Shards | `tests.yml`, job `integration`: six jobs, each on a stack of its own | `-m "not (unit and not docker)"`, which is everything the offline lane leaves out; a shard stops after 25 failures and does not stop the others |
| Scenarios | `tests.yml`, job `scenarios` | the few files that need a reconfigured stack, a second time |
| Report | `tests.yml`, job `suite-report` | no tests: it joins the reports and checks them |

A test marked `docker` runs in a shard whatever else it is marked, since the offline lane leaves it
out. The offline tests are not run again in the shards.

**Which shard a file runs in.** `.github/suite-shards.json` records how many seconds the stack
tests of each test file took in one full run. `.github/scripts/suite_shards.py` deals the listed
files out, heaviest first, each to the shard that is lightest so far. A file it does not list (a
new file, or one whose tests are all offline) goes to the shard a hash of its path gives. So a new
test file needs no entry, and adding or deleting a file moves no other file.

```powershell
# each shard's file count and recorded time
python .github/scripts/suite_shards.py balance

# run one shard's stack tests against a local stack, as CI does
python .github/scripts/suite_shards.py files --shard 3 | Out-File -Encoding ascii shard-files.txt
python -m pytest "@shard-files.txt" -m "not (unit and not docker)" --maxfail=25
```

The list is written with `Out-File -Encoding ascii`, not with `>`: in Windows PowerShell `>` writes
UTF-16 or puts a byte-order mark first, and pytest then looks for a file whose name starts with
that mark. In a POSIX shell, `> shard-files.txt` is fine.

The report job prints how long each shard really took. When they have drifted apart, record the
times again from that run's `pytest-results` artifact:

```powershell
python .github/scripts/suite_shards.py record pytest-results.xml
```

**Every test ran exactly once.** The report job collects the suite, downloads the offline lane's
report and the six shards', and runs `.github/scripts/join_suite_reports.py`: every collected test
must be in exactly one report, by name. It fails on a test in two reports, a test in none, a
missing report, and a report case the collection does not list. The joined report is kept as the
`pytest-results` artifact and goes through the audit the single full-suite job's report went
through (`pytest_result_audit.py`: no failure, the collected count, at most 15% skipped).

**Changed tests ran in their lanes.** The same job runs `.github/scripts/changed_tests_ran.py`: for
every test file added or changed since the last release tag, each offline test must be in the
report of every offline lane of the run, and each stack test in a shard's. A manual run on a
release candidate and a release's own run include the Fast lanes, so there a changed offline test
must be in the Windows lane's report as well. A skip counts when the report shows its reason, and
the job prints each one.

So a test that cannot run on one system is skipped there with a reason
(`pytest.mark.skipif(..., reason=...)`, or `pytest.param(..., marks=...)` for one parameter).
Leaving it out of a parametrization on that system fails the check, because the names are the
ones collected on Linux.

## Config (env vars, all optional)

| Var | Default |
|-----|---------|
| `VAULT_BASE_URL` | `http://localhost:8200` |
| `VAULT_ADMIN_USER` / `VAULT_ADMIN_PASS` | read from `../.env` (`ADMIN_USERNAME` / `ADMIN_PASSWORD`) |

If the container isn't reachable, integration tests **skip** cleanly while the offline unit lane still runs.

## Application settings in unit tests

A unit test runs the application's code in the test process, and the application keeps one settings
object for the whole process. `conftest.py` starts the application's runtime once when a run starts,
from the process environment and the minimal values in `_bare_api_env.py`, and never from the `.env`
in the working directory: that file configures the stack under test, not the test process. Every test
starts from those settings, and they are put back when it ends. So a test finds the same settings
whether its module runs alone, in the offline lane, or in the whole suite beside a stack, and whatever
the tests before it did.

A test that needs another value sets it with `monkeypatch.setattr(settings, ...)` or a
function-scoped fixture of its own. A value that a module- or session-scoped fixture sets on the
settings is undone before each of its tests. `test_settings_isolation.py` holds all of this.

## When the stack stops during a run

After a live test has failed, the run asks `VAULT_BASE_URL/health` once. If the stack gives no usable
answer, or says its database is not connected, the run ends there with exit status 2 and a message
that names the address: the tests left would fail for the same reason. A failed unit test never asks,
and neither does a run that found no stack when it started
(`test_run_ends_when_the_stack_is_gone.py`).
