"""Infrastructure / configuration / abuse-resistance hardening regression tests.

Covers the framework rate limiter wiring, the brute-force login alerting that was dead
code, the proxy-aware transport-security scheme, the production weak-secret startup gate, and the
container/compose/dependency hardening. Live-HTTP tests hit http://localhost:8200; the config-gate
and proxy-scheme tests run inside the vault-api container (they import app modules that need the
credential manager); the rest are static source locks.
"""
import os
import subprocess
from pathlib import Path

import pytest

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8", errors="ignore")


def _in_container(env_overrides=None, args=None, stdin=None, timeout=90):
    """Run a command in the vault-api container; skip cleanly if docker is unavailable."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    cmd = ["docker", "exec"]
    if stdin is not None:
        cmd.append("-i")
    for k, v in (env_overrides or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [container] + list(args or [])
    try:
        return subprocess.run(
            cmd, input=stdin, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")


def test_general_api_rate_limiter_is_attached(admin):
    r = admin.get("/api/dashboard/stats")
    assert r.status_code == 200, r.text
    for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
        assert h in r.headers, f"missing {h} -- the rate-limit middleware is not attached"


def test_health_is_excluded_from_rate_limiting(anon):
    r = anon.get("/health")
    assert r.status_code == 200
    assert "X-RateLimit-Limit" not in r.headers


def test_repeated_failed_logins_raise_brute_force_alerts(admin, anon):
    uniq = unique("bruteforce")
    for i in range(12):
        anon.post("/auth/login", json={"username": uniq, "password": f"wrong-{i}"})
    alerts = admin.get("/api/security/alerts", params={"limit": 200}).json().get("alerts", [])
    mine = [a for a in alerts if uniq in (a.get("message") or "") or a.get("username") == uniq]
    severities = {a.get("severity") for a in mine}
    assert "warning" in severities, f"expected a WARNING alert for {uniq}; got {mine}"
    assert "critical" in severities, f"expected a CRITICAL brute-force alert for {uniq}; got {mine}"


def _import_config(env_overrides):
    return _in_container(env_overrides=env_overrides, args=["python", "-c", "import config"])


def test_production_rejects_sample_admin_password():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "change_this_secure_password"})
    assert proc.returncode == 1, f"sample admin password should fail-closed in production\n{proc.stdout}\n{proc.stderr}"


def test_production_rejects_env_example_placeholder():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "REPLACE_ME"})
    assert proc.returncode == 1, f"placeholder should fail-closed in production\n{proc.stdout}"


def test_production_allows_strong_admin_password():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "Xq7-strong-Rand-92hf"})
    assert proc.returncode == 0, f"strong admin password should boot\n{proc.stdout}\n{proc.stderr}"


def test_development_allows_sample_admin_password():
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "change_this_secure_password"})
    assert proc.returncode == 0, "development must not be gated"


def test_production_allows_blank_admin_password_post_bootstrap():
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": ""})
    assert proc.returncode == 0, "blank admin password must not fail startup (post-bootstrap)"


def test_jwt_algorithm_must_be_canonical_hmac():
    # A non-HMAC or mis-cased JWT_ALGORITHM must fail closed at BOOT (defeats alg-confusion and the
    # PyJWT case-sensitivity 500). Only the exact canonical HMAC names boot.
    assert _import_config({"JWT_ALGORITHM": "HS256"}).returncode == 0
    for bad in ("RS256", "none", "hs256", "ES256"):
        proc = _import_config({"JWT_ALGORITHM": bad})
        assert proc.returncode == 1, f"JWT_ALGORITHM={bad!r} must fail-closed at boot\n{proc.stdout}"


def test_development_rejects_env_example_placeholder():
    # The shipped .env.example placeholder is a publicly known credential and must be refused in
    # EVERY environment — a bare `docker compose up` ships ENVIRONMENT=development and previously
    # seeded admin/REPLACE_ME on a plaintext listener.
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "REPLACE_ME"})
    assert proc.returncode == 1, f"shipped placeholder must fail-closed even in development\n{proc.stdout}\n{proc.stderr}"


def test_production_rejects_short_admin_password():
    # A weak-but-unlisted value below the 12-char floor must not boot a reachable (production) deploy.
    proc = _import_config({"ENVIRONMENT": "production", "ADMIN_PASSWORD": "weakpass"})
    assert proc.returncode == 1, f"a <12-char admin password should fail-closed in production\n{proc.stdout}\n{proc.stderr}"


def test_nonstandard_env_rejects_weak_admin_password():
    # Fail-safe: any non-development environment ("staging", "prod", a typo) is treated as reachable
    # and gets the strict blocklist + length tier — not only the literal "production".
    proc = _import_config({"ENVIRONMENT": "staging", "ADMIN_PASSWORD": "password"})
    assert proc.returncode == 1, f"a weak password must fail-closed in any non-development env\n{proc.stdout}\n{proc.stderr}"


def test_development_allows_short_nonplaceholder_password():
    # Dev convenience preserved: only the shipped placeholder is blocked in development; a short,
    # non-placeholder value still boots (the blocklist + length floor apply outside development).
    proc = _import_config({"ENVIRONMENT": "development", "ADMIN_PASSWORD": "devpass1"})
    assert proc.returncode == 0, f"development must allow a short non-placeholder password\n{proc.stdout}\n{proc.stderr}"


def test_dev_compose_publishes_loopback_only():
    # The plaintext trial must bind to loopback so it isn't reachable off-host.
    dc = _read("docker-compose.yml")
    assert '- "127.0.0.1:8200:8000"' in dc, "trial API port must publish on loopback (127.0.0.1)"
    assert '- "8200:8000"' not in dc, "trial API port must not publish on all interfaces"


_PLAINTEXT_WARN_SELFTEST = r'''
import api_server as a
f = a._should_warn_plaintext_transport
assert f(False, "production", "") is True, "plaintext + production + no proxy should warn"
assert f(False, "staging", "") is True, "plaintext + any non-dev + no proxy should warn"
assert f(False, "development", "") is False, "development suppresses the warning"
assert f(True, "production", "") is False, "in-process HTTPS does not warn"
assert f(False, "production", "10.0.0.0/8") is False, "a configured trusted proxy suppresses the warning"
print("PLAINTEXT_WARN_OK")
'''


def test_plaintext_transport_warning_condition():
    # Locks the net-new startup-warning logic (plaintext AND non-development AND no trusted proxy).
    proc = _in_container(args=["python", "-"], stdin=_PLAINTEXT_WARN_SELFTEST)
    assert "PLAINTEXT_WARN_OK" in proc.stdout, f"{proc.stdout}\n{proc.stderr}"


_SCHEME_SELFTEST = r'''
import api_server, net_utils
sc = api_server._external_scheme

class _H(dict):
    def get(self, k, d=None): return super().get(k, d)

class _Req:
    def __init__(self, peer, xfp=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = _H({"x-forwarded-proto": xfp} if xfp else {})
        self.url = type("U", (), {"scheme": "http"})()

net_utils.settings.trusted_proxies = ""
net_utils._trusted_networks.cache_clear()
assert sc(_Req("172.18.0.5", "https")) == "http", "untrusted peer must not honour XFP"
assert sc(_Req("8.8.8.8", "https")) == "http", "public peer must not honour XFP"

net_utils.settings.trusted_proxies = "172.16.0.0/12"
net_utils._trusted_networks.cache_clear()
try:
    assert sc(_Req("172.18.0.5", "https")) == "https", "trusted proxy XFP should be honoured"
    assert sc(_Req("172.18.0.5", "http")) == "http", "trusted proxy forwarding http stays http"
    assert sc(_Req("8.8.8.8", "https")) == "http", "a direct public client is still ignored"
finally:
    net_utils.settings.trusted_proxies = ""
    net_utils._trusted_networks.cache_clear()
print("SCHEME_OK")
'''


def test_forwarded_proto_scheme_resolution():
    proc = _in_container(args=["python", "-"], stdin=_SCHEME_SELFTEST)
    assert "SCHEME_OK" in proc.stdout, (
        f"external-scheme self-test failed (rc={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def test_requirements_drop_unused_and_refresh_crypto():
    active = [l.strip() for l in _read("requirements.txt").splitlines()
              if l.strip() and not l.strip().startswith("#")]
    names = {l.split("==")[0].split("[")[0].strip().lower() for l in active}
    assert "requests" not in names, "unused requests should be removed from the image deps"
    assert "python-jose" not in names, "the unmaintained python-jose should be dropped in favour of PyJWT"
    assert "pyjwt" in names, "the JWT path is now the maintained PyJWT"
    assert "cryptography==44.0.1" in active, "cryptography should carry the CVE-2024-12797 fix"
    assert "python-multipart==0.0.18" in active, "python-multipart should carry the multipart-DoS fix"
    assert "fastapi==0.115.6" in active, "fastapi should pair with starlette>=0.40 (CVE-2024-47874)"
    assert "starlette==0.41.3" in active, "starlette should be >=0.40 (CVE-2024-47874)"


def test_no_stray_import_of_dropped_libs_in_shipped_code():
    patt = "^import requests|^from jose\\b|^import jose\\b"
    hits = subprocess.run(["git", "grep", "-lE", patt], cwd=str(ROOT),
                          capture_output=True, text=True)
    prod = [p for p in hits.stdout.splitlines() if p and not p.startswith("tests/")]
    assert not prod, f"dropped libs still imported in shipped code: {prod}"


def test_dockerignore_excludes_git_metadata():
    lines = {l.strip() for l in _read(".dockerignore").splitlines()}
    assert ".git" in lines, "VCS metadata should be kept out of the shipped image"


def test_master_password_kdf_iterations_raised():
    ss = _read("startup_security.py")
    assert "iterations=600000" in ss, "master-password KDF should use 600k iterations"
    assert "iterations=100000" not in ss, "the old 100k iteration count should be gone"


def test_dead_fail_open_permission_code_stays_removed():
    # Regression guard: two dead, fail-open permission paths were removed because they would
    # silently allow-all if ever wired in. They must not creep back:
    #   - the module-level `require_permission` decorator (allowed through when the user object
    #     had no _permission_service attribute), and
    #   - the EndpointPermissionChecker / get_endpoint_info catalog checker ("endpoint not in
    #     catalog -> allow"), which the live require_endpoint_permission never consulted.
    authz = _read("authorization.py")
    assert "\ndef require_permission(" not in authz, \
        "the fail-open module-level require_permission decorator must stay removed"
    # the live, non-fail-open PermissionService.require_permission METHOD must remain
    assert "    def require_permission(" in authz

    ep = _read("endpoint_permissions.py")
    assert "class EndpointPermissionChecker" not in ep, "dead fail-open EndpointPermissionChecker must stay removed"
    assert "def get_endpoint_info" not in ep, "dead get_endpoint_info (only the checker used it) must stay removed"
    assert "def require_endpoint_permission(" in ep, "the live endpoint gate must remain"


def test_broken_whole_file_crypto_stays_removed():
    # The whole-file AES-GCM writer had a 9-byte magic vs a 5-byte header field, so every
    # round-trip always failed -- a latent foot-gun if re-wired. It was removed; only the live
    # secure-delete helper remains. Guard against reintroduction.
    src = _read("encrypted_file_storage.py")
    for gone in ("def encrypt_and_save", "def load_and_decrypt", "def verify_file_format", "MAGIC_BYTES"):
        assert gone not in src, f"removed whole-file crypto symbol reappeared: {gone}"
    assert "def secure_delete" in src, "the live secure_delete helper must remain"


def test_zk_seal_names_locks_vault_row():
    # Parity: zk_seal_names must serialize its seal-epoch read + writes under the SAME Vault-row lock its
    # siblings (rename_file / create_folder / retire_dek_versions) hold — otherwise a concurrent retire
    # could strand a name's member key and make the name permanently undecryptable.
    src = _read("api_server.py")
    start = src.index("async def zk_seal_names")
    end = src.index("\n@app.", start)   # up to the next route
    assert "with_for_update()" in src[start:end], \
        "zk_seal_names must lock the Vault row before reading the seal epoch (parity with its siblings)"


def test_dev_compose_hardening():
    dc = _read("docker-compose.yml")
    assert "vault_local_dev_pw" not in dc, "the source-controlled default DB password must be dropped"
    assert dc.count("- ALL") >= 2, "cap_drop [ALL] expected on both app services"
    assert "mem_limit:" in dc, "container memory ceilings expected"
    assert "pids_limit:" in dc
    assert "--requirepass" in dc, "redis requirepass wiring expected"


def test_secure_compose_hardening():
    sc = _read("docker-compose.secure.yml")
    assert sc.count("- ALL") >= 2, "cap_drop [ALL] expected on both app services"
    assert "mem_limit:" in sc
    assert "--requirepass" in sc
