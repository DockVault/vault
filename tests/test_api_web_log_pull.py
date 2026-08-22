"""Live acceptance: the in-app sink makes GET /logs?service=web return request lines even when the API
runs directly (the split/dev shape, where run_combined is NOT the launcher and used to leave the web
pull permanently empty).

Runs only when the log-pull ceiling is enabled on the deployment (PLAN_LOG_PULL + a strong
LOG_TOKEN_PEPPER); skips cleanly otherwise, so a normal round and CI are unaffected.
"""
import os
import time

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")


def test_web_log_pull_returns_request_lines(admin):
    admin.put("/settings/logs", json={"flags": {"web": True}})   # enable the web component
    minted = admin.post("/settings/logs", json={"name": unique("web"), "scope": ["web"]})
    if minted.status_code in (403, 404):
        pytest.skip("log-pull ceiling off (set PLAN_LOG_PULL=true + LOG_TOKEN_PEPPER>=32 to test)")
    assert minted.status_code == 200, minted.text
    token = minted.json()["token"]

    # generate a few [web] access lines (any request flows through the access-logging middleware)
    for _ in range(3):
        admin.get("/users/me")

    lines = []
    for _ in range(40):   # the sink writer flushes off-thread; give it a moment
        pull = requests.get(f"{BASE}/logs", params={"service": "web"},
                            headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if pull.status_code == 404:
            pytest.skip("log endpoint disabled (ceiling) — not testable on this round")
        assert pull.status_code == 200, pull.text
        lines = pull.json().get("lines", [])
        if lines:
            break
        time.sleep(0.25)

    assert lines, "GET /logs?service=web is empty — the in-app web sink is not writing [web] lines"
    assert any(l.startswith("[web] ") for l in lines), lines[:3]
    assert any("/users/me" in l for l in lines), "expected a recent request line in the web pull"


def test_web_log_pull_redacts_path_secrets(admin):
    """A replayable secret carried in the URL PATH (invite token, share-claim secret) must be masked
    before it reaches the web sink, so a web-scoped log-pull token holder can't read it back out."""
    admin.put("/settings/logs", json={"flags": {"web": True}})
    minted = admin.post("/settings/logs", json={"name": unique("web"), "scope": ["web"]})
    if minted.status_code in (403, 404):
        pytest.skip("log-pull ceiling off (set PLAN_LOG_PULL=true + LOG_TOKEN_PEPPER>=32 to test)")
    assert minted.status_code == 200, minted.text
    token = minted.json()["token"]

    secret = "SECRET" + unique("tok").replace("-", "")  # a would-be invite token in the path
    requests.get(f"{BASE}/invites/{secret}", timeout=15)  # 4xx is fine — the middleware logs it either way

    lines = []
    for _ in range(40):
        pull = requests.get(f"{BASE}/logs", params={"service": "web"},
                            headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if pull.status_code == 404:
            pytest.skip("log endpoint disabled (ceiling) — not testable on this round")
        assert pull.status_code == 200, pull.text
        lines = pull.json().get("lines", [])
        if any("/invites/" in l for l in lines):
            break
        time.sleep(0.25)

    invite_lines = [l for l in lines if "/invites/" in l]
    assert invite_lines, "expected the /invites request to appear in the web pull"
    assert any("/invites/<redacted>" in l for l in invite_lines), invite_lines[:3]
    assert not any(secret in l for l in lines), "the raw invite token leaked into the web log pull"
