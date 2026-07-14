"""Authentication: login (success/failure), /users/me, logout, temp-cred login."""
import pytest
import requests

from conftest import ApiClient


def test_login_success(admin_creds, base_url):
    client = ApiClient(base_url)
    data = client.login(admin_creds["username"], admin_creds["password"])
    assert data["access_token"]
    assert data["token_type"].lower() == "bearer"
    assert data["user"]["username"] == admin_creds["username"]
    assert data["user"]["role"] == "admin"


def test_login_wrong_password(anon, admin_creds):
    r = anon.post(
        "/auth/login",
        json={"username": admin_creds["username"], "password": "definitely-wrong"},
    )
    assert r.status_code == 401


def test_login_unknown_user(anon):
    r = anon.post("/auth/login", json={"username": "nobody-here-xyz", "password": "whatever"})
    assert r.status_code == 401


def test_login_missing_fields(anon):
    r = anon.post("/auth/login", json={"username": "admin"})
    assert r.status_code == 422  # pydantic validation


def test_users_me_requires_auth(anon):
    r = anon.get("/users/me")
    assert r.status_code in (401, 403)


def test_users_me_returns_current_user(admin, admin_creds):
    r = admin.get("/users/me")
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == admin_creds["username"]
    assert body["role"] == "admin"


def test_bad_token_rejected(base_url):
    client = ApiClient(base_url)
    client.session.headers.update({"Authorization": "Bearer not-a-real-token"})
    r = client.get("/users/me")
    assert r.status_code in (401, 403)


def test_temp_credential_can_log_in(admin):
    """A freshly issued temp credential should authenticate via /auth/login."""
    r = admin.post("/auth/temp-credentials", json={"validity_minutes": 30})
    assert r.status_code == 200
    creds = r.json()
    temp_client = admin.clone_anonymous()
    data = temp_client.login(creds["temp_username"], creds["credential"])
    assert data["access_token"]
    # one-time: a second login with the same credential must fail with a clean
    # 401 (pin the status so a crash can't be mistaken for correct rejection)
    again = admin.clone_anonymous()
    with pytest.raises(requests.HTTPError) as exc_info:
        again.login(creds["temp_username"], creds["credential"])
    assert exc_info.value.response.status_code == 401


def test_logout(admin_creds, base_url):
    client = ApiClient(base_url)
    client.login(admin_creds["username"], admin_creds["password"])
    r = client.post("/api/logout")
    assert r.status_code == 200
