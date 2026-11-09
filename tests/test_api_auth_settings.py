"""The admin login-attempt / lockout / session-timeout settings override the env at the auth path. A longer
session timeout (a value, or one cleared to a longer default) is saved with the password step-up."""
import base64
import json
import time

from _sf_helpers import put_settings_with_password


def _set(admin, **kw):
    r = admin.put("/settings", json=kw)
    assert r.status_code in (200, 204), r.text


def _reset_auth(admin, admin_creds):
    # 0 = "use the deployment env default" (a non-positive stored value is ignored); going back to the default
    # may make the timeout longer, so the password goes with it.
    r = put_settings_with_password(admin, admin_creds["password"],
                                   {"max_login_attempts": 0, "lockout_duration": 0, "session_timeout": 0})
    assert r.status_code in (200, 204), r.text


def _jwt_exp(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # restore base64 padding
    return json.loads(base64.urlsafe_b64decode(payload))["exp"]


def test_max_login_attempts_override_locks_account(admin, admin_creds):
    _set(admin, max_login_attempts=3)
    u = admin.create_user(role="user")
    try:
        c = admin.clone_anonymous()
        for _ in range(3):
            r = c.post("/auth/login", json={"username": u["_username"], "password": "wrong-pw-xyz"})
            assert r.status_code != 200, r.text
        # after 3 failures at the stored threshold, even the correct password is refused
        r = c.post("/auth/login", json={"username": u["_username"], "password": u["_password"]})
        assert r.status_code != 200, "account should be blocked after 3 failed attempts"
    finally:
        _reset_auth(admin, admin_creds)
        admin.delete_user(u["id"])


def test_session_timeout_override_shapes_token_ttl(admin, admin_creds):
    _set(admin, session_timeout=1)  # 1 minute
    u = admin.create_user(role="user")
    try:
        c = admin.clone_anonymous()
        r = c.post("/auth/login", json={"username": u["_username"], "password": u["_password"]})
        assert r.status_code == 200, r.text
        ttl = _jwt_exp(r.json()["access_token"]) - time.time()
        assert 30 < ttl <= 75, f"session_timeout=1min -> token ttl ~60s, got {ttl:.0f}s"
    finally:
        _reset_auth(admin, admin_creds)
        admin.delete_user(u["id"])


def test_auth_settings_validation(admin, admin_creds):
    try:
        assert admin.put("/settings", json={"max_login_attempts": -1}).status_code == 400
        assert admin.put("/settings", json={"session_timeout": "x"}).status_code == 400
        assert admin.put("/settings", json={"lockout_duration": 1.5}).status_code == 400
        assert put_settings_with_password(admin, admin_creds["password"],
                                          {"max_login_attempts": 5, "session_timeout": 60}).status_code in (200, 204)
    finally:
        _reset_auth(admin, admin_creds)


def test_session_timeout_is_clamped_to_a_maximum(admin, admin_creds):
    """session_timeout has an upper bound (30 days = 43200 min) so a huge value can't mint an
    effectively-immortal token; the boundary is accepted, one minute past it is refused."""
    try:
        pw = admin_creds["password"]
        # A longer timeout without the password is refused before its value is looked at.
        refused = admin.put("/settings", json={"session_timeout": 43200})
        assert refused.status_code == 403 and "step_up_required" in refused.text, refused.text
        assert put_settings_with_password(admin, pw, {"session_timeout": 43200}).status_code in (200, 204)  # exactly 30 days
        assert put_settings_with_password(admin, pw, {"session_timeout": 43201}).status_code == 400          # one minute over
        assert put_settings_with_password(admin, pw, {"session_timeout": 10_000_000}).status_code == 400      # absurd
    finally:
        _reset_auth(admin, admin_creds)
