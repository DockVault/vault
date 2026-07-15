"""POST /settings/test-email — send a test message via the stored SMTP settings.

Admin-only. Must fail cleanly (never a 500) when SMTP is unconfigured or unreachable,
and must never echo the stored SMTP password.
"""


def test_test_email_requires_admin(admin):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        assert c.post("/settings/test-email").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_test_email_returns_clean_error_not_500(admin):
    # In any configuration state the endpoint returns a user-facing 4xx/502 — never a 500.
    r = admin.post("/settings/test-email")
    assert r.status_code != 500, r.text
    assert r.status_code in (400, 502), r.text


def test_test_email_never_echoes_smtp_password(admin):
    secret = "Do-Not-Echo-This-Pw-9271"
    # point at a closed local port so the send fails fast (connection refused, not a 15s timeout)
    admin.put("/settings", json={
        "smtp_server": "127.0.0.1", "smtp_port": 1,
        "from_email": "noreply@example.com", "smtp_password": secret,
    })
    try:
        r = admin.post("/settings/test-email")
        assert r.status_code != 500, r.text          # a clean error, not an unhandled crash
        assert r.status_code in (400, 502), r.text
        assert secret not in r.text                   # the SMTP password must never be echoed
    finally:
        admin.put("/settings", json={"smtp_server": ""})  # clear the bogus host for other tests


def test_test_email_malformed_from_is_clean_error_not_500(admin):
    # a From name with control chars is saveable via PUT /settings (which doesn't validate it);
    # the send must fail cleanly, not crash with a 500.
    admin.put("/settings", json={
        "smtp_server": "127.0.0.1", "smtp_port": 1,
        "from_email": "noreply@example.com", "from_name": "Ops\r\nBcc: attacker@evil.example",
    })
    try:
        r = admin.post("/settings/test-email")
        assert r.status_code != 500, r.text
        assert r.status_code in (400, 502), r.text
    finally:
        admin.put("/settings", json={"smtp_server": "", "from_name": ""})
