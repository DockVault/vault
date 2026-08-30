"""Admin 'Copy reset link': an admin can MINT a one-time password-reset link for a user (no email
required, so an email-less account can be reset) and receive it once. The link reuses the exact reset
machinery — single-use, TTL-bounded, and it revokes the target's sessions when used."""
import pytest

from conftest import ApiClient, BASE_URL

pytestmark = pytest.mark.integration


def _token_from_link(link: str) -> str:
    assert "?reset=" in link, link
    return link.split("?reset=", 1)[1]


def test_admin_mints_reset_link_for_email_less_user_and_it_works(admin):
    # The whole point: a user with NO email can still be reset via a copyable link.
    u = admin.create_user(role="user", email=None)
    try:
        r = admin.post(f"/users/{u['id']}/reset-link")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["username"] == u["_username"]
        assert isinstance(body["expires_in_minutes"], int) and body["expires_in_minutes"] > 0
        link = body["reset_link"]
        token = _token_from_link(link)

        # The link validates and names the account (public reset-form lookup).
        g = ApiClient(BASE_URL).get(f"/reset/{token}")
        assert g.status_code == 200, g.text
        assert g.json()["username"] == u["_username"]

        # Using it sets a new password (single-use claim + session revocation happen server-side).
        newpw = "Rotated-Pw0rd!456"
        d = ApiClient(BASE_URL).post(f"/reset/{token}", json={"new_password": newpw})
        assert d.status_code == 200, d.text

        # The new password now logs in.
        c = ApiClient(BASE_URL)
        assert c.login(u["_username"], newpw) is not None
    finally:
        admin.delete_user(u["id"])


def test_reset_link_is_single_use(admin):
    u = admin.create_user(role="user", email=None)
    try:
        token = _token_from_link(admin.post(f"/users/{u['id']}/reset-link").json()["reset_link"])
        first = ApiClient(BASE_URL).post(f"/reset/{token}", json={"new_password": "First-Pw0rd!789"})
        assert first.status_code == 200, first.text
        # Re-using the same token is refused (generic 404 — no enumeration).
        second = ApiClient(BASE_URL).post(f"/reset/{token}", json={"new_password": "Second-Pw0rd!789"})
        assert second.status_code == 404, second.text
    finally:
        admin.delete_user(u["id"])


def test_minting_again_invalidates_the_previous_link(admin):
    u = admin.create_user(role="user", email=None)
    try:
        t1 = _token_from_link(admin.post(f"/users/{u['id']}/reset-link").json()["reset_link"])
        t2 = _token_from_link(admin.post(f"/users/{u['id']}/reset-link").json()["reset_link"])
        assert t1 != t2
        # The first link is now dead (a fresh mint deletes the prior unconsumed token).
        assert ApiClient(BASE_URL).get(f"/reset/{t1}").status_code == 404
        assert ApiClient(BASE_URL).get(f"/reset/{t2}").status_code == 200
    finally:
        admin.delete_user(u["id"])


def test_reset_link_requires_user_manage(admin):
    # A plain user (no USER_MANAGE) cannot mint a reset link for anyone.
    victim = admin.create_user(role="user", email=None)
    actor = admin.create_user(role="user")
    try:
        c = ApiClient(BASE_URL)
        c.login(actor["_username"], actor["_password"])
        r = c.post(f"/users/{victim['id']}/reset-link")
        assert r.status_code == 403, r.text
    finally:
        admin.delete_user(actor["id"])
        admin.delete_user(victim["id"])


def test_reset_link_rejects_unknown_and_inactive(admin):
    import uuid
    # Unknown user -> 404.
    assert admin.post(f"/users/{uuid.uuid4()}/reset-link").status_code == 404
    # Inactive user -> 400 (reactivate first).
    u = admin.create_user(role="user", email=None)
    try:
        assert admin.patch(f"/users/{u['id']}", json={"is_active": False}).status_code in (200, 204)
        r = admin.post(f"/users/{u['id']}/reset-link")
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(u["id"])
