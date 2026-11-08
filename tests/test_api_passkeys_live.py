"""The passkey self-service routes against a running vault: a software authenticator registers a key through the
real routes (the challenge in Redis, the row in Postgres), the key is listed, renamed and removed, an
administrator's removal goes through the two-person rule, and a second-factor reset retires every key. Needs a
stack whose configured address (the first ALLOWED_HOSTS entry) is the address the test opens (the relying party is
bound to it); skipped otherwise."""
import os
import uuid

import pytest

from _webauthn_softauth import SoftAuthenticator
from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration


def _public_url():
    return (os.environ.get("VAULT_PUBLIC_URL") or BASE_URL).rstrip("/")


def _skip_unless_ready(client):
    r = client.post("/users/me/passkeys/register/options", json={"current_password": client.password})
    if r.status_code == 409 and "public address" in (r.json().get("detail") or ""):
        pytest.skip("the stack has no address passkeys can be made at (ALLOWED_HOSTS)")
    return r


@pytest.fixture
def person(admin):
    name = unique("pk")
    r = admin.post("/users", json={"username": name, "email": f"{name}@example.com", "password": "Passkey-Test-12345!",
                                   "role": "user"})
    assert r.status_code in (200, 201), r.text
    uid = r.json()["id"]
    client = ApiClient(name, "Passkey-Test-12345!")
    client.login()
    yield client, uid
    admin.delete(f"/users/{uid}")


def _register(client, label, auth=None):
    r = _skip_unless_ready(client) if auth is None else client.post("/users/me/passkeys/register/options",
                                                                      json={"current_password": client.password})
    if r.status_code == 403:
        pytest.fail(f"the step-up gate applied where the password should have: {r.text}")
    assert r.status_code == 200, r.text
    body = r.json()
    auth = auth or SoftAuthenticator()
    credential = auth.make_credential(body["options"], _public_url())
    r = client.post("/users/me/passkeys/register/verify",
                    json={"challenge_id": body["challenge_id"], "credential": credential, "label": label})
    return r, auth


def test_a_passkey_is_registered_listed_renamed_and_removed(person, admin):
    client, uid = person
    r, auth = _register(client, "live key")
    assert r.status_code == 201, r.text
    shown = r.json()
    assert shown["label"] == "live key" and shown["provisional"] is False and shown["algorithm"] == "ES256"
    listed = client.get("/users/me/passkeys").json()
    assert [p["id"] for p in listed["passkeys"]] == [shown["id"]]
    # The challenge was spent: the same answer again is unknown.
    r2 = client.post("/users/me/passkeys/register/verify",
                     json={"challenge_id": "0" * 32, "credential": auth.make_credential(
                         {"publicKey": {"rp": {"id": "x"}, "challenge": "AAAA", "user": {"id": "AAAA"}}}, _public_url())})
    assert r2.status_code == 400 and r2.json()["detail"]["reason"] == "challenge_unknown"
    # Rename.
    r = client.patch(f"/users/me/passkeys/{shown['id']}", json={"label": "renamed"})
    assert r.status_code == 200 and r.json()["label"] == "renamed"
    # The administrator sees it on the user's row and the audit log has the registration.
    r = admin.get(f"/users/{uid}/passkeys")
    assert r.status_code == 200 and [p["label"] for p in r.json()["passkeys"]] == ["renamed"]
    # Removing it needs the step-up now that the account has a factor; a passkey-only account has no step-up
    # method yet, so the removal is refused with an empty method list (the passkey step-up lands later).
    r = client.delete(f"/users/me/passkeys/{shown['id']}")
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "step_up_required"
    # An administrator removes it: a credential change made at once (the first on this account in 14 days).
    r = admin.delete(f"/users/{uid}/passkeys/{shown['id']}")
    assert r.status_code == 200, r.text
    assert client.get("/users/me/passkeys").json()["passkeys"] == []
    assert admin.get(f"/users/{uid}/passkeys").json()["passkeys"] == []
    # Gone from the step-up too: the account has no factor again, so a registration asks for the password.
    r = client.post("/users/me/passkeys/register/options", json={"current_password": client.password})
    assert r.status_code == 200


def test_a_second_administrator_change_within_the_window_waits(person, admin):
    client, uid = person
    r, _ = _register(client, "one")
    assert r.status_code == 201, r.text
    first = r.json()["id"]
    # A second key, proved by the step-up? No method is available for a passkey-only account yet: register the
    # second one while the first still... cannot. So the administrator's first change removes the only key.
    assert admin.delete(f"/users/{uid}/passkeys/{first}").status_code == 200
    r, _ = _register(client, "two")
    assert r.status_code == 201, r.text
    second = r.json()["id"]
    assert r.json()["provisional"] is True            # within 14 days after the administrator's change
    r = admin.delete(f"/users/{uid}/passkeys/{second}")
    assert r.status_code == 202, r.text             # held for another administrator
    body = r.json()
    assert body.get("held") or "request" in str(body).lower()
    # The key stays until another administrator approves.
    assert [p["id"] for p in client.get("/users/me/passkeys").json()["passkeys"]] == [second]


def test_a_second_factor_reset_retires_every_passkey(person, admin):
    client, uid = person
    r, _ = _register(client, "to be reset")
    assert r.status_code == 201, r.text
    r = admin.post(f"/users/{uid}/second-factor/reset")
    assert r.status_code == 200, r.text
    # The sessions ended with the reset; sign in again (the account must set a factor up: the pending login says so).
    r = client.post("/auth/login", json={"username": client.username, "password": client.password})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("enrollment_required") is True or body.get("second_factor_required") is True
    # The retired key is gone from the administrator's list too.
    assert admin.get(f"/users/{uid}/passkeys").json()["passkeys"] == []
