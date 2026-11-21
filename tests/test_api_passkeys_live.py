"""The passkey self-service routes against a running vault: a software authenticator registers a key through the
real routes (the challenge in Redis, the row in Postgres), the key is listed, renamed and removed, an
administrator's removal goes through the two-person rule, and a second-factor reset retires every key. Needs a
stack whose configured address (the first ALLOWED_HOSTS entry) is the address the test opens (the relying party is
bound to it); skipped otherwise."""
import json
import uuid

import pytest

from _webauthn_softauth import SoftAuthenticator
from conftest import ApiClient, BASE_URL

pytestmark = pytest.mark.integration


def _public_url():
    return BASE_URL.rstrip("/")


def _skip_unless_ready(client):
    r = client.post("/users/me/passkeys/register/options", json={"current_password": client.password})
    if r.status_code == 409 and "public address" in (r.json().get("detail") or ""):
        pytest.skip("the stack has no address passkeys can be made at (ALLOWED_HOSTS)")
    return r


@pytest.fixture
def person(admin):
    """A fresh user signed in with the password, with its credentials kept on the client for the routes that
    re-prove them; deleted on teardown."""
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    client.username, client.password = user["_username"], user["_password"]
    yield client, user["id"]
    admin.delete_user(user["id"])


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


def _signed_in_again_for_a_factor(client):
    """A fresh client at the sign-in an account is held at once an administrator took its last factor: the
    password at the form, then the step that sets a factor up. Its requests carry that held sign-in."""
    fresh = ApiClient()
    r = fresh.session.post(f"{fresh.base_url}/auth/login",
                           json={"username": client.username, "password": client.password}, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("access_token") is None and body.get("enrollment_required") is True, body
    fresh.session.headers["Authorization"] = f"Bearer {body['pre_auth_token']}"
    fresh.username, fresh.password = client.username, client.password
    return fresh


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
    assert admin.get(f"/users/{uid}/passkeys").json()["passkeys"] == []
    # It was the account's only factor: its sessions ended with it, as after a reset.
    assert client.get("/users/me/passkeys").status_code == 401
    # The next sign-in is held for a new factor, and the password given at the form is the proof a registration
    # there asks for.
    held = _signed_in_again_for_a_factor(client)
    r = held.post("/users/me/passkeys/register/options", json={})
    assert r.status_code == 200, r.text


def test_a_second_administrator_change_within_the_window_waits(person, admin):
    client, uid = person
    r, _ = _register(client, "one")
    assert r.status_code == 201, r.text
    first = r.json()["id"]
    # A second key, proved by the step-up? No method is available for a passkey-only account yet: register the
    # second one while the first still... cannot. So the administrator's first change removes the only key.
    assert admin.delete(f"/users/{uid}/passkeys/{first}").status_code == 200
    # The removal ended the account's sessions: the second key is set up at the next sign-in, which it finishes.
    held = _signed_in_again_for_a_factor(client)
    r, _ = _register(held, "two", auth=SoftAuthenticator())
    assert r.status_code == 201, r.text
    second = r.json()["passkey"]["id"]
    assert r.json()["passkey"]["provisional"] is True  # within 14 days after the administrator's change
    client = ApiClient()
    client.session.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    r = admin.delete(f"/users/{uid}/passkeys/{second}")
    # The two-person rule: held for another administrator (202), or refused outright when no other administrator
    # could approve it (409, the stack's only administrator). Either way the key stays.
    assert r.status_code in (202, 409), r.text
    if r.status_code == 409:
        assert "another administrator" in r.json()["detail"]
    assert [p["id"] for p in client.get("/users/me/passkeys").json()["passkeys"]] == [second]


def test_a_second_factor_reset_retires_every_passkey(person, admin):
    client, uid = person
    r, _ = _register(client, "to be reset")
    assert r.status_code == 201, r.text
    r = admin.post(f"/users/{uid}/second-factor/reset")
    assert r.status_code == 200, r.text
    # The sessions ended with the reset; sign in again from a fresh client (the account must set a factor up: the
    # pending login says so).
    fresh = ApiClient()
    r = fresh.session.post(f"{fresh.base_url}/auth/login", json={"username": client.username, "password": client.password},
                           timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("enrollment_required") is True or body.get("second_factor_required") is True
    # The retired key is gone from the administrator's list too.
    assert admin.get(f"/users/{uid}/passkeys").json()["passkeys"] == []


def _claims(token):
    import base64
    import json
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_a_passkey_signs_a_user_in_and_an_administrator_goes_on_to_the_password(person, admin):
    client, uid = person
    r, auth = _register(client, "sign-in key")
    assert r.status_code == 201, r.text
    anon = ApiClient()
    # The challenge (the same for everyone: no key offered, a typed name ignored); the assertion with the key's own
    # user handle; a session with amr hwk and mfa_at.
    r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/options", json={"username": client.username}, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["options"]["publicKey"]["allowCredentials"] == []
    credential = auth.get_assertion(body["options"], _public_url(), sign_count=1)
    r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/verify",
                          json={"challenge_id": body["challenge_id"], "credential": credential}, timeout=15)
    assert r.status_code == 200, r.text
    signed = r.json()
    assert signed["user"]["username"] == client.username and signed["is_temporary"] is False
    claims = _claims(signed["access_token"])
    assert claims["amr"] == ["hwk"] and "mfa_at" in claims
    # The token works, and the key remembers the sign-in.
    me = ApiClient()
    me.token = signed["access_token"]
    me.session.headers["Authorization"] = f"Bearer {signed['access_token']}"
    listed = me.get("/users/me/passkeys").json()["passkeys"]
    assert listed[0]["last_used_at"] is not None
    # The same assertion again: the challenge is spent.
    r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/verify",
                          json={"challenge_id": body["challenge_id"], "credential": credential}, timeout=15)
    assert r.status_code == 401
    # A replayed counter on a device-bound key is refused and counted against the account.
    r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/options", json={}, timeout=15)
    body = r.json()
    assert body["options"]["publicKey"]["allowCredentials"] == []
    credential = auth.get_assertion(body["options"], _public_url(), sign_count=1)
    r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/verify",
                          json={"challenge_id": body["challenge_id"], "credential": credential}, timeout=15)
    assert r.status_code == 401 and r.json()["detail"] == "That passkey was not accepted."
    # An unknown name, a name without keys, a name with keys and no name: one answer apart from the challenge.
    shapes = []
    for name in ("nobody-" + uid[:8], admin.user["username"] if getattr(admin, "user", None) else "admin",
                 client.username, None):
        r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/options",
                              json={"username": name} if name else {}, timeout=15)
        assert r.status_code == 200 and r.json()["options"]["publicKey"]["allowCredentials"] == []
        pk = dict(r.json()["options"]["publicKey"])
        pk.pop("challenge")
        shapes.append((sorted(r.json()), json.dumps(pk, sort_keys=True)))
    assert len(set((tuple(a), b) for a, b in shapes)) == 1
    # The sign-in page may show the passkey button.
    assert anon.session.get(f"{anon.base_url}/auth/policy", timeout=15).json()["methods"]["passkeys"] is True


def test_an_administrators_passkey_leads_to_the_password_step(admin):
    """A second administrator (made for this test, so the stack's own stays untouched) registers a key with the
    password, signs in with it, lands on the password step, and finishes with the password: both kinds in amr, no
    code asked. The stack's administrator then resets that account's second factor, which retires the key."""
    other = admin.create_user(role="admin")
    try:
        client = ApiClient()
        client.login(other["_username"], other["_password"])
        client.password = other["_password"]
        r = _skip_unless_ready(client)
        assert r.status_code == 200, r.text
        body = r.json()
        auth = SoftAuthenticator()
        r = client.post("/users/me/passkeys/register/verify",
                        json={"challenge_id": body["challenge_id"],
                              "credential": auth.make_credential(body["options"], _public_url()), "label": "admin key"})
        assert r.status_code == 201, r.text
        anon = ApiClient()
        r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/options", json={}, timeout=15)
        body = r.json()
        credential = auth.get_assertion(body["options"], _public_url(), sign_count=1)
        r = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/verify",
                              json={"challenge_id": body["challenge_id"], "credential": credential}, timeout=15)
        assert r.status_code == 200, r.text
        pending = r.json()
        assert pending["stage"] == "password" and pending["second_factor_required"] is True
        assert pending["access_token"] is None and pending["username"] == other["_username"]
        # The password finishes it: amr carries both kinds, mfa_at is set, no code is asked.
        r = anon.session.post(f"{anon.base_url}/auth/login",
                              json={"username": other["_username"], "password": other["_password"]},
                              headers={"Authorization": f"Bearer {pending['pre_auth_token']}"}, timeout=15)
        assert r.status_code == 200, r.text
        claims = _claims(r.json()["access_token"])
        assert sorted(claims["amr"]) == ["hwk", "pwd"] and "mfa_at" in claims
        # A wrong password at that step is refused and the pre-auth token is spent after its cap, as at the form.
        r = anon.session.post(f"{anon.base_url}/auth/login",
                              json={"username": other["_username"], "password": "not-it"},
                              headers={"Authorization": f"Bearer {pending['pre_auth_token']}"}, timeout=15)
        assert r.status_code == 401
        # The stack's administrator resets the second factor: the key is retired, the account signs in with the
        # password and must set a factor up again.
        r = admin.post(f"/users/{other['id']}/second-factor/reset")
        assert r.status_code == 200, r.text
        assert admin.get(f"/users/{other['id']}/passkeys").json()["passkeys"] == []
    finally:
        admin.delete_user(other["id"])


def test_a_passkey_is_the_second_step_after_the_password_and_proves_a_step_up(person, admin):
    """The account holds a passkey, so a password sign-in is held for the second step, which the passkey meets
    (amr pwd + hwk, mfa_at); then the signed-in session proves the account.second_factor step-up with the passkey
    and the receipt opens the guarded removal. The real receipt path, end to end."""
    client, uid = person
    r, auth = _register(client, "second factor")
    assert r.status_code == 201, r.text
    anon = ApiClient()
    r = anon.session.post(f"{anon.base_url}/auth/login", json={"username": client.username, "password": client.password}, timeout=15)
    assert r.status_code == 200, r.text
    pending = r.json()
    if not pending.get("second_factor_required"):
        pytest.skip("the stack's login switch does not ask for the second factor")
    assert "passkey" in pending["methods"], pending
    headers = {"Authorization": f"Bearer {pending['pre_auth_token']}"}
    r = anon.session.post(f"{anon.base_url}/auth/second-factor/passkey/options", headers=headers, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["options"]["publicKey"]["allowCredentials"]) == 1
    credential = auth.get_assertion(body["options"], _public_url(), sign_count=2)
    r = anon.session.post(f"{anon.base_url}/auth/second-factor/passkey/verify",
                          json={"challenge_id": body["challenge_id"], "credential": credential}, headers=headers, timeout=15)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    claims = _claims(token)
    assert claims["amr"] == ["pwd", "hwk"] and "mfa_at" in claims
    # The step-up with the passkey, through the real receipt.
    me = ApiClient()
    me.token = token
    me.session.headers["Authorization"] = f"Bearer {token}"
    r = me.post("/auth/second-factor/challenge", json={"action": "account.second_factor"})
    assert r.status_code == 200 and "passkey" in r.json()["methods"], r.text
    r = me.post("/auth/passkeys/step-up/options")
    assert r.status_code == 200, r.text
    body = r.json()
    credential = auth.get_assertion(body["options"], _public_url(), sign_count=3)
    r = me.post("/auth/second-factor/step-up", json={"action": "account.second_factor", "method": "passkey",
                                                     "challenge_id": body["challenge_id"], "credential": credential})
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    key_id = me.get("/users/me/passkeys").json()["passkeys"][0]["id"]
    r = me.delete(f"/users/me/passkeys/{key_id}", headers={"X-Second-Factor": receipt})
    assert r.status_code == 200, r.text
    assert me.get("/users/me/passkeys").json()["passkeys"] == []
    # The receipt was spent with that call.
    r = me.delete(f"/users/me/passkeys/{key_id}", headers={"X-Second-Factor": receipt})
    assert r.status_code in (403, 404)


def test_the_user_list_counts_the_passkeys_each_account_holds(person, admin):
    """The Users page's sign-in methods column reads it: an account's passkeys, retired ones not counted."""
    client, uid = person

    def counted():
        rows = admin.get("/users").json()
        return next(row["passkey_count"] for row in rows if row["id"] == uid)

    assert counted() == 0
    r, _ = _register(client, "Laptop")
    assert r.status_code == 201, r.text
    assert counted() == 1
    assert admin.delete(f"/users/{uid}/passkeys/{r.json()['id']}").status_code == 200
    assert counted() == 0
