"""The address rule of passkeys and single sign-on against a running vault, on whichever of its two sides the
stack is configured for.

With an address configured (the first ALLOWED_HOSTS entry, as CI sets it): the administrator's pages say so, a
passkey is asked for at that address, and a provider's draft has its redirect, logout and hand-out addresses on it,
also for a request that names another host the vault answers to.

With none (ALLOWED_HOSTS empty): passkeys and single sign-on are refused with a sentence that says what to set, the
sign-in page offers neither, and a provider can be drafted but neither tested nor turned on. Nothing is built from
the host a request names.

Each test runs on its side and is skipped on the other; a round runs the file once on a stack of each kind.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

ACTION = "admin.auth_policy.write"


@pytest.fixture
def boss(admin):
    """An administrator of the test's own (the step-up's budget is kept per account), with its password on the
    client; deleted on teardown, with every provider it made."""
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    client.password = user["_password"]
    client.made = []
    yield client
    for provider_id in client.made:
        client.delete(f"/admin/sso/providers/{provider_id}", headers=_receipt(client))
    admin.delete_user(user["id"])


def _receipt(client):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "password": client.password})
    assert r.status_code == 200, r.text
    return {"X-Second-Factor": r.json()["receipt"]}


def _address(client):
    return client.get("/admin/sso/providers").json()["address"]


def _draft(client):
    r = client.post("/admin/sso/providers", json={"name": unique("idp"), "preset": "keycloak"}, headers=_receipt(client))
    assert r.status_code == 201, r.text
    provider = r.json()["provider"]
    client.made.append(provider["id"])
    return provider


def _filled(client, provider):
    r = client.patch(f"/admin/sso/providers/{provider['id']}", headers=_receipt(client), json={
        "issuer": "https://login.example.org/realms/staff", "client_id": "vault", "client_secret": "s3cret"})
    assert r.status_code == 200, r.text
    assert "s3cret" not in r.text
    return r.json()["provider"]


def test_with_an_address_everything_is_built_on_it_whatever_host_a_request_names(boss):
    address = _address(boss)
    if not address["usable"]:
        pytest.skip("this stack has no configured address (ALLOWED_HOSTS is empty)")
    base = address["base"]
    assert base == BASE_URL and address["why_not"] is None
    readiness = boss.get("/settings/sign-in").json()
    assert readiness["readiness"]["usable"] is True and readiness["readiness"]["origin"] == base
    assert readiness["why_not"] == ""
    provider = _filled(boss, _draft(boss))
    pid = provider["id"]
    assert provider["addresses"] == {"redirect_uri": f"{base}/auth/sso/{pid}/callback",
                                     "backchannel_logout_uri": f"{base}/auth/sso/{pid}/backchannel-logout",
                                     "post_logout_redirect_uri": f"{base}/",
                                     "sign_in_link": f"{base}/?sso={pid}"}
    # Another host the vault answers to (the name the containers reach it by) changes nothing that is given out.
    for host in ("vault-api", "vault-api:8000"):
        r = boss.get(f"/admin/sso/providers/{pid}", headers={"Host": host})
        if r.status_code == 400:
            continue                                   # a stack that does not answer to that name at all
        assert r.status_code == 200, r.text
        assert r.json()["provider"]["addresses"]["redirect_uri"] == f"{base}/auth/sso/{pid}/callback"
        assert boss.get("/settings/sign-in", headers={"Host": host}).json()["readiness"]["origin"] == base
    # Nor do the other headers a caller writes an address in change anything that is given out.
    for forged in ({"Origin": "https://evil.example.org"}, {"Referer": "https://evil.example.org/x"},
                   {"X-Forwarded-Host": "evil.example.org"}, {"X-Forwarded-Proto": "http"},
                   {"X-Forwarded-Port": "1"}, {"Forwarded": "host=evil.example.org;proto=http"}):
        r = boss.get(f"/admin/sso/providers/{pid}", headers=forged)
        assert r.status_code == 200, (forged, r.text)
        assert r.json()["provider"]["addresses"]["redirect_uri"] == f"{base}/auth/sso/{pid}/callback", forged
        assert "evil.example.org" not in r.text, forged
        assert boss.get("/settings/sign-in", headers=forged).json()["readiness"]["origin"] == base, forged
        assert boss.get("/auth/policy", headers=forged).json()["methods"]["origin"] == base, forged
    # A host the vault does not answer to is refused outright, before any route.
    forged = boss.get(f"/admin/sso/providers/{pid}", headers={"Host": "evil.example.org"})
    assert forged.status_code == 400 and "evil.example.org" not in forged.text
    # A passkey is asked for at the configured address.
    r = boss.post("/users/me/passkeys/register/options", json={"current_password": boss.password})
    assert r.status_code == 200, r.text
    assert r.json()["options"]["publicKey"]["rp"]["id"] == base.split("://", 1)[1].split(":")[0]
    # Not turned on without a test sign-in, and that is the only thing in the way.
    r = boss.post(f"/admin/sso/providers/{pid}/state", json={"state": "enabled"}, headers=_receipt(boss))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "not_tested", r.text


def test_without_an_address_passkeys_and_single_sign_on_are_refused_in_words(boss, anon):
    address = _address(boss)
    if address["usable"]:
        pytest.skip("this stack has a configured address (ALLOWED_HOSTS is set)")
    assert address["base"] is None
    assert address["why_not"].startswith("Single sign-on needs the vault's public address. ")
    assert "ALLOWED_HOSTS" in address["why_not"]
    readiness = boss.get("/settings/sign-in").json()
    assert readiness["readiness"]["usable"] is False and "ALLOWED_HOSTS" in readiness["why_not"]
    # The sign-in page offers neither.
    methods = anon.get("/auth/policy").json()["methods"]
    assert methods["passkeys"] is False and methods["providers"] == []
    # A passkey cannot be made, and the sentence says why; a request's own host is no address.
    for headers in ({}, {"Host": "vault.example.org"}, {"X-Forwarded-Host": "vault.example.org"}):
        r = boss.post("/users/me/passkeys/register/options", json={"current_password": boss.password}, headers=headers)
        assert r.status_code == 409, r.text
        assert r.json()["detail"].startswith("Passkeys need the vault's public address. "), r.text
        assert "vault.example.org" not in r.text
    r = anon.post("/auth/passkeys/sign-in/options", json={})
    assert r.status_code == 409 and r.json()["detail"] == "Passkeys are not available on this deployment."
    # A provider can be drafted and filled in; it has no addresses to give, and is neither tested nor turned on.
    provider = _filled(boss, _draft(boss))
    pid = provider["id"]
    assert provider["addresses"] is None and provider["configured"] is True
    for headers in ({}, {"Host": "vault.example.org"}, {"X-Forwarded-Host": "vault.example.org"}):
        r = boss.post(f"/admin/sso/providers/{pid}/test/start", json={"verifier_hash": "a" * 64}, headers=headers)
        assert r.status_code == 409 and r.json()["detail"]["reason"] == "no_public_address", r.text
        assert "vault.example.org" not in r.text
        shown = boss.get(f"/admin/sso/providers/{pid}", headers=headers).json()["provider"]
        assert shown["addresses"] is None
    r = boss.post(f"/admin/sso/providers/{pid}/state", json={"state": "enabled"}, headers=_receipt(boss))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["reason"] == "no_public_address" and detail["message"] == address["why_not"]
    # A sign-in at it cannot start either, for anyone.
    r = anon.post(f"/auth/sso/{pid}/start", json={"verifier_hash": "a" * 64})
    assert r.status_code in (404, 409), r.text


def test_the_provider_pages_keep_their_rules_on_a_running_vault(boss):
    """The order every write keeps, against the real step-up: judged first, then the password, then written."""
    r = boss.post("/admin/sso/providers", json={"name": unique("idp")})
    assert r.status_code == 403 and r.json()["detail"]["action"] == ACTION, r.text       # no receipt: nothing made
    provider = _draft(boss)
    pid = provider["id"]
    assert provider["state"] == "draft" and provider["icon"] == "keycloak" and provider["tested"] is False
    r = boss.patch(f"/admin/sso/providers/{pid}", json={"issuer": "http://plain.example.org"})
    assert r.status_code == 400 and r.json()["detail"]["message"] == "Issuer: The endpoint must use https.", r.text
    r = boss.patch(f"/admin/sso/providers/{pid}", json={"label": "Company sign-in"})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "step_up_required", r.text
    receipt = _receipt(boss)
    r = boss.patch(f"/admin/sso/providers/{pid}", json={"label": "Company sign-in"}, headers=receipt)
    assert r.status_code == 200 and r.json()["changed"] == ["label"], r.text
    # A receipt is used once.
    r = boss.patch(f"/admin/sso/providers/{pid}", json={"label": "Again"}, headers=receipt)
    assert r.status_code == 403, r.text
    listed = [p for p in boss.get("/admin/sso/providers").json()["providers"] if p["id"] == pid]
    assert listed and listed[0]["label"] == "Company sign-in"
    assert not {"client_secret", "client_secret_enc"} & set(listed[0]) and listed[0]["has_client_secret"] is False
    r = boss.delete(f"/admin/sso/providers/{pid}", headers=_receipt(boss))
    assert r.status_code == 200 and r.json() == {"removed": True}
    boss.made.remove(pid)
    assert boss.get(f"/admin/sso/providers/{pid}").status_code == 404
