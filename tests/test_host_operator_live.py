"""Live: the host operator's account tool, run inside the web container as `dockvault.py accounts` runs
it (python -m app.core.host_operator).

  * a password reset (a reset link, or a temporary password on request) and a second-factor reset are
    made even inside an administrator's 14-day window: the host operator is the way round that rule;
  * each is recorded and audited as done by the host operator (operator@host);
  * approving a held request applies it as it was asked for;
  * nothing changes unless the account's username is given twice and matches;
  * the secret is only in the tool's answer: not in the web container's log, not in the audit log.

test_dockvault_accounts.py covers the host side offline.
"""
import json
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent
from _account_change_helpers import API, psql, second_admin, signed_in
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration

HOST = "operator@host"


def tool(*args):
    try:
        r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.host_operator", *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, (r.stderr or "")[-800:]
    answer = json.loads(lines[-1])
    assert r.returncode == (0 if answer["ok"] else 2), (r.returncode, answer)
    return answer


def _audit(admin, action, uid):
    rows = admin.get("/audit/log", params={"action": action, "limit": 500}).json()
    return [a for a in rows if a["resource_id"] == uid]


def test_a_reset_link_from_the_host_even_inside_the_window(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    assert admin.patch(f"/users/{uid}", json={"password": "Admin-Chosen-8x!"}).status_code == 200
    answer = tool("reset-password", "--username", name, "--confirm-username", name)
    assert answer["ok"] and answer["secret_kind"] == "reset_link", answer
    token = answer["secret"].split("?reset=", 1)[1]
    assert ApiClient(BASE_URL).get(f"/reset/{token}").json()["username"] == name

    assert psql(f"SELECT status, requested_by_name, requested_by_id IS NULL FROM credential_changes "
                f"WHERE target_user_id='{uid}' AND kind='reset_link'") == f"made|{HOST}|t"
    rows = _audit(admin, "password_reset_link_minted", uid)
    assert rows and rows[0]["username"] == HOST
    assert token not in json.dumps(rows), "the link is never in the audit log"
    # The log is UTF-8 (warnings carry symbols); decoded with the host's code page it can fail to read.
    logs = subprocess.run(["docker", "logs", "--since", "3m", API], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=60)
    assert token not in logs.stdout + logs.stderr, "the link is never in the container's log"


def test_a_temporary_password_when_asked_for(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    session = signed_in(temp_user)
    answer = tool("reset-password", "--username", name, "--confirm-username", name, "--temporary-password")
    assert answer["ok"] and answer["secret_kind"] == "temporary_password"
    assert ApiClient(BASE_URL).login(name, answer["secret"])
    assert session.get("/users/me").status_code == 401, "the old sessions end"
    rows = _audit(admin, "user_updated", uid)
    assert rows and rows[0]["username"] == HOST and rows[0]["details"]["changes"] == {"password": "changed"}


def test_a_second_factor_reset_from_the_host(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    enroll_totp(temp_user, signed_in(temp_user))
    answer = tool("reset-second-factor", "--username", name, "--confirm-username", name)
    assert answer["ok"] and answer["had_second_factor"] is True
    assert psql(f"SELECT count(*) FROM second_factor_enrollments WHERE user_id='{uid}'") == "0"
    r = ApiClient(BASE_URL).session.post(f"{BASE_URL}/auth/login",
                                         json={"username": name, "password": temp_user["_password"]})
    assert r.json()["enrollment_required"] is True, "they set up a new factor at the next sign-in"
    assert _audit(admin, "second_factor_admin_reset", uid)[0]["username"] == HOST


def test_the_host_approves_a_held_change(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    with second_admin(admin, independent=True) as (_other, other_client):
        # Both changes by the second administrator: the session's administrator could approve the second,
        # so it waits (with nobody who could, it would be refused outright).
        assert other_client.patch(f"/users/{uid}", json={"email": f"{name}-a@example.com"}).status_code == 200
        held = other_client.patch(f"/users/{uid}", json={"email": f"{name}-b@example.com"})
        assert held.status_code == 202, held.text
        request_id = held.json()["held_changes"][0]["request"]["id"]

        # Decided while the administrator who asked still exists: deleting them withdraws the request.
        listed = tool("list")
        assert request_id in [r["id"] for r in listed["requests"]]

        refused = tool("approve", "--request-id", request_id, "--confirm-username", "someone-else")
        assert not refused["ok"] and "does not match" in refused["error"]
        assert admin.get(f"/users/{uid}").json()["email"] == f"{name}-a@example.com"

        approved = tool("approve", "--request-id", request_id, "--confirm-username", name)
        assert approved["ok"], approved
        assert admin.get(f"/users/{uid}").json()["email"] == f"{name}-b@example.com"
    assert psql(f"SELECT status, decided_by_name FROM credential_changes WHERE id='{request_id}'") == f"approved|{HOST}"
    assert _audit(admin, "credential_change_approved", uid)[0]["username"] == HOST


def test_nothing_changes_unless_the_username_is_typed_again(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    before = psql(f"SELECT password_hash FROM users WHERE id='{uid}'")
    for extra in ([], ["--confirm-username", name.upper()], ["--confirm-username", ""]):
        answer = tool("reset-password", "--username", name, "--temporary-password", *extra)
        assert not answer["ok"] and "match" in answer["error"], answer
    assert psql(f"SELECT password_hash FROM users WHERE id='{uid}'") == before
    assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{uid}'") == "0"


def test_a_reset_for_an_account_that_signs_in_only_through_its_provider_is_refused_in_words(admin, temp_user):
    """Such an account holds no password: a reset link made for it would be refused when it is used. The tool
    says so before anything is written, and shows that the account is provider-only where it is looked up."""
    uid, name = temp_user["id"], temp_user["_username"]
    psql(f"UPDATE users SET sso_only = true WHERE id='{uid}'")
    try:
        shown = tool("lookup", "--username", name)["account"]
        assert shown["sso_only"] is True and shown["providers"] == []
        for extra in ([], ["--temporary-password"]):
            answer = tool("reset-password", "--username", name, "--confirm-username", name, *extra)
            assert not answer["ok"] and "holds no password" in answer["error"], answer
        assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{uid}'") == "0"
        assert psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{uid}'") == "0"
        answer = tool("reset-second-factor", "--username", name, "--confirm-username", name)
        assert answer["ok"] and answer["sso_only"] is True, answer
    finally:
        psql(f"UPDATE users SET sso_only = false WHERE id='{uid}'")


def test_an_unknown_account_is_refused(admin):
    answer = tool("lookup", "--username", "no-such-account-anywhere")
    assert not answer["ok"] and "no account" in answer["error"].lower()


def test_the_host_lists_who_may_manage_users_without_being_an_administrator(admin):
    # An administrator demoted before 0.33.0 kept the administrator's defaults, stored with no granter:
    # the demotion is made here in the database, as such a release left it. A delegate names who granted.
    former = admin.create_user(role="admin")
    delegate = admin.create_user(role="user")
    try:
        psql(f"UPDATE users SET role = 'USER' WHERE id = '{former['id']}'")
        r = admin.post(f"/permissions/users/{delegate['id']}/grant", json={"endpoint_group": "USER_MANAGE"})
        assert r.status_code == 200, r.text
        answer = tool("user-managers")
        assert answer["ok"], answer
        listed = {a["username"]: a for a in answer["accounts"]}
        assert [(p["group"], p["granted_by"]) for p in listed[former["_username"]]["permissions"]] == [
            ("USER_MANAGE", None), ("USER_VIEW", None)]
        assert [(p["group"], p["granted_by"]) for p in listed[delegate["_username"]]["permissions"]] == [
            ("USER_MANAGE", admin.user["username"]), ("USER_VIEW", admin.user["username"])]
        assert all(a["role"] != "admin" for a in answer["accounts"])
        # A demotion through the routes resets them: the account is no longer listed.
        psql(f"UPDATE users SET role = 'ADMIN' WHERE id = '{former['id']}'")
        assert admin.patch(f"/users/{former['id']}", json={"role": "user"}).status_code == 200
        assert former["_username"] not in {a["username"] for a in tool("user-managers")["accounts"]}
    finally:
        admin.delete_user(former["id"])
        admin.delete_user(delegate["id"])


SIGN_IN_SETTINGS = "admin.auth_policy.write"


def _save_passkey_setting(client, setting, value):
    """One passkey setting saved through the Sign-in page's route, behind its step-up."""
    r = client.post("/auth/second-factor/step-up", json={"action": SIGN_IN_SETTINGS, "password": client.password})
    assert r.status_code == 200, r.text
    return client.put(f"/settings/sign-in/{setting}", json={"value": value},
                      headers={"X-Second-Factor": r.json()["receipt"]})


def test_the_tool_acts_on_the_passkey_settings_as_they_were_saved(admin, temp_user):
    """The tool is a process of its own, started for one answer: it reads the settings an administrator saved
    when it starts. It read none, so to the tool passkeys were always "optional" and on, whatever the Sign-in page
    held:

      * lifting a role's passkey requirement for one account (the way out for a person whose browser cannot make
        a passkey) was refused for every account, "there is nothing to lift";
      * an account's passkeys were reported usable, and passkeys "on", in a vault that had turned them off.

    Here the settings are saved through the page's own route in the running server, and the tool is run in the
    container as `dockvault.py accounts` runs it."""
    from _webauthn_softauth import SoftAuthenticator
    uid, name = temp_user["id"], temp_user["_username"]
    boss_account = admin.create_user(role="admin")
    boss = ApiClient()
    boss.login(boss_account["_username"], boss_account["_password"])
    boss.password = boss_account["_password"]
    saved = []
    try:
        page = boss.get("/settings/sign-in").json()
        if not page["readiness"].get("usable"):
            pytest.skip("this stack has no address a passkey can be made at (ALLOWED_HOSTS is empty)")
        before = {row["key"]: row["value"] for row in page["settings"]}
        if before["webauthn_mode"] != "optional" or before["webauthn_required_roles"]:
            pytest.skip("this stack's passkey settings are not the defaults this test starts from")
        # The person registers a passkey while passkeys are on.
        person = signed_in(temp_user)
        r = person.post("/users/me/passkeys/register/options", json={"current_password": temp_user["_password"]})
        assert r.status_code == 200, r.text
        credential = SoftAuthenticator().make_credential(r.json()["options"], BASE_URL.rstrip("/"))
        r = person.post("/users/me/passkeys/register/verify",
                        json={"challenge_id": r.json()["challenge_id"], "credential": credential, "label": "Laptop"})
        assert r.status_code == 201, r.text
        assert tool("lookup", "--username", name)["account"]["passkeys_usable"] == 1
        assert tool("passkey-addresses")["on"] is True

        # No requirement names the role: nothing to lift, and the tool says so.
        answer = tool("clear-passkey-requirement", "--username", name, "--confirm-username", name)
        assert answer["ok"] is False and "there is nothing to lift" in answer["error"], answer

        # Required for the role "user", saved through the route. The tool lifts it for the account.
        for setting, value in (("webauthn_required_roles", ["user"]), ("webauthn_mode", "required_for_roles")):
            r = _save_passkey_setting(boss, setting, value)
            assert r.status_code == 200 and r.json()["status"] == "applied", r.text
            saved.append(setting)
        answer = tool("clear-passkey-requirement", "--username", name, "--confirm-username", name)
        assert answer == {"ok": True, "account": name}, answer
        assert psql(f"SELECT passkey_requirement_cleared_at IS NOT NULL FROM users WHERE id='{uid}'") == "t"
        rows = _audit(admin, "passkey_requirement_cleared", uid)
        assert rows and rows[0]["username"] == HOST
        lifted = [row["username"] for row in boss.get("/settings/sign-in").json()["requirement_lifted_for"]]
        assert name in lifted, lifted
        # Lifted already: said as that, not as "nothing to lift".
        answer = tool("clear-passkey-requirement", "--username", name, "--confirm-username", name)
        assert answer["ok"] is False and "already lifted" in answer["error"], answer

        # Passkeys turned off in the page: the tool reports none usable, and "off".
        r = _save_passkey_setting(boss, "webauthn_mode", "off")
        assert r.status_code == 200 and r.json()["status"] == "applied", r.text
        assert tool("lookup", "--username", name)["account"]["passkeys_usable"] == 0
        assert tool("passkey-addresses")["on"] is False
    finally:
        for setting in ("webauthn_mode", "webauthn_required_roles"):
            if setting in saved:
                restored = _save_passkey_setting(boss, setting, None)
                assert restored.status_code == 200, restored.text
        admin.delete_user(boss_account["id"])

