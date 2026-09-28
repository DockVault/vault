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
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
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


def test_an_unknown_account_is_refused(admin):
    answer = tool("lookup", "--username", "no-such-account-anywhere")
    assert not answer["ok"] and "no account" in answer["error"].lower()
