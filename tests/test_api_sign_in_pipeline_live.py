"""The sign-in pipeline on a live stack: the sign-in paths answer as they always did, their tokens carry
the proofs (``amr``), ``auth_time`` and ``mfa_at``, the audit row names the proofs, and the password
stage (a sign-in that proved who the person is another way and must add the password) counts wrong
answers like the form does.

No route reaches the password stage yet (passkeys and single sign-on arrive later), so its token is
minted inside the API container with the server's own secret and its pending login is written to the
database, as those routes will do.
"""
import base64
import json
import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import ApiClient, BASE_URL                                    # noqa: E402
from _sf_helpers import enrolled_admin, enroll_totp, step_up_receipt, totp  # noqa: E402

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")

LOGIN = f"{BASE_URL}/auth/login"
VERIFY = f"{BASE_URL}/auth/second-factor/verify"
CANCEL = f"{BASE_URL}/auth/second-factor/cancel"

# The answers the web app knows, pinned key for key.
LOGIN_KEYS = {"access_token", "token_type", "user", "is_temporary", "is_scoped_temp"}
PENDING_KEYS = {"access_token", "second_factor_required", "enrollment_required", "methods", "enrollment_methods",
                "stage", "pre_auth_token"}
VERIFY_KEYS = {"access_token", "token_type", "recovery_code_used", "recovery_codes_remaining"}
ACKNOWLEDGE_KEYS = {"enrolled", "method", "access_token", "token_type"}
# A session token's claims (every sign-in has an id of its own, which its renewals keep), and what a second kind of
# factor adds.
TOKEN_KEYS = {"sub", "username", "session_token", "is_temporary", "amr", "auth_time", "sign_in_id", "exp", "iat"}
PRE_AUTH_KEYS = {"sub", "username", "stage", "pre_auth", "methods_so_far", "ended", "exp", "iat"}


def _db(sql):
    r = subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _claims(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def _near_now(ts):
    return abs(int(ts) - time.time()) < 300


def _login_success_methods(user_id):
    row = _db(f"select details::text from audit_logs where user_id = '{user_id}' and action = 'login_success' "
              f"order by timestamp desc limit 1")
    assert row, "no login_success row"
    return json.loads(row).get("methods")


def _pending_row(user_id):
    """A pending login for the account, unspent, with five minutes to live, as a passkey or provider sign-in
    will write it."""
    pid = str(uuid.uuid4())
    _db(f"insert into pending_logins (id, user_id, client_ip, enrollment_required, attempts, expires_at, created_at) "
        f"values ('{pid}', '{user_id}', null, false, 0, (now() at time zone 'utc') + interval '5 minutes', "
        f"now() at time zone 'utc')")
    return pid


def _ended(user_id) -> int:
    """How many times the account's sessions were ended as a whole: what a held sign-in carries from its first
    proof, and is compared with when it is completed."""
    return int(_db(f"select sessions_ended from users where id = '{user_id}'"))


def _mint(claims, minutes=5):
    """A pre-authentication token signed with the server's own key, minted inside the API container. It carries
    the account's count as it stands, as a sign-in held just now would."""
    claims = {"ended": _ended(claims["sub"]), **claims}
    code = ("import json, sys; from datetime import timedelta; from app.core.security import create_access_token; "
            f"print(create_access_token(json.loads(sys.argv[1]), expires_delta=timedelta(minutes={minutes})))")
    r = subprocess.run(["docker", "exec", _API_CONTAINER, "python", "-c", code, json.dumps(claims)],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().splitlines()[-1]


def _attempts(pid):
    return int(_db(f"select attempts from pending_logins where id = '{pid}'"))


def _spent(pid):
    return _db(f"select consumed_at is not null from pending_logins where id = '{pid}'") == "t"


def test_a_password_sign_in_answers_as_before_and_its_token_names_the_proof(temp_user):
    c = ApiClient()
    r = c.session.post(LOGIN, json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == LOGIN_KEYS
    assert body["token_type"] == "bearer" and body["is_temporary"] is False and body["is_scoped_temp"] is False
    assert body["user"]["username"] == temp_user["_username"]
    claims = _claims(body["access_token"])
    assert set(claims) == TOKEN_KEYS, claims
    assert claims["amr"] == ["pwd"] and claims["is_temporary"] is False and _near_now(claims["auth_time"])
    assert claims["sub"] == temp_user["id"] and claims["session_token"]
    me = c.session.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert _login_success_methods(temp_user["id"]) == ["pwd"]
    # A second sign-in of the same person is another sign-in: its id differs, whatever second it happens in.
    again = c.session.post(LOGIN, json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert again.status_code == 200, again.text
    second = _claims(again.json()["access_token"])
    assert claims["sign_in_id"] and second["sign_in_id"] and second["sign_in_id"] != claims["sign_in_id"]


def test_a_temporary_credential_sign_in_answers_as_before_and_names_the_proof(admin):
    minted = admin.post("/auth/temp-credentials", json={}).json()
    c = ApiClient()
    r = c.session.post(LOGIN, json={"username": minted["temp_username"], "password": minted["credential"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == LOGIN_KEYS and body["is_temporary"] is True
    claims = _claims(body["access_token"])
    assert set(claims) == TOKEN_KEYS, claims
    assert claims["amr"] == ["pwd"] and claims["is_temporary"] is True and _near_now(claims["auth_time"])


def test_a_two_step_sign_in_answers_as_before_plus_the_stage_and_its_token_names_both_proofs(temp_user,
                                                                                                temp_user_client):
    secret, _codes = enroll_totp(temp_user, temp_user_client)
    fresh = ApiClient()
    r = fresh.session.post(LOGIN, json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == PENDING_KEYS, body
    assert body["access_token"] is None and body["second_factor_required"] is True
    assert body["enrollment_required"] is False and body["stage"] == "second_factor"
    assert body["methods"] == ["totp", "recovery"] and body["enrollment_methods"] == []
    pre = _claims(body["pre_auth_token"])
    assert set(pre) == PRE_AUTH_KEYS, pre
    assert pre["stage"] == "second_factor" and pre["methods_so_far"] == ["pwd"]
    ph = {"Authorization": f"Bearer {body['pre_auth_token']}"}
    # The pre-auth token is no session.
    assert fresh.session.get(f"{BASE_URL}/users/me", headers=ph).status_code == 401
    # The next code (the enrollment confirm spent this step's).
    v = fresh.session.post(VERIFY, headers=ph, json={"method": "totp", "code": totp(secret, 1)})
    assert v.status_code == 200, v.text
    vb = v.json()
    assert set(vb) == VERIFY_KEYS, vb
    assert vb["token_type"] == "bearer" and vb["recovery_code_used"] is False
    assert isinstance(vb["recovery_codes_remaining"], int) and vb["recovery_codes_remaining"] > 0
    claims = _claims(vb["access_token"])
    assert set(claims) == TOKEN_KEYS | {"mfa_at"}, claims
    assert claims["amr"] == ["pwd", "totp"] and _near_now(claims["auth_time"]) and _near_now(claims["mfa_at"])
    me = fresh.session.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {vb['access_token']}"})
    assert me.status_code == 200
    assert _login_success_methods(temp_user["id"]) == ["pwd", "totp"]
    # The pending login is spent.
    assert fresh.session.post(VERIFY, headers=ph, json={"method": "totp", "code": totp(secret, 1)}).status_code == 401


def _set_mfa_mode(c, codes, mode):
    r = c.put("/settings", json={"mfa_mode": mode},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
    r.raise_for_status()


def test_a_forced_enrollment_answers_as_before_plus_what_may_be_enrolled(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    newu = admin.create_user(role="user")
    try:
        _set_mfa_mode(c, codes, "required")
        try:
            fresh = ApiClient()
            r = fresh.session.post(LOGIN, json={"username": newu["_username"], "password": newu["_password"]})
            assert r.status_code == 200, r.text
            body = r.json()
            assert set(body) == PENDING_KEYS, body
            assert body["access_token"] is None and body["second_factor_required"] is True
            assert body["enrollment_required"] is True and body["stage"] == "second_factor"
            assert body["methods"] == [] and body["enrollment_methods"] == ["totp"]
            assert _claims(body["pre_auth_token"])["methods_so_far"] == ["pwd"]
            ph = {"Authorization": f"Bearer {body['pre_auth_token']}"}
            secret = fresh.session.post(f"{BASE_URL}/users/me/second-factor/totp/enroll", headers=ph,
                                        json={"current_password": newu["_password"]}).json()["secret"]
            cr = fresh.session.post(f"{BASE_URL}/users/me/second-factor/totp/confirm", headers=ph,
                                    json={"code": totp(secret)})
            assert cr.status_code == 200, cr.text
            ar = fresh.session.post(f"{BASE_URL}/users/me/second-factor/recovery/acknowledge", headers=ph)
            assert ar.status_code == 200, ar.text
            ab = ar.json()
            assert set(ab) == ACKNOWLEDGE_KEYS, ab
            assert ab["enrolled"] is True and ab["method"] == "totp" and ab["token_type"] == "bearer"
            claims = _claims(ab["access_token"])
            assert set(claims) == TOKEN_KEYS | {"mfa_at"}, claims
            assert claims["amr"] == ["pwd", "totp"] and _near_now(claims["mfa_at"])
            me = fresh.session.get(f"{BASE_URL}/users/me/second-factor",
                                   headers={"Authorization": f"Bearer {ab['access_token']}"})
            assert me.status_code == 200 and me.json()["enrolled"] is True
            assert _login_success_methods(newu["id"]) == ["pwd", "totp"]
            # Spent: a second acknowledge is refused.
            assert fresh.session.post(f"{BASE_URL}/users/me/second-factor/recovery/acknowledge",
                                      headers=ph).status_code == 401
        finally:
            _set_mfa_mode(c, codes, "optional")
    finally:
        admin.delete_user(newu["id"])
        admin.delete_user(ta["id"])


def test_the_password_stage_adds_the_password_to_a_proof_and_counts_wrong_answers(admin):
    user = admin.create_user(role="user")
    other = admin.create_user(role="user")
    try:
        pid = _pending_row(user["id"])
        token = _mint({"sub": user["id"], "username": user["_username"], "stage": "password", "pre_auth": pid,
                       "methods_so_far": ["hwk"]})
        h = {"Authorization": f"Bearer {token}"}
        # The token is no session either.
        assert ApiClient().session.get(f"{BASE_URL}/users/me", headers=h).status_code == 401
        # A wrong password: refused as at the form, and counted against the pending login.
        r = ApiClient().session.post(LOGIN, headers=h,
                                     json={"username": user["_username"], "password": "wrong-" + user["_password"]})
        assert r.status_code == 401, r.text
        assert _attempts(pid) == 1 and not _spent(pid)
        # Another account's name with that account's right password: the token cannot be turned on it.
        r = ApiClient().session.post(LOGIN, headers=h,
                                     json={"username": other["_username"], "password": other["_password"]})
        assert r.status_code == 401, r.text
        assert _attempts(pid) == 2 and not _spent(pid)
        # The right password finishes the sign-in: both kinds of factor were present.
        c = ApiClient()
        r = c.session.post(LOGIN, headers=h, json={"username": user["_username"], "password": user["_password"]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == LOGIN_KEYS and body["user"]["username"] == user["_username"]
        claims = _claims(body["access_token"])
        assert set(claims) == TOKEN_KEYS | {"mfa_at"}, claims
        assert claims["amr"] == ["hwk", "pwd"] and _near_now(claims["mfa_at"]) and _near_now(claims["auth_time"])
        assert c.session.get(f"{BASE_URL}/users/me",
                             headers={"Authorization": f"Bearer {body['access_token']}"}).status_code == 200
        assert _spent(pid)
        assert _login_success_methods(user["id"]) == ["hwk", "pwd"]
        # Spent: the same token with the right password is refused.
        r = ApiClient().session.post(LOGIN, headers=h,
                                     json={"username": user["_username"], "password": user["_password"]})
        assert r.status_code == 401, r.text

        # The pending login's own cap: five wrong passwords for the right name spend it (each also counts in
        # the account's lockouts, as at the form), and the right password is refused afterwards.
        pid2 = _pending_row(user["id"])
        token2 = _mint({"sub": user["id"], "username": user["_username"], "stage": "password", "pre_auth": pid2,
                        "methods_so_far": ["swk"]})
        h2 = {"Authorization": f"Bearer {token2}"}
        for n in range(1, 6):
            r = ApiClient().session.post(LOGIN, headers=h2,
                                         json={"username": user["_username"], "password": f"wrong-{n}"})
            assert r.status_code in (401, 403), r.text
            assert _attempts(pid2) == n
        assert _spent(pid2)
        r = ApiClient().session.post(LOGIN, headers=h2,
                                     json={"username": user["_username"], "password": user["_password"]})
        assert r.status_code in (401, 403), r.text

        # A password-stage token is no second-factor token: refused at the verify and cancel routes.
        pid4 = _pending_row(user["id"])
        token4 = _mint({"sub": user["id"], "username": user["_username"], "stage": "password", "pre_auth": pid4,
                        "methods_so_far": ["hwk"]})
        h4 = {"Authorization": f"Bearer {token4}"}
        assert ApiClient().session.post(VERIFY, headers=h4, json={"method": "totp", "code": "000000"}).status_code == 401
        assert ApiClient().session.post(CANCEL, headers=h4).status_code == 401
        assert not _spent(pid4)

        # A second-factor stage a passkey reached without the password is refused wherever the token is read.
        pid3 = _pending_row(user["id"])
        token3 = _mint({"sub": user["id"], "username": user["_username"], "stage": "second_factor", "pre_auth": pid3,
                        "methods_so_far": ["hwk"]})
        h3 = {"Authorization": f"Bearer {token3}"}
        assert ApiClient().session.post(VERIFY, headers=h3, json={"method": "totp", "code": "000000"}).status_code == 401
        assert ApiClient().session.post(CANCEL, headers=h3).status_code == 401
        assert not _spent(pid3)
    finally:
        admin.delete_user(user["id"])
        admin.delete_user(other["id"])


def test_an_administrator_without_the_password_is_asked_for_it_and_then_signed_in(admin):
    """An administrator who proved a user-verified passkey still types the password: the stage after it is the
    password, and password plus passkey is the whole sign-in (no code asked on top)."""
    ta = admin.create_user(role="admin")
    try:
        pid = _pending_row(ta["id"])
        token = _mint({"sub": ta["id"], "username": ta["_username"], "stage": "password", "pre_auth": pid,
                       "methods_so_far": ["hwk"]})
        r = ApiClient().session.post(LOGIN, headers={"Authorization": f"Bearer {token}"},
                                     json={"username": ta["_username"], "password": ta["_password"]})
        assert r.status_code == 200, r.text
        assert set(r.json()) == LOGIN_KEYS
        claims = _claims(r.json()["access_token"])
        assert set(claims) == TOKEN_KEYS | {"mfa_at"}, claims
        assert claims["amr"] == ["hwk", "pwd"]
    finally:
        admin.delete_user(ta["id"])


def _store_code(user_id, methods, verifier, **flags):
    """A one-time sign-in code written to the stack's own code store, as a passkey or provider sign-in will
    write it, with the tab verifier's hash."""
    code = ("import json, sys; from app.core import sign_in_codes as c; d = json.loads(sys.argv[1]); "
            "print(c.store(c.Handover(verifier_hash=c.digest(sys.argv[2]), **d)))")
    record = {"user_id": user_id, "methods": methods, "client_ip": None, "ended": _ended(user_id), **flags}
    r = subprocess.run(["docker", "exec", _API_CONTAINER, "python", "-c", code, json.dumps(record), verifier],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().splitlines()[-1]


def test_a_one_time_code_finishes_a_sign_in_once_and_holds_a_half_proof_for_the_password(admin):
    user = admin.create_user(role="user")
    try:
        # A user-verified passkey the policy allows alone: the code becomes the session, once.
        verifier = uuid.uuid4().hex + uuid.uuid4().hex
        code = _store_code(user["id"], ["hwk"], verifier, user_verified=True, passwordless_allowed=True)
        c = ApiClient()
        r = c.session.post(f"{BASE_URL}/auth/finish", json={"code": code, "verifier": verifier})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == LOGIN_KEYS and body["user"]["username"] == user["_username"]
        claims = _claims(body["access_token"])
        assert set(claims) == TOKEN_KEYS | {"mfa_at"} and claims["amr"] == ["hwk"]
        assert c.session.get(f"{BASE_URL}/users/me",
                             headers={"Authorization": f"Bearer {body['access_token']}"}).status_code == 200
        assert _login_success_methods(user["id"]) == ["hwk"]
        assert ApiClient().session.post(f"{BASE_URL}/auth/finish",
                                        json={"code": code, "verifier": verifier}).status_code == 401
        # A wrong verifier spends the code.
        code = _store_code(user["id"], ["hwk"], verifier, user_verified=True, passwordless_allowed=True)
        assert ApiClient().session.post(f"{BASE_URL}/auth/finish", json={"code": code, "verifier": "x"}).status_code == 401
        assert ApiClient().session.post(f"{BASE_URL}/auth/finish",
                                        json={"code": code, "verifier": verifier}).status_code == 401
        # A passkey without user verification: held for the password, which then finishes it with both proofs.
        code = _store_code(user["id"], ["hwk"], verifier)
        r = ApiClient().session.post(f"{BASE_URL}/auth/finish", json={"code": code, "verifier": verifier})
        assert r.status_code == 200, r.text
        held = r.json()
        assert held["access_token"] is None and held["stage"] == "password" and held["username"] == user["_username"]
        r = ApiClient().session.post(LOGIN, headers={"Authorization": f"Bearer {held['pre_auth_token']}"},
                                     json={"username": user["_username"], "password": user["_password"]})
        assert r.status_code == 200, r.text
        assert _claims(r.json()["access_token"])["amr"] == ["hwk", "pwd"]
    finally:
        admin.delete_user(user["id"])


def test_a_second_factor_stage_token_at_the_sign_in_form_is_ignored(temp_user):
    """Only a password-stage token means anything at POST /auth/login: a second-factor token sent there leaves
    the form sign-in exactly as it always was, and the pending login it names untouched."""
    pid = _pending_row(temp_user["id"])
    token = _mint({"sub": temp_user["id"], "username": temp_user["_username"], "stage": "second_factor",
                   "pre_auth": pid, "methods_so_far": ["pwd"]})
    r = ApiClient().session.post(LOGIN, headers={"Authorization": f"Bearer {token}"},
                                 json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200, r.text
    assert set(r.json()) == LOGIN_KEYS and _claims(r.json()["access_token"])["amr"] == ["pwd"]
    assert not _spent(pid) and _attempts(pid) == 0
