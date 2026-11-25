"""Shared helpers for the live tests of the auditor right: a compliance step-up receipt, a pass of the pruner,
the audit rows about an account, and an account holding the right granted by two administrators. Imported by
the test modules that need them; holds no tests."""
import json
import time
from contextlib import contextmanager

from _account_change_helpers import in_api_container, own_password, psql, second_admin, signed_in
from _sf_helpers import enroll_totp


def compliance_receipt(client, action, password, codes):
    """A receipt for a compliance step: the password and a recovery code, both, every time."""
    r = client.post("/auth/second-factor/step-up", json={"action": action, "method": "recovery",
                                                         "code": codes.pop(0), "password": password})
    assert r.status_code == 200, r.text
    return {"X-Second-Factor": r.json()["receipt"]}


def signed_in_with_code(user, codes, client=None):
    """A client signed in as ``user``, whose account has an authenticator: the password, then one of its
    recovery codes (``codes``, consumed). ``client``: sign this one in again, in place of making another (its
    session was ended, and every reference a test holds to it goes on working)."""
    from conftest import ApiClient, BASE_URL
    client = client or ApiClient(BASE_URL)
    client.session.headers.pop("Authorization", None)
    r = client.session.post(f"{BASE_URL}/auth/login",
                            json={"username": user["_username"], "password": user["_password"]}, timeout=15)
    assert r.status_code == 200 and r.json().get("second_factor_required"), r.text
    pre = {"Authorization": f"Bearer {r.json()['pre_auth_token']}"}
    r = client.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=pre,
                            json={"method": "recovery", "code": codes.pop(0)}, timeout=15)
    assert r.status_code == 200, r.text
    client.token = r.json()["access_token"]
    client.session.headers.update({"Authorization": f"Bearer {client.token}"})
    return client


def run_pass():
    """One pass of the pruner in the web container, retried while the web app's own runner holds its lock.
    Returns {job: whether it ran}."""
    source = ("import json\n"
              "from app.core import retention\n"
              "done = retention.run_pass()\n"
              "print(json.dumps(None if done is None else {n: r is not None for n, r in done}))\n")
    for _ in range(30):
        out = json.loads(in_api_container(source).stdout.strip().splitlines()[-1])
        if out is not None:
            return out
        time.sleep(1)
    raise AssertionError("the pruner's lock never came free")


def audit_rows(admin, action, uid):
    rows = admin.get("/audit/log", params={"action": action, "limit": 500}).json()
    return [a for a in rows if a["resource_id"] == uid]


@contextmanager
def two_admins(admin):
    """Two independent administrators of long standing (ada proposes, bob approves), each with their own
    password and an authenticator: {"ada": (account, client, codes), "bob": (...)}."""
    with second_admin(admin, independent=True) as (ada, ada_c), second_admin(admin, independent=True) as (bob, bob_c):
        _s, ada_codes = enroll_totp(ada, ada_c)
        _s, bob_codes = enroll_totp(bob, bob_c)
        yield {"ada": (ada, ada_c, ada_codes), "bob": (bob, bob_c, bob_codes)}


# The accounts made here, by id: (account, client, recovery codes). The approval of an auditor right ends the
# holder's sessions (a session made before it does not carry the right), so the holder's client signs in again
# where the right is granted.
_HOLDERS = {}


def new_auditor_account(admin):
    """An account that set its own password and has an authenticator: (account, client, recovery codes)."""
    uma = own_password(admin.create_user(role="user"))
    uma_c = signed_in(uma)
    _s, codes = enroll_totp(uma, uma_c)
    _HOLDERS[str(uma["id"])] = (uma, uma_c, codes)
    return uma, uma_c, codes


def sign_in_after_the_approval(user, client, codes):
    """The holder's sessions ended when their right was approved, a moment after the approval's answer: wait for
    that, then sign ``client`` in again with the password and a recovery code."""
    deadline = time.time() + 15
    while time.time() < deadline and client.get("/compliance/me").status_code != 401:
        time.sleep(0.2)
    return signed_in_with_code(user, codes, client=client)


def grant_right(admins, user_id):
    """Propose the right for ``user_id`` as ada and approve it as bob. Returns the grant's id."""
    ada, ada_c, ada_codes = admins["ada"]
    bob, bob_c, bob_codes = admins["bob"]
    r = ada_c.post("/compliance/auditor-grants", json={"user_id": user_id},
                   headers=compliance_receipt(ada_c, "compliance.grant.propose", ada["_password"], ada_codes))
    assert r.status_code == 201, r.text
    grant_id = r.json()["id"]
    r = bob_c.post(f"/compliance/auditor-grants/{grant_id}/approve",
                   headers=compliance_receipt(bob_c, "compliance.grant.approve", bob["_password"], bob_codes))
    assert r.status_code == 200 and r.json()["status"] == "active", r.text
    held = _HOLDERS.get(str(user_id))
    if held is not None:
        sign_in_after_the_approval(*held)
    return grant_id


def forget_grants(*user_ids):
    """Remove the test's grants (the right's records are otherwise kept for ever)."""
    ids = ", ".join(f"'{u}'" for u in user_ids if u)
    if ids:
        psql(f"DELETE FROM auditor_grants WHERE user_id IN ({ids}) OR proposed_by IN ({ids})")
