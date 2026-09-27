"""Live: an administrator cannot remove themselves, and two cannot remove each other at once.

The first half drives every route that could change an administrator's own role, activity or lock
and checks each refuses with the message the dedicated endpoints already used, while resaving the
values you already have (which the admin edit form does on every save) still works.

The second half is the race the last-administrator rule exists for: two administrators removing each
other at the same moment. For the duration of one round every other administrator is given a short
timed lock, so these two are the only ones who can act.

* Over HTTP, on each route that can (demote, deactivate, lock, delete), both requests are sent at
  once. Whichever wins, the other must not succeed as well: it is refused, either by the rule (400)
  or because its sender was just removed (401 or 403). Afterwards at least one of the two can act.
  The web server runs each request's handler to the end before the next one's starts, so the second
  request is usually refused by authentication; this checks the outcome on every route, not that
  the race was hit.
* So the race itself is driven inside the web container, on the real database: one session counts
  and holds the administrator rows, a second one asks about the other administrator and has to wait,
  the first removes its target and commits, and the second then finds the one it asked about is the
  last who can act.

The timed lock expires by itself after a few minutes, so an interrupted run cannot leave the
deployment's own administrator locked out; each round also restores it exactly on the way out.

test_last_admin.py covers the rule offline.
"""
import json
import os
import subprocess
import threading

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent

pytestmark = pytest.mark.integration

LAST_ADMIN_DETAIL = ("This would leave no active administrator. Make another account an "
                     "administrator first.")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    try:
        r = subprocess.run(
            ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-Atc", sql],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, _DB_CONTAINER)
    assert r.returncode == 0, r.stderr[:300]
    return r.stdout.strip()


def _admin_client(admin):
    u = admin.create_user(role="admin")
    c = ApiClient(BASE_URL)
    c.login(u["_username"], u["_password"])
    c.account = u
    return c


def _uid(client):
    return str(client.account["id"])


@pytest.fixture
def admins(admin):
    made = []

    def make():
        c = _admin_client(admin)
        made.append(c)
        return c

    yield make
    ids = [_uid(c) for c in made]
    if ids:
        # Put back whatever a round changed, so the accounts can be deleted normally.
        _psql("UPDATE users SET role='ADMIN', is_active=true, is_locked=false, locked_until=NULL "
              f"WHERE id IN ({', '.join(repr(i) for i in ids)})")
    for c in made:
        r = admin.delete_user(_uid(c))
        assert r.status_code in (200, 404), f"{c.account['_username']} was left behind: {r.text}"


# --------------------------------------------------------------------------- yourself

def test_an_administrator_cannot_change_their_own_role_deactivate_or_lock_themselves(admin, admins):
    me = admins()
    uid = _uid(me)

    for body, message in (({"role": "user"}, "Cannot change your own role"),
                          ({"role": "external"}, "Cannot change your own role"),
                          ({"is_active": False}, "Cannot deactivate your own account"),
                          ({"is_locked": True}, "Cannot lock your own account")):
        r = me.patch(f"/users/{uid}", json=body)
        assert r.status_code == 400, (body, r.status_code, r.text)
        assert r.json()["detail"] == message, r.text

    for body, message in (({"role": "user"}, "Cannot change your own role"),
                          ({"is_active": False}, "Cannot deactivate your own account")):
        r = me.put(f"/api/user-management/users/{uid}", json=body)
        assert r.status_code == 400, (body, r.status_code, r.text)
        assert r.json()["detail"] == message, r.text

    # The dedicated endpoints already refused; they still do, with the same messages.
    r = me.patch(f"/api/user-management/users/{uid}/role", json={"new_role": "user"})
    assert (r.status_code, r.json()["detail"]) == (400, "Cannot change your own role"), r.text
    r = me.post(f"/api/user-management/users/{uid}/toggle-active")
    assert (r.status_code, r.json()["detail"]) == (400, "Cannot deactivate your own account"), r.text
    r = me.post(f"/api/user-management/users/{uid}/toggle-locked")
    assert (r.status_code, r.json()["detail"]) == (400, "Cannot lock your own account"), r.text

    # Resaving what you already have is not a change: the edit form sends every field.
    r = me.patch(f"/users/{uid}", json={"email": me.account["email"], "role": "admin",
                                        "is_active": True, "storage_quota_gb": None})
    assert r.status_code == 200, r.text
    r = me.put(f"/api/user-management/users/{uid}", json={"role": "admin", "is_active": True})
    assert r.status_code == 200, r.text

    shown = admin.get(f"/users/{uid}").json()
    assert (shown["role"], shown["is_active"], shown["is_locked"]) == ("admin", True, False), shown
    assert me.get("/users/me").status_code == 200, "still signed in and still an administrator"


def test_an_administrator_can_still_remove_another_while_others_remain(admin, admins):
    actor, other = admins(), admins()
    r = actor.patch(f"/users/{_uid(other)}", json={"role": "user"})
    assert r.status_code == 200, r.text
    assert admin.get(f"/users/{_uid(other)}").json()["role"] == "user"
    r = actor.post(f"/users/{_uid(other)}/delete")
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- each other, at once

_PATHS = {
    "patch-demote": lambda c, t: c.patch(f"/users/{t}", json={"role": "user"}),
    "patch-deactivate": lambda c, t: c.patch(f"/users/{t}", json={"is_active": False}),
    "patch-lock": lambda c, t: c.patch(f"/users/{t}", json={"is_locked": True}),
    "put-demote": lambda c, t: c.put(f"/api/user-management/users/{t}", json={"role": "user"}),
    "put-deactivate": lambda c, t: c.put(f"/api/user-management/users/{t}", json={"is_active": False}),
    "role-endpoint": lambda c, t: c.patch(f"/api/user-management/users/{t}/role", json={"new_role": "user"}),
    "toggle-active": lambda c, t: c.post(f"/api/user-management/users/{t}/toggle-active"),
    "toggle-locked": lambda c, t: c.post(f"/api/user-management/users/{t}/toggle-locked"),
    "delete": lambda c, t: c.post(f"/users/{t}/delete"),
}


class _OnlyThese:
    """Give every other administrator who can act a short timed lock, and put each back exactly.

    A timed lock rather than a permanent one on purpose: if the run dies inside this block, the lock
    runs out on its own and the deployment's administrator can sign in again."""

    def __init__(self, keep_ids):
        self.keep = keep_ids
        self.saved = []

    def __enter__(self):
        keep = ", ".join(repr(i) for i in self.keep)
        rows = _psql(
            "SELECT id, is_locked, coalesce(locked_until::text, '') FROM users "
            f"WHERE role='ADMIN' AND is_active IS NOT FALSE AND id NOT IN ({keep}) AND "
            "(is_locked IS NOT TRUE OR (locked_until IS NOT NULL AND locked_until < (now() AT TIME ZONE 'utc')))")
        self.saved = [line.split("|") for line in rows.splitlines() if line]
        if self.saved:
            ids = ", ".join(repr(r[0]) for r in self.saved)
            _psql("UPDATE users SET is_locked=true, "
                  "locked_until=(now() AT TIME ZONE 'utc') + interval '3 minutes' "
                  f"WHERE id IN ({ids})")
        return self

    def __exit__(self, *exc):
        statements = []
        for uid, was_locked, until in self.saved:
            until_sql = f"'{until}'" if until else "NULL"
            locked_sql = "true" if was_locked == "t" else "false"
            statements.append(f"UPDATE users SET is_locked={locked_sql}, locked_until={until_sql} "
                              f"WHERE id='{uid}';")
        if statements:
            _psql(" ".join(statements))
        return False


def _able(uid):
    return _psql(
        "SELECT count(*) FROM users WHERE role='ADMIN' AND is_active IS NOT FALSE AND "
        f"(is_locked IS NOT TRUE OR locked_until < (now() AT TIME ZONE 'utc')) AND id='{uid}'") == "1"


def _at_once(first, second):
    start = threading.Barrier(2)
    out = [None, None]

    def run(i, fn):
        start.wait()
        out[i] = fn()

    threads = [threading.Thread(target=run, args=(0, first)), threading.Thread(target=run, args=(1, second))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return out


@pytest.mark.parametrize("path", sorted(_PATHS))
def test_two_administrators_removing_each_other_at_once_leave_one(admin, admins, path):
    a, b = admins(), admins()
    act = _PATHS[path]
    with _OnlyThese([_uid(a), _uid(b)]):
        ra, rb = _at_once(lambda: act(a, _uid(b)), lambda: act(b, _uid(a)))
        still = [c.account["_username"] for c in (a, b) if _able(_uid(c))]

    assert still, f"{path}: both administrators were removed ({ra.status_code}, {rb.status_code})"
    statuses = sorted([ra.status_code, rb.status_code])
    assert statuses[0] == 200 and statuses[1] in (400, 401, 403), (path, ra.text, rb.text)
    for r in (ra, rb):
        if r.status_code == 400:
            assert r.json()["detail"] == LAST_ADMIN_DETAIL, r.text


_RACE = r"""
import json, sys, threading, time, uuid
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("last-admin-test")
from app.core.database import SessionLocal
from app.core.last_admin import removes_last_admin
from app.core.models import RoleEnum, User

args = json.load(sys.stdin)
a, b = uuid.UUID(args["a"]), uuid.UUID(args["b"])
changes = {"demote": ("role", RoleEnum.USER), "deactivate": ("is_active", False), "lock": ("is_locked", True)}
out = {}
for name, (column, value) in changes.items():
    first, second = SessionLocal(), SessionLocal()
    try:
        # Each session has loaded its target, and would count the other as able, before either locks.
        target_b = first.query(User).filter(User.id == b).first()
        target_a = second.query(User).filter(User.id == a).first()
        second.query(User).filter(User.id == b).first()
        first_answer = removes_last_admin(first, target_b)       # holds every administrator row now
        box = {}
        waiter = threading.Thread(target=lambda: box.update(answer=removes_last_admin(second, target_a)))
        waiter.start()
        time.sleep(1.0)
        waited = waiter.is_alive()
        setattr(target_b, column, value)
        first.commit()
        waiter.join(10)
        out[name] = {"first": first_answer, "waited": waited, "second": box.get("answer")}
    finally:
        second.rollback()
        second.close()
        first.close()
        fix = SessionLocal()
        fix.query(User).filter(User.id == b).update(
            {"role": RoleEnum.ADMIN, "is_active": True, "is_locked": False, "locked_until": None})
        fix.commit()
        fix.close()
print(json.dumps(out))
"""


def test_two_removals_at_once_are_serialised_by_the_row_lock(admins):
    """The race, driven directly on the real database: the second count waits for the first change to
    commit, then sees it, and refuses."""
    a, b = admins(), admins()
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    with _OnlyThese([_uid(a), _uid(b)]):
        try:
            run = subprocess.run(["docker", "exec", "-i", container, "python", "-c", _RACE],
                                 input=json.dumps({"a": _uid(a), "b": _uid(b)}),
                                 capture_output=True, text=True, timeout=120)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"docker unavailable: {exc}")
        skip_if_container_absent(run, container)
    assert run.returncode == 0, (run.stderr or run.stdout)[-800:]
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result == {name: {"first": False, "waited": True, "second": True}
                      for name in ("demote", "deactivate", "lock")}, result
