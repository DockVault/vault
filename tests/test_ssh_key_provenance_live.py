"""Live: an SSH key shows who added it, and when an administrator who added keys to other people's
accounts is demoted, deactivated, locked or deleted, through each route that does it, the key's owner and
the other administrators are told, one audit row is written per account, and the key still signs in.
At start, keys from before the name was kept are named from the account that added them, or from the
audit row of the addition when that account is gone.

test_ssh_key_provenance.py covers the rules offline.
"""
import os
import subprocess
import time
import uuid

import pytest
import requests

paramiko = pytest.importorskip("paramiko")

from conftest import ApiClient, BASE_URL  # noqa: E402
from _account_change_helpers import API, MAILPIT_URL, mail_sink, mail_to, psql, signed_in  # noqa: E402

pytestmark = pytest.mark.sftp

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


def _key():
    k = paramiko.RSAKey.generate(2048)
    return k, f"{k.get_name()} {k.get_base64()}"


def _reopen_window(user_id):
    """Forget the credential changes made to an account, so the next one is made at once rather than
    held for a second administrator (a second change within 14 days is: app/core/credential_changes.py)."""
    psql(f"DELETE FROM credential_changes WHERE target_user_id = '{user_id}'")


def _key_signs_in(username, pkey):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, pkey=pkey)
        s = paramiko.SFTPClient.from_transport(t)
        try:
            s.listdir("/")
        finally:
            s.close()
        return True
    finally:
        t.close()


def _notices(client, ntype="ssh_keys_adder_left"):
    r = client.get("/notifications", params={"limit": 100})
    assert r.status_code == 200, r.text
    return [n for n in r.json()["notifications"] if n["type"] == ntype]


@pytest.fixture
def ada(admin):
    """An administrator the session's administrator made, signed in. Deleted afterwards (if still there)."""
    account = admin.create_user(role="admin")
    client = ApiClient(BASE_URL)
    client.login(account["_username"], account["_password"])
    yield account, client
    admin.delete_user(account["id"])


def _bob(admin):
    return admin.create_user(role="user")


# How the session's administrator takes ada's standing away, through each route that does it:
# (the request, what the notices say, what the audit row keeps).
_DEMOTED = ("is no longer an administrator", "demoted")
_DEACTIVATED = ("was deactivated", "deactivated")
_LOCKED = ("was locked by an administrator", "locked")
LEAVES = {
    "demote (PATCH)": (lambda a, i: a.patch(f"/users/{i}", json={"role": "user"}), *_DEMOTED),
    "demote (role route)": (lambda a, i: a.patch(f"/api/user-management/users/{i}/role", json={"new_role": "user"}),
                            *_DEMOTED),
    "demote (PUT)": (lambda a, i: a.put(f"/api/user-management/users/{i}", json={"role": "user"}), *_DEMOTED),
    "deactivate (PATCH)": (lambda a, i: a.patch(f"/users/{i}", json={"is_active": False}), *_DEACTIVATED),
    "deactivate (toggle)": (lambda a, i: a.post(f"/api/user-management/users/{i}/toggle-active"), *_DEACTIVATED),
    "deactivate (PUT)": (lambda a, i: a.put(f"/api/user-management/users/{i}", json={"is_active": False}),
                         *_DEACTIVATED),
    "lock (PATCH)": (lambda a, i: a.patch(f"/users/{i}", json={"is_locked": True}), *_LOCKED),
    "lock (toggle)": (lambda a, i: a.post(f"/api/user-management/users/{i}/toggle-locked"), *_LOCKED),
    "delete": (lambda a, i: a.post(f"/users/{i}/delete"), "was deleted", "deleted"),
}


def test_a_key_shows_who_added_it(admin, ada):
    _ada, ada_client = ada
    bob = _bob(admin)
    try:
        _pk, pub = _key()
        assert ada_client.post(f"/users/{bob['id']}/ssh-keys", json={"name": "desk", "public_key": pub}).status_code == 200
        bob_client = signed_in(bob)
        _pk2, pub2 = _key()
        r = bob_client.post(f"/users/{bob['id']}/ssh-keys", json={"name": "laptop", "public_key": pub2})
        assert r.status_code == 200, r.text
        assert (r.json()["added_by"], r.json()["added_by_other"]) == (bob["_username"], False)
        for viewer in (admin, bob_client):
            shown = {k["name"]: (k["added_by"], k["added_by_other"])
                     for k in viewer.get(f"/users/{bob['id']}/ssh-keys").json()}
            assert shown == {"desk": (_ada["_username"], True), "laptop": (bob["_username"], False)}
        assert psql(f"SELECT created_by_name FROM user_ssh_keys WHERE user_id = '{bob['id']}' AND name = 'desk'") \
            == _ada["_username"]
    finally:
        admin.delete_user(bob["id"])


@pytest.mark.parametrize("leave", sorted(LEAVES))
def test_the_owner_is_told_when_the_administrator_who_added_a_key_leaves(admin, ada, leave):
    _ada, ada_client = ada
    bob, carol = _bob(admin), _bob(admin)
    try:
        keys = {}
        for owner, name in ((bob, "desk"), (bob, "build"), (carol, "phone")):
            _reopen_window(owner["id"])
            pk, pub = _key()
            r = ada_client.post(f"/users/{owner['id']}/ssh-keys", json={"name": name, "public_key": pub})
            assert r.status_code == 200, r.text
            keys[name] = (owner, pk, r.json()["fingerprint"])
        # Her own key, and one the session's administrator added: neither is reported.
        _own_pk, own_pub = _key()
        assert ada_client.post(f"/users/{_ada['id']}/ssh-keys", json={"name": "hers", "public_key": own_pub}).status_code == 200

        make, why, because = LEAVES[leave]
        r = make(admin, _ada["id"])
        assert r.status_code == 200, r.text

        bob_client = signed_in(bob)
        (to_bob,) = _notices(bob_client)
        assert to_bob["title"] == "Check the SSH keys on your account" and to_bob["target"] == "#profile"
        assert f"The administrator {_ada['_username']} added the SSH keys \"desk\"" in to_bob["body"], to_bob["body"]
        assert keys["build"][2] in to_bob["body"] and f"{_ada['_username']} {why}" in to_bob["body"]
        assert "They still sign in to SFTP as you." in to_bob["body"]
        (to_carol,) = _notices(signed_in(carol))
        assert '"phone"' in to_carol["body"] and "It still signs in to SFTP as you." in to_carol["body"]
        (to_admin,) = [n for n in _notices(admin) if _ada["_username"] in (n["body"] or "")]
        assert to_admin["title"] == "SSH keys an administrator added" and to_admin["target"] == "#users"
        assert f"added SSH keys to the accounts of {bob['_username']} and {carol['_username']}" in to_admin["body"] \
            or f"added SSH keys to the accounts of {carol['_username']} and {bob['_username']}" in to_admin["body"]

        rows = psql("SELECT resource_id || '|' || username || '|' || (details::json ->> 'added_by') || '|' || "
                    "(details::json ->> 'added_by_left_because') FROM audit_logs "
                    f"WHERE action = 'ssh_keys_adder_left' AND details::json ->> 'added_by' = '{_ada['_username']}' "
                    "ORDER BY resource_id").splitlines()
        assert sorted(rows) == sorted(f"{o['id']}|admin|{_ada['_username']}|{because}" for o in (bob, carol)), rows

        # Never switched off: each key still signs in, and still says who added it.
        for name in ("desk", "phone"):
            owner, pk, _fp = keys[name]
            assert _key_signs_in(owner["_username"], pk), name
        shown = {k["name"]: (k["added_by"], k["added_by_other"])
                 for k in admin.get(f"/users/{bob['id']}/ssh-keys").json()}
        assert shown == {"desk": (_ada["_username"], True), "build": (_ada["_username"], True)}
    finally:
        for owner in (bob, carol):
            admin.delete_user(owner["id"])


def test_a_second_loss_of_standing_is_not_reported_again(admin, ada):
    _ada, ada_client = ada
    bob = _bob(admin)
    try:
        _pk, pub = _key()
        assert ada_client.post(f"/users/{bob['id']}/ssh-keys", json={"name": "desk", "public_key": pub}).status_code == 200
        assert admin.patch(f"/users/{_ada['id']}", json={"is_active": False}).status_code == 200
        assert admin.post(f"/users/{_ada['id']}/delete").status_code == 200
        assert len(_notices(signed_in(bob))) == 1
        assert psql("SELECT count(*) FROM audit_logs WHERE action = 'ssh_keys_adder_left' "
                    f"AND resource_id = '{bob['id']}'") == "1"
    finally:
        admin.delete_user(bob["id"])


@pytest.mark.skipif(not MAILPIT_URL, reason="needs a mail sink (VAULT_MAILPIT_URL and VAULT_MAILPIT_SMTP_HOST)")
def test_the_owner_is_emailed_with_the_way_to_remove_it(admin, ada):
    _ada, ada_client = ada
    bob = _bob(admin)
    try:
        with mail_sink(admin) as real:
            if not real:
                pytest.skip("no mail sink")
            _pk, pub = _key()
            assert ada_client.post(f"/users/{bob['id']}/ssh-keys", json={"name": "desk", "public_key": pub}).status_code == 200
            assert admin.patch(f"/api/user-management/users/{_ada['id']}/role", json={"new_role": "user"}).status_code == 200
            mail = mail_to(bob["email"], "Check the SSH keys")
            assert mail is not None, "no email"
            assert '"desk"' in mail["text"] and f"{_ada['_username']} is no longer an administrator" in mail["text"]
            # The link to Your account is in the HTML part (the text part keeps the link's words).
            found = requests.get(f"{MAILPIT_URL}/api/v1/search", params={"query": f"to:{bob['email']}"},
                                 timeout=10).json()["messages"]
            (message,) = [m for m in found if (m.get("Subject") or "").startswith("Check the SSH keys")]
            html = requests.get(f"{MAILPIT_URL}/api/v1/message/{message['ID']}", timeout=10).json()["HTML"]
            assert f'href="{BASE_URL}/#profile"' in html, html
    finally:
        admin.delete_user(bob["id"])


def _restart_web():
    r = subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        pytest.skip(f"cannot restart the web container: {r.stderr[:200]}")
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    pytest.fail("the web container did not come back")


def test_the_start_names_the_makers_of_older_keys(admin, ada):
    _ada, ada_client = ada
    bob = _bob(admin)
    bob_client = signed_in(bob)
    try:
        def add(client, name, pub):
            _reopen_window(bob["id"])
            r = client.post(f"/users/{bob['id']}/ssh-keys", json={"name": name, "public_key": pub})
            assert r.status_code == 200, r.text
            return r.json()

        kept = add(ada_client, "kept", _key()[1])
        # "gone": bob added this key once himself and removed it; then ada added it. Its maker is the
        # newest addition's, ada.
        gone_pub = _key()[1]
        first = add(bob_client, "gone", gone_pub)
        assert bob_client.delete(f"/users/{bob['id']}/ssh-keys/{first['id']}").status_code == 200
        gone = add(ada_client, "gone", gone_pub)
        add(bob_client, "own", _key()[1])
        named = add(ada_client, "named", _key()[1])
        orphan, host = f"SHA256:{uuid.uuid4().hex}", f"SHA256:{uuid.uuid4().hex}"
        # As an older release left them: no name kept, except on "named". "gone" as if its maker had been
        # deleted (its id cleared), "orphan" a key no audit row names.
        psql(f"UPDATE user_ssh_keys SET created_by_name = NULL WHERE user_id = '{bob['id']}' AND name <> 'named'")
        psql(f"UPDATE user_ssh_keys SET created_by = NULL WHERE id = '{gone['id']}'")
        psql(f"INSERT INTO user_ssh_keys (id, user_id, name, public_key, fingerprint, created_at) VALUES "
             f"('{uuid.uuid4()}', '{bob['id']}', 'orphan', 'ssh-ed25519 AAAA', '{orphan}', now())")
        # A name already kept is left as it is, and its row is not written again: one whose maker's account
        # is there ("named"), and the server's operator's, which no audit row of an addition names.
        psql(f"INSERT INTO user_ssh_keys (id, user_id, name, public_key, fingerprint, created_at, created_by_name) "
             f"VALUES ('{uuid.uuid4()}', '{bob['id']}', 'host', 'ssh-ed25519 AAAB', '{host}', now(), 'operator@host')")
        untouched = psql(f"SELECT string_agg(name || ':' || xmin::text, ',' ORDER BY name) FROM user_ssh_keys "
                         f"WHERE fingerprint IN ('{host}', '{named['fingerprint']}')")
        _restart_web()
        names = dict(line.split("|", 1) for line in psql(
            f"SELECT name || '|' || coalesce(created_by_name, '-') FROM user_ssh_keys WHERE user_id = '{bob['id']}'"
        ).splitlines())
        assert names == {"kept": _ada["_username"], "gone": _ada["_username"], "own": bob["_username"],
                         "named": _ada["_username"], "orphan": "-", "host": "operator@host"}, names
        assert kept["added_by"] == _ada["_username"]
        assert psql(f"SELECT string_agg(name || ':' || xmin::text, ',' ORDER BY name) FROM user_ssh_keys "
                    f"WHERE fingerprint IN ('{host}', '{named['fingerprint']}')") == untouched
    finally:
        admin.delete_user(bob["id"])
