"""Live: a sign-in with a password ends only its own channel's earlier sessions.

SFTP checks on every operation that its session is still marked active, and a password sign-in used to
mark every other session of the account inactive. So a second SFTP password connection cut off the
first, and a web sign-in cut off the account's SFTP connections, key ones too, dropping an upload in
flight while the client was told it had stored it. Now:

  * SFTP password connections, one after another or at once, all keep working;
  * a web sign-in leaves SFTP password and key connections working, and a key upload in flight lands;
  * a web sign-in still marks the account's earlier web session (which the web never refused on that
    mark alone, and still does not);
  * ending an account's sessions, locking it and deactivating it still end its SFTP connections.

test_sign_in_channels.py covers the rules offline.
"""
import os
import threading
import uuid

import pytest
import requests

paramiko = pytest.importorskip("paramiko")

from conftest import BASE_URL  # noqa: E402
from _account_change_helpers import psql  # noqa: E402

pytestmark = [pytest.mark.integration, pytest.mark.sftp]

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
_REFUSED = (IOError, OSError, EOFError, paramiko.SSHException)


def _web(name, password):
    s = requests.Session()
    s.trust_env = False
    r = s.post(f"{BASE_URL}/auth/login", json={"username": name, "password": password}, timeout=30)
    assert r.status_code == 200, r.text
    s.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return s


def _password_connection(name, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    t.connect(username=name, password=password)
    return t, paramiko.SFTPClient.from_transport(t)


def _key_connection(name, pkey):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    t.connect(username=name, pkey=pkey)
    return t, paramiko.SFTPClient.from_transport(t)


def _works(sftp):
    try:
        sftp.listdir("/")
        return True
    except _REFUSED:
        return False


@pytest.fixture
def person(admin):
    """An account with a password and an SSH key it added itself, and a vault of its own."""
    account = admin.create_user()
    name, password = account["_username"], account["_password"]
    web = _web(name, password)
    pkey = paramiko.RSAKey.generate(2048)
    r = web.post(f"{BASE_URL}/users/{account['id']}/ssh-keys",
                 json={"name": "channels", "public_key": f"{pkey.get_name()} {pkey.get_base64()}"})
    assert r.status_code == 200, r.text
    vault = f"ch{uuid.uuid4().hex[:8]}"
    r = web.post(f"{BASE_URL}/vaults", json={"name": vault, "description": "sign-in channels"})
    assert r.status_code in (200, 201), r.text
    opened = []
    yield {"id": account["id"], "name": name, "password": password, "pkey": pkey, "vault": vault,
           "opened": opened}
    for t in opened:
        t.close()
    admin.delete_user(account["id"])


def test_sftp_password_connections_do_not_end_each_other(person):
    one_after_another = [_password_connection(person["name"], person["password"]) for _ in range(3)]
    person["opened"].extend(t for t, _s in one_after_another)
    assert [_works(s) for _t, s in one_after_another] == [True] * 3

    at_once, lock = [], threading.Lock()

    def connect():
        conn = _password_connection(person["name"], person["password"])
        with lock:
            at_once.append(conn)

    threads = [threading.Thread(target=connect) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(90)
    person["opened"].extend(t for t, _s in at_once)
    assert len(at_once) == 3
    assert [_works(s) for _t, s in at_once] == [True] * 3
    assert [_works(s) for _t, s in one_after_another] == [True] * 3, "the later ones did not end the earlier"


def test_a_web_sign_in_leaves_sftp_connections_working(person):
    pw_t, pw_s = _password_connection(person["name"], person["password"])
    key_t, key_s = _key_connection(person["name"], person["pkey"])
    person["opened"].extend([pw_t, key_t])
    assert _works(pw_s) and _works(key_s)
    _web(person["name"], person["password"])
    assert _works(pw_s), "a web sign-in ended an SFTP password connection"
    assert _works(key_s), "a web sign-in ended an SFTP key connection"


def test_a_web_sign_in_during_a_key_upload_keeps_the_upload(person):
    key_t, key_s = _key_connection(person["name"], person["pkey"])
    person["opened"].append(key_t)
    chunk, chunks = os.urandom(256 * 1024), 24
    path = f"/{person['vault']}/in-flight.bin"
    with key_s.open(path, "wb") as fh:
        for i in range(chunks):
            fh.write(chunk)
            if i == chunks // 3:
                _web(person["name"], person["password"])
    assert key_s.stat(path).st_size == len(chunk) * chunks, "the upload was not stored"
    assert _works(key_s)
    stored = psql(f"SELECT count(*) FROM files f JOIN vaults v ON v.id = f.vault_id "
                  f"WHERE v.owner_id = '{person['id']}' AND f.size_bytes = {len(chunk) * chunks}")
    assert stored == "1"


def test_a_web_sign_in_still_marks_the_earlier_web_session(person):
    first = _web(person["name"], person["password"])
    pw_t, pw_s = _password_connection(person["name"], person["password"])
    person["opened"].append(pw_t)
    second = _web(person["name"], person["password"])
    rows = psql("SELECT channel, is_active FROM active_sessions WHERE user_id = '%s' AND temp_credential_id IS NULL "
                "ORDER BY started_at" % person["id"]).splitlines()
    # The fixture's web sign-in, then `first`, both marked by `second`; the SFTP one is not.
    assert rows == ["web|f", "web|f", "sftp|t", "web|t"], rows
    # As before, the web refuses a session only once it is revoked, so the first still works.
    assert first.get(f"{BASE_URL}/users/me").status_code == 200
    assert second.get(f"{BASE_URL}/users/me").status_code == 200
    assert _works(pw_s)


@pytest.mark.parametrize("action", ["end sessions", "lock", "deactivate"])
def test_ending_locking_and_deactivating_still_end_sftp_connections(person, admin, action):
    pw_t, pw_s = _password_connection(person["name"], person["password"])
    key_t, key_s = _key_connection(person["name"], person["pkey"])
    person["opened"].extend([pw_t, key_t])
    assert _works(pw_s) and _works(key_s)
    uid = person["id"]
    if action == "end sessions":
        r = admin.post(f"/users/{uid}/terminate-sessions")
    elif action == "lock":
        r = admin.post(f"/api/user-management/users/{uid}/toggle-locked")
    else:
        r = admin.post(f"/api/user-management/users/{uid}/toggle-active")
    assert r.status_code == 200, r.text
    assert not _works(pw_s), f"{action}: the SFTP password connection still works"
    assert not _works(key_s), f"{action}: the SFTP key connection still works"
