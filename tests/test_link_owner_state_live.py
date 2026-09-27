"""Live: locking or deactivating an owner stops their note, file and upload links, and undoing it
brings them back. The lock that wrong passwords arm does not.

Each link is created by a regular user and used anonymously. An administrator then locks the owner
(an admin lock, which has no expiry) or deactivates them. Every anonymous use must answer 404, the
same as a missing link, and must do so for a file grant or an upload session obtained BEFORE the
lock too: a token holder must not be able to finish what they started. Unlocking or reactivating the
owner makes the same link work again, so the link itself was never touched.

The automatic lock armed by wrong passwords has an end time, and anyone who knows a username can arm
it, so it must leave all three links working.

test_link_owner_state.py covers the same rule offline, owner state by owner state.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent, unique

pytestmark = pytest.mark.integration

_MB = 1024 * 1024
_UNAVAILABLE = 404
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")

# name -> (the PATCH /users body that takes the owner out, the one that brings them back)
OWNER_CHANGES = {
    "admin_lock": ({"is_locked": True}, {"is_locked": False}),
    "deactivate": ({"is_active": False}, {"is_active": True}),
}


@pytest.fixture
def links_on(admin):
    """All three anonymous link kinds switched on for the test, then put back as they were."""
    keys = ("public_note_links_enabled", "public_file_links_enabled", "public_note_link_user_cap",
            "public_receivers_enabled", "public_receiver_user_cap")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in keys}
    r = admin.put("/settings", json={"public_note_links_enabled": True, "public_file_links_enabled": True,
                                     "public_note_link_user_cap": 50, "public_receivers_enabled": True,
                                     "public_receiver_user_cap": 50})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def owner(admin):
    """A regular user who publishes the links, logged in. Their vaults are removed before the user."""
    u = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(u["_username"], u["_password"])
    client.account = u
    yield client
    # Every test leaves the owner active again, so the owner removes what they made (a user who
    # still owns a vault cannot be deleted). A fresh sign-in, because locking or deactivating the
    # account ended the session the test used.
    again = ApiClient(BASE_URL)
    again.login(u["_username"], u["_password"])
    listed = again.get("/vaults")
    for v in (listed.json() if listed.status_code == 200 else []):
        if str(v.get("owner_id")) == str(u["id"]):
            again.delete_vault(v["id"])
    r = admin.delete_user(u["id"])
    assert r.status_code == 200, f"the owner was left behind: {r.status_code} {r.text}"


@pytest.fixture
def tags(admin):
    """Throwaway tags every user may publish under. Deleting a tag deactivates it."""
    made = []

    def make(path, **fields):
        payload = {"name": unique("ownertag"), "min_token_len": 6, "require_secret": "none",
                   "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True}
        payload.update(fields)
        r = admin.post(path, json=payload)
        assert r.status_code == 200, r.text
        made.append((path, r.json()["id"]))
        return r.json()

    yield make
    for path, tag_id in made:
        admin.delete(f"{path}/{tag_id}")


def _take_out_and_back(admin, owner, change, check):
    """Run `check(expected_status)` with the owner active, out, and back again."""
    out, back = OWNER_CHANGES[change]
    uid = owner.account["id"]
    check(200)
    r = admin.patch(f"/users/{uid}", json=out)
    assert r.status_code == 200, r.text
    try:
        check(_UNAVAILABLE)
    finally:
        r = admin.patch(f"/users/{uid}", json=back)
        assert r.status_code == 200, r.text
    check(200)


@pytest.mark.parametrize("change", sorted(OWNER_CHANGES))
def test_a_note_link_stops_with_its_owner(admin, owner, links_on, tags, change):
    note = owner.post("/notes", json={"title": "T", "body": "the note body"})
    assert note.status_code == 200, note.text
    tag = tags("/note-link-tags")
    link = owner.post("/note-links", json={"note_id": note.json()["id"], "tag_id": tag["id"]})
    assert link.status_code == 200, link.text
    token = link.json()["token"]
    anon = ApiClient(BASE_URL)

    def check(expected):
        r = anon.post(f"/note-links/{token}/redeem", json={})
        assert r.status_code == expected, (expected, r.status_code, r.text)
        if expected == 200:
            assert r.json()["body"] == "the note body"
        else:
            assert r.json()["detail"] == "This link is not available.", r.text

    _take_out_and_back(admin, owner, change, check)

    refused = [row for row in admin.get("/audit/log?action=note_link_redeem").json()
               if (row.get("details") or {}).get("reason") == "owner_unavailable"
               and str(row.get("resource_id")) == str(link.json()["id"])]
    assert refused, "a redeem refused because of the owner should be recorded with that reason"


def test_a_protected_note_link_of_a_locked_owner_answers_404_not_a_secret_prompt(
        admin, owner, links_on, tags):
    note = owner.post("/notes", json={"title": "T", "body": "pin protected"})
    tag = tags("/note-link-tags", require_secret="pin")
    link = owner.post("/note-links", json={"note_id": note.json()["id"], "tag_id": tag["id"],
                                           "secret_kind": "pin", "pin": "4321"})
    assert link.status_code == 200, link.text
    token = link.json()["token"]
    anon = ApiClient(BASE_URL)
    assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 401, "baseline: asks for the PIN"

    uid = owner.account["id"]
    assert admin.patch(f"/users/{uid}", json={"is_locked": True}).status_code == 200
    try:
        r = anon.post(f"/note-links/{token}/redeem", json={})
        assert r.status_code == _UNAVAILABLE, r.text
        r = anon.post(f"/note-links/{token}/redeem", json={"secret": "4321"})
        assert r.status_code == _UNAVAILABLE, "the right PIN must not open a locked owner's link"
    finally:
        assert admin.patch(f"/users/{uid}", json={"is_locked": False}).status_code == 200
    r = anon.post(f"/note-links/{token}/redeem", json={"secret": "4321"})
    assert r.status_code == 200 and r.json()["body"] == "pin protected", r.text


def _own_file(owner, name, content):
    vault = owner.create_vault()
    r = owner.post(f"/vaults/{vault['id']}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    items = owner.get(f"/vaults/{vault['id']}/files").json()["items"]
    return vault, next(it["id"] for it in items if it.get("name") == name and it.get("type") == "file")


@pytest.mark.parametrize("change", sorted(OWNER_CHANGES))
def test_a_file_link_stops_with_its_owner(admin, owner, links_on, tags, change):
    vault, file_id = _own_file(owner, "report.txt", b"file link bytes")
    tag = tags("/note-link-tags", allowed_targets=["file", "folder"])
    link = owner.post("/public-links", json={"vault_id": vault["id"], "target_type": "file",
                                             "target_file_id": file_id, "tag_id": tag["id"]})
    assert link.status_code == 200, link.text
    token = link.json()["token"]
    anon = ApiClient(BASE_URL)

    def download(grant):
        return anon.get(f"/public-links/{token}/download/{file_id}", headers={"X-Download-Grant": grant})

    def check(expected):
        r = anon.post(f"/public-links/{token}/redeem", json={})
        assert r.status_code == expected, (expected, r.status_code, r.text)
        if expected == 200:
            d = download(r.json()["grant"])
            assert d.status_code == 200 and d.content == b"file link bytes", d.text

    # A grant taken while the owner was active must not be spendable once they are out.
    held = anon.post(f"/public-links/{token}/redeem", json={})
    assert held.status_code == 200, held.text
    out, back = OWNER_CHANGES[change]
    uid = owner.account["id"]
    assert admin.patch(f"/users/{uid}", json=out).status_code == 200
    try:
        d = download(held.json()["grant"])
        assert d.status_code == _UNAVAILABLE, f"a grant from before the change still downloads: {d.status_code}"
    finally:
        assert admin.patch(f"/users/{uid}", json=back).status_code == 200

    _take_out_and_back(admin, owner, change, check)


@pytest.mark.parametrize("change", sorted(OWNER_CHANGES))
def test_an_upload_link_stops_with_its_owner(admin, owner, links_on, tags, change):
    tag = tags("/receiver-tags", kind_floor="standard", max_total_bytes_cap=50 * _MB,
               max_file_bytes_cap=10 * _MB, retention_max_days=30, retention_default_days=7)
    rec = owner.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB})
    assert rec.status_code == 200, rec.text
    token = rec.json()["token"]
    anon = ApiClient(BASE_URL)
    payload = b"dropped through the upload link"

    def open_session():
        return anon.post(f"/receivers/{token}/upload-session",
                         json={"filename": unique("drop") + ".txt", "total_size": len(payload),
                               "total_chunks": 1})

    def put_chunk(sid):
        return anon.put(f"/receivers/{token}/upload-session/{sid}/chunks/0", data=payload,
                        headers={"Content-Type": "application/octet-stream"})

    def check(expected):
        r = open_session()
        assert r.status_code == expected, (expected, r.status_code, r.text)
        if expected == 200:
            sid = r.json()["session_id"]
            assert put_chunk(sid).status_code == 200
            done = anon.post(f"/receivers/{token}/upload-session/{sid}/complete", json={})
            assert done.status_code == 200, done.text

    # A session opened while the owner was active must not take bytes once they are out.
    held = open_session()
    assert held.status_code == 200, held.text
    out, back = OWNER_CHANGES[change]
    uid = owner.account["id"]
    assert admin.patch(f"/users/{uid}", json=out).status_code == 200
    try:
        r = put_chunk(held.json()["session_id"])
        assert r.status_code == _UNAVAILABLE, f"an open session still accepts bytes: {r.status_code}"
    finally:
        assert admin.patch(f"/users/{uid}", json=back).status_code == 200

    _take_out_and_back(admin, owner, change, check)


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


def _sign_in(username, password):
    return ApiClient(BASE_URL).session.post(f"{BASE_URL}/auth/login", timeout=30,
                                            json={"username": username, "password": password})


def _arm_the_automatic_lock(owner):
    """Lock the owner the way strangers can: with wrong passwords, from anywhere. The account-wide
    count is primed far past any threshold after a first failure has created it, so one more wrong
    password arms the account-wide lock whatever the deployment's setting."""
    uid, name = owner.account["id"], owner.account["_username"]
    assert _sign_in(name, "definitely-not-the-password").status_code == 401
    _psql(f"UPDATE sign_in_lockouts SET failed_attempts = 1000000 WHERE user_id = '{uid}' AND source = '*'")
    assert _sign_in(name, "definitely-not-the-password").status_code == 401
    locked = _psql(f"SELECT locked_at IS NOT NULL FROM sign_in_lockouts WHERE user_id = '{uid}' AND source = '*'")
    assert locked == "t", "a wrong password past the threshold is expected to lock the account"
    assert _sign_in(name, owner.account["_password"]).status_code != 200, \
        "anchor: the automatic lock keeps even the owner from signing in"


def test_the_lock_wrong_passwords_arm_leaves_every_link_working(admin, owner, links_on, tags):
    anon = ApiClient(BASE_URL)

    note = owner.post("/notes", json={"title": "T", "body": "still readable"})
    assert note.status_code == 200, note.text
    note_link = owner.post("/note-links", json={"note_id": note.json()["id"],
                                                "tag_id": tags("/note-link-tags")["id"]})
    assert note_link.status_code == 200, note_link.text

    vault, file_id = _own_file(owner, "kept.txt", b"still downloadable")
    file_link = owner.post("/public-links", json={
        "vault_id": vault["id"], "target_type": "file", "target_file_id": file_id,
        "tag_id": tags("/note-link-tags", allowed_targets=["file", "folder"])["id"]})
    assert file_link.status_code == 200, file_link.text

    receiver = owner.post("/receivers", json={
        "tag_id": tags("/receiver-tags", kind_floor="standard", max_total_bytes_cap=50 * _MB,
                       max_file_bytes_cap=10 * _MB, retention_max_days=30,
                       retention_default_days=7)["id"],
        "max_total_bytes": 10 * _MB})
    assert receiver.status_code == 200, receiver.text

    _arm_the_automatic_lock(owner)
    try:
        r = anon.post(f"/note-links/{note_link.json()['token']}/redeem", json={})
        assert r.status_code == 200 and r.json()["body"] == "still readable", r.text

        token = file_link.json()["token"]
        r = anon.post(f"/public-links/{token}/redeem", json={})
        assert r.status_code == 200, r.text
        d = anon.get(f"/public-links/{token}/download/{file_id}",
                     headers={"X-Download-Grant": r.json()["grant"]})
        assert d.status_code == 200 and d.content == b"still downloadable", d.text

        token = receiver.json()["token"]
        payload = b"dropped while the owner cannot sign in"
        r = anon.post(f"/receivers/{token}/upload-session",
                      json={"filename": unique("drop") + ".txt", "total_size": len(payload),
                            "total_chunks": 1})
        assert r.status_code == 200, r.text
        sid = r.json()["session_id"]
        assert anon.put(f"/receivers/{token}/upload-session/{sid}/chunks/0", data=payload,
                        headers={"Content-Type": "application/octet-stream"}).status_code == 200
        done = anon.post(f"/receivers/{token}/upload-session/{sid}/complete", json={})
        assert done.status_code == 200, done.text
    finally:
        # An administrator's unlock also clears the automatic lock and the counts primed above.
        assert admin.patch(f"/users/{owner.account['id']}", json={"is_locked": False}).status_code == 200
