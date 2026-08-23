"""Notes — personal server-side notes, and "send note" as a snapshot copy.

A note is owned by one account and private to it. "Send" creates an independent COPY owned by the
recipient (no live link, no cascade): the recipient can adopt it into their own notes, and the
sender's later edits never touch the copy. A temporary-credential session has no access to notes.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration


def _client_for(user):
    c = ApiClient(BASE_URL)
    c.login(user["_username"], user["_password"])
    return c


def _create(client, title="t", body="b"):
    r = client.post("/notes", json={"title": title, "body": body})
    r.raise_for_status()
    return r.json()


def _list_ids(client, path="/notes"):
    return {n["id"] for n in client.get(path).json()["notes"]}


def test_create_list_update_delete_roundtrip(admin):
    u = admin.create_user(role="user")
    c = _client_for(u)
    try:
        n = _create(c, unique("title"), "first body")
        assert n["adopted"] is True and n["sent_from"] is None
        assert n["id"] in _list_ids(c)
        r = c.patch(f"/notes/{n['id']}", json={"body": "edited body"})
        assert r.status_code == 200 and r.json()["body"] == "edited body"
        assert c.delete(f"/notes/{n['id']}").status_code == 200
        assert n["id"] not in _list_ids(c)
        assert c.get(f"/notes/{n['id']}").status_code == 404
    finally:
        admin.delete_user(u["id"])


def test_favourite_sorts_first(admin):
    u = admin.create_user(role="user")
    c = _client_for(u)
    try:
        _create(c, "plain")
        fav = _create(c, "fav")
        c.patch(f"/notes/{fav['id']}", json={"is_favorite": True}).raise_for_status()
        notes = c.get("/notes").json()["notes"]
        assert notes[0]["id"] == fav["id"] and notes[0]["is_favorite"] is True
    finally:
        admin.delete_user(u["id"])


def test_send_creates_independent_recipient_copy_and_notifies(admin):
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    ca, cb = _client_for(a), _client_for(b)
    try:
        n = _create(ca, "shared idea", "original body")
        r = ca.post(f"/notes/{n['id']}/send", json={"recipient_user_id": b["id"]})
        assert r.status_code == 200, r.text
        # B has a received copy (not in "my notes" yet), attributed to A.
        received = cb.get("/notes/received").json()["notes"]
        assert len(received) == 1
        copy = received[0]
        assert copy["title"] == "shared idea" and copy["body"] == "original body"
        assert copy["sent_from"] == a["_username"]
        assert copy["id"] != n["id"]                       # a distinct row
        assert copy["id"] not in _list_ids(cb)             # not in B's own notes until adopted
        # B got an in-app notification about it.
        notifs = cb.get("/notifications").json()
        assert any(x["type"] == "note_received" for x in notifs["notifications"])
        # Snapshot: A editing the original does NOT change B's copy.
        ca.patch(f"/notes/{n['id']}", json={"body": "A changed this later"}).raise_for_status()
        again = cb.get("/notes/received").json()["notes"][0]
        assert again["body"] == "original body"
        # A's own note is unchanged in count/ownership.
        assert n["id"] in _list_ids(ca)
    finally:
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])


def test_adopt_moves_received_into_my_notes(admin):
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    ca, cb = _client_for(a), _client_for(b)
    try:
        n = _create(ca, "adopt me")
        ca.post(f"/notes/{n['id']}/send", json={"recipient_user_id": b["id"]}).raise_for_status()
        copy_id = cb.get("/notes/received").json()["notes"][0]["id"]
        assert cb.post(f"/notes/{copy_id}/adopt").status_code == 200
        assert copy_id in _list_ids(cb)                    # now in B's notes
        assert copy_id not in _list_ids(cb, "/notes/received")   # gone from "sent to me"
        # And B can now edit their adopted copy.
        assert cb.patch(f"/notes/{copy_id}", json={"body": "B owns this now"}).status_code == 200
    finally:
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])


def test_send_to_self_and_unknown_recipient_rejected(admin):
    import uuid
    u = admin.create_user(role="user")
    c = _client_for(u)
    try:
        n = _create(c)
        assert c.post(f"/notes/{n['id']}/send", json={"recipient_user_id": u["id"]}).status_code == 400
        assert c.post(f"/notes/{n['id']}/send",
                      json={"recipient_user_id": str(uuid.uuid4())}).status_code == 404
    finally:
        admin.delete_user(u["id"])


def test_notes_are_isolated_per_owner(admin):
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    ca, cb = _client_for(a), _client_for(b)
    try:
        n = _create(ca, "private to A")
        assert cb.get(f"/notes/{n['id']}").status_code == 404       # B cannot read A's note
        assert cb.patch(f"/notes/{n['id']}", json={"body": "x"}).status_code == 404
        assert cb.delete(f"/notes/{n['id']}").status_code == 404
        assert n["id"] not in _list_ids(cb)
    finally:
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])


def test_body_length_is_capped(admin):
    u = admin.create_user(role="user")
    c = _client_for(u)
    try:
        r = c.post("/notes", json={"title": "big", "body": "x" * 100_001})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(u["id"])


def test_temp_session_has_no_notes(admin):
    u = admin.create_user(role="user")
    c = _client_for(u)
    n = _create(c, "owner note")
    # A scoped temp credential minted from this account must not see or create notes.
    minted = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30,
        "scope": {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": [], "temp": {}},
        "vault_access_mode": "all", "selected_vaults": []}).json()
    temp = ApiClient(BASE_URL)
    temp.login(minted["temp_username"], minted["credential"])
    try:
        assert temp.get("/notes").json()["notes"] == []             # sees none
        assert temp.post("/notes", json={"title": "x", "body": "y"}).status_code == 403
    finally:
        admin.post(f"/temp-creds/{minted['temp_username']}/delete")
        admin.delete_user(u["id"])
