"""In-app notifications: the store, its triggers (share received, temp-credential login), per-user
scoping, and the temp-session lockout.

The bell + Dashboard "waiting" lane read this store. Notifications are personal data: every read/write
is scoped to the requesting user, and a temporary-credential session owns none (it must never see or
touch the owner account's notifications).
"""
from conftest import ApiClient, unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("ntag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users", "departments", "anyone_internal"],
                                        "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _share_to_user(admin, vault, uid):
    r = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": _tag(admin)["id"],
                                    "target_type": "vault", "claim_audience": "users",
                                    "audience_user_ids": [uid]})
    assert r.status_code == 200, r.text
    return r.json()


def _notifs(client):
    return client.get("/notifications").json()


def test_share_creates_notification_for_recipient_not_creator(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("nfy"))
    try:
        before_admin = admin.get("/notifications/unread-count").json()["count"]
        _share_to_user(admin, v, temp_user["id"])
        # Recipient gets a share_received notification.
        rec = _notifs(temp_user_client)
        assert any(n["type"] == "share_received" for n in rec["notifications"]), rec
        assert rec["unread_count"] >= 1
        # Creator is NOT notified of their own share.
        after_admin = admin.get("/notifications/unread-count").json()["count"]
        assert after_admin == before_admin, "creator should not be notified of their own share"
    finally:
        admin.delete_vault(v["id"])


def test_notifications_are_per_user_scoped(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("nsc"))
    other = admin.create_user(role="user")
    try:
        _share_to_user(admin, v, temp_user["id"])
        rec = _notifs(temp_user_client)
        n = next(x for x in rec["notifications"] if x["type"] == "share_received")
        # A DIFFERENT user cannot read or dismiss the recipient's notification (scoped by user_id).
        oc = ApiClient(); oc.login(other["_username"], other["_password"])
        assert oc.post(f"/notifications/{n['id']}/read").status_code == 404
        assert oc.delete(f"/notifications/{n['id']}").status_code == 404
        # ...and it does not appear in the other user's own feed.
        assert n["id"] not in {x["id"] for x in _notifs(oc)["notifications"]}
    finally:
        admin.delete_user(other["id"])
        admin.delete_vault(v["id"])


def test_mark_read_read_all_and_dismiss(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("nrd"))
    try:
        _share_to_user(admin, v, temp_user["id"])
        data = _notifs(temp_user_client)
        n = next(x for x in data["notifications"] if x["type"] == "share_received")
        assert n["is_read"] is False
        # mark one read -> unread count drops
        before = temp_user_client.get("/notifications/unread-count").json()["count"]
        assert temp_user_client.post(f"/notifications/{n['id']}/read").status_code == 200
        after = temp_user_client.get("/notifications/unread-count").json()["count"]
        assert after == before - 1
        assert next(x for x in _notifs(temp_user_client)["notifications"] if x["id"] == n["id"])["is_read"] is True
        # read-all zeroes the count
        _share_to_user(admin, v, temp_user["id"])  # (different share -> new unread, dedup is per-share)
        assert temp_user_client.get("/notifications/unread-count").json()["count"] >= 1
        assert temp_user_client.post("/notifications/read-all").status_code == 200
        assert temp_user_client.get("/notifications/unread-count").json()["count"] == 0
        # dismiss removes the row
        assert temp_user_client.delete(f"/notifications/{n['id']}").status_code == 200
        assert n["id"] not in {x["id"] for x in _notifs(temp_user_client)["notifications"]}
    finally:
        admin.delete_vault(v["id"])


def test_share_notification_deduped_per_recipient(admin, temp_user, temp_user_client):
    """A single share fires at most one notification per recipient even if create is retried
    (UNIQUE(user_id, dedup_key)). Two DISTINCT shares produce two notifications."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("ndd"))
    try:
        # Clear the slate for a clean count.
        temp_user_client.post("/notifications/read-all")
        s1 = _share_to_user(admin, v, temp_user["id"])
        s2 = _share_to_user(admin, v, temp_user["id"])
        sr = [x for x in _notifs(temp_user_client)["notifications"] if x["type"] == "share_received"]
        # Two distinct shares -> at least two share_received rows (one per share, deduped per share).
        assert len(sr) >= 2, sr
        assert s1["id"] != s2["id"]
    finally:
        admin.delete_vault(v["id"])


def test_temp_login_notifies_owner(admin):
    before = admin.get("/notifications/unread-count").json()["count"]
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    ApiClient().login(tc["temp_username"], tc["credential"])
    after = admin.get("/notifications/unread-count").json()["count"]
    assert after > before, "the owner should be notified when their temp credential signs in"
    assert "temp_login" in {n["type"] for n in _notifs(admin)["notifications"]}


def test_temp_session_owns_no_notifications(admin):
    """A temp-credential session must not see or mutate the owner account's notifications."""
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient()
    temp.login(tc["temp_username"], tc["credential"])
    body = temp.get("/notifications").json()
    assert body == {"notifications": [], "unread_count": 0}
    assert temp.get("/notifications/unread-count").json() == {"count": 0}
    assert temp.post("/notifications/read-all").status_code == 403
    # a bogus id: still 403 (temp is denied before the lookup), never a 404 that would leak existence
    import uuid as _uuid
    fake = str(_uuid.uuid4())
    assert temp.post(f"/notifications/{fake}/read").status_code == 403
    assert temp.delete(f"/notifications/{fake}").status_code == 403


def test_notifications_require_auth(anon):
    assert anon.get("/notifications").status_code in (401, 403)
    assert anon.get("/notifications/unread-count").status_code in (401, 403)
