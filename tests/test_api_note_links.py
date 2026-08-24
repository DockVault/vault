"""Live API: public note links — create (tag-floor tighten-only + allowlist + per-user cap),
anonymous redemption (snapshot, secret prompt, lockout, expiry/use-limits), revoke."""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration


@pytest.fixture
def links_enabled(admin):
    """Turn public note links on for the test, restoring the prior settings after."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _mk_note(client, title="T", body="secret body"):
    r = client.post("/notes", json={"title": title, "body": body})
    r.raise_for_status()
    return r.json()["id"]


def _mk_tag(admin, **over):
    # auto_enroll defaults ON here so the creating admin is allowlisted; the allowlist itself is
    # exercised separately in test_allowlist_blocks_disallowed_user.
    payload = {"name": unique("nltag"), "min_token_len": 6, "require_secret": "none",
               "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True}
    payload.update(over)
    r = admin.post("/note-link-tags", json=payload)
    r.raise_for_status()
    return r.json()


def _open_tag(admin):
    return next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")


def test_note_link_policy_reader(admin, links_enabled):
    # The non-admin reader returns the feature flag, the per-user cap, and the tags the caller may
    # use — with floor fields only, NEVER the create-allowlist internals.
    p = admin.get("/note-link-policy").json()
    assert p["enabled"] is True
    assert isinstance(p["user_cap"], int) and p["user_cap"] >= 1
    names = {t["name"] for t in p["tags"]}
    assert {"Open", "Restricted", "Confidential"} <= names, names
    open_tag = next(t for t in p["tags"] if t["name"] == "Open")
    for floor_field in ("min_token_len", "require_secret", "min_pin_len", "password_min_len",
                        "max_ttl_hours", "max_uses_cap", "border_color", "icon"):
        assert floor_field in open_tag, floor_field
    # allowlist internals must never be exposed
    for leak in ("allowed_user_ids", "blocked_user_ids", "allowed_department_ids", "auto_enroll_new_users"):
        assert leak not in open_tag, f"leaked {leak}"


def test_note_link_policy_off_returns_no_tags(admin):
    before = admin.get("/settings").json().get("public_note_links_enabled")
    admin.put("/settings", json={"public_note_links_enabled": False})
    try:
        p = admin.get("/note-link-policy").json()
        assert p["enabled"] is False and p["tags"] == []
    finally:
        admin.put("/settings", json={"public_note_links_enabled": bool(before)})


def test_note_link_policy_filters_by_allowlist_and_temp(admin, links_enabled):
    u = admin.create_user(role="user")
    user = admin.clone_anonymous(); user.login(u["_username"], u["_password"])
    # A tag that auto-enrolls nobody: the user does not see it; an auto-enroll tag: they do.
    denied = _mk_tag(admin, auto_enroll_new_users=False)
    allowed = _mk_tag(admin, auto_enroll_new_users=True)
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient(BASE_URL); temp.login(tc["temp_username"], tc["credential"])
    try:
        names = {t["name"] for t in user.get("/note-link-policy").json()["tags"]}
        assert allowed["name"] in names
        assert denied["name"] not in names
        # A temp session can never create links -> no tags.
        assert temp.get("/note-link-policy").json()["tags"] == []
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")
        admin.delete_user(u["id"])


def test_feature_gate_off_blocks_create(admin):
    # Ensure OFF, then a create attempt is 403.
    before = admin.get("/settings").json().get("public_note_links_enabled")
    admin.put("/settings", json={"public_note_links_enabled": False})
    try:
        note_id = _mk_note(admin)
        tag = _open_tag(admin)
        r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
        assert r.status_code == 403, r.text
    finally:
        admin.put("/settings", json={"public_note_links_enabled": bool(before)})


def test_create_and_redeem_no_secret_snapshot(admin, links_enabled):
    note_id = _mk_note(admin, title="Hello", body="body-v1")
    tag = _open_tag(admin)
    r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
    assert r.status_code == 200, r.text
    link = r.json()
    assert link["secret_kind"] == "none"
    assert len(link["token"]) == tag["min_token_len"]

    anon = admin.clone_anonymous()
    rr = anon.post(f"/note-links/{link['token']}/redeem", json={})
    assert rr.status_code == 200, rr.text
    assert rr.json() == {"title": "Hello", "body": "body-v1", "secret_kind": "none"}

    # Editing the source note does NOT change the snapshot.
    admin.patch(f"/notes/{note_id}", json={"body": "body-v2-edited"})
    rr2 = anon.post(f"/note-links/{link['token']}/redeem", json={})
    assert rr2.json()["body"] == "body-v1"

    # view/use counts advanced.
    mine = {l["id"]: l for l in admin.get("/note-links").json()["links"]}
    assert mine[link["id"]]["view_count"] >= 2


def test_password_redeem_flow_and_wrong_secret(admin, links_enabled):
    note_id = _mk_note(admin, body="protected content")
    tag = _mk_tag(admin, require_secret="password", password_min_len=8)
    r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                        "password": "hunter2x"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert r.json()["secret_kind"] == "password"

    anon = admin.clone_anonymous()
    # No secret -> 401 secret_required (no consume).
    r0 = anon.post(f"/note-links/{token}/redeem", json={})
    assert r0.status_code == 401
    assert r0.json()["detail"]["error"] == "secret_required"
    assert r0.json()["detail"]["secret_kind"] == "password"
    # Wrong -> 401 wrong_secret.
    r1 = anon.post(f"/note-links/{token}/redeem", json={"secret": "nope1234"})
    assert r1.status_code == 401 and r1.json()["detail"]["error"] == "wrong_secret"
    # Correct -> content.
    r2 = anon.post(f"/note-links/{token}/redeem", json={"secret": "hunter2x"})
    assert r2.status_code == 200 and r2.json()["body"] == "protected content"


def test_tighten_only_rejects_loosening(admin, links_enabled):
    note_id = _mk_note(admin)
    # token below the tag floor -> 400
    tag = _mk_tag(admin, min_token_len=12)
    r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"], "token_len": 8})
    assert r.status_code == 400, r.text
    # tag mandates a password; dropping to none -> 400
    ptag = _mk_tag(admin, require_secret="password", password_min_len=8)
    r2 = admin.post("/note-links", json={"note_id": note_id, "tag_id": ptag["id"],
                                         "secret_kind": "none"})
    assert r2.status_code == 400, r2.text
    # user MAY strengthen: Open (no secret) + add a pin
    otag = _open_tag(admin)
    r3 = admin.post("/note-links", json={"note_id": note_id, "tag_id": otag["id"],
                                         "secret_kind": "pin", "pin": "1234"})
    assert r3.status_code == 200 and r3.json()["secret_kind"] == "pin"


def test_max_uses_exhaustion_is_atomic(admin, links_enabled):
    note_id = _mk_note(admin, body="one-time")
    tag = _mk_tag(admin, max_uses_cap=1)
    r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"], "max_uses": 1})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    anon = admin.clone_anonymous()
    assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 200
    # second view is refused (exhausted -> generic 404)
    assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 404


def test_revoke_then_redeem_404(admin, links_enabled):
    note_id = _mk_note(admin)
    tag = _open_tag(admin)
    link = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    assert admin.post(f"/note-links/{link['id']}/revoke").status_code == 200
    anon = admin.clone_anonymous()
    assert anon.post(f"/note-links/{link['token']}/redeem", json={}).status_code == 404


def test_secret_lockout_after_repeated_failures(admin, links_enabled):
    note_id = _mk_note(admin, body="locked content")
    tag = _mk_tag(admin, require_secret="pin", min_pin_len=4)
    token = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                            "pin": "4321"}).json()["token"]
    anon = admin.clone_anonymous()
    codes = []
    for _ in range(5):
        codes.append(anon.post(f"/note-links/{token}/redeem", json={"secret": "0000"}).status_code)
    # first 4 wrong -> 401; the 5th trips the lockout -> 429
    assert codes[:4] == [401, 401, 401, 401], codes
    assert codes[4] == 429, codes
    # even the CORRECT pin is now refused during the lockout
    assert anon.post(f"/note-links/{token}/redeem", json={"secret": "4321"}).status_code == 429


def test_unknown_token_is_404(admin, links_enabled):
    anon = admin.clone_anonymous()
    assert anon.post("/note-links/doesnotexist123/redeem", json={}).status_code == 404


def test_only_owner_can_revoke(admin, links_enabled):
    note_id = _mk_note(admin)
    tag = _open_tag(admin)
    link = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    u = admin.create_user(role="user")
    other = admin.clone_anonymous(); other.login(u["_username"], u["_password"])
    try:
        # someone else's link id is invisible -> 404, not a revoke
        assert other.post(f"/note-links/{link['id']}/revoke").status_code == 404
        assert other.get("/note-links").json()["links"] == []
    finally:
        admin.delete_user(u["id"])


def test_allowlist_blocks_disallowed_user(admin, links_enabled):
    u = admin.create_user(role="user")
    user = admin.clone_anonymous(); user.login(u["_username"], u["_password"])
    try:
        note_id = _mk_note(user)
        # a tag that auto-enrolls nobody and doesn't list this user -> denied
        tag = _mk_tag(admin, auto_enroll_new_users=False)
        r = user.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
        assert r.status_code == 403, r.text
        # an open-to-all tag -> allowed
        tag2 = _mk_tag(admin, auto_enroll_new_users=True)
        assert user.post("/note-links", json={"note_id": note_id, "tag_id": tag2["id"]}).status_code == 200
    finally:
        admin.delete_user(u["id"])


def test_per_user_cap_enforced(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 1})
    u = admin.create_user(role="user")
    user = admin.clone_anonymous(); user.login(u["_username"], u["_password"])
    try:
        note_id = _mk_note(user)
        tag = _mk_tag(admin, auto_enroll_new_users=True)
        first = user.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
        assert first.status_code == 200, first.text
        second = user.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
        assert second.status_code == 409, second.text
        # revoking frees a slot
        assert user.post(f"/note-links/{first.json()['id']}/revoke").status_code == 200
        assert user.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).status_code == 200
    finally:
        admin.delete_user(u["id"])
        admin.put("/settings", json=snap)


def test_disabling_feature_is_a_redeem_kill_switch(admin):
    # A link minted while the feature is ON must STOP serving once an admin turns the feature OFF.
    before = admin.get("/settings").json().get("public_note_links_enabled")
    admin.put("/settings", json={"public_note_links_enabled": True})
    note_id = _mk_note(admin, body="kill-switch body")
    tag = _open_tag(admin)
    token = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()["token"]
    anon = admin.clone_anonymous()
    try:
        assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 200
        admin.put("/settings", json={"public_note_links_enabled": False})
        assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 404
        # Re-enabling restores access (the snapshot is still frozen).
        admin.put("/settings", json={"public_note_links_enabled": True})
        assert anon.post(f"/note-links/{token}/redeem", json={}).status_code == 200
    finally:
        admin.put("/settings", json={"public_note_links_enabled": bool(before)})


def test_password_with_surrounding_whitespace_is_verbatim(admin, links_enabled):
    # A password is stored + verified verbatim (whitespace preserved) — no create/redeem asymmetry.
    note_id = _mk_note(admin, body="spaced content")
    tag = _mk_tag(admin, require_secret="password", password_min_len=8)
    pw = "  spaced12  "
    token = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                            "password": pw}).json()["token"]
    anon = admin.clone_anonymous()
    # the stripped form must NOT unlock it...
    assert anon.post(f"/note-links/{token}/redeem", json={"secret": pw.strip()}).status_code == 401
    # ...the exact (verbatim) password does.
    assert anon.post(f"/note-links/{token}/redeem", json={"secret": pw}).status_code == 200


def test_overlong_secret_rejected(admin, links_enabled):
    note_id = _mk_note(admin)
    tag = _mk_tag(admin, require_secret="password", password_min_len=8)
    token = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                            "password": "goodpass1"}).json()["token"]
    anon = admin.clone_anonymous()
    # a huge secret is treated as wrong (not hashed, no crash)
    assert anon.post(f"/note-links/{token}/redeem", json={"secret": "x" * 5000}).status_code == 401
    # an over-long password at CREATION is refused
    r = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                        "password": "a1" * 200})
    assert r.status_code == 400, r.text


def test_temp_session_cannot_create(admin, links_enabled):
    note_id = _mk_note(admin)
    tag = _open_tag(admin)
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient(BASE_URL); temp.login(tc["temp_username"], tc["credential"])
    try:
        r = temp.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]})
        assert r.status_code == 403, r.text
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")
