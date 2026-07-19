"""Share-tag CRUD + sharing master-switch validation.

Exercises the deployed surface over HTTP: interactive-admin tag CRUD (create/list/patch/soft-deactivate),
the cross-field + allowlist-existence validation, the admin-only gate, and the sharing_enabled settings
key. No share creation yet.
"""
from conftest import unique


def _minimal_tag_body(name):
    return {"name": name}


def test_create_list_patch_deactivate_tag(admin):
    name = unique("tag")
    r = admin.post("/share-tags", json={
        "name": name,
        "description": "confidential docs",
        "color": "indigo",
        "max_lifetime_minutes": 4320,
        "default_lifetime_minutes": 1440,
        "max_recipients_cap": 10,
        "max_recipients_default": 3,
        "max_downloads_cap": 5,
        "max_downloads_default": 2,
        "allow_view_only": True,
        "default_view_only": True,
        "allowed_audiences": ["users", "departments"],
        "auto_enroll_new_users": True,
    })
    assert r.status_code == 200, r.text
    tag = r.json()
    tid = tag["id"]
    assert tag["name"] == name and tag["is_active"] is True
    assert tag["allowed_audiences"] == ["users", "departments"]
    assert tag["default_view_only"] is True

    # list contains it
    listing = admin.get("/share-tags").json()
    assert any(t["id"] == tid for t in listing)

    # patch: rename + tighten a cap
    r = admin.patch(f"/share-tags/{tid}", json={"description": "updated", "max_recipients_default": 1})
    assert r.status_code == 200, r.text
    assert r.json()["description"] == "updated"
    assert r.json()["max_recipients_default"] == 1

    # soft-deactivate (DELETE) -> is_active False but STILL listed (never hard-deleted)
    r = admin.delete(f"/share-tags/{tid}")
    assert r.status_code == 200, r.text
    assert r.json()["is_active"] is False
    still = admin.get("/share-tags").json()
    row = next((t for t in still if t["id"] == tid), None)
    assert row is not None and row["is_active"] is False

    # reactivate via PATCH
    r = admin.patch(f"/share-tags/{tid}", json={"is_active": True})
    assert r.status_code == 200 and r.json()["is_active"] is True


def test_tag_validation_rejects_bad_values(admin):
    base = unique("tagv")
    # default recipients above the cap
    assert admin.post("/share-tags", json={
        "name": base + "-a", "max_recipients_cap": 3, "max_recipients_default": 9,
    }).status_code == 400
    # default lifetime above the ceiling
    assert admin.post("/share-tags", json={
        "name": base + "-b", "max_lifetime_minutes": 60, "default_lifetime_minutes": 120,
    }).status_code == 400
    # unknown audience token
    assert admin.post("/share-tags", json={
        "name": base + "-c", "allowed_audiences": ["users", "bogus"],
    }).status_code == 400
    # empty audiences (a tag usable for nothing)
    assert admin.post("/share-tags", json={
        "name": base + "-d", "allowed_audiences": [],
    }).status_code == 400
    # unknown allowlist id (fail-loud, not silently ignored)
    assert admin.post("/share-tags", json={
        "name": base + "-e", "allowed_user_ids": ["00000000-0000-0000-0000-000000000000"],
    }).status_code == 400
    # negative / zero caps rejected by the schema (ge=1)
    assert admin.post("/share-tags", json={"name": base + "-f", "max_downloads_cap": 0}).status_code == 422


def test_tag_name_must_be_unique(admin):
    name = unique("dup")
    assert admin.post("/share-tags", json={"name": name}).status_code == 200
    assert admin.post("/share-tags", json={"name": name}).status_code == 400


def test_tag_crud_requires_interactive_admin(anon, temp_user_client, admin):
    # unauthenticated
    assert anon.get("/share-tags").status_code in (401, 403)
    assert anon.post("/share-tags", json={"name": unique("x")}).status_code in (401, 403)
    # a regular (non-admin) user cannot list or mutate tags
    assert temp_user_client.get("/share-tags").status_code == 403
    assert temp_user_client.post("/share-tags", json={"name": unique("x")}).status_code == 403
    # sanity: admin can
    assert admin.get("/share-tags").status_code == 200


def test_sharing_enabled_settings_key_bool_only_and_effective(admin):
    # non-bool rejected
    assert admin.put("/settings", json={"sharing_enabled": "yes"}).status_code == 400
    # bool accepted + reflected in GET /settings (effective overlay)
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200
    assert admin.get("/settings").json().get("sharing_enabled") is True
    assert admin.put("/settings", json={"sharing_enabled": False}).status_code == 200
    assert admin.get("/settings").json().get("sharing_enabled") is False


def test_patch_explicit_null_on_required_field_rejected_not_500(admin):
    tid = admin.post("/share-tags", json={"name": unique("nul")}).json()["id"]
    # explicit JSON null on a NOT-NULL field -> clean 400 (never a 500 IntegrityError, never a broken tag)
    for field in ("max_lifetime_minutes", "default_lifetime_minutes", "is_active",
                  "allow_view_only", "auto_enroll_new_users", "allowed_audiences"):
        r = admin.patch(f"/share-tags/{tid}", json={field: None})
        assert r.status_code == 400, f"{field}=null should 400, got {r.status_code}: {r.text}"
    # the tag survived every rejected patch, still active + still has audiences
    row = next(t for t in admin.get("/share-tags").json() if t["id"] == tid)
    assert row["is_active"] is True and row["allowed_audiences"]
    # a NULLABLE cap CAN be cleared to null (unlimited) -> 200
    assert admin.patch(f"/share-tags/{tid}", json={"max_recipients_cap": None}).status_code == 200


def test_patch_tolerates_stale_user_id_but_rejects_new_bogus_id(admin):
    # a tag whose allowlist references a real user
    u = admin.create_user(role="user")
    tid = admin.post("/share-tags", json={"name": unique("stale"), "allowed_user_ids": [u["id"]]}).json()["id"]
    # deleting the user does NOT scrub its id from the tag; an unrelated edit must still succeed (not 400)
    admin.delete_user(u["id"])
    assert admin.patch(f"/share-tags/{tid}", json={"description": "unrelated edit"}).status_code == 200
    # but adding a genuinely-unknown id still fails loud (only newly-added ids are existence-checked)
    r = admin.patch(f"/share-tags/{tid}", json={
        "allowed_user_ids": [u["id"], "00000000-0000-0000-0000-000000000000"],
    })
    assert r.status_code == 400


def test_description_rejects_markup_on_create_and_patch(admin):
    # create with markup in description -> 400 (input-boundary hygiene, like every sibling free-text field)
    assert admin.post("/share-tags", json={
        "name": unique("xss"), "description": "<script>alert(1)</script>",
    }).status_code in (400, 422)
    tid = admin.post("/share-tags", json={"name": unique("xss2")}).json()["id"]
    assert admin.patch(f"/share-tags/{tid}", json={"description": "<img src=x onerror=alert(1)>"}).status_code in (400, 422)
