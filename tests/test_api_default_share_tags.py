"""A fresh deployment seeds a usable starter set of share tags.

The create-allowlist is fail-closed (auto_enroll off + empty lists grants no one), so before this a
fresh deployment had zero share tags and sharing was unusable until an admin hand-built one. Startup
now seeds Normal / Internal / Confidential / Confidential (Read) — each auto-enrolled so every
internal user can use them, only when the table is empty (a one-time fresh-deploy bootstrap).
"""

_EXPECTED = ["Normal", "Internal", "Confidential", "Confidential (Read)"]


def test_default_share_tags_seeded(admin):
    tags = admin.get("/share-tags").json()
    by_name = {t["name"]: t for t in tags}
    for n in _EXPECTED:
        assert n in by_name, f"seeded starter tag {n!r} is missing (present: {sorted(by_name)})"

    # Every starter tag is usable by all internal users (a fail-closed allowlist would grant no one).
    for n in _EXPECTED:
        assert by_name[n]["auto_enroll_new_users"] is True, f"{n} not auto-enrolled -> unusable"
        assert by_name[n]["is_active"] is True, n
        assert by_name[n]["allow_custom"] is True, n

    # Confidential (Read) mandates view-only (no download); the others stay downloadable.
    assert by_name["Confidential (Read)"]["force_view_only"] is True
    assert by_name["Normal"]["force_view_only"] is False
    assert by_name["Confidential"]["force_view_only"] is False

    # The Confidential tags are targeted (named users / departments), never a link-to-anyone-internal.
    for n in ("Confidential", "Confidential (Read)"):
        assert "anyone_internal" not in by_name[n]["allowed_audiences"], n
    # Normal / Internal permit the anyone-internal link.
    assert "anyone_internal" in by_name["Normal"]["allowed_audiences"]
    assert "anyone_internal" in by_name["Internal"]["allowed_audiences"]


def test_seed_gate_only_fresh_and_sharing_off():
    """The seed fires only on an empty tag table AND when sharing is not already enabled — so a fresh
    deploy gets the starter set, but an existing deployment that already turned sharing on is never
    silently given permissive auto-enroll tags on upgrade."""
    from app.core.sharing_policy import should_seed_default_tags
    assert should_seed_default_tags(has_existing_tags=False, sharing_already_enabled=False) is True
    assert should_seed_default_tags(has_existing_tags=True, sharing_already_enabled=False) is False
    assert should_seed_default_tags(has_existing_tags=False, sharing_already_enabled=True) is False
    assert should_seed_default_tags(has_existing_tags=True, sharing_already_enabled=True) is False


def test_no_duplicate_default_tags(admin):
    # Idempotency: seeding runs only when the table is empty and names are DB-unique, so there is
    # exactly one of each starter tag even across many restarts.
    names = [t["name"] for t in admin.get("/share-tags").json()]
    for n in _EXPECTED:
        assert names.count(n) == 1, f"{n} appears {names.count(n)} times (expected exactly 1)"
