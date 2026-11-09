"""What a new install is seeded with (read from the seed specs; a running deployment keeps its own tags).

The everyday share tags last long enough for real work (a 90-day ceiling, a 30-day default), the
confidential ones keep the model's short defaults, and a "Client delivery" link tag (30 days, password
required, files and folders) is among the starter link tags. A long extension is a fixed step-up every
route for it registers.
"""
import pytest

pytestmark = pytest.mark.unit


def test_everyday_share_tags_get_long_lifetimes_and_confidential_ones_do_not():
    from app.api import api_server
    by_name = {t["name"]: t for t in api_server._DEFAULT_SHARE_TAGS}
    for name in ("Normal", "Internal"):
        assert by_name[name]["max_lifetime_minutes"] == 90 * 24 * 60, name
        assert by_name[name]["default_lifetime_minutes"] == 30 * 24 * 60, name
    for name in ("Confidential", "Confidential (Read)"):
        assert "max_lifetime_minutes" not in by_name[name] and "default_lifetime_minutes" not in by_name[name], name


def test_a_client_delivery_link_tag_is_seeded():
    from app.core import note_link_policy as p
    tag = next(t for t in p.DEFAULT_NOTE_LINK_TAGS if t["name"] == "Client delivery")
    assert tag["default_ttl_hours"] == 720 and tag["max_ttl_hours"] == 720
    assert tag["require_secret"] == "password" and tag["password_min_len"] >= 8
    assert set(tag["allowed_targets"]) == {"file", "folder"}
    assert tag["auto_enroll_new_users"] is True
    # Every seeded tag still validates as a tag.
    for t in p.DEFAULT_NOTE_LINK_TAGS:
        p.validate_tag_fields(dict(t))


def test_a_long_extension_is_a_fixed_step_up_that_the_routes_guard():
    from app.core import second_factor_actions as acts, fixed_step_up
    from app.api import api_server  # noqa: F401 - importing registers the guard
    assert acts.fixed_policy("link.extend_long") == "factor_when_enrolled"
    assert "link.extend_long" in fixed_step_up.GUARDED
