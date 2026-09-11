"""A fresh install must not switch a feature on and then leave it unreachable.

This is a regression test for a bug I introduced. The fresh-install seeder writes
`public_receivers_enabled = true`. The tag seeder then read that same key to answer "has an admin
already set this up?", saw true, concluded yes, and seeded ZERO tags. The navigation requires
`enabled && tags.length > 0`, so a brand-new deployment came up with upload links enabled, no tags,
and no way to reach them — including the "Drop vault" tag another item requires. Measured on a fresh
stack at the time: receiver_tags = 0, note_link_tags = 3, share_tags = 4.

The cause is one question standing in for another. "Is the key set" and "has an admin engaged with
this feature" were the same thing until our own seeder started writing the key, and then they were
not. The seeders now ask the admin bootstrap instead: on a genuinely new database nobody can have
engaged with anything, so the answer is simply no.

Ordering would also have fixed it — seed the settings after the tags — but that leaves the coupling
in place for whoever adds the next seeder. This removes it.

Lanes:
  * integration — the invariant itself, on a running deployment: every feature the fresh install
                  enables has the tags it needs to be usable. This is the lane that would have caught
                  it, and the only one that can.
  * unit        — a source guard that the seeders take the bootstrap status and no longer trust a
                  settings value we write ourselves.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"

SEEDERS = ["_seed_default_share_tags", "_seed_default_note_link_tags", "_seed_default_receiver_tags"]


def _fn_body(src, name):
    start = src.index(f"def {name}(")
    return src[start:src.index("\ndef ", start + 1)]


@pytest.mark.unit
@pytest.mark.parametrize("fn", SEEDERS)
def test_the_tag_seeders_ask_the_bootstrap_not_a_key_we_write(fn):
    src = API.read_text(encoding="utf-8")
    assert re.search(rf"def {fn}\(bootstrap_status", src), (
        f"{fn} must be told whether this is a new database")
    body = _fn_body(src, fn)
    assert "settings_bootstrap.FRESH_BOOTSTRAP_STATUS" in body, (
        f"{fn} still decides 'already engaged' from a settings key that our own fresh-install "
        f"seeder writes — which is what made it seed nothing")


@pytest.mark.unit
def test_every_seeder_is_actually_given_the_status():
    """A parameter with a default of None is inert if no caller passes it."""
    src = API.read_text(encoding="utf-8")
    for fn in SEEDERS:
        assert f"{fn}(_admin_bootstrap_status)" in src, (
            f"{fn} takes the status but startup never passes it, so the fix does nothing")


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_everything_the_fresh_install_enables_is_actually_reachable(admin):
    """The invariant, stated once: enabled implies usable.

    Only meaningful against a deployment CREATED by this build — an upgraded one keeps whatever it
    had, which is the point of fresh-install seeding and not a failure. Skips rather than lies when
    the feature is off.
    """
    settings = admin.get("/settings").json()

    checks = [
        ("public_receivers_enabled", "/receiver-tags", "upload links"),
        ("public_note_links_enabled", "/note-link-tags", "public note links"),
        ("sharing_enabled", "/share-tags", "sharing"),
    ]
    checked = 0
    for key, endpoint, label in checks:
        if settings.get(key) is not True:
            continue                      # off on this deployment; nothing to be reachable
        tags = admin.get(endpoint).json()
        tags = tags if isinstance(tags, list) else tags.get("tags", [])
        assert tags, (
            f"{label} is enabled but has no tags, so its navigation stays hidden and the feature "
            f"cannot be reached at all")
        checked += 1

    # Non-vacuous: if nothing was enabled we proved nothing, and should say so rather than pass.
    if not checked:
        pytest.skip("no seeded feature is enabled on this deployment; nothing to check")


@pytest.mark.integration
def test_the_open_upload_link_tag_is_present_on_a_fresh_install(admin):
    """The specific tag the rebrand depends on. A fresh install seeds "Drop vault"; an older
    deployment keeps "Drop box", and both are correct."""
    settings = admin.get("/settings").json()
    if settings.get("public_receivers_enabled") is not True:
        pytest.skip("upload links are off on this deployment")
    names = {t["name"] for t in admin.get("/receiver-tags").json()}
    assert {"Drop vault", "Drop box"} & names, (
        f"the open upload-link tag was never seeded: {sorted(names)}")
