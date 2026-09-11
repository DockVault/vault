"""A fresh install starts usable. A deployment that already exists is not touched.

The second sentence is the whole risk, and it is why this is written as a seed rather than as new
defaults. Three features ship off: temporary vault passcodes, upload links, and public links that may
target files and folders. Turning them on by changing `.get(key, False)` to `.get(key, True)` would
have switched them on for every EXISTING deployment that had simply never saved the key. Someone's
server would start accepting anonymous uploads because they upgraded.

It would also have been invisible to the obvious check. A settings-blob diff across an upgrade would
show nothing, because nothing in the blob would have changed — the behaviour moved, the data did not.

So the code defaults stay off, and a brand-new deployment gets the keys WRITTEN. "Brand-new" is not
guessed: the admin bootstrap returns "seeded" only when it just created the first admin on an empty
database, and every other status means the deployment predates this run.

Lanes:
  * unit        — the seed writes on "seeded" and on nothing else, never overwrites an existing key,
                  and the code defaults are still off. No server, no database.
  * integration — a fresh deployment really does come up with the features on.
"""
import re
from pathlib import Path

import pytest

from app.core import (note_link_policy, receiver_policy, settings_bootstrap,
                      temp_passcode_policy)

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"

# Every status bootstrap_admin can return that means the deployment already existed.
PRE_EXISTING = ["already-bootstrapped", "marked-existing", "no-password", "error"]


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_a_brand_new_deployment_gets_the_features_switched_on():
    assert settings_bootstrap.should_seed_settings("seeded") is True
    added = settings_bootstrap.settings_to_add({})
    assert added == settings_bootstrap.FRESH_INSTALL_SETTINGS
    for key, value in settings_bootstrap.FRESH_INSTALL_SETTINGS.items():
        assert value is True, f"{key} is seeded as {value!r}; these are all meant to be on"


@pytest.mark.unit
@pytest.mark.parametrize("status", PRE_EXISTING)
def test_an_existing_deployment_is_never_seeded(status):
    """Every status that is not "seeded" means the deployment predates this run."""
    assert settings_bootstrap.should_seed_settings(status) is False, (
        f"status {status!r} would seed an existing deployment")


@pytest.mark.unit
def test_an_operator_who_already_chose_keeps_their_choice():
    """A key already present is never returned, whatever its value."""
    blob = {"public_receivers_enabled": False, "session_timeout": 30}
    added = settings_bootstrap.settings_to_add(blob)
    assert "public_receivers_enabled" not in added, (
        "an explicit False must survive the seed — the operator said no")
    assert added["temp_passcodes_enabled"] is True, "keys they did not set are still seeded"
    assert "session_timeout" not in added, "unrelated settings are not the seed's business"


@pytest.mark.unit
def test_the_code_defaults_are_still_off():
    """The half that keeps this a seed rather than a behaviour change.

    If any of these flipped, an existing deployment would gain the feature on upgrade whatever the
    seed does — and the blob diff used to police that would show nothing at all.
    """
    assert temp_passcode_policy.passcodes_enabled({}) is False
    assert receiver_policy.public_receivers_enabled({}) is False
    assert note_link_policy.public_file_links_enabled({}) is False


@pytest.mark.unit
def test_the_startup_seed_is_gated_on_the_bootstrap_status():
    """This test used to assert that the settings seed ran BEFORE the tag seeders.

    That ordering is exactly what caused a regression: the settings seed wrote
    public_receivers_enabled, and the receiver-tag seeder then read that key back as "an admin has
    already set this up" and seeded nothing — a deployment with the feature enabled and no tags,
    which its navigation hides entirely.

    Ordering is no longer load-bearing and must not be asserted, because asserting it would pin the
    coupling back in place. The tag seeders are told whether this is a new database instead, which is
    the question they were really asking. See test_fresh_install_is_usable.py for the invariant.
    """
    src = API.read_text(encoding="utf-8")
    assert "settings_bootstrap.should_seed_settings(bootstrap_status)" in src, (
        "the startup seed must ask the gate rather than deciding for itself")
    assert "_seed_default_settings(_admin_bootstrap_status)" in src, (
        "startup must pass the status, or the gate never sees it")


@pytest.mark.unit
def test_every_seeded_note_link_tag_permits_files_and_folders():
    for tag in note_link_policy.DEFAULT_NOTE_LINK_TAGS:
        assert tag.get("allowed_targets") == ["note", "file", "folder"], (
            f"{tag['name']} should permit all three targets out of the box, got "
            f"{tag.get('allowed_targets')!r} — without it a fresh deployment can publish a note but "
            f"not a file until an admin edits a tag by hand")


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_a_running_fresh_deployment_reports_the_features_on(admin):
    """Only meaningful against a deployment CREATED by this build. An upgraded one correctly reports
    whatever it always had, which is the point of the change and not a failure."""
    settings = admin.get("/settings").json()
    for key in ("temp_passcodes_enabled", "public_receivers_enabled", "public_file_links_enabled"):
        assert settings.get(key) is True, f"{key} should be on for a fresh install: {settings.get(key)}"
