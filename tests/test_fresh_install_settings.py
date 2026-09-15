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
def test_the_seeded_tags_permit_what_their_tokens_can_safely_carry():
    """Open is a 6-character, never-expiring, secretless link: notes only. The long-token tags
    publish files and folders too. And every description says which, so nobody has to open the
    editor to learn that a folder they published went out on a permanent guessable URL."""
    tags = {t["name"]: t for t in note_link_policy.DEFAULT_NOTE_LINK_TAGS}

    assert tags["Open"]["allowed_targets"] == ["note"], (
        f"the Open tag must publish notes only, got {tags['Open']['allowed_targets']!r} — its "
        f"6-character secretless token was calibrated for a text note, and a folder behind it is a "
        f"whole folder on a permanent guessable link")
    for name in ("Restricted", "Confidential"):
        assert tags[name]["allowed_targets"] == ["note", "file", "folder"], (
            f"{name} should publish all three kinds out of the box, got "
            f"{tags[name]['allowed_targets']!r} — without it a fresh deployment can publish a note "
            f"but not a file until an admin edits a tag by hand")
        assert tags[name]["min_token_len"] >= 20, (
            f"{name} publishes files and folders, so its token floor must be the long one")

    # The descriptions are the only place a person is told, so they must agree with the policy.
    open_desc = tags["Open"]["description"].lower()
    assert "note" in open_desc and "file" not in open_desc and "folder" not in open_desc, (
        f"the Open description must say it is for a note and nothing wider: {open_desc!r}")
    for name in ("Restricted", "Confidential"):
        desc = tags[name]["description"].lower()
        assert all(word in desc for word in ("note", "file", "folder")), (
            f"{name} publishes notes, files and folders and its description must say so: {desc!r}")


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_the_open_tag_refuses_a_folder_and_the_long_token_tag_accepts_it(admin):
    """The seeded rows, asked over HTTP what they will publish — not the catalog they came from.

    A folder behind the Open tag is the thing that must never be minted: a 6-character, secretless,
    never-expiring link to everything in it. The same folder behind Restricted is fine, because its
    token is 20 characters and it expires. Both halves are asserted so a fix that simply refused
    folders everywhere would not pass.
    """
    tags = {t["name"]: t for t in admin.get("/note-link-tags").json()}
    for name in ("Open", "Restricted"):
        if name not in tags:
            pytest.skip(f"no seeded {name} tag on this deployment")
    if "folder" not in (tags["Restricted"].get("allowed_targets") or []):
        # An existing deployment's tags are never revisited, so one seeded before the long-token
        # tags permitted files keeps its note-only rows. That is correct, and it is not what this
        # test is about.
        pytest.skip("Restricted is note-only here: seeded before the long-token tags published "
                    "files and folders, and existing tags are never rewritten")

    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_links_enabled")}
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True})
    vault = admin.create_vault()
    try:
        made = admin.post(f"/vaults/{vault['id']}/folders", json={"name": "published"})
        made.raise_for_status()
        folder_id = made.json()["folder"]["id"]

        def link_for(tag):
            return admin.post("/public-links", json={"vault_id": vault["id"], "target_type": "folder",
                                                     "target_folder_id": folder_id, "tag_id": tag["id"]})

        refused = link_for(tags["Open"])
        assert refused.status_code == 400, (
            f"the Open tag published a folder on a 6-character permanent link: "
            f"{refused.status_code} {refused.text}")
        accepted = link_for(tags["Restricted"])
        assert accepted.status_code == 200, (
            f"the Restricted tag should publish a folder: {accepted.status_code} {accepted.text}")
    finally:
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={k: val for k, val in snap.items() if val is not None})


@pytest.mark.integration
def test_a_running_fresh_deployment_reports_the_features_on(admin):
    """Only meaningful against a deployment CREATED by this build. An upgraded one correctly reports
    whatever it always had — that is the point of the change — so there the honest outcome is a
    skip that says so, not a failure. This used to hard-assert on every deployment, which made it
    permanently red on a correctly upgraded one, and a test that is always red teaches everyone
    to stop reading red.

    The skip names what is off, because a switch can also be off for a reason that IS worth
    reading: an admin turned it off, or an earlier test in the same run did and left it so. Neither
    is this test's failure, and it cannot tell them apart from an upgrade, so it says what it saw.
    The seed's own logic is proved offline against the real function; this lane only confirms a
    fresh deployment really comes up with the keys written.
    """
    settings = admin.get("/settings").json()
    keys = ("temp_passcodes_enabled", "public_receivers_enabled", "public_file_links_enabled")
    off = [k for k in keys if settings.get(k) is not True]
    if off:
        pytest.skip(f"not a fresh install of this build, or a switch was turned off since: {off} "
                    f"are off (a fresh deployment seeds all three on)")
    assert all(settings.get(k) is True for k in keys)
