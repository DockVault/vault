"""An upload link's retention can be changed by its owner, within what the link's type allows.

An upload link keeps what it receives in its own vault, and the link's retention is that vault's
"expire files after" setting. The vault's settings refuse to change it for this vault, because the
link's type (its tag) bounds it; until this route existed the refusal pointed at a control that was
not there, so the retention chosen at creation could never be changed.

PATCH /receivers/{id}/retention takes {retention_days: N} or {retention_days: null} (keep uploads
until someone deletes them):

* at most the tag's maximum retention as the tag stands now, and never more than MAX_RETENTION_DAYS;
* null only when the tag sets no maximum;
* a link whose tag has been deactivated or deleted can only be shortened;
* a new number of days applies to files that arrive from now on, and null takes the deadline off
  every file already in the vault, as a vault's own setting does since file expiry is enforced.

Lanes:
  * unit        -- the bounds, offline (receiver_policy.retention_limits / resolve_retention_change).
  * integration -- the route against a running stack: owner only, bounds, deadlines, the audit row,
                   the vault settings refusal, and the details dialog in the browser.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique, skip_if_container_absent

from app.core import receiver_policy as rp

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_MB = 1024 * 1024


# --------------------------------------------------------------------------- unit lane

def _tag(**over):
    tag = {"is_active": True, "retention_max_days": 30}
    tag.update(over)
    return tag


@pytest.mark.unit
def test_a_tag_with_a_maximum_bounds_the_change_and_forbids_keeping():
    assert rp.retention_limits(_tag(), 7) == (30, False)
    assert rp.resolve_retention_change(_tag(), 7, 30) == 30
    assert rp.resolve_retention_change(_tag(), 7, 1) == 1
    with pytest.raises(rp.PolicyViolation, match="at most 30 days for this link type"):
        rp.resolve_retention_change(_tag(), 7, 31)
    with pytest.raises(rp.PolicyViolation, match="cannot be kept forever"):
        rp.resolve_retention_change(_tag(), 7, None)


@pytest.mark.unit
def test_a_tag_without_a_maximum_allows_keeping_and_up_to_the_hard_ceiling():
    tag = _tag(retention_max_days=None)
    assert rp.retention_limits(tag, 7) == (rp.MAX_RETENTION_DAYS, True)
    assert rp.resolve_retention_change(tag, 7, None) is None
    assert rp.resolve_retention_change(tag, None, rp.MAX_RETENTION_DAYS) == rp.MAX_RETENTION_DAYS
    with pytest.raises(rp.PolicyViolation, match="at most %d days" % rp.MAX_RETENTION_DAYS):
        rp.resolve_retention_change(tag, 7, rp.MAX_RETENTION_DAYS + 1)


@pytest.mark.unit
@pytest.mark.parametrize("gone", [None, _tag(is_active=False), _tag(is_active=False, retention_max_days=None)])
def test_a_link_whose_tag_is_gone_can_only_be_shortened(gone):
    # Nothing is left to lengthen it under: the tag's own maximum no longer counts either way.
    assert rp.retention_limits(gone, 10) == (10, False)
    assert rp.resolve_retention_change(gone, 10, 3) == 3
    assert rp.resolve_retention_change(gone, 10, 10) == 10
    with pytest.raises(rp.PolicyViolation, match="can only be shortened, to 10 days or fewer"):
        rp.resolve_retention_change(gone, 10, 11)
    with pytest.raises(rp.PolicyViolation, match="cannot be kept forever"):
        rp.resolve_retention_change(gone, 10, None)


@pytest.mark.unit
def test_a_link_already_kept_forever_under_a_gone_tag_can_be_given_any_retention():
    # Keeping is the loosest setting, so every number of days is a tightening of it.
    assert rp.retention_limits(None, None) == (rp.MAX_RETENTION_DAYS, True)
    assert rp.resolve_retention_change(None, None, 400) == 400
    assert rp.resolve_retention_change(None, None, None) is None


@pytest.mark.unit
@pytest.mark.parametrize("bad", [0, -1, True, False, 2.5, 3.0, "7", [7], {}])
def test_anything_but_a_whole_number_of_days_is_refused_in_plain_words(bad):
    with pytest.raises(rp.PolicyViolation, match="a whole number, 1 or more"):
        rp.resolve_retention_change(_tag(retention_max_days=None), 7, bad)


@pytest.mark.unit
def test_the_tag_is_read_as_it_stands_now():
    # An admin who lowered the tag's maximum after the link was made has lowered it for the link.
    assert rp.retention_limits(_tag(retention_max_days=5), 20) == (5, False)
    with pytest.raises(rp.PolicyViolation, match="at most 5 days"):
        rp.resolve_retention_change(_tag(retention_max_days=5), 20, 20)


# --------------------------------------------------------------------------- integration lane

def _psql(sql):
    try:
        r = subprocess.run(
            ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, _DB)
    assert r.returncode == 0, r.stderr[:300]
    return (r.stdout or "").strip()


@pytest.fixture
def receivers_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json={k: v for k, v in snap.items() if v is not None})


@pytest.fixture
def made(admin, receivers_on):
    """Make upload links under fresh tags; delete their vaults (and so the links) afterwards."""
    vaults = []

    def make(retention_max_days=30, retention_days=7, label=None):
        tag = admin.post("/receiver-tags", json={
            "name": unique("rtret"), "min_token_len": 10, "require_secret": "none",
            "auto_enroll_new_users": True, "kind_floor": "standard",
            "max_total_bytes_cap": 50 * _MB, "retention_max_days": retention_max_days,
            "retention_default_days": None})
        assert tag.status_code in (200, 201), tag.text
        rec = admin.post("/receivers", json={"tag_id": tag.json()["id"], "max_total_bytes": 10 * _MB,
                                             "retention_days": retention_days, "label": label})
        assert rec.status_code == 200, rec.text
        vaults.append(rec.json()["vault_id"])
        return tag.json(), rec.json()

    yield make
    for vid in vaults:
        admin.delete_vault(vid)


def _upload(client, vid, name):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, b"kept?", "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _days_left(fid):
    """Whole days from now to the file's deadline, or 'none'."""
    return _psql(f"SELECT coalesce(round(extract(epoch FROM expires_at - (now() AT TIME ZONE 'utc'))"
                 f" / 86400)::text, 'none') FROM files WHERE id = '{fid}'")


def _audit_rows(rid):
    return _psql(f"SELECT count(*) FROM audit_logs WHERE action = 'receiver_retention_changed' "
                 f"AND resource_id = '{rid}'")


@pytest.mark.integration
def test_the_owner_changes_the_retention_and_new_uploads_follow_it(admin, made):
    _tag_row, rec = made(retention_max_days=30, retention_days=7)
    listed = next(x for x in admin.get("/receivers").json()["receivers"] if x["id"] == rec["id"])
    assert (listed["retention_limit_days"], listed["retention_may_keep"]) == (30, False)

    before = _upload(admin, rec["vault_id"], unique("before") + ".txt")
    assert _days_left(before) == "7"

    r = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 20})
    assert r.status_code == 200, r.text
    assert r.json()["retention_days"] == 20
    assert _psql(f"SELECT retention_days FROM receivers WHERE id = '{rec['id']}'") == "20"
    assert _psql(f"SELECT expire_files_after_days || ' ' || coalesce(expire_files_unit, 'days') "
                 f"FROM vaults WHERE id = '{rec['vault_id']}'") == "20 days"

    after = _upload(admin, rec["vault_id"], unique("after") + ".txt")
    assert _days_left(after) == "20", "an upload after the change must take the new retention"
    assert _days_left(before) == "7", "a file already in the vault keeps the deadline it was given"

    assert _audit_rows(rec["id"]) == "1"
    again = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 20})
    assert again.status_code == 200, again.text
    assert _audit_rows(rec["id"]) == "1", "setting the same retention again changes nothing to record"
    details = _psql(f"SELECT details::text FROM audit_logs WHERE action = 'receiver_retention_changed' "
                    f"AND resource_id = '{rec['id']}'")
    assert '"retention_days": 20' in details and '"previous_retention_days": 7' in details, details


@pytest.mark.integration
def test_the_tag_bounds_the_change(admin, made):
    _tag_row, rec = made(retention_max_days=30, retention_days=7)
    too_long = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 31})
    assert too_long.status_code == 400, too_long.text
    assert "at most 30 days" in too_long.json()["detail"]
    keep = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": None})
    assert keep.status_code == 400, keep.text
    assert "cannot be kept forever" in keep.json()["detail"]
    text = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": "20"})
    assert text.status_code == 400, text.text
    missing = admin.patch(f"/receivers/{rec['id']}/retention", json={})
    assert missing.status_code == 422, missing.text
    assert _psql(f"SELECT retention_days FROM receivers WHERE id = '{rec['id']}'") == "7"
    assert _psql(f"SELECT expire_files_after_days FROM vaults WHERE id = '{rec['vault_id']}'") == "7"
    assert _audit_rows(rec["id"]) == "0"


@pytest.mark.integration
def test_keeping_uploads_takes_the_deadline_off_every_file(admin, made):
    _tag_row, rec = made(retention_max_days=None, retention_days=7)
    fid = _upload(admin, rec["vault_id"], unique("kept") + ".txt")
    assert _days_left(fid) == "7"

    r = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": None})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["retention_days"] is None and body["deadlines_removed"] == 1, body
    assert _days_left(fid) == "none", "a file the link received must not expire once uploads are kept"
    assert _psql(f"SELECT coalesce(expire_files_after_days::text, 'off') FROM vaults "
                 f"WHERE id = '{rec['vault_id']}'") == "off"
    later = _upload(admin, rec["vault_id"], unique("later") + ".txt")
    assert _days_left(later) == "none"


@pytest.mark.integration
def test_a_link_whose_tag_is_deactivated_can_only_be_shortened(admin, made):
    tag, rec = made(retention_max_days=30, retention_days=10)
    assert admin.delete(f"/receiver-tags/{tag['id']}").status_code == 200
    longer = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 20})
    assert longer.status_code == 400, longer.text
    assert "can only be shortened" in longer.json()["detail"]
    shorter = admin.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 4})
    assert shorter.status_code == 200, shorter.text
    assert shorter.json()["retention_limit_days"] == 4


@pytest.mark.integration
def test_only_the_owner_can_change_it(admin, made):
    _tag_row, rec = made()
    u = admin.create_user(role="user")
    other = ApiClient(BASE_URL)
    other.login(u["_username"], u["_password"])
    try:
        r = other.patch(f"/receivers/{rec['id']}/retention", json={"retention_days": 1})
        assert r.status_code == 404, r.text
    finally:
        admin.delete_user(u["id"])
    assert _psql(f"SELECT retention_days FROM receivers WHERE id = '{rec['id']}'") == "7"


@pytest.mark.integration
def test_the_vault_settings_refusal_points_at_the_link(admin, made):
    _tag_row, rec = made()
    r = admin.patch(f"/vaults/{rec['vault_id']}/settings", json={"expire_files_after_days": 3})
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert "Upload links" in detail and "Info" in detail, detail


@pytest.mark.ui
def test_the_details_dialog_changes_the_retention(page, admin, admin_creds, made):
    from playwright.sync_api import expect

    label = unique("retention-ui")
    _tag_row, rec = made(retention_max_days=30, retention_days=7, label=label)
    page.goto("/")
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
    page.locator("#nav-uploadlinks").click()
    expect(page.locator("#uploadlinks-section")).to_be_visible()

    page.locator("#receivers-list tr", has_text=label).locator(".rc-info-btn").click()
    dialog = page.locator(".rc-info-modal")
    expect(dialog).to_be_visible()
    expect(page.locator("#rc-info-retention-text")).to_have_text("Deleted 7 days after upload")
    page.click("#rc-info-retention-change")
    expect(page.locator("#rc-info-retention-days")).to_have_attribute("max", "30")
    expect(page.locator("#rc-info-retention-keep")).to_have_count(0)   # the tag sets a maximum

    page.fill("#rc-info-retention-days", "40")
    page.click("#rc-info-retention-save")
    expect(page.locator("#rc-info-retention-error")).to_contain_text("at most 30 days")

    page.fill("#rc-info-retention-days", "12")
    page.click("#rc-info-retention-save")
    expect(page.locator("#rc-info-retention-text")).to_have_text("Deleted 12 days after upload", timeout=10000)
    assert _psql(f"SELECT retention_days FROM receivers WHERE id = '{rec['id']}'") == "12"
