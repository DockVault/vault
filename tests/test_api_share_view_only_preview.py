"""Whether a view-only share lets its recipient view files in the browser: a switch on each share tag,
copied into each share when it is made.

A tag made without the field has the switch on, and an update changes it. A view-only share made under a tag with
the switch off shows its recipient names and sizes only: the preview route refuses with a sentence that says so,
and the vault tells the web app (via_share.preview) so that it offers no preview. Under a tag with the switch on,
the recipient views the file in the browser. Neither downloads. Switching a tag on later does not open a share
made before; a share whose column holds its default (as every share made before the switch existed does after
the upgrade) is refused the preview too.
"""
import os
import subprocess

import pytest

from conftest import unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
NAMES_AND_SIZES = "This share shows names and sizes only"


def _psql(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


def _upload(client, vault_id, name, content):
    r = client.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code == 200, r.text
    return next(f["id"] for f in client.get(f"/vaults/{vault_id}/files").json()["items"] if f["name"] == name)


# The tags a test makes, deactivated when it ends (a tag is never deleted: shares keep their record of it).
_MADE = []


@pytest.fixture
def sharing(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    yield
    while _MADE:
        admin.delete(f"/share-tags/{_MADE.pop()}")
    admin.put("/settings", json={"sharing_enabled": before})


def _tag(admin, **over):
    body = {"name": unique("vptag"), "auto_enroll_new_users": True, "allowed_audiences": ["anyone_internal"],
            "max_recipients_cap": 10, "allow_view_only": True}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    _MADE.append(r.json()["id"])
    return r.json()


def _share(admin, vault, tag, **over):
    body = {"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "anyone_internal", "view_only": True}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    s = r.json()
    s["_id"] = s.get("id") or s.get("share_id")
    return s


def _claimed(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def _preview(client, vault, fid):
    return client.get(f"/vaults/{vault['id']}/files/{fid}/preview")


def test_a_tag_made_without_the_field_lets_view_only_recipients_view_files_and_an_update_changes_it(admin, sharing):
    tag = _tag(admin)
    assert tag["view_only_preview"] is True
    r = admin.patch(f"/share-tags/{tag['id']}", json={"view_only_preview": False})
    assert r.status_code == 200, r.text
    got = next(t for t in admin.get("/share-tags").json() if t["id"] == tag["id"])
    assert got["view_only_preview"] is False
    assert admin.patch(f"/share-tags/{tag['id']}", json={"view_only_preview": None}).status_code == 400
    off = _tag(admin, view_only_preview=False)
    assert off["view_only_preview"] is False


def test_a_view_only_share_under_a_tag_with_the_switch_off_shows_names_and_sizes_only(admin, sharing,
                                                                                    temp_user_client):
    vault = admin.create_vault(name=unique("vpoff"))
    try:
        fid = _upload(admin, vault["id"], "plan.txt", b"the plan")
        share = _share(admin, vault, _tag(admin, view_only_preview=False))
        # The share copied the switch, in its own column and in the record of the tag it was made under.
        assert share["view_only_preview"] is False
        assert _psql(f"SELECT view_only_preview::text || ':' || (tag_policy_snapshot->>'view_only_preview') "
                     f"FROM shares WHERE id='{share['_id']}'") == "false:false"
        _claimed(temp_user_client, share)
        # The recipient sees the file listed, and the vault says nothing here can be viewed.
        items = temp_user_client.get(f"/vaults/{vault['id']}/files").json()["items"]
        assert any(i["id"] == fid for i in items)
        assert temp_user_client.get(f"/vaults/{vault['id']}").json()["via_share"] == {"view_only": True,
                                                                                        "preview": False}
        p = _preview(temp_user_client, vault, fid)
        assert p.status_code == 403, p.text
        assert NAMES_AND_SIZES in p.json()["detail"]
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 403
        # A refused preview spends nothing.
        assert _psql(f"SELECT preview_count FROM share_claims WHERE share_id='{share['_id']}'") == "0"
    finally:
        admin.delete_vault(vault["id"])


def test_a_view_only_share_under_a_tag_with_the_switch_on_is_viewed_and_never_downloaded(admin, sharing,
                                                                                        temp_user_client):
    vault = admin.create_vault(name=unique("vpon"))
    try:
        fid = _upload(admin, vault["id"], "plan.txt", b"the plan")
        share = _share(admin, vault, _tag(admin, view_only_preview=True))
        assert share["view_only_preview"] is True
        assert _psql(f"SELECT view_only_preview::text || ':' || (tag_policy_snapshot->>'view_only_preview') "
                     f"FROM shares WHERE id='{share['_id']}'") == "true:true"
        _claimed(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{vault['id']}").json()["via_share"] == {"view_only": True,
                                                                                        "preview": True}
        p = _preview(temp_user_client, vault, fid)
        assert p.status_code == 200 and p.content == b"the plan", p.text
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_vault(vault["id"])


def test_switching_a_tag_on_later_leaves_a_share_made_before_closed(admin, sharing, temp_user_client):
    vault = admin.create_vault(name=unique("vplater"))
    try:
        fid = _upload(admin, vault["id"], "plan.txt", b"the plan")
        tag = _tag(admin, view_only_preview=False)
        share = _share(admin, vault, tag)
        _claimed(temp_user_client, share)
        assert admin.patch(f"/share-tags/{tag['id']}", json={"view_only_preview": True}).status_code == 200
        p = _preview(temp_user_client, vault, fid)
        assert p.status_code == 403 and NAMES_AND_SIZES in p.json()["detail"], p.text
        # Shared again under the tag as it is now, the file is viewed.
        again = _share(admin, vault, tag)
        assert again["view_only_preview"] is True
        _claimed(temp_user_client, again)
        assert _preview(temp_user_client, vault, fid).status_code == 200
    finally:
        admin.delete_vault(vault["id"])


def test_a_share_that_reads_its_column_default_is_refused_the_preview(admin, sharing, temp_user_client):
    # Made under a tag with the switch on, then given the column's default, as every share that existed before the
    # upgrade has: the preview is refused.
    vault = admin.create_vault(name=unique("vpold"))
    try:
        fid = _upload(admin, vault["id"], "plan.txt", b"the plan")
        share = _share(admin, vault, _tag(admin, view_only_preview=True))
        _claimed(temp_user_client, share)
        assert _preview(temp_user_client, vault, fid).status_code == 200
        _psql(f"UPDATE shares SET view_only_preview = DEFAULT WHERE id='{share['_id']}'")
        assert _psql(f"SELECT view_only_preview FROM shares WHERE id='{share['_id']}'") == "f"
        p = _preview(temp_user_client, vault, fid)
        assert p.status_code == 403 and NAMES_AND_SIZES in p.json()["detail"], p.text
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_vault(vault["id"])


def test_a_share_that_allows_downloads_previews_whatever_the_switch_says(admin, sharing, temp_user_client):
    vault = admin.create_vault(name=unique("vpdl"))
    try:
        fid = _upload(admin, vault["id"], "plan.txt", b"the plan")
        share = _share(admin, vault, _tag(admin, view_only_preview=False), view_only=False)
        _claimed(temp_user_client, share)
        assert _preview(temp_user_client, vault, fid).status_code == 200
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 200
    finally:
        admin.delete_vault(vault["id"])


def test_a_share_is_viewable_only_when_its_maker_was_not_told_otherwise(admin, sharing):
    # The share dialog says what view-only gives from the tags it read when it opened, and sends that with the
    # share. The tag may have been switched on since: what the maker was shown wins.
    vault = admin.create_vault(name=unique("vpshown"))
    try:
        tag = _tag(admin, view_only_preview=True)
        assert _share(admin, vault, tag, view_only_preview_shown=False)["view_only_preview"] is False
        assert _share(admin, vault, tag, view_only_preview_shown=True)["view_only_preview"] is True
        # A caller that says nothing gets the tag's switch as it is.
        assert _share(admin, vault, tag)["view_only_preview"] is True
        off = _tag(admin, view_only_preview=False)
        assert _share(admin, vault, off)["view_only_preview"] is False
        # Being told the files can be viewed does not open a share the tag does not allow.
        assert _share(admin, vault, off, view_only_preview_shown=True)["view_only_preview"] is False
    finally:
        admin.delete_vault(vault["id"])


def test_the_upgrade_gave_both_columns_a_default_off():
    out = _psql("SELECT table_name || ':' || column_default || ':' || is_nullable FROM information_schema.columns "
                "WHERE column_name='view_only_preview' AND table_name IN ('shares', 'share_tags') ORDER BY 1")
    assert out.splitlines() == ["share_tags:false:NO", "shares:false:NO"], out


def test_a_share_its_maker_was_shown_as_view_only_stays_view_only(admin, sharing):
    # The dialog read a tag that forced view-only; an administrator stopped forcing it before the share was made.
    # What the maker was shown wins, and it only ever narrows.
    vault = admin.create_vault(name=unique("voshown"))
    try:
        free = _tag(admin, allow_custom=False, default_view_only=False, force_view_only=False)
        assert _share(admin, vault, free, view_only=None, view_only_shown=True)["view_only"] is True
        assert _share(admin, vault, free, view_only=None)["view_only"] is False
        forced = _tag(admin, force_view_only=True)
        assert _share(admin, vault, forced, view_only=None, view_only_shown=False)["view_only"] is True
        # A tag that makes its shares view-only by its default stays so, whatever the dialog says.
        assert _share(admin, vault, _tag(admin, allow_custom=False, default_view_only=True), view_only=None,
                      view_only_shown=False)["view_only"] is True
        # A tag that no longer allows view-only refuses a share its maker was shown as view-only, and makes none.
        before = {s["id"] for s in admin.get("/shares").json()}
        no_vo = _tag(admin, allow_view_only=False)
        r = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": no_vo["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only_shown": True})
        assert r.status_code == 409, r.text
        assert r.json()["detail"] == "this tag does not allow view-only shares", r.text
        assert {s["id"] for s in admin.get("/shares").json()} == before
        # A share its maker was not shown as view-only is made on that tag as before.
        assert _share(admin, vault, no_vo, view_only=None, view_only_shown=False)["view_only"] is False
        assert _share(admin, vault, no_vo, view_only=None)["view_only"] is False
        # The record of the share made says whether it is viewable.
        made = _share(admin, vault, _tag(admin, view_only_preview=False))
        assert _psql("SELECT details->>'view_only_preview' FROM audit_logs WHERE action='share_created' "
                     f"AND details->>'share_id'='{made['_id']}'") == "false"
        # A downloadable share's record does not say: its recipients may view and download its files.
        loose = _share(admin, vault, _tag(admin, view_only_preview=False), view_only=False)
        assert loose["view_only"] is False
        assert _psql("SELECT (details::jsonb ? 'view_only_preview')::text || ':' || (details->>'view_only') FROM audit_logs "
                     f"WHERE action='share_created' AND details->>'share_id'='{loose['_id']}'") == "false:false"
    finally:
        admin.delete_vault(vault["id"])
