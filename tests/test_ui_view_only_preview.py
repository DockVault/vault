"""A view-only share's recipient can view a file in the browser, and is given no Download button.

The share dialog says "View only (recipients can view files in the browser, with no Download button)" and that a
preview cannot stop them keeping a copy. In the recipient's own session the shared vault opens from the Shared page, a
file's preview shows its content through the preview route, and the download route refuses them.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def view_only_share(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    recipient = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(recipient["_username"], recipient["_password"])
    vault = admin.create_vault(name=unique("deck"))
    r = admin.post(f"/vaults/{vault['id']}/files", files=[("files", ("brief.txt", b"look, do not take\n" * 5, "text/plain"))])
    assert r.status_code == 200, r.text
    fid = next(f["id"] for f in admin.get(f"/vaults/{vault['id']}/files").json()["items"] if f["name"] == "brief.txt")
    tag = admin.post("/share-tags", json={"name": unique("votag"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
                                          "allow_view_only": True}).json()
    share = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only": True})
    assert share.status_code == 200, share.text
    assert client.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    try:
        yield recipient, client, vault, fid
    finally:
        admin.delete_vault(vault["id"])
        admin.delete_user(recipient["id"])
        admin.delete(f"/share-tags/{tag['id']}")
        admin.put("/settings", json={"sharing_enabled": before})


def test_the_recipient_previews_in_the_browser_and_cannot_download(page: Page, view_only_share):
    recipient, client, vault, fid = view_only_share
    _login(page, recipient)
    page.click('.sidebar-item[data-section="shared"]')
    card = page.locator(f'[data-share-id]', has_text=vault["name"]).first
    expect(card).to_be_visible(timeout=15000)
    expect(card).to_contain_text("View only (preview in the browser, no Download button)")
    page.evaluate("id => openSharedItem(id)", vault["id"])
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    # The vault says the claim is view-only, and the recipient is offered only what works: no Download on the
    # row, no Share or Public links on the toolbar, no row checkboxes (no bulk action is possible).
    assert page.evaluate("() => state.currentVault.via_share") == {"view_only": True, "preview": True}
    row = page.locator(f'#vault-files-table-body tr:has(.file-name[data-file-id="{fid}"])')
    expect(row).to_be_visible(timeout=15000)
    assert row.locator(".file-actions button[data-action]").evaluate_all(
        "els => els.map(b => b.getAttribute('data-action'))") == ["more"]
    expect(page.locator("#share-vault-btn")).to_be_hidden()
    expect(page.locator("#public-links-btn")).to_be_hidden()
    expect(page.locator("#vault-files-table-body .file-check")).to_have_count(0)
    # The one menu lists Preview and File info, nothing that downloads, copies or shares.
    row.locator('button[data-action="more"]').click()
    menu = page.locator("#file-context-menu")
    expect(menu).to_be_visible()
    labels = [l.strip() for l in menu.locator(".context-menu-item").all_text_contents()]
    assert "Preview" in labels and "File info" in labels, labels
    for absent in ("Download", "Copy", "Share", "Public link", "Copy SHA-256", "Rename", "Delete", "Move"):
        assert absent not in labels, labels
    page.keyboard.press("Escape")
    expect(menu).to_be_hidden()
    page.click(f'.file-name[data-file-id="{fid}"]')
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#file-preview-body")).to_contain_text("look, do not take", timeout=15000)
    # The preview header offers no Download either.
    expect(page.locator("#file-preview-download")).to_be_hidden()
    page.keyboard.press("Escape")
    # The same session cannot download; the refusal says why, and the app shows the server's words when a
    # download is still attempted.
    refused = client.get(f"/vaults/{vault['id']}/files/{fid}/download")
    assert refused.status_code == 403 and "view-only" in refused.json()["detail"]
    said = page.evaluate(
        """id => { const said = []; const orig = window.showError; window.showError = (m) => said.push(m);
            return _downloadFile(id, 'brief.txt').then(() => { window.showError = orig; return said; }); }""", fid)
    assert any("view-only" in m for m in said), said


def test_the_owner_keeps_download_share_and_the_preview_download(page: Page, view_only_share, admin_creds):
    """The same vault, opened by its owner: Download on the row, Share on the toolbar, checkboxes, and Download in
    the preview header."""
    _recipient, _client, vault, fid = view_only_share
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    assert page.evaluate("() => state.currentVault.via_share") is None
    row = page.locator(f'#vault-files-table-body tr:has(.file-name[data-file-id="{fid}"])')
    expect(row).to_be_visible(timeout=15000)
    assert row.locator(".file-actions button[data-action]").evaluate_all(
        "els => els.map(b => b.getAttribute('data-action'))") == ["more", "share-file", "download"]
    expect(page.locator("#share-vault-btn")).to_be_visible()
    expect(page.locator("#vault-files-table-body .file-check")).to_have_count(1)
    page.click(f'.file-name[data-file-id="{fid}"]')
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#file-preview-download")).to_be_visible()


def test_the_share_dialog_says_what_view_only_means(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    label = page.locator('label:has(#share-view-only)')
    expect(label).to_have_text("View only (recipients can view files in the browser, with no Download button)")
    expect(page.locator("#share-viewonly-group .form-help")).to_contain_text("cannot stop them keeping a copy")


NAMES_AND_SIZES = "This share shows names and sizes only"


@pytest.fixture
def names_only_share(admin):
    """A view-only share made under a tag that does not let view-only recipients view files, as every share made
    before that choice existed reads after the upgrade."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    recipient = admin.create_user(role="user")
    vault = admin.create_vault(name=unique("names"))
    r = admin.post(f"/vaults/{vault['id']}/files", files=[("files", ("brief.txt", b"look, do not take\n", "text/plain"))])
    assert r.status_code == 200, r.text
    fid = next(f["id"] for f in admin.get(f"/vaults/{vault['id']}/files").json()["items"] if f["name"] == "brief.txt")
    tag = admin.post("/share-tags", json={"name": unique("notag"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
                                          "allow_view_only": True, "view_only_preview": False}).json()
    share = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only": True})
    assert share.status_code == 200, share.text
    client = ApiClient(BASE_URL)
    client.login(recipient["_username"], recipient["_password"])
    assert client.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    try:
        yield recipient, vault, fid
    finally:
        admin.delete_vault(vault["id"])
        admin.delete_user(recipient["id"])
        admin.delete(f"/share-tags/{tag['id']}")
        admin.put("/settings", json={"sharing_enabled": before})


def test_the_recipient_of_a_names_only_share_is_told_why_and_no_preview_opens(page: Page, names_only_share):
    recipient, vault, fid = names_only_share
    previews = []
    page.on("request", lambda r: previews.append(r.url) if "/preview" in r.url else None)
    _login(page, recipient)
    page.click('.sidebar-item[data-section="shared"]')
    card = page.locator('[data-share-id]', has_text=vault["name"]).first
    expect(card).to_be_visible(timeout=15000)
    expect(card).to_contain_text("View only (names and sizes only)")
    page.evaluate("id => openSharedItem(id)", vault["id"])
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    assert page.evaluate("() => state.currentVault.via_share") == {"view_only": True, "preview": False}
    row = page.locator(f'#vault-files-table-body tr:has(.file-name[data-file-id="{fid}"])')
    expect(row).to_be_visible(timeout=15000)
    # The row's menu offers no preview.
    row.locator(".action-more").click()
    menu = page.locator("#file-context-menu")
    expect(menu).to_be_visible()
    expect(menu.get_by_role("menuitem").first).to_be_visible()
    expect(menu.get_by_role("menuitem", name="Preview", exact=True)).to_have_count(0)
    page.keyboard.press("Escape")
    # Opening the file says why, and asks the server for nothing it would refuse.
    page.click(f'.file-name[data-file-id="{fid}"]')
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#file-preview-body")).to_contain_text(NAMES_AND_SIZES)
    expect(page.locator("#file-preview-download")).to_be_hidden()
    page.wait_for_timeout(500)
    assert previews == [], previews


def test_a_refused_preview_shows_the_servers_sentence(page: Page, names_only_share):
    # A page that could not tell (the vault's answer is set here to say it could preview) is refused by the
    # server, and shows the server's own sentence rather than a status code.
    recipient, vault, fid = names_only_share
    _login(page, recipient)
    page.click('.sidebar-item[data-section="shared"]')
    page.evaluate("id => openSharedItem(id)", vault["id"])
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_be_visible(timeout=15000)
    page.evaluate("() => { state.currentVault.via_share.preview = true; }")
    with page.expect_response(lambda r: "/preview" in r.url and r.status == 403):
        page.click(f'.file-name[data-file-id="{fid}"]')
    expect(page.locator("#file-preview-body .alert")).to_contain_text(NAMES_AND_SIZES)


def test_the_share_dialog_says_what_view_only_gives_under_the_chosen_tag(page: Page, admin, admin_creds):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("label"))
    # The administrator may share under both tags (auto-enrolment covers accounts made after a tag).
    me = admin.get("/users/me").json()["id"]
    tags = {}
    for views in (True, False):
        r = admin.post("/share-tags", json={
            "name": unique("lbl"), "allowed_user_ids": [me], "allowed_audiences": ["anyone_internal"],
            "allow_view_only": True, "view_only_preview": views})
        assert r.status_code == 200, r.text
        tags[views] = r.json()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", admin_creds["username"])
        page.fill("#password", admin_creds["password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        # The vault opened, its whole-vault share dialog from the toolbar.
        page.click('.sidebar-item[data-section="vaults"]')
        page.locator(f'.vault-card[data-vault-id="{vault["id"]}"] .open-vault-btn').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.click("#share-vault-btn")
        select = page.locator("#share-tag-select")
        expect(select.locator(f'option[value="{tags[False]["id"]}"]')).to_have_count(1, timeout=10000)
        label = page.locator("#share-view-only-text")
        select.select_option(tags[False]["id"])
        expect(label).to_have_text("View only (recipients see names and sizes; they cannot open or download)")
        expect(page.locator("#share-view-only-help")).not_to_contain_text("preview")
        select.select_option(tags[True]["id"])
        expect(label).to_have_text("View only (recipients can view files in the browser, with no Download button)")
        expect(page.locator("#share-view-only-help")).to_contain_text("cannot stop them keeping a copy")
    finally:
        for t in tags.values():
            admin.delete(f"/share-tags/{t['id']}")
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={"sharing_enabled": before})


def test_a_share_made_after_the_tag_changed_keeps_what_its_maker_was_shown(page: Page, admin, admin_creds):
    """The share dialog read the tag with the switch off and said "names and sizes"; an administrator turns the
    switch on before the maker presses Create. The share is made as its maker was told: not viewable."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("race"))
    me = admin.get("/users/me").json()["id"]
    r = admin.post("/share-tags", json={"name": unique("racetag"), "allowed_user_ids": [me],
                                        "allowed_audiences": ["anyone_internal"], "allow_view_only": True,
                                        "default_view_only": True, "view_only_preview": False})
    assert r.status_code == 200, r.text
    tag = r.json()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", admin_creds["username"])
        page.fill("#password", admin_creds["password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.click('.sidebar-item[data-section="vaults"]')
        page.locator(f'.vault-card[data-vault-id="{vault["id"]}"] .open-vault-btn').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.click("#share-vault-btn")
        select = page.locator("#share-tag-select")
        expect(select.locator(f'option[value="{tag["id"]}"]')).to_have_count(1, timeout=10000)
        select.select_option(tag["id"])
        page.select_option("#share-audience-select", "anyone_internal")
        expect(page.locator("#share-view-only")).to_be_checked()
        expect(page.locator("#share-view-only-text")).to_contain_text("names and sizes")
        assert admin.patch(f"/share-tags/{tag['id']}", json={"view_only_preview": True}).status_code == 200
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.ok, resp.value.status
        assert resp.value.request.post_data_json["view_only_preview_shown"] is False
        made = resp.value.json()
        assert made["view_only"] is True and made["view_only_preview"] is False, made
    finally:
        admin.delete(f"/share-tags/{tag['id']}")
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={"sharing_enabled": before})


@pytest.mark.parametrize("kind", ["forced", "fixed_default"])
def test_a_share_made_after_the_tag_stopped_requiring_view_only_stays_view_only(page: Page, admin, admin_creds, kind):
    """The dialog read a tag whose view-only the maker cannot change (forced, or the tag's own default on a tag
    that allows no changes) and showed "View only"; before the maker presses Create, an administrator lets the tag
    share with downloads, and the same PATCH turns allow_custom off, so the server no longer takes view-only from
    the request. The dialog says what it showed, and the share is made view-only."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("vorace"))
    me = admin.get("/users/me").json()["id"]
    body = {"name": unique("voracetag"), "allowed_user_ids": [me], "allowed_audiences": ["anyone_internal"],
            "allow_view_only": True, "default_view_only": True, "view_only_preview": True}
    body.update({"force_view_only": True} if kind == "forced" else {"allow_custom": False})
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    tag = r.json()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", admin_creds["username"])
        page.fill("#password", admin_creds["password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.click('.sidebar-item[data-section="vaults"]')
        page.locator(f'.vault-card[data-vault-id="{vault["id"]}"] .open-vault-btn').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.click("#share-vault-btn")
        select = page.locator("#share-tag-select")
        expect(select.locator(f'option[value="{tag["id"]}"]')).to_have_count(1, timeout=10000)
        select.select_option(tag["id"])
        page.select_option("#share-audience-select", "anyone_internal")
        expect(page.locator("#share-view-only")).to_be_checked()
        expect(page.locator("#share-view-only")).to_be_disabled()
        assert admin.patch(f"/share-tags/{tag['id']}", json={"force_view_only": False, "default_view_only": False,
                                                             "allow_custom": False}).status_code == 200
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.ok, resp.value.status
        sent = resp.value.request.post_data_json
        assert sent["view_only_shown"] is True and sent["view_only_preview_shown"] is True, sent
        # A tag that allows no changes gets no view_only from the dialog (the tag decides, and what the dialog
        # showed narrows it); a forced tag that allows changes gets the box as shown, checked.
        assert sent.get("view_only") is (None if kind == "fixed_default" else True), sent
        made = resp.value.json()
        assert made["view_only"] is True and made["view_only_preview"] is True, made
    finally:
        admin.delete(f"/share-tags/{tag['id']}")
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={"sharing_enabled": before})


def test_a_share_refused_because_the_tag_changed_shows_the_tags_rules_again(page: Page, admin, admin_creds):
    """The dialog read a tag that forced view-only; an administrator stops the tag allowing view-only at all before
    the maker presses Create share. The server refuses what the dialog showed; the dialog reads the tags again,
    keeps the tag, says so, and no longer shows the share as view-only; pressing Create share again makes it."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("vochanged"))
    me = admin.get("/users/me").json()["id"]
    r = admin.post("/share-tags", json={"name": unique("vochangedtag"), "allowed_user_ids": [me],
                                         "allowed_audiences": ["anyone_internal"], "allow_view_only": True,
                                         "default_view_only": True, "force_view_only": True,
                                         "view_only_preview": True})
    assert r.status_code == 200, r.text
    tag = r.json()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", admin_creds["username"])
        page.fill("#password", admin_creds["password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.click('.sidebar-item[data-section="vaults"]')
        page.locator(f'.vault-card[data-vault-id="{vault["id"]}"] .open-vault-btn').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.click("#share-vault-btn")
        select = page.locator("#share-tag-select")
        expect(select.locator(f'option[value="{tag["id"]}"]')).to_have_count(1, timeout=10000)
        select.select_option(tag["id"])
        page.select_option("#share-audience-select", "anyone_internal")
        expect(page.locator("#share-view-only")).to_be_checked()
        assert admin.patch(f"/share-tags/{tag['id']}", json={"force_view_only": False, "default_view_only": False,
                                                             "allow_view_only": False}).status_code == 200
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.status == 409, resp.value.status
        expect(page.locator("#share-create-error")).to_have_text(
            "This tag changed while the dialog was open. Check the share's settings and press Create share again.")
        expect(page.locator("#share-tag-select")).to_have_value(tag["id"])
        expect(page.locator("#share-view-only")).not_to_be_checked()
        expect(page.locator("#share-viewonly-group")).to_be_hidden()
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.ok, resp.value.status
        assert resp.value.request.post_data_json["view_only_shown"] is False
        assert resp.value.json()["view_only"] is False
        expect(page.locator("#share-create-result")).to_be_visible()
    finally:
        admin.delete(f"/share-tags/{tag['id']}")
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={"sharing_enabled": before})


def test_a_share_refused_because_the_tag_changed_keeps_the_people_picked(page: Page, admin, admin_creds):
    """The maker shares with a named person under a tag whose audiences start with "anyone internal", and ticks
    view-only; an administrator stops the tag allowing view-only before the maker presses Create share. After the
    refusal the dialog still shares with that person, and pressing Create share again makes the share for them."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("vopeople"))
    me = admin.get("/users/me").json()["id"]
    person = admin.create_user(role="user")
    r = admin.post("/share-tags", json={"name": unique("vopeopletag"), "allowed_user_ids": [me],
                                         "allowed_audiences": ["anyone_internal", "users"], "allow_custom": True,
                                         "allow_view_only": True, "default_view_only": False,
                                         "view_only_preview": True})
    assert r.status_code == 200, r.text
    tag = r.json()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", admin_creds["username"])
        page.fill("#password", admin_creds["password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.click('.sidebar-item[data-section="vaults"]')
        page.locator(f'.vault-card[data-vault-id="{vault["id"]}"] .open-vault-btn').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.click("#share-vault-btn")
        select = page.locator("#share-tag-select")
        expect(select.locator(f'option[value="{tag["id"]}"]')).to_have_count(1, timeout=10000)
        select.select_option(tag["id"])
        page.select_option("#share-audience-select", "users")
        page.fill("#share-user-search", person["_username"])
        page.locator("#share-user-results .pick-row", has_text=person["_username"]).click()
        expect(page.locator("#share-user-chips")).to_contain_text(person["_username"])
        page.check("#share-view-only")
        assert admin.patch(f"/share-tags/{tag['id']}", json={"allow_view_only": False}).status_code == 200
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.status == 409, resp.value.status
        expect(page.locator("#share-create-error")).to_have_text(
            "This tag changed while the dialog was open. Check the share's settings and press Create share again.")
        expect(page.locator("#share-audience-select")).to_have_value("users")
        expect(page.locator("#share-user-chips")).to_contain_text(person["_username"])
        expect(page.locator("#share-viewonly-group")).to_be_hidden()
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST") as resp:
            page.click("#share-create-submit")
        assert resp.value.ok, resp.value.status
        sent = resp.value.request.post_data_json
        assert sent["claim_audience"] == "users" and sent["audience_user_ids"] == [person["id"]], sent
        assert sent["view_only_shown"] is False, sent
        made = resp.value.json()
        assert made["claim_audience"] == "users" and made["view_only"] is False, made
    finally:
        admin.delete(f"/share-tags/{tag['id']}")
        admin.delete_vault(vault["id"])
        admin.delete_user(person["id"])
        admin.put("/settings", json={"sharing_enabled": before})
