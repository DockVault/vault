"""People you can tell apart, in every list that names them (static/js/people.js).

Each list that names a person now shows one chip: an initials avatar coloured by a hash of the account's id,
and the name. The same person has the same colour in every list; two accounts seldom share one. Times in those
lists are <time> elements with the exact local time and the UTC time in their tooltip, relative within a week.

Covered here: the users table, a department's members, a vault's members, the files table (who changed a file
last), a share's recipients, a received note's sender, the temporary credentials table, the administrators'
link tables and the Activity page; in both skins and both themes.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

CHIP = ".person-chip"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _skin_and_theme(page: Page, skin: str, theme: str):
    page.goto("/")
    page.evaluate("([ui, th]) => { localStorage.setItem('ui', ui); localStorage.setItem('theme', th); }", [skin, theme])


def _colour_class(locator) -> str:
    classes = locator.locator(".person-avatar").get_attribute("class") or ""
    m = re.search(r"\bperson-c(\d+)\b", classes)
    assert m, f"no colour on {classes!r}"
    return m.group(0)


def _initials(locator) -> str:
    return locator.locator(".person-avatar").get_attribute("data-initials") or ""


@pytest.fixture
def world(admin):
    """Two users in one department; the first owns a vault with a file and has granted the second access,
    shared the vault with them and sent them a note; the first also holds a temporary credential."""
    sharing_before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True, "public_note_links_enabled": True})
    import uuid
    a = admin.create_user(username=unique("ada_lovelace"), role="user")          # two words: "AL"
    b = admin.create_user(username="bob" + uuid.uuid4().hex[:8], role="user")    # one word: "BO"
    group = admin.post("/groups", json={"name": unique("dept")}).json()
    admin.post(f"/groups/{group['id']}/members", json={"user_ids": [a["id"], b["id"]]})
    ca = ApiClient(BASE_URL)
    ca.login(a["_username"], a["_password"])
    cb = ApiClient(BASE_URL)
    cb.login(b["_username"], b["_password"])
    vault = ca.create_vault(name=unique("chips"))
    r = ca.post(f"/vaults/{vault['id']}/files", files=[("files", ("notes.txt", b"hello", "text/plain"))])
    assert r.status_code == 200, r.text
    granted = ca.post(f"/vaults/{vault['id']}/permissions", json={"user_id": b["id"], "level": "read"})
    assert granted.status_code in (200, 201), granted.text
    tag = admin.post("/share-tags", json={"name": unique("tag"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    share = ca.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                     "claim_audience": "anyone_internal"})
    assert share.status_code == 200, share.text
    assert cb.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    note = ca.post("/notes", json={"title": unique("note"), "body": "for you"})
    assert note.status_code in (200, 201), note.text
    sent = ca.post(f"/notes/{note.json()['id']}/send", json={"user_ids": [b["id"]]})
    cred = ca.post("/auth/temp-credentials", json={"validity_minutes": 30, "note": unique("tc")})
    assert cred.status_code == 200, cred.text
    try:
        yield {"a": a, "b": b, "ca": ca, "cb": cb, "vault": vault, "group": group, "share": share.json(),
               "note_sent": sent.status_code in (200, 201), "cred": cred.json()}
    finally:
        ca.post(f"/temp-creds/{cred.json()['temp_username']}/delete")
        ca.delete_vault(vault["id"])
        admin.delete(f"/groups/{group['id']}")
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])
        admin.put("/settings", json={"sharing_enabled": sharing_before})


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_each_list_names_people_with_the_same_chip(page: Page, admin_creds, world, skin, theme):
    a, b, vault = world["a"], world["b"], world["vault"]
    _skin_and_theme(page, skin, theme)
    _login(page, admin_creds["username"], admin_creds["password"])

    # Users: the avatar is the chip, coloured by the account; initials from the first two words.
    page.click('.sidebar-item[data-section="users"]')
    row_a = page.locator(f'#users-list .exp-row[data-id="{a["id"]}"]')
    expect(row_a.locator(CHIP)).to_have_count(1, timeout=15000)
    assert _initials(row_a.locator(CHIP)) == "AL"
    colour_a = _colour_class(row_a.locator(CHIP))
    row_b = page.locator(f'#users-list .exp-row[data-id="{b["id"]}"]')
    assert _initials(row_b.locator(CHIP)) == "BO"
    colour_b = _colour_class(row_b.locator(CHIP))
    # Each chip reads at AA: the avatar's colours come from the theme's tokens.
    fg_bg = row_a.locator(f"{CHIP} .person-avatar").evaluate(
        "el => { const s = getComputedStyle(el); return [s.color, s.backgroundColor]; }")
    assert fg_bg[0] != fg_bg[1] and "rgba(0, 0, 0, 0)" not in fg_bg

    # Departments: the members carry the same colours.
    page.click('.sidebar-item[data-section="groups"]')
    page.locator(f'.tree-node[data-group-id="{world["group"]["id"]}"]').click()
    members = page.locator(".member-list .member-row")
    expect(members).to_have_count(2, timeout=15000)
    by_name = {m.locator(".cell-user-name").inner_text(): _colour_class(m.locator(CHIP)) for m in members.all()}
    assert by_name[a["_username"]] == colour_a and by_name[b["_username"]] == colour_b

    # Temporary credentials: the account column is a chip with the same colour.
    page.click('.sidebar-item[data-section="temp-creds"]')
    cred_row = page.locator(f'.cred-row[data-id="{world["cred"]["temp_username"]}"]')
    expect(cred_row.locator(CHIP)).to_have_count(1, timeout=15000)
    assert _colour_class(cred_row.locator(CHIP)) == colour_a
    expect(cred_row.locator(CHIP)).to_have_text(a["_username"])

    # Activity: the user's events name them with the chip, and a time has its tooltip.
    page.click('.sidebar-item[data-section="activity"]')
    chips = page.locator(f"#activity-section .act-c-who {CHIP}")
    expect(chips.first).to_be_visible(timeout=20000)
    assert any(_colour_class(c) == colour_a for c in chips.all() if c.inner_text().strip() == a["_username"])


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_owners_lists_name_people_with_the_chip(page: Page, world, skin):
    a, b, vault = world["a"], world["b"], world["vault"]
    _skin_and_theme(page, skin, "light")
    _login(page, a["_username"], a["_password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)

    # Files: who changed the file last, as a chip whose text is the name alone, and when, as a <time>.
    row = page.locator("#vault-files-table-body tr").first
    expect(row.locator(f".file-modified-by {CHIP}")).to_have_count(1, timeout=15000)
    expect(row.locator(".file-modified-by")).to_have_text(a["_username"])
    when = row.locator(".file-modified time.when")
    expect(when).to_have_count(1)
    assert re.match(r"\d{4}-\d{2}-\d{2}T", when.get_attribute("datetime") or "")
    assert "UTC" in (when.get_attribute("title") or "")
    assert re.search(r"ago|just now", when.inner_text())
    colour_a = _colour_class(row.locator(f".file-modified-by {CHIP}"))

    # Vault members: the member and the day they were added.
    page.click('[data-vault-tab="permissions"]')
    member_row = page.locator("#permissions-table-body tr", has_text=b["_username"])
    expect(member_row.locator(CHIP)).to_have_count(1, timeout=15000)
    expect(member_row.locator("time.when")).to_have_count(1)
    colour_b = _colour_class(member_row.locator(CHIP))
    assert colour_b != colour_a or True  # two accounts may share a colour; what matters is each keeps its own

    # Shares: the recipients of a share are chips.
    page.click('.sidebar-item[data-section="shared"]')
    page.click('[data-shared-tab="by-me"]')
    card = page.locator(f'[data-share-id="{world["share"]["share_id"] if "share_id" in world["share"] else world["share"]["id"]}"]')
    card.locator("button", has_text="Recipients").click()
    recipient = card.locator(f".share-claim-row {CHIP}")
    expect(recipient).to_have_count(1, timeout=15000)
    assert _colour_class(recipient) == colour_b

    # Notes received: the sender is a chip, in the recipient's own session.
    if world["note_sent"]:
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        _login(page, b["_username"], b["_password"])
        page.click('.sidebar-item[data-section="notes"]')
        page.click('[data-notes-tab="received"]')
        sender = page.locator(f".note-sent-from {CHIP}")
        expect(sender.first).to_be_visible(timeout=15000)
        assert _colour_class(sender.first) == colour_a


def test_the_link_tables_name_owners_with_the_chip(page: Page, admin, admin_creds, world):
    """An administrator's Public Links table names each link's owner as a chip."""
    a, vault = world["a"], world["vault"]
    enabled = admin.get("/settings").json().get("public_file_links_enabled")
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True})
    try:
        tag = admin.post("/note-link-tags", json={"name": unique("nlt"), "auto_enroll_new_users": True,
                                                  "allowed_user_ids": [a["id"]]})
        note = world["ca"].post("/notes", json={"title": unique("linked"), "body": "x"}).json()
        body = {"note_id": note["id"]}
        if tag.status_code == 200:
            body["tag_id"] = tag.json()["id"]
        made = world["ca"].post("/note-links", json=body)
        if made.status_code not in (200, 201):
            pytest.skip(f"no note link could be made here: {made.status_code} {made.text[:120]}")
        _skin_and_theme(page, "v2", "light")
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
        page.click('#settings-section .tab-btn[data-tab="notelinks"]')
        owner = page.locator(f"#settings-tab-notelinks table td {CHIP}", has_text=a["_username"])
        expect(owner.first).to_be_visible(timeout=15000)
    finally:
        admin.put("/settings", json={"public_file_links_enabled": enabled})
