"""An unlocked zero-knowledge vault shows its name: in the header of the open vault and in the dashboard lanes.

A zero-knowledge vault's name and description are sealed in the browser; the server holds only an optional
non-secret label. The header of a vault opened from the list was drawn before the passphrase prompt, with the
label (or "Encrypted vault" when there is none), and nothing drew it again once the key was unlocked. The
dashboard lanes drew the raw list, where a label-less vault reads "Vault", never the real name, unlocked or not.

Now the header is drawn again after the unlock, with the real name and description; the dashboard decrypts the
names it can (never a prompt) and redraws on an unlock and on a lock; a lock puts the labels back everywhere.
The decrypted names stay in the browser: no request carries one.
"""
from urllib.parse import unquote

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

PASSPHRASE = "lanes-and-header-passphrase-1"
TITLE = "#vault-view-title"
LANE_TITLES = "#dashboard-lanes .dashboard-lane-title"


@pytest.fixture
def zk_on(admin):
    before = bool(admin.get("/settings").json().get("zero_knowledge_enabled", False))
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    yield
    admin.put("/settings", json={"zero_knowledge_enabled": before})


@pytest.fixture
def person(admin, zk_on):
    u = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(u["_username"], u["_password"])
    yield u, client
    admin.delete_user(u["id"])


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _set_up_key(page: Page):
    """The account's encryption key, through the standalone dialog; leaves it unlocked in this page."""
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.click("#confirm-modal-confirm-btn")
    for _ in range(2):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    expect(page.locator("#encryption-key-modal")).to_be_hidden(timeout=5000)


def _create_zk(page: Page, name: str, description: str, label: str):
    """A zero-knowledge vault through the form, with the key already unlocked in this page."""
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal.active")).to_be_visible()
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=5000)
    page.select_option("#vault-type", "zero_knowledge")
    page.fill("#vault-name", name)
    page.fill("#vault-desc", description)
    expect(page.locator("#vault-label-group")).to_be_visible(timeout=5000)
    page.fill("#vault-label", label)
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden(timeout=15000)


def _answer_passphrase(page: Page):
    expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=10000)
    page.fill("#confirm-modal-input", PASSPHRASE)
    page.click("#confirm-modal-confirm-btn")


def _watch_for(page: Page, secrets) -> list:
    """Every request whose URL or body carries one of ``secrets``, from now on."""
    leaks = []

    def on_request(req):
        text = unquote(req.url) + " " + (req.post_data or "")
        for s in secrets:
            if s in text:
                leaks.append(f"{req.method} {req.url}")

    page.on("request", on_request)
    return leaks


@pytest.fixture
def two_vaults(page: Page, person):
    """A labelled and an unlabelled zero-knowledge vault, made in the browser; then the page reloaded, so the
    key is locked again. Yields the names and the labels, and the list of requests that carried a name."""
    user, client = person
    labelled = {"name": unique("Payroll"), "desc": unique("The payroll runs"), "label": unique("work")}
    bare = {"name": unique("Legal"), "desc": unique("Contracts under review"), "label": ""}
    _login(page, user)
    _set_up_key(page)
    _create_zk(page, labelled["name"], labelled["desc"], labelled["label"])
    _create_zk(page, bare["name"], bare["desc"], bare["label"])
    # The server knows the labels only.
    names = {v["name"] for v in client.get("/vaults").json()}
    assert labelled["label"] in names and labelled["name"] not in names and bare["name"] not in names, names
    leaks = _watch_for(page, [labelled["name"], bare["name"], labelled["desc"], bare["desc"]])
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    yield labelled, bare, leaks
    assert not leaks, f"a request carried a decrypted name: {leaks}"


def test_the_open_vaults_header_shows_the_real_name_after_the_unlock_and_the_label_after_a_lock(page: Page, two_vaults):
    labelled, bare, _ = two_vaults
    page.click('.sidebar-item[data-section="vaults"]')
    # Locked: the list shows the label, or the placeholder.
    expect(page.locator(".vault-card", has_text=labelled["label"])).to_be_visible(timeout=10000)
    card = page.locator(".vault-card[data-zk='1']", has_text="Encrypted vault")
    expect(card).to_have_count(1)
    card.locator(".vault-open").click()
    _answer_passphrase(page)
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    expect(page.locator(TITLE)).to_have_text(bare["name"], timeout=15000)
    expect(page.locator("#vault-view-description")).to_have_text(bare["desc"])
    expect(page.locator("#vault-view-description")).to_be_visible()
    # A lock puts the placeholder back in the header.
    page.evaluate("() => zkLockAllVaults()")
    expect(page.locator(TITLE)).to_have_text("Encrypted vault")
    expect(page.locator("#vault-view-description")).to_be_hidden()


def test_the_dashboard_lanes_show_labels_while_locked_and_real_names_once_unlocked(page: Page, two_vaults):
    labelled, bare, _ = two_vaults
    # The reload restored the vaults page (where the vaults were made); the dashboard draws its lanes when opened.
    page.click('.sidebar-item[data-section="dashboard"]')
    expect(page.locator("#dashboard-section")).to_be_visible(timeout=10000)
    lanes = page.locator(LANE_TITLES)
    expect(lanes.filter(has_text=labelled["label"])).to_have_count(1, timeout=10000)
    expect(lanes.filter(has_text="Encrypted vault")).to_have_count(1)
    expect(lanes.filter(has_text=labelled["name"])).to_have_count(0)
    expect(lanes.filter(has_text="Vault").filter(has_not_text="Encrypted")).to_have_count(0)
    # Unlocked from the dashboard itself: the lanes redraw in place.
    page.evaluate("() => { zkUnlockAllVaults(); }")
    _answer_passphrase(page)
    expect(lanes.filter(has_text=labelled["name"])).to_have_count(1, timeout=15000)
    expect(lanes.filter(has_text=bare["name"])).to_have_count(1)
    expect(lanes.filter(has_text="Encrypted vault")).to_have_count(0)
    # A lock puts the labels back in place too.
    page.evaluate("() => zkLockAllVaults()")
    expect(lanes.filter(has_text=labelled["label"])).to_have_count(1, timeout=10000)
    expect(lanes.filter(has_text="Encrypted vault")).to_have_count(1)
    expect(lanes.filter(has_text=bare["name"])).to_have_count(0)
    # Leaving and coming back while unlocked draws the real names from a fresh read, without a prompt.
    page.evaluate("() => { zkUnlockAllVaults(); }")
    _answer_passphrase(page)
    expect(lanes.filter(has_text=bare["name"])).to_have_count(1, timeout=15000)
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible()
    page.click('.sidebar-item[data-section="dashboard"]')
    expect(lanes.filter(has_text=bare["name"])).to_have_count(1, timeout=15000)
    expect(page.locator("#confirm-modal.active")).to_have_count(0)
