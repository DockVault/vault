"""Shared helpers for the browser tests of what a sign-out hands to the next person on the tab: signing in and
out on the tab as it is (no reload), and making a folder through the page. Imported by the test modules that need
them; holds no tests."""
from playwright.sync_api import Page, expect


def sign_in_on_the_tab(page: Page, account):
    """Sign in on the tab as it is (no reload): the login screen of a first visit, or the one a sign-out left."""
    if page.url in ("", "about:blank"):
        page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def sign_out(page: Page):
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def new_folder_through_the_page(page: Page, client, vault_id, name):
    """Open the vault from the vault list and make a folder with New folder, as a person does; returns once the
    page's request for it is answered. The folder is read back from the server with ``client``."""
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=15000)
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    page.click("#create-folder-btn")
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_be_visible(timeout=10000)
    prompt.locator("#confirm-modal-input").fill(name)
    with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith(f"/vaults/{vault_id}/folders"),
                              timeout=15000) as made:
        prompt.locator("#confirm-modal-confirm-btn").click()
    assert made.value.status in (200, 201), made.value.status
    items = client.get(f"/vaults/{vault_id}/files").json()["items"]
    assert [it["name"] for it in items if it["type"] == "folder"] == [name], items
