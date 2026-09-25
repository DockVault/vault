"""The size a new vault is offered must be one the form will accept.

The Create vault dialog prefills 10 GB, and the availability note that loads a moment later sets the
input's max to what the account may still allocate, bounded by the admin's per-vault ceiling. When
that max is under 10, the prefill sits above it: native form validation then refuses the submit
with no toast and no request, so "Create Vault" simply does nothing. On a constrained deployment,
the very first thing a person tries is the thing that silently fails.

The prefill is now clamped to the ceiling once it is known. Proved the way a person would find it:
with a 2 GB per-vault ceiling, open the dialog, type a name, press Create, and see the vault exist.

With nothing to clamp it, the dialog must offer the 10 GB default itself, read from the field a
person sees rather than from the markup the dialog overwrites.

Lanes:
  * ui — the real dialog against a real ceiling. Also asserts the prefill it shows, so a fix that
         merely suppressed the validation (or sent 10 GB anyway) does not pass. And the real dialog
         for a fresh account with no ceiling, which must offer 10.
"""
import re
import time

import pytest
from playwright.sync_api import Page

from conftest import unique


def _login(page: Page, username: str, password: str):
    """Sign in, waiting out the login rate limit rather than failing on it."""
    for _ in range(8):
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#login-form button[type=submit]")
        try:
            page.wait_for_selector("#dashboard-screen.active", timeout=8000)
            return
        except Exception:
            msg = page.evaluate(
                "() => (document.getElementById('login-error') || {}).textContent || ''")
            m = re.search(r"(\d+) seconds", msg or "")
            if not m:
                raise AssertionError(f"login failed, and not because of rate limiting: {msg!r}")
            time.sleep(int(m.group(1)) + 3)
    raise AssertionError("login was rate limited on every attempt")


@pytest.fixture
def two_gb_ceiling(admin):
    before = admin.get("/settings").json().get("max_vault_size")
    r = admin.put("/settings", json={"max_vault_size": 2})
    assert r.status_code == 200, r.text
    yield 2
    admin.put("/settings", json={"max_vault_size": before if before else 0})


@pytest.fixture
def no_ceiling(admin):
    before = admin.get("/settings").json().get("max_vault_size")
    r = admin.put("/settings", json={"max_vault_size": 0})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json={"max_vault_size": before if before else 0})


@pytest.mark.ui
def test_the_dialog_offers_ten_gb_when_nothing_caps_it_lower(page: Page, temp_user, no_ceiling):
    """The default a person meets is the number in the field, and it is 10 GB.

    Read from the real dialog, not the markup: opening it rewrites the field, and in 0.32.0 it wrote
    5 while the markup, the hint and the server all said 10. A fresh account with no per-vault ceiling
    has nothing to clamp the prefill, so anything but 10 here is the wrong default.
    """
    page.goto("/")
    _login(page, temp_user["_username"], temp_user["_password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.wait_for_selector("#vaults-section.active", timeout=10000)
    page.click("#create-vault-btn")
    page.wait_for_selector("#create-vault-modal.active", timeout=10000)
    # The availability note loads afterwards and may clamp the field; let it land before reading.
    page.wait_for_load_state("networkidle")
    time.sleep(1)
    offered, ceiling = page.evaluate(
        "() => { const i = document.getElementById('vault-size-gb'); return [i.value, i.max]; }")
    assert not ceiling or float(ceiling) >= 10, (
        f"a fresh account with no per-vault ceiling should have room for 10 GB, but the field's max is {ceiling}")
    assert float(offered) == 10, f"the Create vault dialog offers {offered} GB; the default is 10"


@pytest.mark.ui
def test_create_vault_works_when_the_ceiling_is_under_the_default_prefill(
        page: Page, admin, admin_creds, two_gb_ceiling):
    name = unique("Small")
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.wait_for_selector("#vaults-section.active", timeout=10000)
    page.click("#create-vault-btn")
    page.wait_for_selector("#create-vault-modal.active", timeout=10000)

    # The ceiling arrives asynchronously; wait for the input to learn it before reading the value.
    page.wait_for_function(
        "() => parseFloat((document.getElementById('vault-size-gb') || {}).max) === 2", timeout=15000)
    offered = page.evaluate("() => document.getElementById('vault-size-gb').value")
    assert float(offered) <= 2, (
        f"the dialog offers {offered} GB against a 2 GB ceiling; the form will refuse that on submit")

    page.fill("#vault-name", name)
    page.click("#create-vault-form button[type=submit]")

    created = None
    for _ in range(20):
        created = next((v for v in admin.get("/vaults").json() if v.get("name") == name), None)
        if created:
            break
        time.sleep(0.5)
    try:
        assert created, (
            "Create did nothing: " + page.evaluate(
                "() => { const i = document.getElementById('vault-size-gb');"
                "       return `size=${i.value} max=${i.max} valid=${i.checkValidity()}`"
                "            + ` says=${JSON.stringify(i.validationMessage)}`; }"))
        assert created["size_limit_gb"] <= 2 if "size_limit_gb" in created else True, created
    finally:
        if created:
            admin.delete_vault(created["id"])
