"""What the Activity page's UI tests share: a throwaway administrator, signing in and out, opening the
page, and writing an event the page can find.

A throwaway administrator, so that a skin, a page size or a saved search stored on the shared account
cannot change what a test sees, and nothing a test stores outlives it."""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import unique


@pytest.fixture
def activity_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def login(page: Page, user, width=1440, height=900, path="/"):
    page.set_viewport_size({"width": width, "height": height})
    page.goto(path)
    sign_in(page, user)


def sign_in(page: Page, user):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def sign_out(page: Page):
    """Through the profile menu, as a person does."""
    page.click("#profile-btn")
    page.click("#dropdown-logout-btn")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)


def open_activity(page: Page):
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.is_visible():
        toggle.click()
    page.click('.sidebar-item[data-section="activity"]')
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
    ready(page)


def ready(page: Page):
    """The list and the band have been read once."""
    expect(page.locator("#act-pager")).to_be_visible(timeout=15000)
    expect(page.locator("#act-p-time .act-key-btn").first).to_be_visible(timeout=15000)


def rows(page: Page):
    return page.locator("#activity-rows tr.act-row")


def failed_sign_in(anon, name=None) -> str:
    """A sign-in with a name no account has: one "Sign-in failed" event, named as typed."""
    name = name or unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    return name


def filter_by_person(page: Page, name):
    """Free text in the filter panel's Person field is a "contains" match; Escape closes the panel."""
    page.click("#act-filter-btn")
    field = page.locator("#act-fp-user")
    expect(field).to_be_visible()
    field.fill(name)
    field.press("Enter")
    expect(page.locator("#act-chips")).to_contain_text(f"Person contains: {name}")
    page.keyboard.press("Escape")
    expect(page.locator("#act-filter-panel")).to_be_hidden()


def summary(page: Page) -> str:
    return page.locator("#activity-summary").inner_text()


def total_of(text: str) -> int:
    """The N of "1–25 of N" or "100 of N loaded"."""
    m = re.search(r"of ([\d,]+)", text)
    assert m, text
    return int(m.group(1).replace(",", ""))
