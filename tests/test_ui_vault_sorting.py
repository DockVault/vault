"""Vault-list ordering: sort key, direction, and where favourites sit.

The ordering runs on the already-fetched list, so most of these drive sortVaults() over a synthetic
set rather than trying to manufacture real vaults with particular sizes and view times. That keeps
the ordering assertions deterministic; the tests that matter for wiring (persistence, no refetch,
the rendered order) still go through the real UI.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vaults(page: Page):
    """Open the vaults section and WAIT for its initial load to land.

    loadVaults() runs asynchronously off the sidebar click and assigns state.allVaults when it
    resolves. Injecting a synthetic list before that lands would be silently overwritten by the
    real (empty) one, and the rendered-order assertions would see no cards at all.
    """
    with page.expect_response(
            lambda r: r.request.method == "GET" and r.url.rstrip("/").endswith("/vaults")):
        page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
    expect(page.locator("#vault-sort")).to_be_visible(timeout=10000)
    page.wait_for_timeout(250)


# Every sort key must yield a DIFFERENT order over this set, or a copy-paste bug in
# vaultSortValue (say `case 'files'` returning total_size_bytes) would pass every parametrization.
# Ascending: name a,b,c | size b,c,a | files c,a,b | created a,c,b | viewed c,b,a
# The favourite is `cherry`, deliberately NOT the alphabetically-first entry, so favourites-first
# is distinguishable from plain name ordering.
_SET = [
    {"id": "11111111-1111-1111-1111-111111111111", "name": "banana", "is_favorite": False,
     "total_size_bytes": 100, "file_count": 3, "created_at": "2026-01-03T00:00:00",
     "last_viewed_at": "2026-03-01T00:00:00"},
    {"id": "22222222-2222-2222-2222-222222222222", "name": "apple", "is_favorite": False,
     "total_size_bytes": 300, "file_count": 2, "created_at": "2026-01-01T00:00:00",
     "last_viewed_at": None},
    {"id": "33333333-3333-3333-3333-333333333333", "name": "cherry", "is_favorite": True,
     "total_size_bytes": 200, "file_count": 1, "created_at": "2026-01-02T00:00:00",
     "last_viewed_at": "2026-02-01T00:00:00"},
]


def _order(page: Page, key, dir_, fav):
    """Names in the order sortVaults() produces for the synthetic set."""
    return page.evaluate(
        "([set, k, d, f]) => sortVaults(set, k, d, f).map(v => v.name)",
        [_SET, key, dir_, fav],
    )


@pytest.mark.parametrize("key,expected_asc", [
    ("name", ["apple", "banana", "cherry"]),
    ("size", ["banana", "cherry", "apple"]),
    ("files", ["cherry", "apple", "banana"]),
    ("created", ["apple", "cherry", "banana"]),
])
def test_each_sort_key_orders_both_ways(page: Page, fresh_user, key, expected_asc):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    assert _order(page, key, "asc", "mixed") == expected_asc
    assert _order(page, key, "desc", "mixed") == list(reversed(expected_asc))


def test_never_viewed_sorts_last_in_both_directions(page: Page, fresh_user):
    """A vault you have never opened is not the most recently viewed one — and flipping to
    ascending must not float every never-viewed vault to the top either."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    asc = _order(page, "viewed", "asc", "mixed")
    desc = _order(page, "viewed", "desc", "mixed")
    assert asc == ["cherry", "banana", "apple"], asc   # apple has last_viewed_at = null
    assert desc[-1] == "apple", desc
    # ...and the two that DO have timestamps still reverse relative to each other.
    assert [n for n in asc if n != "apple"] == list(reversed([n for n in desc if n != "apple"]))


@pytest.mark.parametrize("fav,expected", [
    ("first", ["cherry", "apple", "banana"]),
    ("last", ["apple", "banana", "cherry"]),
])
def test_favourites_grouping_overrides_the_sort_key(page: Page, fresh_user, fav, expected):
    """cherry is the only favourite and sorts LAST by name, so grouping is distinguishable from
    plain alphabetical order rather than coinciding with it."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    assert _order(page, "name", "asc", fav) == expected


def test_mixed_ignores_favourites_entirely(page: Page, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    assert _order(page, "name", "asc", "mixed") == ["apple", "banana", "cherry"]


def test_ties_are_broken_deterministically_and_direction_does_not_reshuffle_them(page, fresh_user):
    """Equal keys must keep a stable order, and flipping direction must not shuffle equal rows."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    tied = [dict(v, total_size_bytes=500) for v in _SET]   # every size identical
    asc = page.evaluate("(s) => sortVaults(s, 'size', 'asc', 'mixed').map(v => v.name)", tied)
    desc = page.evaluate("(s) => sortVaults(s, 'size', 'desc', 'mixed').map(v => v.name)", tied)
    assert asc == ["apple", "banana", "cherry"], asc
    assert desc == asc, f"direction reshuffled rows that tie on the sort key: {desc}"
    # And repeated sorting is idempotent — a re-render must not reorder equal rows.
    again = page.evaluate("(s) => sortVaults(s, 'size', 'asc', 'mixed').map(v => v.name)", tied)
    assert again == asc


def test_unknown_sort_key_falls_back_to_name(page: Page, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    assert _order(page, "not-a-key", "asc", "mixed") == ["apple", "banana", "cherry"]


def test_sorting_re_renders_without_refetching(page: Page, fresh_user):
    """The whole point of ordering client-side: changing it must not hit /vaults again."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    calls = []
    page.on("request", lambda r: calls.append(r.url)
            if r.url.rstrip("/").endswith("/vaults") and r.method == "GET" else None)
    page.select_option("#vault-sort", "created")
    page.click("#vault-sort-dir")
    page.select_option("#vault-fav-group", "last")
    page.wait_for_timeout(800)
    assert not calls, f"changing the ordering refetched the list: {calls}"


def test_the_choice_follows_the_account_to_a_new_browser(page: Page, fresh_user, context, base_url):
    """Persisted server-side, so it is not merely this browser's localStorage."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    page.select_option("#vault-sort", "created")
    page.select_option("#vault-fav-group", "last")
    page.click("#vault-sort-dir")
    page.wait_for_timeout(1200)   # let the preferences PUT land

    fresh = context.browser.new_context(base_url=base_url)
    try:
        p2 = fresh.new_page()
        _login(p2, fresh_user["_username"], fresh_user["_password"])
        _open_vaults(p2)
        assert p2.input_value("#vault-sort") == "created"
        assert p2.input_value("#vault-fav-group") == "last"
        assert p2.locator("#vault-sort-dir").get_attribute("data-dir") == "desc"
    finally:
        fresh.close()


def test_the_rendered_card_order_follows_the_controls(page: Page, fresh_user):
    """End to end through renderVaults, not just the comparator."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    page.evaluate("(s) => { state.allVaults = s; state.vaultFilter = 'all'; }", _SET)
    page.select_option("#vault-fav-group", "mixed")
    page.select_option("#vault-sort", "name")
    names = page.eval_on_selector_all(".vault-card .vault-name", "els => els.map(e => e.textContent)")
    assert names == ["apple", "banana", "cherry"], names
    page.click("#vault-sort-dir")
    names = page.eval_on_selector_all(".vault-card .vault-name", "els => els.map(e => e.textContent)")
    assert names == ["cherry", "banana", "apple"], names


def test_the_direction_button_reports_its_state_to_assistive_tech(page: Page, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_vaults(page)
    btn = page.locator("#vault-sort-dir")
    assert btn.get_attribute("aria-label") == "Sort ascending"
    page.click("#vault-sort-dir")
    assert btn.get_attribute("aria-label") == "Sort descending"
    assert page.locator("#vault-sort").get_attribute("aria-label") == "Sort vaults by"
