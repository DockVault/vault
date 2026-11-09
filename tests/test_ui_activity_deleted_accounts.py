"""UI: a deleted account's events in Activity name it with the person chip every list uses, greyed as a deleted
account is, never as plain text; an account that still exists keeps its coloured chip."""
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, filter_by_person, login, open_activity, rows  # noqa: F401
from conftest import ApiClient

pytestmark = pytest.mark.ui


def test_a_deleted_accounts_rows_draw_a_greyed_chip(page: Page, admin, activity_admin):
    gone = admin.create_user(role="user")
    client = ApiClient()
    client.login(gone["_username"], gone["_password"])          # a sign-in, recorded under the account
    admin.delete_user(gone["id"])                                # the rows keep the name, lose the account
    login(page, activity_admin)
    open_activity(page)
    filter_by_person(page, gone["_username"])
    first = rows(page).first
    expect(first).to_be_visible(timeout=15000)
    chip = first.locator(".act-who .person-chip")
    expect(chip).to_have_count(1)
    expect(chip).to_have_class(re.compile(r"\bperson-deleted\b"))
    expect(chip.locator(".person-name")).to_have_text(gone["_username"])
    assert "no account" in (chip.get_attribute("title") or ""), chip.get_attribute("title")
