"""The tables library (static/js/tables.js) and the two preferences it keeps.

The library sorts, searches and sets the density with DOM calls only; the server stores the sort each table was
left in and the density under two whitelisted preference keys, for the account that set them.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "tables.js").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")


def test_the_library_builds_dom_and_never_assigns_markup():
    assert "innerHTML" not in JS and "insertAdjacentHTML" not in JS and "outerHTML" not in JS


def test_sorting_announces_itself_to_assistive_technology():
    assert "aria-sort" in JS and "'ascending'" in JS and "'descending'" in JS
    assert "setAttribute('tabindex', '0')" in JS and "e.key === 'Enter'" in JS


def test_the_two_preferences_are_whitelisted_on_the_server():
    assert '"density": {"comfortable", "compact"}' in API
    assert '_PREF_CHECKS = {"tables": _tables_preference_ok}' in API, "the tables key is checked as the JSON its reader expects"
    assert "    density: Optional[str] = None\n    tables: Optional[str] = None" in API


def test_the_density_switch_sits_beside_the_interface_switch():
    assert HTML.index('data-ui-choice="v2"') < HTML.index('data-density="compact"')
    assert 'aria-label="Table density"' in HTML


def test_the_users_table_has_its_two_new_columns_and_the_detail_row_spans_them():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    head = app[app.index("function renderUsersTable() {"):]
    head = head[:head.index("\nfunction ")]
    assert len(re.findall(r"<th[ >]", head)) == 8, re.findall(r"<th[ >]", head)
    assert "<th>Last sign-in</th>" in head and "<th>Created</th>" in head
    assert 'colspan="8"' in app[app.index("function renderUserRow(u) {"):app.index("function renderUserDetail(u) {")]


def test_the_stylesheets_keep_their_order():
    links = re.findall(r'<link rel="stylesheet" href="/static/css/([a-z0-9-]+)\.css', HTML)
    assert links.index("tables") < links.index("mobile")
