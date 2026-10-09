"""The Compliance page's wiring, offline (static/js/compliance.js, static/css/compliance.css, static/index.html,
the hooks in static/js/app.js and static/js/activity.js). test_ui_compliance.py drives the screens in a browser.

The page is built with createElement and textContent only; the sidebar item, the section and the stylesheet are
in the page once; the app opens the section through initCompliance; the Activity page asks the administrators'
own reads only of an administrator, and sends the selected case and its receipts with every read.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
# Ways a page runs text as markup or as code (spelled in parts: they are only searched for).
SINKS = ("inner" + "HTML", "outer" + "HTML", "insertAdjacent" + "HTML", "document." + "write", "ev" + "al(",
         "new " + "Function")


def _read(*parts) -> str:
    return STATIC.joinpath(*parts).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["compliance.js", "activity.js"])
def test_the_screens_build_nothing_from_markup(name):
    source = _read("js", name)
    for sink in SINKS:
        assert sink not in source, (name, sink)


def test_the_page_has_the_nav_item_the_section_and_the_stylesheet_once():
    page = _read("index.html")
    assert page.count('data-section="compliance" id="nav-compliance" style="display: none;"') == 1
    assert page.count('id="nav-compliance-count" hidden') == 1
    assert page.count('<div id="compliance-section" class="content-section compliance">') == 1
    assert page.count('<div id="cmp-root"></div>') == 1
    assert len(re.findall(r'<link rel="stylesheet" href="/static/css/compliance\.css\?v=\d+a">', page)) == 1
    assert len(re.findall(r'<script src="/static/js/compliance\.js\?v=\d+a"></script>', page)) == 1


def test_the_app_opens_the_section_through_init_compliance():
    app = _read("js", "app.js")
    branch = app[app.index("} else if (section === 'compliance') {"):]
    branch = branch[:branch.index("} else if (section === 'settings')")]
    assert "if (typeof initCompliance === 'function') initCompliance();" in branch
    assert app.count("window.dispatchEvent(new CustomEvent('dockvault:auditor-right'))") == 1
    assert app.count("window.openNotifTarget(n.target);") == 1
    assert "window.initCompliance = initCompliance;" in _read("js", "compliance.js")


def test_the_activity_page_leaves_the_administrators_reads_to_administrators():
    activity = _read("js", "activity.js")
    now = activity[activity.index("async function loadNow() {"):]
    assert now.split("\n")[1].strip().startswith("if (S.auditor) return;")
    tc = activity[activity.index("async function lookupTcState(id, name) {"):]
    assert tc.split("\n")[1].strip().startswith("if (S.auditor) return;")
    at = activity.index("const d = await get(`/activity/temp-credentials?q=${encodeURIComponent(q)}&limit=8`);")
    assert "if (S.auditor) return [];" in activity[at - 80:at]


def test_every_activity_read_carries_the_selected_case_and_its_receipts():
    activity = _read("js", "activity.js")
    filters = activity[activity.index("function filterParams(f) {"):]
    filters = filters[:filters.index("\n    }\n")]
    assert "if (S.caseId) p.set('case', S.caseId);" in filters
    assert activity.count("unlockHeader(), caseHeader())") == 2
    assert ("'/activity/events/' + encodeURIComponent(id) + (S.caseId ? '?case=' + encodeURIComponent(S.caseId) : '')"
            in activity)
