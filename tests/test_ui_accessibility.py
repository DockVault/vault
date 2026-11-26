"""The accessibility pass: axe-core (tests/vendor/axe-core, a test file only) run on every main screen and every
Settings page of the signed-in app, in both skins, as an administrator, and on the sign-in screen. A result of
"serious" or "critical" impact fails the test, unless its rule is in EXEMPT with the reason it is accepted.
"""
import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from _settings_ui import settings_item
from conftest import ApiClient, unique
from test_ui_widths import ADMIN_SECTIONS, SETTINGS_PAGES, _go, _login

pytestmark = pytest.mark.ui

AXE = Path(__file__).resolve().parent / "vendor" / "axe-core" / "axe.min.js"
FAILING = ("serious", "critical")
DESKTOP = (1280, 800)

# Rules whose serious or critical findings are accepted, each with its reason; keyed by rule id, and by the
# screens they are accepted on ("*" for all). Empty means nothing is accepted.
EXEMPT: dict[str, tuple[str, str]] = {}


RUN_AXE = """async (root) => {
  const scope = root ? document.querySelector(root) : document;
  const result = await axe.run(scope, { resultTypes: ['violations'] });
  return result.violations.map(v => ({
    id: v.id, impact: v.impact, help: v.help,
    nodes: v.nodes.slice(0, 8).map(n => ({ target: n.target.join(' '), summary: n.failureSummary })),
    count: v.nodes.length,
  }));
}"""


def _load_axe(page: Page) -> None:
    """axe into the page through the browser's debugging channel: the vault's Content-Security-Policy (scripts
    from its own origin only, none inline) refuses an injected script tag, and the test leaves it as shipped."""
    if not page.evaluate("() => typeof window.axe === 'object'"):
        page.evaluate(AXE.read_text(encoding="utf-8") + "\n;void 0")
        assert page.evaluate("() => typeof window.axe === 'object' && typeof window.axe.run === 'function'")


def _findings(page: Page, where: str, root: str = None) -> list:
    _load_axe(page)
    found = page.evaluate(RUN_AXE, root)
    report = os.environ.get("AXE_REPORT")        # optional: every finding, in full, one JSON line each
    if report:
        with open(report, "a", encoding="utf-8") as out:
            for v in found:
                out.write(json.dumps({"where": where, "skin": page.evaluate("() => localStorage.getItem('ui')"), **v}) + "\n")
    out = []
    for v in found:
        if v["impact"] not in FAILING:
            continue
        exempt = EXEMPT.get(v["id"])
        if exempt and exempt[0] in ("*", where):
            continue
        out.append({"where": where, **v})
    return out


def _said(problems: list) -> str:
    """Each finding whole, one line per element, so a failure names what to fix: the page, the rule, the
    element's selector and axe's summary (for a contrast rule, the colours and the ratio)."""
    lines = []
    for v in problems:
        lines.append(f"{v['where']}: {v['id']} ({v['impact']}), {v.get('count', 0)} element(s)")
        for n in v.get("nodes", []):
            summary = " ".join(str(n.get("summary") or "").split())
            lines.append(f"  {n.get('target')}: {summary}")
    return "\n".join(lines)


@pytest.fixture
def an_admin(admin):
    a = admin.create_user(role="admin")
    ca = ApiClient(); ca.login(a["_username"], a["_password"])
    v = ca.create_vault(name=unique("Axe"))
    ca.post(f"/vaults/{v['id']}/files", files=[("files", ("notes.txt", b"x", "text/plain"))])
    try:
        yield a, v
    finally:
        ca.delete_vault(v["id"])
        admin.delete_user(a["id"])


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_sign_in_screen_has_no_serious_finding(page: Page, skin):
    page.set_viewport_size({"width": DESKTOP[0], "height": DESKTOP[1]})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    found = _findings(page, "sign-in")
    assert found == [], _said(found)


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_every_main_screen_has_no_serious_finding(page: Page, an_admin, skin):
    a, v = an_admin
    _login(page, a, skin, DESKTOP)
    problems, visited = [], []
    for section in ADMIN_SECTIONS:
        if not _go(page, section):
            continue
        visited.append(section)
        problems += _findings(page, section)
    # A vault opened, its files listed.
    _go(page, "vaults")
    page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    page.wait_for_timeout(500)
    problems += _findings(page, "vault")
    assert len(visited) >= 8, visited
    assert problems == [], _said(problems)


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_every_settings_page_has_no_serious_finding(page: Page, an_admin, skin):
    a, _v = an_admin
    _login(page, a, skin, DESKTOP)
    assert _go(page, "settings")
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    problems, visited = [], []
    # The settings menu in the rail: its head (Back, the Advanced switch) and its pages.
    problems += _findings(page, "settings:menu", "#sidebar")
    for tab in SETTINGS_PAGES:
        item = settings_item(page, tab)
        if not item.is_visible():
            continue
        item.click()
        expect(page.locator(f"#settings-tab-{tab}")).to_be_visible(timeout=10000)
        page.wait_for_timeout(400)
        visited.append(tab)
        problems += _findings(page, f"settings:{tab}", "#settings-section")
    assert len(visited) >= 10, visited
    assert problems == [], _said(problems)
