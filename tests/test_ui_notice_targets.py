"""Where a notice about the Settings page leads (static/js/app.js, openAppTarget).

The administrators' notices about settings and single sign-on providers carry the target "#settings", and the ones
about sign-in "#settings/signin". The first opens the Settings page; the second opens it on its Sign-in methods tab,
also where the page opens only after its sidebar item was decided. A target the page does not know still opens
nothing.

Driven in Node against the page's own functions (the tab bar's wiring included), on the small document of
tests/js/mini_dom.js. Offline."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", APP)
    assert found, name
    start = found.start() + 1
    return APP[start:APP.index("\n}\n", start) + 3]


def _const(name):
    start = APP.index(f"\nconst {name} = ") + 1
    line_end = APP.index("\n", start)
    if APP[start:line_end].rstrip().endswith("{"):
        return APP[start:APP.index("\n};\n", start) + 4]
    return APP[start:APP.index(";\n", start) + 2]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const print = console.log.bind(console);
console.log = () => {}; console.error = () => {}; console.warn = () => {};
// The Settings page as index.html has it: the tab bar, and a content panel per tab, General open.
const sections = {};
for (const name of ['dashboard', 'settings']) {
    const s = document.createElement('div'); s.id = name + '-section'; s.className = 'content-section';
    document.body.appendChild(s); sections[name] = s;
}
sections.dashboard.classList.add('active');
const bar = document.createElement('div'); bar.className = 'tabs'; sections.settings.appendChild(bar);
for (const tab of ['general', 'accounts', 'signin']) {
    const b = document.createElement('button'); b.className = 'tab-btn'; b.setAttribute('data-tab', tab); bar.appendChild(b);
    const c = document.createElement('div'); c.id = 'settings-tab-' + tab; c.className = 'settings-tab-content';
    sections.settings.appendChild(c);
    if (tab === 'general') { b.classList.add('active'); c.classList.add('active'); }
}
// A click on a sidebar item shows its section and, for Settings, runs initSettings, whose first step wires the tab bar.
// DECIDING stands for a sidebar item still being decided: the page then opens a moment later.
let DECIDING = false;
const went = [];
function openSection(section) {
    went.push(section);
    Object.values(sections).forEach((s) => s.classList.remove('active'));
    if (sections[section]) sections[section].classList.add('active');
    if (section === 'settings') setupSettingsTabs();
}
function navigateToSection(section) {
    if (DECIDING) { setTimeout(() => openSection(section), 250); return; }
    openSection(section);
}
function openUserSettingsModal() { went.push('your account'); }
function loadLogSettings() {} function setupShareTagsUI() {} function loadShareTags() {}
function setupAccountsPolicyUI() {} function refreshAccountsPolicyUI() {}
const settle = (ms) => new Promise((r) => setTimeout(r, ms));
const state = {};
const tabs = () => ({
    section: Object.keys(sections).filter((k) => sections[k].classList.contains('active')),
    tab: document.querySelectorAll('.settings-tab-content').filter((c) => c.classList.contains('active')).map((c) => c.id),
    button: document.querySelectorAll('.tab-btn').filter((b) => b.classList.contains('active')).map((b) => b.dataset.tab),
});
const out = (value) => print(JSON.stringify(value));
"""

CONSTS = ("_NOTIF_TARGET_SECTION", "_NOTIF_TARGET_OPEN", "_NOTIF_VAULT_TARGET", "_UUID_PATTERN", "_TAB_TARGET",
          "_VAULT_LINKS_TARGET")


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    code = "\n".join([_const(c) for c in CONSTS]
                     + [_function(n) for n in ("_markCurrentTab", "setupSettingsTabs", "_flashWhenDrawn",
                                               "_openSettingsTab", "openAppTarget")])
    script = (PRELUDE + code + "\n(async () => {\n" + scenario
              + "\n})().catch((e) => { print('FAILED ' + e.stack); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_settings_notice_opens_the_settings_page():
    got = _node(r"""
const understood = await openAppTarget('#settings');
await settle(50);
out({ understood, went, now: tabs() });
""")
    assert got["understood"] is True
    assert got["went"] == ["settings"]
    assert got["now"] == {"section": ["settings"], "tab": ["settings-tab-general"], "button": ["general"]}


def test_a_sign_in_notice_opens_the_sign_in_methods_tab():
    got = _node(r"""
const understood = await openAppTarget('#settings/signin');
await settle(400);
out({ understood, went, now: tabs() });
""")
    assert got["understood"] is True
    assert got["went"] == ["settings"]
    assert got["now"] == {"section": ["settings"], "tab": ["settings-tab-signin"], "button": ["signin"]}


def test_the_tab_is_chosen_once_a_page_still_being_decided_opens():
    got = _node(r"""
DECIDING = true;
const understood = await openAppTarget('#settings/signin');
const before = tabs();
await settle(800);
out({ understood, before, went, now: tabs() });
""")
    assert got["understood"] is True
    assert got["before"]["section"] == ["dashboard"]
    assert got["now"] == {"section": ["settings"], "tab": ["settings-tab-signin"], "button": ["signin"]}


def test_a_page_that_never_opens_is_not_waited_for_forever():
    """A sidebar item refused to the reader (Settings for anyone but an administrator) leaves the page where it is:
    nothing clicks a tab of a page that is not shown, and the waiting ends."""
    got = _node(r"""
navigateToSection = (section) => { went.push('refused ' + section); };
let looks = 0;
const byId = document.getElementById.bind(document);
document.getElementById = (id) => { if (id === 'settings-section') looks += 1; return byId(id); };
const understood = await openAppTarget('#settings/signin');
await settle(3500);
const looked = looks;
await settle(500);
out({ understood, went, now: tabs(), looked, more: looks - looked });
""")
    assert got["understood"] is True
    assert got["went"] == ["refused settings"]
    assert got["now"] == {"section": ["dashboard"], "tab": ["settings-tab-general"], "button": ["general"]}
    assert got["looked"] > 1 and got["more"] == 0


def test_other_targets_still_lead_where_they_did():
    got = _node(r"""
const profile = await openAppTarget('#profile');
const unknown = await openAppTarget('#settings/nowhere');
const odd = await openAppTarget('#settings-signin');
out({ profile, unknown, odd, went });
""")
    assert got == {"profile": True, "unknown": False, "odd": False, "went": ["your account"]}
