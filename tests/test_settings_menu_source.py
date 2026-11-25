"""Static checks (no running instance needed) of the app shell: the settings menu in the side rail, the one menu
button in the top bar, and the one Advanced switch.

- static/js/settings-menu.js draws the menu from the page's own list (#settings-section .settings-nav) with
  createElement and textContent only, clicks that list's buttons, and has Back, the title and a nav named Settings;
- the page's own list is hidden once the menu exists, and #settings-section is no longer a grid;
- the rail's own toggle (#sidebar-toggle) and the room it needed above the menu are gone; #mobile-nav-toggle shows
  at every width and app.js sets its aria-expanded and aria-label for both uses, keeping 'sidebarCollapsed';
  on a wide screen it is disabled and hidden in place while Settings is open;
- a reload that restores Settings moves focus into the rail only when focus was already there;
- static/js/settings-levels.js has no per-page "Show advanced settings (N)" button: one role="switch" with its
  label, kept in localStorage inside try/catch, and the page note says how to see the advanced settings;
- index.html loads settings-menu.js after app.js with a cache-buster like the other scripts.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
# The markup sinks no script here may use (spelled in parts, so this file does not name them whole).
SINKS = ("inner" + "HTML", "outer" + "HTML", "insertAdjacent" + "HTML", "document." + "write")


def _read(*parts):
    return (STATIC.joinpath(*parts)).read_text(encoding="utf-8")


def _code(js):
    """The script as it is: the pins below are code, and no comment of these files names what they refuse. (A
    comment stripper would be fooled by a "/*" inside a string, such as an accept list.)"""
    return js


def test_the_settings_menu_is_drawn_from_the_pages_own_list_without_markup():
    code = _code(_read("js", "settings-menu.js"))
    for sink in SINKS:
        assert sink not in code, sink
    assert "':scope > .settings-nav'" in code
    assert "btn.click()" in code                       # each item clicks its page's own button
    assert "item.dataset.tab = page.tab" in code       # and keeps its data-tab
    assert "'sidebar-item sidebar-settings-item'" in code
    assert "'nav-group-label'" in code
    assert "nav.setAttribute('aria-label', 'Settings')" in code
    assert "back.setAttribute('aria-label', 'Back')" in code
    assert "createElementNS(SVG, 'svg')" in code
    assert "icon('chevron-left')" in code
    assert "box.hidden = group.hidden" in code         # a hidden group stays hidden
    assert "SettingsLevels.switchControl()" in code    # the Advanced switch in the head
    assert "navigateToSection(name)" in code           # Back opens the section as its item would
    # A rail saved collapsed opens in full in Settings; leaving puts back what is saved.
    assert "sidebar.classList.remove('collapsed')" in code
    assert re.search(r"try\s*\{\s*return localStorage\.getItem\('sidebarCollapsed'\)", code)


def test_index_loads_the_settings_menu_after_app_js():
    html = _read("index.html")
    menu = re.search(r'<script src="/static/js/settings-menu\.js\?v=\d{8}[a-z]"></script>', html)
    app = re.search(r'<script src="/static/js/app\.js\?v=\d{8}[a-z]"></script>', html)
    assert menu and app
    assert app.start() < menu.start()


def test_the_rails_own_toggle_and_its_room_are_gone():
    html = _read("index.html")
    assert 'id="sidebar-toggle"' not in html
    assert "sidebar-toggle" not in _code(_read("js", "app.js"))
    for css in ("components.css", "ui-v2.css", "redesign.css", "mobile.css"):
        assert ".sidebar-toggle" not in _read("css", css), css
    nav = re.search(r"\n\.sidebar-nav\s*\{([^}]*)\}", _read("css", "components.css"))
    assert nav and "margin-top" not in nav.group(1), "the room for the old toggle is still above the menu"


def test_the_menu_button_shows_at_every_width():
    assert not re.search(r"\.mobile-nav-toggle\s*\{\s*display:\s*none", _read("css", "mobile.css"))
    base = re.search(r"\n\.mobile-nav-toggle\s*\{([^}]*)\}", _read("css", "components.css"))
    assert base and "display: inline-flex" in base.group(1)


def test_the_menu_button_says_what_it_does_at_each_width():
    code = _code(_read("js", "app.js"))
    for label in ("'Close menu'", "'Open menu'", "'Collapse menu'", "'Expand menu'"):
        assert label in code, label
    assert "mobileNavToggle.setAttribute('aria-expanded'" in code
    assert "mobileNavToggle.setAttribute('aria-label'" in code
    assert re.search(r"try\s*\{\s*localStorage\.setItem\('sidebarCollapsed'", code)
    assert re.search(r"try\s*\{\s*savedCollapsed = localStorage\.getItem\('sidebarCollapsed'\)", code)
    # The sections' click handler leaves the settings menu's items (they have no data-section) alone.
    assert re.search(r"document\.querySelectorAll\('\.sidebar-item\[data-section\]'\)\.forEach\(item => \{\s*"
                     r"item\.addEventListener\('click'", code)


def test_the_menu_button_rests_while_settings_is_open_on_a_wide_screen():
    """Inside Settings the rail stays expanded on a wide screen, so collapsing it would leave no way to switch
    pages: the button is disabled there and hidden in place, and Settings never writes 'sidebarCollapsed'."""
    code = _code(_read("js", "app.js"))
    assert ("const navToggleIdle = () => !mobileNavQuery.matches && "
            "document.body.classList.contains('settings-mode');") in code
    sync = code[code.index("const syncNavToggle = () => {"):]
    sync = sync[:sync.index("\n    };\n")]
    assert "const idle = navToggleIdle();" in sync
    assert "if (mobileNavToggle.disabled !== idle) mobileNavToggle.disabled = idle;" in sync
    # The click: the phone's drawer first, then nothing at all while idle, before anything is saved.
    click = code[code.index("mobileNavToggle.addEventListener('click', () => {"):]
    click = click[:click.index("\n        });\n")]
    assert click.index("setMobileNav(") < click.index("if (navToggleIdle()) return;") \
        < click.index("localStorage.setItem('sidebarCollapsed'")
    # It follows body.settings-mode as well as the rail's own class.
    assert ("new MutationObserver(syncNavToggle).observe(document.body, "
            "{ attributes: true, attributeFilter: ['class'] });") in code
    # Hidden in place: the logo beside it keeps its position.
    assert ".mobile-nav-toggle[disabled] { visibility: hidden; }" in _read("css", "components.css")
    # The settings menu reads the saved value and never writes it.
    menu = _code(_read("js", "settings-menu.js"))
    assert "localStorage.setItem" not in menu and "localStorage.removeItem" not in menu


def test_restoring_settings_moves_focus_only_from_the_rail():
    """A reload that restores Settings leaves focus on the page: the menu takes focus only from the rail."""
    code = _code(_read("js", "settings-menu.js"))
    in_rail = code[code.index("function focusInRail() {"):]
    in_rail = in_rail[:in_rail.index("\n    }\n")]
    assert "return !!(active && active !== document.body && sidebar && sidebar.contains(active));" in in_rail
    assert "focusInRailOrLost" not in code
    assert "const moveFocus = focusInRail() && !PHONE.matches;" in code


def test_the_switch_follows_another_tab_even_when_it_clears_the_storage():
    """localStorage.clear() in another tab fires a storage event whose key is null: the switch reads again."""
    code = _code(_read("js", "settings-levels.js"))
    listener = code[code.index("window.addEventListener('storage', (e) => {"):]
    listener = listener[:listener.index("\n    });\n")]
    assert "if (e.key !== ADVANCED_KEY && e.key !== null) return;" in listener
    assert "S.advanced = readAdvanced();" in listener


def test_the_page_list_is_hidden_and_the_section_is_not_a_grid():
    css = _read("css", "components.css")
    assert "body.has-settings-menu #settings-section > .settings-nav { display: none; }" in css
    assert "body.settings-mode .sidebar > .sidebar-nav:not(.sidebar-settings-nav) { display: none; }" in css
    assert not re.search(r"#settings-section\.active\s*\{[^}]*display:\s*grid", css)


def test_one_advanced_switch_replaces_the_per_page_button():
    code = _code(_read("js", "settings-levels.js"))
    assert "settings-advanced-toggle" not in code
    assert "Show advanced settings (" not in code and "Hide advanced settings" not in code
    assert "button.setAttribute('role', 'switch')" in code
    assert "button.setAttribute('aria-checked'" in code
    # Its accessible name starts with its visible label.
    assert "button.setAttribute('aria-label', 'Advanced: show advanced settings on every page');" in code
    assert "'Advanced'" in code
    assert "'Every setting on this page is advanced. Turn on Advanced to see them.'" in code
    # Kept per browser, every access guarded; off unless this browser kept it on.
    assert re.search(r"try\s*\{\s*return localStorage\.getItem\(ADVANCED_KEY\)", code)
    assert re.search(r"try\s*\{\s*localStorage\.setItem\(ADVANCED_KEY", code)
    assert "advanced: readAdvanced()" in code
    # A search that goes to an advanced setting turns the switch on.
    assert "if (isAdvanced(entry)) setAdvanced(true);" in code
    for sink in SINKS:
        assert sink not in code, sink
    assert "settings-advanced-toggle" not in _read("css", "settings-levels.css")
