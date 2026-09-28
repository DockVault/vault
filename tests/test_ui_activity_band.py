"""UI — the Activity page's summary band: every mark in it is a filter, each panel counts under every
filter but its own, and a selection in a chart is drawn in ink, never in the accent colour a person
picked (a rose or orange accent beside the red of failures would read as a failure)."""
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, failed_sign_in, login, open_activity, rows  # noqa: F401

pytestmark = pytest.mark.ui


def _chips(page: Page):
    return page.locator("#act-chips .act-chip")


def _remove_chip(page: Page, text):
    chip = _chips(page).filter(has_text=text)
    expect(chip).to_have_count(1)
    chip.locator(".act-chip-x").click()
    expect(_chips(page).filter(has_text=text)).to_have_count(0)


def _title(page: Page, panel):
    return page.locator(f"#act-p-{panel} .act-ptitle")


def test_every_panel_filters_the_list_and_its_chip_undoes_it(page: Page, anon, activity_admin):
    failed_sign_in(anon)                      # a failed sign-in, and a name with no account, in range
    login(page, activity_admin)
    open_activity(page)

    # Events: a column is a time filter; the column is marked in ink under the baseline.
    hits = page.locator("#act-p-time .act-hit")
    last = hits.last
    last.click()
    expect(_chips(page).filter(has_text=re.compile(r"^Time: "))).to_have_count(1)
    expect(page.locator("#act-p-time .act-hit").last).to_have_attribute("aria-pressed", "true")
    expect(page.locator("#act-p-time .act-col.is-sel")).to_have_count(1)
    expect(page.locator("#act-p-time .act-sel-mark")).to_have_count(1)
    # The panel still shows every column: its own filter does not narrow it.
    assert page.locator("#act-p-time .act-hit").count() == hits.count()
    _remove_chip(page, "Time: ")
    expect(page.locator("#act-p-time .act-hit").last).to_have_attribute("aria-pressed", "false")

    # The "failed or refused" key.
    page.click("#act-p-time .act-key-btn[data-fkey=key-bad]")
    expect(_chips(page)).to_have_text(["Status: Failed or refused"])
    expect(page.locator("#act-p-time .act-key-btn[data-fkey=key-bad]")).to_have_attribute("aria-pressed", "true")
    expect(rows(page).first.locator(".badge")).to_have_text("Failed", timeout=10000)
    expect(_title(page, "cat")).to_contain_text("· filtered")              # counted under another filter
    page.click("#act-p-time .act-key-btn[data-fkey=key-all]")              # the neutral key clears it
    expect(_chips(page)).to_have_count(0)
    expect(_title(page, "cat")).not_to_contain_text("filtered")

    # By category: a row is a category filter. The panel keeps listing the other categories, dimmed, so
    # the next one can be added; the panels that count under it say so.
    cats = page.locator("#act-p-cat .act-rank-row")
    # The band is read again without the status filter; the title changes at once, the rows on arrival.
    page.wait_for_function("() => document.querySelectorAll('#act-p-cat .act-rank-row').length >= 2", timeout=10000)
    listed = cats.count()
    assert listed >= 2, "the log should hold events of more than one category by now"
    label = cats.first.locator(".act-rank-label").inner_text()
    cats.first.click()
    expect(_chips(page)).to_have_text([f"Category: {label}"])
    chosen = page.locator("#act-p-cat .act-rank-row[aria-pressed=true]")
    expect(chosen).to_have_count(1)
    expect(chosen).to_have_class(re.compile(r"\bis-sel\b"))
    expect(page.locator("#act-p-cat .act-rank-row")).to_have_count(listed)
    expect(page.locator("#act-p-cat .act-rank-row.is-dim")).to_have_count(listed - 1)
    expect(_title(page, "cat")).not_to_contain_text("filtered")
    expect(_title(page, "time")).to_contain_text("· filtered")
    expect(_title(page, "signin")).to_contain_text("· filtered")
    _remove_chip(page, f"Category: {label}")
    expect(page.locator("#act-p-cat .act-rank-row[aria-pressed=true]")).to_have_count(0)

    # Sign-ins: "Failed" is the failed sign-in events.
    failed = page.locator("#act-p-signin .act-signin-row[data-fkey=si-failed]")
    failed.click()
    chip = _chips(page)
    expect(chip).to_have_count(1)
    expect(chip).to_contain_text("Event: Sign-in failed")
    expect(page.locator("#act-p-signin .act-signin-row[data-fkey=si-failed]")).to_have_attribute("aria-pressed", "true")
    expect(rows(page).first).to_contain_text("Sign-in failed", timeout=10000)
    expect(_title(page, "signin")).not_to_contain_text("filtered")
    _remove_chip(page, "Event: ")

    # Most active: the names typed at failed sign-ins are one row, never listed one by one.
    nobody = page.locator("#act-p-active .act-rank-row.is-noaccount")
    expect(nobody).to_have_count(1)
    nobody.click()
    expect(_chips(page)).to_have_text(["Person: names with no account"])
    expect(page.locator("#act-p-active .act-rank-row.is-noaccount")).to_have_attribute("aria-pressed", "true")
    _remove_chip(page, "Person: names with no account")

    person = page.locator("#act-p-active .act-rank-row:not(.is-noaccount)").first
    who = person.locator(".act-rank-label").inner_text()
    person.click()
    expect(_chips(page)).to_have_text([f"Person: {who}"])
    expect(rows(page).first.locator(".act-who-name")).to_have_text(who, timeout=10000)
    _remove_chip(page, f"Person: {who}")

    page.click("#act-p-active .act-toggle-btn[data-fkey=mode-addresses]")
    address = page.locator("#act-p-active .act-rank-row").first
    ip = (address.get_attribute("aria-label") or "").split(",")[0]          # the full address, never cut
    address.click()
    expect(_chips(page)).to_have_text([f"Address: {ip}"])
    _remove_chip(page, f"Address: {ip}")


_INK = """(sel) => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--text-primary)';
    document.getElementById('activity-section').appendChild(probe);
    const ink = getComputedStyle(probe).color;
    probe.style.color = 'var(--brand-secondary)';
    const accent = getComputedStyle(probe).color;
    probe.remove();
    const mark = document.querySelector('#act-p-time .act-sel-mark');
    const row = document.querySelector('#act-p-cat .act-rank-row[aria-pressed=true]');
    const key = document.querySelector('#act-p-time .act-key-btn[data-fkey=key-bad] .act-key-text');
    return { ink, accent,
             mark: getComputedStyle(mark).fill,
             rule: getComputedStyle(row, '::before').backgroundColor,
             underline: getComputedStyle(key).textDecorationColor };
}"""


def _skin(page: Page, skin, theme, accent):
    page.evaluate("""([skin, theme, accent]) => {
        const html = document.documentElement;
        document.getElementById('skin-v2').disabled = skin !== 'v2';
        document.getElementById('skin-v1').disabled = skin !== 'v1';
        if (skin === 'v2') html.setAttribute('data-ui', 'v2'); else html.removeAttribute('data-ui');
        html.setAttribute('data-theme', theme);
        html.setAttribute('data-accent', accent);
    }""", [skin, theme, accent])
    # A skin's stylesheet that started disabled is read only now: measure once it is in.
    page.wait_for_function("id => { const s = document.getElementById(id).sheet; return !!(s && s.cssRules.length); }",
                           arg=f"skin-{skin}", timeout=10000)


def test_a_selection_in_the_charts_is_ink_whatever_the_accent(page: Page, anon, activity_admin):
    failed_sign_in(anon)
    login(page, activity_admin)
    open_activity(page)
    page.locator("#act-p-time .act-hit").last.click()
    page.locator("#act-p-cat .act-rank-row").first.click()
    page.click("#act-p-time .act-key-btn[data-fkey=key-bad]")
    expect(page.locator("#act-p-cat .act-rank-row[aria-pressed=true]")).to_have_count(1)
    expect(page.locator("#act-p-time .act-sel-mark")).to_have_count(1)
    for skin in ("v2", "v1"):
        for theme in ("light", "dark"):
            for accent in ("rose", "orange"):
                _skin(page, skin, theme, accent)
                got = page.evaluate(_INK)
                where = f"{skin} {theme} {accent}"
                assert got["ink"] != got["accent"], where
                assert got["mark"] == got["ink"], (where, got)
                assert got["rule"] == got["ink"], (where, got)
                assert got["underline"] == got["ink"], (where, got)


def test_a_selected_failed_row_keeps_its_red_rule_and_badge(page: Page, anon, activity_admin):
    """The selected row is tinted with the accent; under a rose accent a failed row must still read as
    failed by its rule and badge, and a successful one must not."""
    failed_sign_in(anon)
    login(page, activity_admin)
    open_activity(page)
    _skin(page, "v2", "light", "rose")
    bad = page.locator("#activity-rows tr.act-row.is-bad").first
    good = page.locator("#activity-rows tr.act-row:not(.is-bad):not(.is-warn)").first
    rule = "r => getComputedStyle(r.querySelector('td')).boxShadow"
    bad.click()
    expect(bad).to_have_attribute("aria-current", "true")
    assert "inset" in bad.evaluate(rule) and bad.locator(".badge-danger").count() == 1
    page.keyboard.press("Escape")
    good.click()
    expect(good).to_have_attribute("aria-current", "true")
    assert good.evaluate(rule) in ("none", "") and good.locator(".badge").count() == 0


def test_the_band_is_a_few_tab_stops_and_works_from_the_keyboard(page: Page, anon, activity_admin):
    """Each panel is one tab stop, the arrows move inside it, and a value shows on focus as on hover."""
    failed_sign_in(anon)
    login(page, activity_admin)
    open_activity(page)
    stops = page.evaluate("""() => Array.from(document.querySelectorAll('#act-band button'))
        .filter((b) => b.tabIndex >= 0 && !b.disabled && b.offsetParent !== null).length""")
    assert stops <= 9, stops

    hits = page.locator("#act-p-time .act-hit")
    hits.last.focus()
    tip = page.locator("#act-p-time .act-tip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("failed or refused")
    page.keyboard.press("ArrowLeft")
    expect(hits.nth(hits.count() - 2)).to_be_focused()
    page.keyboard.press("End")
    expect(hits.last).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.locator("#act-chips")).to_contain_text("Time: ")

    cats = page.locator("#act-p-cat .act-rank-row")
    cats.first.focus()
    page.keyboard.press("ArrowDown")
    expect(cats.nth(1)).to_be_focused()
    label = cats.nth(1).locator(".act-rank-label").inner_text()
    page.keyboard.press("Space")
    expect(page.locator("#act-chips")).to_contain_text(f"Category: {label}")
    page.keyboard.press("/")
    expect(page.locator("#act-search")).to_be_focused()


@pytest.mark.parametrize("skin", ["v2", "v1"])
def test_no_title_count_or_header_is_cut_short(page: Page, anon, activity_admin, skin):
    """The band's titles, its counts and labels, and the table's headers fit their room in both skins; a
    long category or person name is the only thing that may be ellipsized, with the full text in its
    title."""
    failed_sign_in(anon)
    page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    login(page, activity_admin)
    open_activity(page)
    cut = page.evaluate("""() => ['.act-ptitle-text', '.act-ptitle-note', '.act-now-row', '.act-now-label',
                                  '.act-signin-label', '.act-key-text', '#act-table thead th']
        .flatMap((sel) => Array.from(document.querySelectorAll(sel)))
        .filter((e) => e.offsetParent && e.scrollWidth > e.clientWidth)
        .map((e) => e.textContent.trim())""")
    assert cut == []


_NOW_CUT = """() => Array.from(document.querySelectorAll('#act-p-now .act-now-label'))
    .filter((e) => e.offsetParent && e.scrollWidth > e.clientWidth).map((e) => e.textContent.trim())"""


@pytest.mark.parametrize("skin", ["v2", "v1"])
def test_the_now_panel_fits_four_digit_counts_without_widening_the_band(page: Page, activity_admin, skin):
    """A busy server has hundreds of sessions and temporary credentials. Now grows to fit its widest row
    rather than cutting "Temp. credentials", and only into the room the charts would share: at the
    narrowest section that keeps the band on one row, the band still fits. Web transfers keeps its count
    under its label, so that row does not widen the panel."""
    def busy(route):
        response = route.fetch()
        body = response.json()
        body.update(people=1234, sessions=1234, temporary_credentials=1234)
        route.fulfill(response=response, json=body)

    page.route(re.compile(r".*/activity/now(\?.*)?$"), busy)
    page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    login(page, activity_admin)
    open_activity(page)
    temp = page.locator("#act-p-now .act-now-row").nth(2)
    expect(temp.locator(".act-now-value")).to_contain_text("234")
    assert page.evaluate(_NOW_CUT) == []
    transfers = page.locator("#act-p-now .act-now-transfers")
    label_box = transfers.locator(".act-now-label").bounding_box()
    value_box = transfers.locator(".act-now-value").bounding_box()
    assert value_box["y"] >= label_box["y"] + label_box["height"] - 1, "the transfer count sits under its label"

    # The section's content box is what the band's container query measures; bring it to 980 px.
    content = "() => { const s = document.querySelector('#activity-section'), cs = getComputedStyle(s); " \
              "return s.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight); }"
    page.set_viewport_size({"width": 1440 - round(page.evaluate(content) - 980), "height": 900})
    expect(page.locator("#act-p-now")).to_be_visible()
    assert abs(page.evaluate(content) - 980) <= 1
    one_row = page.evaluate("""() => {
        const band = document.querySelector('.act-band');
        const tops = ['now', 'time', 'cat', 'signin', 'active']
            .map((k) => document.querySelector('#act-p-' + k).getBoundingClientRect().top);
        return {overflow: band.scrollWidth - band.clientWidth, rows: new Set(tops.map(Math.round)).size};
    }""")
    assert one_row == {"overflow": 0, "rows": 1}, one_row
