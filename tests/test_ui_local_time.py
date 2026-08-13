"""Server timestamps are UTC; the UI must render them in the viewer's zone.

The API serialises stored datetimes naively — `datetime.isoformat()` yields
"2026-08-13T11:25:12.951177", with no trailing Z and no offset — while the value
itself is UTC. ECMAScript parses a date-TIME string in that form as LOCAL time
(date-ONLY strings are the opposite: those are defined as UTC). On a machine at
UTC+3 that made a record written one second ago parse three hours into the past:
the dashboard showed "3h ago" for a just-logged event, and any duration computed
from `expires_at` was three hours out — a correctness bug, not just a display one.

`parseServerTime()` in static/js/app.js normalises the instant; `formatTimeAgo()`
and `formatServerTime()` build on it. These tests pin the behaviour in a real
browser under a non-UTC timezone, because the bug is invisible when the test
machine happens to run UTC.
"""
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

APP_JS = (
    Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
).read_text(encoding="utf-8")

# A zone with a large, non-zero offset makes an off-by-the-offset bug obvious.
TZ = "Europe/Athens"


@pytest.fixture
def tz_page(browser, base_url):
    """A page pinned to a non-UTC timezone, so a naive-parse bug cannot hide."""
    context = browser.new_context(timezone_id=TZ, base_url=base_url)
    page = context.new_page()
    yield page
    context.close()


# --------------------------------------------------------------------------
# static guards
# --------------------------------------------------------------------------
@pytest.mark.unit
def test_parse_server_time_has_one_definition():
    assert len(re.findall(r"(?m)^function parseServerTime\s*\(", APP_JS)) == 1
    assert len(re.findall(r"(?m)^function formatServerTime\s*\(", APP_JS)) == 1


@pytest.mark.unit
def test_no_server_timestamp_is_parsed_with_a_bare_date_constructor():
    """Every API timestamp must go through parseServerTime.

    A bare `new Date(someServerField)` reintroduces the bug for that one field.
    The allowed remainders are: the two constructions inside parseServerTime
    itself, a clock read (`new Date()`), a client-side `Date.now()` expression,
    an epoch-seconds value (unambiguous), and the <input type="datetime-local">
    read, which is local wall-clock by definition and must NOT be normalised.
    """
    def argument_at(text, open_paren):
        """Balanced scan from `new Date(` to its matching close paren.

        A naive `\\(([^)]*)\\)` truncates at the first inner `)`, which turns
        `new Date(Date.now() - 60000)` into the bogus arg `Date.now(` and makes
        this guard report false positives.
        """
        depth, i = 0, open_paren
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    return text[open_paren + 1:i].strip()
            i += 1
        return None

    offenders = []
    for i, line in enumerate(APP_JS.splitlines(), 1):
        for m in re.finditer(r"new Date\(", line):
            arg = argument_at(line, m.end() - 1)
            if arg is None or arg == "":        # a clock read, or split over lines
                continue
            if "Date.now()" in arg:             # client-side arithmetic
                continue
            if arg == "value" or arg.startswith("isDateTime"):
                continue                        # inside parseServerTime itself
            if "* 1000" in arg:                 # epoch seconds
                continue
            if arg == "endValue":               # datetime-local input
                continue
            offenders.append(f"  line {i}: new Date({arg})")
    assert not offenders, (
        "these parse a value with the bare Date constructor; if the value comes "
        "from the API it will be read as local time instead of UTC:\n"
        + "\n".join(offenders)
    )


# --------------------------------------------------------------------------
# behaviour, in a browser, under a non-UTC zone
# --------------------------------------------------------------------------
@pytest.mark.ui
def test_naive_utc_timestamp_is_not_shifted_by_the_local_offset(tz_page: Page):
    """The exact reported symptom: a just-now event reading hours old."""
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof parseServerTime === 'function'")

    result = page.evaluate(
        """() => {
            const offsetMin = new Date().getTimezoneOffset();
            // What the API emits for "now": UTC, serialised without a designator.
            const naiveUtcNow = new Date().toISOString().replace('Z', '');
            const parsed = parseServerTime(naiveUtcNow);
            return {
                offsetMin,
                skewSeconds: Math.abs((Date.now() - parsed.getTime()) / 1000),
                ago: formatTimeAgo(naiveUtcNow),
            };
        }"""
    )
    assert result["offsetMin"] != 0, (
        "the browser is running at UTC, so this test cannot detect the bug; "
        f"the {TZ} context did not apply"
    )
    assert result["skewSeconds"] < 5, (
        f"a naive-UTC 'now' parsed {result['skewSeconds']:.0f}s away from now — "
        f"it is being read as local time rather than UTC"
    )
    assert result["ago"] == "just now", (
        f"a just-written record renders as {result['ago']!r}, not 'just now'"
    )


@pytest.mark.ui
def test_timestamps_with_an_explicit_zone_are_left_alone(tz_page: Page):
    """A designator-carrying value must not be double-shifted, so the helper
    keeps working if the API later starts emitting one."""
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof parseServerTime === 'function'")

    result = page.evaluate(
        """() => {
            const iso = '2026-08-13T11:25:12.000Z';
            const expected = Date.parse(iso);
            return {
                zulu: parseServerTime(iso).getTime() - expected,
                offset: parseServerTime('2026-08-13T14:25:12.000+03:00').getTime() - expected,
                spaceSeparated: parseServerTime('2026-08-13 11:25:12').getTime() - expected,
                naive: parseServerTime('2026-08-13T11:25:12').getTime() - expected,
            };
        }"""
    )
    for label, delta in result.items():
        assert delta == 0, (
            f"{label!r} resolved to an instant {delta}ms away from the expected "
            f"UTC instant"
        )


@pytest.mark.ui
def test_absolute_times_render_in_the_viewers_zone(tz_page: Page):
    """formatServerTime must show local wall-clock, not UTC wall-clock."""
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof formatServerTime === 'function'")

    result = page.evaluate(
        """() => {
            // 11:25 UTC. Athens is UTC+3 in August, so this must read 14:25 local.
            const naive = '2026-08-13T11:25:12';
            const shown = formatServerTime(naive);
            const local = new Date('2026-08-13T11:25:12Z').toLocaleString();
            return { shown, local, hour: new Date('2026-08-13T11:25:12Z').getHours() };
        }"""
    )
    assert result["shown"] == result["local"], (
        f"rendered {result['shown']!r} but the viewer's local rendering of that "
        f"instant is {result['local']!r}"
    )
    assert result["hour"] == 14, (
        f"expected the {TZ} local hour for 11:25Z to be 14, got {result['hour']}"
    )


@pytest.mark.ui
def test_hour_only_utc_offset_is_not_misread_as_utc(tz_page: Page):
    """ISO 8601 allows a two-digit offset ("...-05"). This API never emits that
    form, and the ECMAScript Date grammar does not accept it either, so it
    cannot be resolved to an instant. What matters is that it is recognised as
    carrying a zone: treating it as zone-less would append a second designator
    and silently produce a WRONG instant rather than no instant."""
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof parseServerTime === 'function'")

    result = page.evaluate(
        """() => {
            const d = parseServerTime('2026-08-13T11:25:12-05');
            // The dangerous outcome: read as if it were 11:25 UTC.
            const asIfUtc = Date.parse('2026-08-13T11:25:12Z');
            return { value: d === null ? null : d.getTime(), asIfUtc };
        }"""
    )
    assert result["value"] != result["asIfUtc"], (
        "an offset-bearing timestamp was reinterpreted as UTC, shifting the "
        "instant by the offset"
    )
    assert result["value"] is None, (
        f"expected no instant for a form the engine cannot parse, got "
        f"{result['value']}"
    )


@pytest.mark.ui
def test_unreadable_credential_expiry_does_not_break_the_row(tz_page: Page):
    """Rendering a temp-credential row must not throw on a bad expires_at.

    parseServerTime returns null where the old bare Date constructor returned an
    Invalid Date, and `null.toLocaleString()` throws where `Invalid Date
    .toLocaleString()` merely returned "Invalid Date". Because the rows are
    built inside a map() over the whole list, one unreadable value would blank
    the entire table rather than one cell.
    """
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof renderTempCredRow === 'function'")

    result = page.evaluate(
        """() => {
            const out = [];
            for (const bad of [null, undefined, '', 'not-a-date']) {
                const cred = {
                    username: 'u', temp_username: 't', expires_at: bad,
                    is_used: false, is_active: true,
                };
                try {
                    const html = renderTempCredRow(cred);
                    out.push({ value: String(bad), threw: false,
                               expired: html.includes('Expired') });
                } catch (e) {
                    out.push({ value: String(bad), threw: true, error: e.message });
                }
            }
            return out;
        }"""
    )
    threw = [r for r in result if r["threw"]]
    assert not threw, f"rendering threw on an unreadable expires_at: {threw}"
    assert all(r["expired"] for r in result), (
        "an unreadable expiry must be reported as expired, never as active — "
        f"got {result}"
    )


@pytest.mark.unit
def test_no_timestamp_falls_back_to_the_current_instant():
    """`parseServerTime(x) || new Date()` is the tempting way to keep a render
    from throwing, and it is wrong: it presents an unreadable timestamp as the
    current moment. On an audit row — a security record — that makes an old or
    corrupted event look like it just happened, with nothing on screen to say
    otherwise. Every render path must degrade to a visible sentinel instead.
    """
    offenders = [
        f"  line {i}: {line.strip()}"
        for i, line in enumerate(APP_JS.splitlines(), 1)
        if re.search(r"parseServerTime\([^)]*\)\s*\|\|\s*new Date\(\)", line)
    ]
    assert not offenders, (
        "these substitute the current instant for an unreadable timestamp:\n"
        + "\n".join(offenders)
    )


@pytest.mark.ui
def test_unreadable_timestamp_renders_as_a_visible_sentinel(tz_page: Page):
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof formatServerTime === 'function'")

    result = page.evaluate(
        """() => ({
            bad: formatServerTime('not-a-date'),
            missing: formatServerTime(null),
            now: new Date().toLocaleString(),
        })"""
    )
    assert result["bad"] == "—", f"unreadable timestamp rendered as {result['bad']!r}"
    assert result["missing"] == "—"
    assert result["bad"] != result["now"]


@pytest.mark.ui
def test_bad_and_empty_values_degrade_instead_of_throwing(tz_page: Page):
    """Timestamp fields are nullable across the API (last_login, expires_at…)."""
    page = tz_page
    page.goto("/")
    page.wait_for_function("() => typeof parseServerTime === 'function'")

    result = page.evaluate(
        """() => ({
            nulls: [null, undefined, '', 'not-a-date'].map(v => parseServerTime(v)),
            agoNull: formatTimeAgo(null),
            fmtNull: formatServerTime(null),
            fmtFallback: formatServerTime(null, 'Never'),
            passthroughDate: parseServerTime(new Date(0)).getTime(),
            passthroughEpoch: parseServerTime(0).getTime(),
        })"""
    )
    assert result["nulls"] == [None, None, None, None], (
        f"expected null for every unusable value, got {result['nulls']}"
    )
    assert result["agoNull"] == "—"
    assert result["fmtNull"] == "—"
    assert result["fmtFallback"] == "Never"
    assert result["passthroughDate"] == 0, "a Date instance must pass through"
    # Numbers are epoch milliseconds and are already unambiguous, so 0 is the
    # epoch itself — not an "unset" sentinel. Only null/undefined/'' are unset.
    assert result["passthroughEpoch"] == 0
