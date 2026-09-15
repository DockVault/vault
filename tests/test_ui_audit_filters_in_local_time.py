"""The audit page's time filters mean the time the viewer typed, in the viewer's own zone.

The From/To inputs are `datetime-local`: a wall-clock time in the browser's zone, with no zone
attached. The page used to send that value as typed, and the server read it as UTC — so every timed
filter was off by the viewer's UTC offset. An admin east of Greenwich filtering "from two minutes
ago" around an event they could see on the same screen got an empty table, and the CSV export,
built from the same inputs, had the same hole. On the page whose job is forensic completeness.

This runs the browser fourteen hours ahead of UTC, so that a wall-clock value read as UTC lands
fourteen hours in the future and matches nothing. The assertion is what a person sees: the sign-in
that just happened is found by a filter that starts two minutes before it.

Lanes:
  * ui — the only lane that can prove this. It has to be a real browser in a real zone.
"""
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from playwright.sync_api import Page


@pytest.fixture(scope="module")
def browser_context_args(browser_context_args):
    # Far from UTC on purpose, and with no daylight saving: +14:00 all year.
    return {**browser_context_args, "timezone_id": "Pacific/Kiritimati"}


def _login(page: Page, username: str, password: str):
    """Sign in, waiting out the login rate limit rather than failing on it."""
    for _ in range(8):
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#login-form button[type=submit]")
        try:
            page.wait_for_selector("#dashboard-screen.active", timeout=8000)
            return
        except Exception:
            msg = page.evaluate(
                "() => (document.getElementById('login-error') || {}).textContent || ''")
            m = re.search(r"(\d+) seconds", msg or "")
            if not m:
                raise AssertionError(f"login failed, and not because of rate limiting: {msg!r}")
            time.sleep(int(m.group(1)) + 3)
    raise AssertionError("login was rate limited on every attempt")


def _open_audit_tab(page: Page):
    page.evaluate("() => navigateToSection('settings')")
    page.wait_for_selector("#settings-section.active", timeout=15000)
    page.evaluate(
        """() => { const t = [...document.querySelectorAll('.tabs .tab-btn')]
               .find(x => x.getAttribute('data-tab') === 'audit'); if (t) t.click(); }"""
    )
    page.wait_for_selector("#settings-tab-audit.active", timeout=10000)


def _entry_count(page: Page) -> int:
    text = page.evaluate("() => (document.getElementById('audit-count') || {}).textContent || ''")
    m = re.search(r"(\d+)", text or "")
    return int(m.group(1)) if m else -1


def _sent(url: str, key: str) -> str:
    return (parse_qs(urlparse(url).query).get(key) or [""])[0]


@pytest.mark.ui
def test_a_from_time_typed_in_the_viewers_zone_finds_the_sign_in_that_just_happened(
        page: Page, admin_creds):
    sent = []
    page.on("request", lambda req: sent.append(req.url) if "/audit/" in req.url else None)

    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])     # writes an audit row, now
    _open_audit_tab(page)

    # "Two minutes ago", exactly as the page's own clock would show it in the viewer's zone. This is
    # what a person types into a datetime-local input; the browser is in +14:00, so read as UTC it
    # would name a moment fourteen hours from now.
    local_two_minutes_ago = page.evaluate(
        """() => { const pad = n => String(n).padStart(2, '0');
                   const d = new Date(Date.now() - 2 * 60 * 1000);
                   return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T`
                        + `${pad(d.getHours())}:${pad(d.getMinutes())}`; }""")
    page.fill("#audit-filter-from", local_two_minutes_ago)
    page.click("#audit-search-btn")
    page.wait_for_function(
        "() => /\\d+/.test((document.getElementById('audit-count') || {}).textContent || '')"
        " && !document.querySelector('#audit-log-body .loading-spinner')", timeout=15000)

    assert _entry_count(page) > 0, (
        f"a filter starting two minutes ago found nothing, although the sign-in that opened this "
        f"page is in the log; the From value {local_two_minutes_ago!r} was read in the wrong zone")

    # What went over the wire is the instant meant, with its zone made explicit — within a few
    # minutes of now in UTC, not fourteen hours away.
    search = next(u for u in sent if "/audit/log?" in u)
    from_sent = _sent(search, "from_date")
    at = datetime.fromisoformat(from_sent)
    assert at.tzinfo is not None, f"the filter must be sent as an explicit instant: {from_sent!r}"
    drift = abs(datetime.now(timezone.utc) - at)
    assert timedelta(minutes=1) < drift < timedelta(minutes=5), (
        f"the instant sent should be about two minutes ago, not {drift} away: {from_sent!r}")

    # The CSV export is built from the same inputs and must send the same instant. Answered here so
    # nothing is downloaded; what matters is the query it asks for.
    page.route("**/audit/export*", lambda route: route.fulfill(
        status=200, content_type="text/csv", body="timestamp\n"))
    try:
        page.click("#audit-export-btn")
        page.wait_for_function("() => document.body.innerText.includes('Audit log exported')",
                               timeout=10000)
    finally:
        page.unroute("**/audit/export*")
    export = next(u for u in sent if "/audit/export?" in u)
    assert _sent(export, "from_date") == from_sent, (
        f"the export asked for a different window than the search: {export!r} vs {search!r}")
