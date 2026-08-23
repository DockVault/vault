"""The notification bell renders its feed safely.

Drives the render helpers directly against the always-present navbar bell DOM (deterministic, no live
events needed): the badge count/threshold/hidden states, unread styling, the empty state, and — most
importantly — that a notification title/body carrying another user's name or a file name is rendered
as TEXT (createElement + textContent), never as HTML.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_bell_renders_and_is_xss_safe(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate(
        """() => {
            window.__xss = false;
            notifItems = [
                { id: 'n1', type: 'share_received',
                  title: '<img src=x onerror="window.__xss=true">',
                  body: 'shared "<b>secret.pdf</b>" with you', is_read: false,
                  created_at: new Date().toISOString(), target: '#shared' },
                { id: 'n2', type: 'temp_login', title: 'Temporary credential signed in',
                  body: null, is_read: true, created_at: new Date().toISOString(),
                  target: '#temp-creds' }
            ];
            notifUnread = 1;
            renderNotifications();
            const list = document.getElementById('notif-list');
            const rows = list.querySelectorAll('.notif-item');
            const badge = document.getElementById('notif-badge');
            return {
                rows: rows.length,
                badgeShown: !badge.hidden,
                badgeText: badge.textContent,
                xssFired: window.__xss === true,
                titleText: rows[0].querySelector('.notif-item-title').textContent,
                firstUnread: rows[0].classList.contains('unread'),
                secondRead: !rows[1].classList.contains('unread'),
                emptyHidden: document.getElementById('notif-empty').style.display === 'none'
            };
        }"""
    )
    assert res["rows"] == 2, res
    assert res["badgeShown"] and res["badgeText"] == "1", res
    assert res["xssFired"] is False, "notification title must render as text, not execute HTML"
    assert "<img" in res["titleText"], "the literal title text should be present (escaped)"
    assert res["firstUnread"] is True and res["secondRead"] is True, res
    assert res["emptyHidden"] is True, res


def test_bell_badge_thresholds_and_empty_state(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate(
        """() => {
            const out = {};
            notifItems = []; notifUnread = 0; renderNotifications();
            out.zeroHidden = document.getElementById('notif-badge').hidden;
            out.emptyShown = document.getElementById('notif-empty').style.display !== 'none';
            notifUnread = 150; updateNotifBadge();
            out.capped = document.getElementById('notif-badge').textContent;
            out.cappedShown = !document.getElementById('notif-badge').hidden;
            return out;
        }"""
    )
    assert res["zeroHidden"] is True, "badge hides at zero unread"
    assert res["emptyShown"] is True, "empty state shows when there are no notifications"
    assert res["capped"] == "99+" and res["cappedShown"] is True, res
