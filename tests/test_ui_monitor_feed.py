"""Live Monitor renders the events it receives — the feed is no longer dead.

The monitor's WS frames wrap the event under `event` (Path A). The render code used to read the row
fields off the TOP-LEVEL frame (`data.type`, `data.message`), so every wrapped upload/download/login
frame became type:'unknown' with an empty message and was then filtered out — the feed looked dead.
These tests drive `handleMonitorEvent` directly (deterministic, no live traffic needed) and assert:

- a wrapped Path A frame renders with its real type + description (the core fix);
- events carry the owner's requested enrichment — vault name, Standard vs zero-knowledge, temp actor, IP;
- Path B (unwrapped operation_*) frames are suppressed (they duplicate Path A by operation_id);
- repeated frames of one operation coalesce into a single updating row;
- the "Security" chip covers both error and size-limit incidents;
- the audit-action -> event-type map used by history backfill is correct.
"""
import re

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


def _open_monitor(page: Page):
    page.click('.sidebar-item[data-section="monitor"]')
    expect(page.locator("#monitor-section")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#monitor-events-list")).to_be_visible()


def test_wrapped_pathA_frame_renders_with_type_and_enrichment(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => {
            monitorEvents = []; monitorCurrentFilter = 'all';
            handleMonitorEvent({ event: {
                type: 'upload', operation_id: 't-op1',
                description: 'photo.jpg - 1,024 bytes uploaded', user: 'admin',
                vault_name: 'Team Vault', vault_type: 'standard', ip: '10.1.2.3'
            }});
            const e = monitorEvents[0] || {};
            const html = document.getElementById('monitor-events-list').innerHTML;
            return {
                count: monitorEvents.length, type: e.type, user: e.user, message: e.message,
                vaultName: e.vaultName, vaultType: e.vaultType,
                domHasVault: html.indexOf('Team Vault') !== -1,
                domHasStandard: html.indexOf('>Standard<') !== -1,
                domHasIP: html.indexOf('10.1.2.3') !== -1,
                domHasMsg: html.indexOf('photo.jpg') !== -1
            };
        }"""
    )
    assert res["count"] == 1
    # The core fix: a wrapped frame's type is read from `ev`, not the top-level `data` (was 'unknown').
    assert res["type"] == "upload", res
    assert res["message"] == "photo.jpg - 1,024 bytes uploaded", res
    assert res["user"] == "admin", res
    assert res["vaultName"] == "Team Vault" and res["vaultType"] == "standard", res
    assert res["domHasVault"] and res["domHasStandard"] and res["domHasIP"] and res["domHasMsg"], res


def test_zk_badge_pathB_suppressed_and_operation_coalesced(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => {
            monitorEvents = []; monitorCurrentFilter = 'all';
            // Path B (UNWRAPPED operation_*) duplicates Path A by operation_id -> must be suppressed.
            handleMonitorEvent({ type: 'operation_start', operation_id: 't-op2', username: 'admin' });
            // The auth-handshake control frame is not activity and must not render as a feed row.
            handleMonitorEvent({ type: 'connected' });
            const afterPathB = monitorEvents.length;
            // Three frames of one download coalesce into ONE updating row (keyed by operation_id).
            const base = { type: 'download', operation_id: 't-op3', user: 'admin',
                           vault_name: 'Secret ZK', vault_type: 'zero_knowledge' };
            handleMonitorEvent({ event: Object.assign({}, base, { description: 'a - 0 bytes' }) });
            handleMonitorEvent({ event: Object.assign({}, base, { description: 'a - 500 bytes' }) });
            handleMonitorEvent({ event: Object.assign({}, base, { description: 'a - done', completed: true }) });
            const html = document.getElementById('monitor-events-list').innerHTML;
            return {
                afterPathB, coalescedCount: monitorEvents.length,
                topMsg: monitorEvents[0].message,
                domHasZK: html.indexOf('>ZK<') !== -1,
                rows: document.querySelectorAll('#monitor-events-list .monitor-event-item').length
            };
        }"""
    )
    assert res["afterPathB"] == 0, f"Path B operation_start should not render: {res}"
    assert res["coalescedCount"] == 1, f"one operation should be one row: {res}"
    assert res["rows"] == 1, res
    assert res["topMsg"] == "a - done", res
    assert res["domHasZK"], f"zero-knowledge vault should show a ZK badge: {res}"


def test_security_filter_group_and_temp_actor_badge(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => {
            monitorEvents = [];
            handleMonitorEvent({ event: { type: 'error', description: 'boom', user: 'x' } });
            handleMonitorEvent({ event: { type: 'security_incident', description: 'limit exceeded', user: 'y' } });
            handleMonitorEvent({ event: { type: 'login', description: 'signed in', user: 'z',
                                          is_temporary: true, temp_username: 'contractor' } });
            monitorCurrentFilter = 'security'; updateMonitorUI();
            const securityRows = document.querySelectorAll('#monitor-events-list .monitor-event-item').length;
            monitorCurrentFilter = 'all'; updateMonitorUI();
            const html = document.getElementById('monitor-events-list').innerHTML;
            return {
                securityRows,
                allRows: document.querySelectorAll('#monitor-events-list .monitor-event-item').length,
                domHasTemp: html.indexOf('temp: contractor') !== -1
            };
        }"""
    )
    # Security chip = error + security_incident (2), NOT the login event.
    assert res["securityRows"] == 2, res
    assert res["allRows"] == 3, res
    assert res["domHasTemp"], f"a temp-credential actor should show a temp badge: {res}"


def test_logout_scrubs_monitor_feed(page: Page, admin_creds):
    """Shared-tab isolation: the feed is kept across section re-entry, so logout MUST wipe it.
    Otherwise the previous user's activity + admin-only /audit/log backfill would show to the next
    user who logs in on the same tab (logout is a pure SPA action, no page reload)."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => {
            monitorEvents = []; monitorHistoryLoaded = true;
            handleMonitorEvent({ event: { type: 'upload', operation_id: 'x1',
                description: 'secret.pdf uploaded', user: 'admin',
                vault_name: 'Finance', vault_type: 'standard' } });
            const before = monitorEvents.length;
            logout();
            return { before, after: monitorEvents.length, histReset: monitorHistoryLoaded };
        }"""
    )
    assert res["before"] == 1
    assert res["after"] == 0, "logout must scrub the retained monitor feed (shared-tab leak)"
    assert res["histReset"] is False, "logout must re-arm history backfill for the next user"


def test_generic_cancel_frame_preserves_transfer_row(page: Page, admin_creds):
    """The /api/operations/{id}/cancel endpoint emits a generic wrapped `operation_cancelled` that
    shares the transfer's operation_id but carries no vault fields. Coalescing must MERGE it: keep
    the specific download/upload type (so it stays under the Downloads/Uploads filter) and the vault
    enrichment, just marking the row cancelled."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => {
            monitorEvents = []; monitorCurrentFilter = 'download';
            handleMonitorEvent({ event: { type: 'download', operation_id: 'c1',
                description: 'report.pdf (2,000 bytes)', user: 'admin',
                vault_name: 'Finance', vault_type: 'standard' } });
            // Generic cancel frame: same op id, NO vault fields, generic type.
            handleMonitorEvent({ event: { type: 'operation_cancelled', operation_id: 'c1',
                description: 'Operation cancelled by admin', user: 'admin' } });
            const row = monitorEvents.find(e => e.operationId === 'c1') || {};
            return {
                count: monitorEvents.length, type: row.type, vaultName: row.vaultName,
                cancelled: row.cancelled,
                visibleUnderDownload: document.querySelectorAll('#monitor-events-list .monitor-event-item').length
            };
        }"""
    )
    assert res["count"] == 1, f"cancel should coalesce, not add a row: {res}"
    assert res["type"] == "download", f"specific transfer type must survive a generic cancel: {res}"
    assert res["vaultName"] == "Finance", f"vault enrichment must survive a thin cancel frame: {res}"
    assert res["cancelled"] is True, res
    assert res["visibleUnderDownload"] == 1, f"the cancelled download must stay under Downloads: {res}"


def test_empty_state_uses_centered_class(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    has = page.evaluate(
        """() => {
            monitorEvents = []; monitorCurrentFilter = 'all'; updateMonitorUI();
            return !!document.querySelector('#monitor-events-list .empty-state-center');
        }"""
    )
    assert has, "empty state should use the shared .empty-state-center layout"


def test_audit_action_to_type_map(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_monitor(page)
    res = page.evaluate(
        """() => ({
            up: auditActionToType('file_upload'),
            down: auditActionToType('file_download_completed'),
            login: auditActionToType('login_success'),
            logout: auditActionToType('logout'),
            sec: auditActionToType('size_limit_violation'),
            other: auditActionToType('settings_updated')
        })"""
    )
    assert res == {
        "up": "upload", "down": "download", "login": "login",
        "logout": "logout", "sec": "security_incident", "other": "info",
    }, res
