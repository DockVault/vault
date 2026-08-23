"""Create-share limits get a live client-side red flag before Create.

The three optional create-share inputs (expiry days / max recipients / max downloads per recipient)
had no client-side range check: an over-cap value was submitted and only rejected server-side with a
400 (ShareCreate ge=1/le=_INT4_MAX + resolve_share_limits tag caps). This validates them live,
mirroring the effective per-tag caps the /share-policy payload already ships, and blocks Create until
they're valid.

These drive the validation helpers directly against the (always-present, hidden) create-share modal
DOM — no need to enable sharing or seed tags — by injecting a fabricated selected tag, which is
deterministic and exercises the exact effective-cap math the server enforces.
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


# Setup statements (run INSIDE each evaluate's function body): fabricate a selected tag with
# recipients cap 100, 7-day lifetime, unlimited downloads, and build the limit spec exactly as
# onShareTagChange would — without opening the modal or enabling sharing.
_SETUP = """
    _shareCreate.policy = { sharing_enabled: true, tags: [{
        id: 't1', name: 'Test', allow_custom: true,
        max_lifetime_minutes: 7 * 1440, max_recipients_cap: 100, max_downloads_cap: null,
        allowed_audiences: ['anyone_internal']
    }] };
    const sel = document.getElementById('share-tag-select');
    sel.replaceChildren();
    const o = document.createElement('option'); o.value = 't1'; o.textContent = 'Test';
    sel.appendChild(o); sel.value = 't1';
    _shareRefreshLimitHints();
"""


def test_defensive_input_attributes(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate(
        """() => {
            const g = id => {
                const e = document.getElementById(id);
                return { type: e.getAttribute('type'), inputmode: e.getAttribute('inputmode'),
                         maxlength: e.getAttribute('maxlength') };
            };
            return { days: g('share-lifetime-days'), rec: g('share-max-recipients'),
                     dl: g('share-max-downloads') };
        }"""
    )
    # Defensive: numeric text inputs so maxlength actually applies (it is inert on type=number).
    for k in ("days", "rec", "dl"):
        assert res[k]["type"] == "text" and res[k]["inputmode"] == "numeric", res
    assert res["days"]["maxlength"] == "7", res
    assert res["rec"]["maxlength"] == "10" and res["dl"]["maxlength"] == "10", res


def test_baseline_hints_reflect_effective_caps(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate("() => {" + _SETUP + """
        return {
            rec: document.getElementById('share-recipients-hint').textContent,
            dl: document.getElementById('share-downloads-hint').textContent,
            day: document.getElementById('share-lifetime-hint').textContent
        };
    }""")
    assert "100" in res["rec"] and "recipient" in res["rec"].lower(), res
    # A null download cap = unlimited: no number, just "any number".
    assert "any number" in res["dl"].lower(), res
    assert "7" in res["day"] and "day" in res["day"].lower(), res


def test_over_cap_values_flag_and_block(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate("() => {" + _SETUP + """
        document.getElementById('share-max-recipients').value = '101';   // > cap 100
        document.getElementById('share-lifetime-days').value = '8';       // > 7 days
        document.getElementById('share-max-downloads').value = '999999';  // unlimited cap -> ok
        const allValid = _shareValidateAllLimits();
        const inv = id => document.getElementById(id).classList.contains('is-invalid');
        return {
            allValid,
            recInvalid: inv('share-max-recipients'),
            recHint: document.getElementById('share-recipients-hint').textContent,
            dayInvalid: inv('share-lifetime-days'),
            dayHint: document.getElementById('share-lifetime-hint').textContent,
            dlInvalid: inv('share-max-downloads')
        };
    }""")
    assert res["allValid"] is False, res
    assert res["recInvalid"] and "100" in res["recHint"], res
    assert res["dayInvalid"] and "7" in res["dayHint"], res
    assert res["dlInvalid"] is False, "an unlimited-cap field within INT4 must stay valid: %r" % res


def test_tag_switch_reflags_retained_value(page: Page, admin_creds):
    """Switching to a stricter tag must re-flag a value carried over from the previous tag
    immediately (not only on the next keystroke)."""
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate("() => {" + _SETUP + """
        // Value valid under tag t1 (cap 100).
        document.getElementById('share-max-recipients').value = '90';
        _shareValidateAllLimits();
        const invalidUnderT1 = document.getElementById('share-max-recipients').classList.contains('is-invalid');
        // Switch to a stricter tag t2 (cap 50) — value 90 is now over-cap.
        _shareCreate.policy.tags.push({ id: 't2', name: 'Strict', allow_custom: true,
            max_lifetime_minutes: 7 * 1440, max_recipients_cap: 50, max_downloads_cap: null,
            allowed_audiences: ['anyone_internal'] });
        const sel2 = document.getElementById('share-tag-select');
        const o2 = document.createElement('option'); o2.value = 't2'; o2.textContent = 'Strict';
        sel2.appendChild(o2); sel2.value = 't2';   // an option must exist for .value to take
        _shareRefreshLimitHints();
        return {
            invalidUnderT1,
            invalidUnderT2: document.getElementById('share-max-recipients').classList.contains('is-invalid'),
            hint: document.getElementById('share-recipients-hint').textContent
        };
    }""")
    assert res["invalidUnderT1"] is False, res
    assert res["invalidUnderT2"] is True, "a retained over-cap value must re-flag on tag switch: %r" % res
    assert "50" in res["hint"], res


def test_valid_and_malformed_values(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate("() => {" + _SETUP + """
        const out = {};
        // Exactly at the caps: valid.
        document.getElementById('share-max-recipients').value = '100';
        document.getElementById('share-lifetime-days').value = '7';
        document.getElementById('share-max-downloads').value = '5';
        out.atCapValid = _shareValidateAllLimits();
        out.noInvalidAtCap = !document.querySelector('#share-limits-group .is-invalid');
        // Empty is valid (optional; tag default applies).
        document.getElementById('share-max-recipients').value = '';
        document.getElementById('share-lifetime-days').value = '';
        document.getElementById('share-max-downloads').value = '';
        out.emptyValid = _shareValidateAllLimits();
        // Malformed / zero.
        document.getElementById('share-max-recipients').value = 'abc';
        document.getElementById('share-lifetime-days').value = '0';
        out.malformedValid = _shareValidateAllLimits();
        out.recHint = document.getElementById('share-recipients-hint').textContent;
        out.dayHint = document.getElementById('share-lifetime-hint').textContent;
        return out;
    }""")
    assert res["atCapValid"] is True and res["noInvalidAtCap"] is True, res
    assert res["emptyValid"] is True, res
    assert res["malformedValid"] is False, res
    assert "whole number" in res["recHint"].lower(), res
    assert "at least 1" in res["dayHint"].lower(), res
