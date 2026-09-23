"""The deployment's ceiling on self-signup (BRAND_ENABLE_SIGNUP) reaches every place that asks.

The pure rule is pinned in test_account_policy. Here the real API module is driven: the one policy
reader every signup decision goes through, the save that refuses to turn it on, the Settings
response, and the tab that shows the switch as unavailable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


class _Row:
    def __init__(self, value):
        self.value = value


class _Query:
    def __init__(self, value):
        self._value = value

    def filter(self, *a, **k):
        return self

    def first(self):
        return _Row(self._value)


class _DB:
    """Just enough session for _account_policy: one stored settings row."""

    def __init__(self, value):
        self._value = value

    def query(self, *a):
        return _Query(self._value)


@pytest.fixture()
def api(monkeypatch):
    import _bare_api_env
    _bare_api_env.set_bare_api_env()
    import importlib
    from app.api import api_server
    # The module itself: app.config re-exports the INSTANCE under the name `branding`.
    branding_module = importlib.import_module("app.config.branding")
    return api_server, branding_module


@pytest.mark.parametrize("allowed, effective", [(True, True), (False, False)])
def test_the_policy_every_signup_decision_reads_obeys_the_ceiling(api, monkeypatch, allowed, effective):
    api_server, branding_module = api
    monkeypatch.setattr(branding_module.branding, "enable_signup", allowed)
    db = _DB({"signup_enabled": True})          # the admin turned it on
    assert api_server._signup_allowed() is allowed
    assert api_server._account_policy(db)["signup_enabled"] is effective


def _code(src):
    return "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))


def _body(src, anchor):
    start = src.index(anchor)
    nxt = src.find("\n@app.", start + len(anchor))
    return src[start:nxt if nxt != -1 else len(src)]


def test_signup_decisions_read_the_one_policy_reader():
    """The login page's policy and the signup endpoint both decide from _account_policy -- the
    reader that applies the ceiling -- and the save and the Settings response apply it too."""
    src = _code((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    assert "pol = _account_policy(db)" in _body(src, '@app.get("/auth/policy")')
    assert "pol = _account_policy(db)" in _body(src, '@app.post("/auth/signup")')
    assert src.count("signup_allowed=_signup_allowed())") == 1
    assert src.count('data["signup_locked"] = not _signup_allowed()') == 1
    assert src.count("apply_signup_ceiling(effective_account_policy(") == 2   # reader + Settings
    # No other path reads the raw stored switch.
    assert src.count('.get("signup_enabled")') == 2        # /auth/policy and /auth/signup, via pol


def test_the_settings_tab_shows_a_ruled_out_switch_as_unavailable():
    js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = js.index("function populateAccountsPolicy(")
    body = _code(js[start:js.index("\nfunction ", start + 1)])
    assert "settings.signup_locked === true" in body
    assert "signupEl.disabled = signupLocked" in body
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert html.count('id="setting-signup-locked-note"') == 1
