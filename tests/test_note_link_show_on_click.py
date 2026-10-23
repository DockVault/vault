"""A note link with no secret shows its note only on a "Show note" click, offline.

The page used to redeem a link as it loaded, so anything that loaded the page and ran its script (a
mail scanner, a chat app's link preview) spent the view and the person it was sent to found it used
up. The page now peeks first: a peek says whether the link opens and with what, spends nothing and
checks no secret. A link with no secret answers that it can be shown, and the click redeems for real.
A link with a secret answers a peek with its prompt, as a first request without the secret always
has, so nothing changes for it.

The real redeem handler runs here against a stand-in database that counts the updates sent (the
view is spent by the one guarded update). The page's own half is pinned below and run in a browser in
tests/test_ui_note_link_show_on_click.py.
"""
import re
import types
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import rate_limiter as R  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


class _Rows:
    def __init__(self, row):
        self._row = row

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._row


class _DB:
    def __init__(self, rows):
        self.rows, self.updates = rows, 0

    def query(self, model, *more):
        return _Rows(self.rows.get(model))

    def execute(self, *args, **kwargs):
        self.updates += 1
        return types.SimpleNamespace(rowcount=1)

    def add(self, obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


@pytest.fixture
def redeem(monkeypatch):
    monkeypatch.setattr(R.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.10")
    monkeypatch.setattr(S.note_link_policy, "public_note_links_enabled", lambda blob: True)
    monkeypatch.setattr(S, "_notelink_locked", lambda token: False)
    checked = []
    import app.core.security as security
    monkeypatch.setattr(security, "verify_password", lambda secret, hashed: checked.append(secret) or True)
    owner = types.SimpleNamespace(id=uuid.uuid4(), is_active=True, is_locked=False, locked_until=None)

    def run(secret_kind="none", owner_state=None, **payload):
        token = "tok-" + uuid.uuid4().hex
        link = types.SimpleNamespace(
            id=uuid.uuid4(), token_hash=S._notelink_token_hash(token), owner_id=owner.id, revoked=False,
            expires_at=None, max_uses=1, use_count=0, secret_kind=secret_kind,
            password_hash=None if secret_kind == "none" else "a-hash", title_snapshot="T", body_snapshot="the note")
        account = owner if owner_state is None else (
            None if owner_state == "gone" else types.SimpleNamespace(id=owner.id, **OWNER_STATES[owner_state]))
        db = _DB({S.NoteLink: link, S.User: account})
        out = types.SimpleNamespace(db=db, checked=checked, body=None, refused=None)
        try:
            out.body = run_coroutine(S.redeem_note_link(token, S.NoteLinkRedeem(**payload), None, db))
        except HTTPException as refused:
            out.refused = refused
        return out

    return run


def test_a_peek_at_a_link_with_no_secret_spends_nothing_and_shows_nothing(redeem):
    out = redeem(peek=True)
    assert out.body == {"available": True, "secret_kind": "none"}
    assert "the note" not in str(out.body) and out.db.updates == 0


def test_the_click_spends_one_view_and_shows_the_note(redeem):
    out = redeem()
    assert out.body == {"title": "T", "body": "the note", "secret_kind": "none"}
    assert out.db.updates == 1


@pytest.mark.parametrize("kind", ["pin", "password"])
@pytest.mark.parametrize("payload", [{"peek": True}, {"peek": True, "secret": "the-right-one"}])
def test_a_peek_at_a_protected_link_prompts_and_never_checks_a_secret(redeem, kind, payload):
    out = redeem(secret_kind=kind, **payload)
    assert out.refused.status_code == 401
    assert out.refused.detail == {"error": "secret_required", "secret_kind": kind}
    assert out.db.updates == 0 and out.checked == []


# The owner's account as the link sees it: taken out by an administrator, or not.
OWNER_STATES = {
    "deactivated": dict(is_active=False, is_locked=False, locked_until=None),
    "locked by an administrator": dict(is_active=True, is_locked=True, locked_until=None),
    # The timed lock wrong passwords arm leaves the links working (the control: a peek still answers).
    "locked for a while": dict(is_active=True, is_locked=True,
                               locked_until=datetime.utcnow() + timedelta(minutes=15)),
}


@pytest.mark.parametrize("kind", ["none", "pin", "password"])
@pytest.mark.parametrize("owner_state", ["deactivated", "locked by an administrator", "gone"])
def test_a_peek_at_a_link_whose_owner_is_out_answers_like_a_missing_link(redeem, kind, owner_state):
    # A peek must not tell a link whose owner was taken out from one that is still live: it gets the
    # same 404 as a missing link, before anything that would say the link exists (its "available", its
    # prompt).
    out = redeem(secret_kind=kind, owner_state=owner_state, peek=True)
    assert out.body is None, f"a peek answered {out.body!r} for a link whose owner is {owner_state}"
    assert out.refused.status_code == 404 and out.refused.detail == "This link is not available."
    assert out.db.updates == 0 and out.checked == []


@pytest.mark.parametrize("kind, answer", [("none", None), ("pin", 401), ("password", 401)])
def test_a_peek_still_answers_while_the_timed_lock_holds(redeem, kind, answer):
    out = redeem(secret_kind=kind, owner_state="locked for a while", peek=True)
    if answer is None:
        assert out.body == {"available": True, "secret_kind": "none"}
    else:
        assert out.refused.status_code == answer
    assert out.db.updates == 0


@pytest.mark.parametrize("kind", ["pin", "password"])
def test_a_protected_link_still_opens_with_its_secret(redeem, kind):
    out = redeem(secret_kind=kind, secret="the-right-one")
    assert out.body["body"] == "the note" and out.db.updates == 1 and out.checked == ["the-right-one"]


# ---- the page --------------------------------------------------------------------------------------

def _code(js):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)


def test_the_page_peeks_on_load_and_redeems_only_on_a_click():
    code = _code((ROOT / "static" / "js" / "note-link.js").read_text(encoding="utf-8"))
    start = code[code.index("function start() {"):code.index("if (document.readyState")]
    assert start.count("redeem(null, true)") == 1 and "redeem(null, false)" not in start
    reveal = code[code.index("function reveal() {"):code.index("function start() {")]
    assert reveal.count("redeem(null, false)") == 1
    assert code.count('$("reveal-btn").addEventListener("click", reveal);') == 1
    # A peek's answer offers the button, and only a redeem's answer (which carries the note) renders it.
    assert 'if (data && data.available === true && !("body" in data)) { offerReveal(); return; }' in code
    html = (ROOT / "static" / "note-link.html").read_text(encoding="utf-8")
    assert re.search(r'<button id="reveal-btn" type="button">Show note</button>', html)
