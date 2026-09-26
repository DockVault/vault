"""A locked or deactivated owner's anonymous links stop serving.

Note links, public file links and upload links are used with no login: whoever holds the token uses
it. Each one is published on its owner's behalf, so it must stop the moment an administrator locks or
deactivates that owner, and answer exactly as a missing link does.

Before this, file and upload links compared only the lock's expiry. An administrator's lock has no
expiry, so an admin-locked owner's links kept serving files and accepting uploads. A note link never
looked at its owner at all, so a lock and a deactivation both left it serving the note. All three
now go through one check, _link_owner_if_live, which reads a lock the way sign-in does
(account_locked).

These tests drive the real resolvers and the real note-link redeem handler against a stand-in
database, one owner state at a time. test_link_owner_state_live.py does the same against a running
deployment.
"""
import types
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import rate_limiter as R  # noqa: E402

pytestmark = pytest.mark.unit


class _Query:
    def __init__(self, result):
        self._result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _FakeDB:
    """Answers db.query(Model)...first() from a {Model: row} map. Writes are accepted and dropped,
    so the audit rows the handlers write (best-effort) cost nothing here."""

    def __init__(self, rows):
        self.rows = rows

    def query(self, model, *more):
        return _Query(self.rows.get(model))

    def execute(self, *args, **kwargs):
        return types.SimpleNamespace(rowcount=1)

    def add(self, obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


def _owner(**state):
    fields = dict(id=uuid.uuid4(), is_active=True, is_locked=False, locked_until=None)
    fields.update(state)
    return types.SimpleNamespace(**fields)


# name -> (owner fields, may the owner's links serve?)
OWNER_STATES = {
    "active": ({}, True),
    "admin_locked": ({"is_locked": True, "locked_until": None}, False),
    "login_locked": ({"is_locked": True, "locked_until": datetime.utcnow() + timedelta(hours=1)}, False),
    "login_lock_expired": ({"is_locked": True,
                            "locked_until": datetime.utcnow() - timedelta(minutes=1)}, True),
    "deactivated": ({"is_active": False}, False),
}


@pytest.mark.parametrize("state", sorted(OWNER_STATES))
def test_the_owner_check_reads_a_lock_the_way_sign_in_does(state):
    fields, serves = OWNER_STATES[state]
    owner = _owner(**fields)
    got = S._link_owner_if_live(_FakeDB({S.User: owner}), owner.id)
    assert (got is owner) if serves else (got is None), state


def test_a_missing_owner_is_not_live():
    assert S._link_owner_if_live(_FakeDB({}), uuid.uuid4()) is None


@pytest.mark.parametrize("state", sorted(OWNER_STATES))
def test_an_upload_link_follows_its_owner(state):
    fields, serves = OWNER_STATES[state]
    owner = _owner(**fields)
    vault = types.SimpleNamespace(id=uuid.uuid4(), type="standard")
    receiver = types.SimpleNamespace(vault_id=vault.id, owner_id=owner.id)
    got = S._receiver_resolve_live(_FakeDB({S.Vault: vault, S.User: owner}), receiver)
    assert (got == (vault, owner)) if serves else (got is None), state


@pytest.mark.parametrize("state", sorted(OWNER_STATES))
def test_a_file_link_follows_its_owner(state, monkeypatch):
    class _Allowed:
        def __init__(self, db):
            pass

        def can_access_vault(self, *args, **kwargs):
            return True

    # The owner still reads the vault in every state, so only the owner's account decides.
    monkeypatch.setattr(S, "PermissionService", _Allowed)
    fields, serves = OWNER_STATES[state]
    owner = _owner(**fields)
    vault = types.SimpleNamespace(id=uuid.uuid4(), type="standard", password_hash=None)
    link = types.SimpleNamespace(vault_id=vault.id, owner_id=owner.id)
    got = S._publiclink_resolve_live(_FakeDB({S.Vault: vault, S.User: owner}), link)
    assert (got == (vault, owner)) if serves else (got is None), state


@pytest.fixture
def note_redeem(monkeypatch):
    """Call the real redeem handler with the rate limiter and the feature switch out of the way."""
    monkeypatch.setattr(R.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.10")
    monkeypatch.setattr(S.note_link_policy, "public_note_links_enabled", lambda blob: True)

    def redeem(owner, secret_kind="none"):
        token = "tok-" + uuid.uuid4().hex
        link = types.SimpleNamespace(
            id=uuid.uuid4(), token_hash=S._notelink_token_hash(token), owner_id=owner.id,
            revoked=False, expires_at=None, max_uses=None, use_count=0, secret_kind=secret_kind,
            password_hash=None, title_snapshot="T", body_snapshot="the note")
        db = _FakeDB({S.NoteLink: link, S.User: owner})
        return run_coroutine(S.redeem_note_link(token, S.NoteLinkRedeem(), None, db))

    return redeem


@pytest.mark.parametrize("state", sorted(OWNER_STATES))
def test_a_note_link_follows_its_owner(state, note_redeem):
    fields, serves = OWNER_STATES[state]
    owner = _owner(**fields)
    if serves:
        assert note_redeem(owner)["body"] == "the note"
        return
    with pytest.raises(HTTPException) as refused:
        note_redeem(owner)
    assert refused.value.status_code == 404
    assert refused.value.detail == "This link is not available.", "must read exactly as a missing link"


def test_a_protected_note_link_of_a_locked_owner_does_not_ask_for_its_secret(note_redeem):
    """Checked before the secret prompt. A 401 asking for the PIN would tell a token holder that
    the link is still alive; a missing link never asks."""
    with pytest.raises(HTTPException) as refused:
        note_redeem(_owner(is_locked=True, locked_until=None), secret_kind="pin")
    assert refused.value.status_code == 404
