"""A held credential change is applied once, however many administrators approve it at the same moment,
offline on a real database.

Approving a held reset link mints the link, and minting commits on its own, part-way through the
approval. That released the request's row lock while the request still read "held", so a second approval
waiting on the lock went on to apply the change again: a second link, a second approval record. The
approval now claims the request in one guarded statement before anything is applied.
test_credential_change_rule_live.py races two approvals on a running stack."""
import tempfile
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core.models import AuditLog, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'approve.db'}")
        for model in (User, CredentialChange, AuditLog):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


@pytest.fixture
def applied(monkeypatch):
    """Each application of a change, recorded. It commits part-way, as minting a reset link does."""
    out = []

    def apply(db, kind, target, payload, **_kw):
        out.append((kind, dict(payload)))
        db.commit()
        return {"reset_link": f"https://vault.example.com/?reset=link-{len(out)}", "expires_in_minutes": 30}

    monkeypatch.setattr(api, "_apply_credential_change", apply)
    monkeypatch.setattr(api, "_announce_decided_change", lambda *a, **k: None)
    return out


def _setup(factory):
    s = factory()
    names = ("alice", "bob", "dave")
    admins = [User(username=n, password_hash="x", role=RoleEnum.ADMIN, is_active=True, is_locked=False)
              for n in names]
    carol = User(username="carol", password_hash="x", role=RoleEnum.USER, is_active=True, is_locked=False)
    s.add_all(admins + [carol])
    s.commit()
    held = cc.hold(s, kind=cc.RESET_LINK, target_id=carol.id, requester_id=admins[0].id,
                   requester_name="alice", summary="s", payload={"delivery": "copy"})
    s.commit()
    ids = (held.id, carol.id, admins[1].id, admins[2].id)
    s.close()
    return ids


def test_two_approvals_at_once_apply_the_change_once(factory, applied):
    change_id, carol_id, bob_id, dave_id = _setup(factory)
    first, second = factory(), factory()
    try:
        # Both administrators have read the request while it was held.
        loaded = []
        for s, approver_id in ((first, bob_id), (second, dave_id)):
            loaded.append((s.get(CredentialChange, change_id), s.get(User, carol_id), s.get(User, approver_id)))
        (c1, t1, bob), (c2, t2, dave) = loaded
        assert c1.status == c2.status == cc.HELD

        result = api._approve_credential_change(first, c1, t1, approver=bob)
        assert result["reset_link"].endswith("link-1")
        with pytest.raises(HTTPException) as refused:
            api._approve_credential_change(second, c2, t2, approver=dave)
        assert refused.value.status_code == 409
    finally:
        first.close()
        second.close()

    assert applied == [(cc.RESET_LINK, {"delivery": "copy"})]
    check = factory()
    try:
        row = check.get(CredentialChange, change_id)
        assert (row.status, row.decided_by_name, row.payload) == (cc.APPROVED, "bob", None)
        approvals = check.query(AuditLog).filter(AuditLog.action == "credential_change_approved").all()
        assert len(approvals) == 1
    finally:
        check.close()


def test_a_change_refused_while_applying_leaves_the_request_held(factory, monkeypatch):
    # The host tool's session commits whatever is left when it ends, so a refusal must roll the claim back.
    change_id, carol_id, bob_id, _dave = _setup(factory)

    def refuse(*_a, **_k):
        raise HTTPException(status_code=400, detail="That email address is already in use.")

    monkeypatch.setattr(api, "_apply_credential_change", refuse)
    s = factory()
    try:
        with pytest.raises(HTTPException):
            api._approve_credential_change(s, s.get(CredentialChange, change_id), s.get(User, carol_id),
                                           approver=s.get(User, bob_id))
        s.commit()
        assert s.get(CredentialChange, change_id).status == cc.HELD
    finally:
        s.close()
