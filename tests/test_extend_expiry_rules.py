"""The rules behind moving an expiry later (the four extend routes), offline.

Every route goes through one shared check, and that check asks for the account's second factor when the new
expiry is more than a week away; an administrator who extends someone else's thing gets back the id, the
expiry and the ceiling and nothing of the thing's content; a thing that never expires has nothing to extend.
"""
import ast
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import otp_service  # noqa: E402
from app.core import second_factor as sf  # noqa: E402
from app.core.models import (AuditLog, OtpCode, RoleEnum, SecondFactorAction, SecondFactorEnrollment,  # noqa: E402
                             SecondFactorRecoveryCode, User)
from app.core.security import encrypt_secret, hash_password  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
EXTEND_ROUTES = ("extend_share", "extend_public_link", "extend_note_link", "extend_receiver")


def _function(name):
    for node in ast.walk(ast.parse(SOURCE)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"no function {name}")


def _calls(node):
    out = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            f = call.func
            out.add(f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None))
    return out


def _keyword_values(node, func_name, keyword):
    """The source of ``keyword=`` in every call of ``func_name`` inside ``node``."""
    values = []
    for call in ast.walk(node):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == func_name:
            for kw in call.keywords:
                if kw.arg == keyword:
                    values.append(ast.unparse(kw.value))
    return values


def test_every_extend_route_goes_through_the_shared_check_which_asks_for_the_factor():
    for name in EXTEND_ROUTES:
        node = _function(name)
        assert any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "post"
                   for d in node.decorator_list), f"{name} is not a POST route"
        assert "_extend_expiry" in _calls(node), f"{name} does not use the shared check"
    assert "_extend_long_step_up" in _calls(_function("_extend_expiry"))


def test_every_extend_route_answers_through_the_helper_that_withholds_content_from_others():
    for name in EXTEND_ROUTES:
        node = _function(name)
        assert "_extend_answer" in _calls(node), f"{name} builds its own answer"
        assert _keyword_values(node, "_extend_answer", "by_owner") == ["by_owner"], name
        # The maker's view is only built for the maker; anyone else gets an empty dict to start from.
        body = ast.unparse(node)
        assert "if by_owner else {}" in body, name


def test_an_administrators_answer_carries_only_the_id_the_expiry_and_the_ceiling():
    item = SimpleNamespace(id=uuid.uuid4(), expires_at=datetime(2026, 11, 20, 10, 0))
    full = {"id": str(item.id), "title": "salary review", "body": "the private note", "expires_at": "x"}
    theirs = api._extend_answer(full, item=item, ceiling=datetime(2026, 11, 30), by_owner=False)
    assert theirs == {"id": str(item.id), "expires_at": "2026-11-20T10:00:00", "ceiling": "2026-11-30T00:00:00Z"}
    mine = api._extend_answer(full, item=item, ceiling=None, by_owner=True)
    assert mine["body"] == "the private note" and mine["ceiling"] is None


# ---------------------------------------------------------------------------- the check, on a database

@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(otp_service, "_resolve_redis", lambda redis: None)
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: request.headers.get("x-test-session"))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'extend.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, OtpCode, SecondFactorAction, SecondFactorEnrollment, SecondFactorRecoveryCode):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role=RoleEnum.USER):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=role, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _enroll_totp(db, user):
    db.add(SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc=encrypt_secret(sf.generate_totp_secret()),
                                  status="active", last_used_step=0))
    db.commit()


def _request():
    return Request({"type": "http", "method": "POST", "path": "/extend", "headers": [(b"x-test-session", b"s-1")],
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def _extend(db, user, item, new, ceiling=None):
    body = api.ExtendExpiryBody(expires_at=new.replace(microsecond=0).isoformat() + "Z")
    return api._extend_expiry(db, _request(), user, item=item, kind="share", id_key="share_id",
                              owner_id=user.id, body=body, ceiling=ceiling)


def _item(hours_from_now=24):
    return SimpleNamespace(id=uuid.uuid4(), expires_at=datetime.utcnow() + timedelta(hours=hours_from_now))


def test_a_long_extension_asks_an_enrolled_account_for_its_factor_and_a_short_one_does_not(db):
    maker = _user(db, "maker")
    _enroll_totp(db, maker)
    with pytest.raises(HTTPException) as refused:
        _extend(db, maker, _item(), datetime.utcnow() + timedelta(days=10))
    assert refused.value.status_code == 403
    assert "step_up_required" in str(refused.value.detail)
    item = _item()
    details = _extend(db, maker, item, datetime.utcnow() + timedelta(days=3))
    assert item.expires_at > datetime.utcnow() + timedelta(days=2, hours=23)
    assert details["by_admin"] is False and details["previous_expiry"].endswith("Z")


def test_an_account_with_no_second_factor_extends_far_without_being_asked(db):
    maker = _user(db, "plain")
    item = _item()
    _extend(db, maker, item, datetime.utcnow() + timedelta(days=10))
    assert item.expires_at > datetime.utcnow() + timedelta(days=9)


def test_a_thing_that_never_expires_has_nothing_to_extend(db):
    maker = _user(db, "forever")
    item = SimpleNamespace(id=uuid.uuid4(), expires_at=None)
    with pytest.raises(HTTPException) as refused:
        _extend(db, maker, item, datetime.utcnow() + timedelta(days=1))
    assert refused.value.status_code == 400 and "never expires" in refused.value.detail
    assert item.expires_at is None


def test_the_ceiling_is_named_in_words_a_person_can_read(db):
    assert api._readable_utc(datetime(2026, 11, 16, 1, 44)) == "16 Nov 2026, 01:44 UTC"
    assert api._readable_utc(datetime(2026, 11, 6, 23, 5)) == "6 Nov 2026, 23:05 UTC"
    maker = _user(db, "capped")
    ceiling = (datetime.utcnow() + timedelta(hours=30)).replace(microsecond=0)
    with pytest.raises(HTTPException) as refused:
        _extend(db, maker, _item(), datetime.utcnow() + timedelta(days=3), ceiling=ceiling)
    assert refused.value.status_code == 400 and api._readable_utc(ceiling) in refused.value.detail
    assert "T0" not in refused.value.detail and "T1" not in refused.value.detail and "T2" not in refused.value.detail   # no raw timestamp
