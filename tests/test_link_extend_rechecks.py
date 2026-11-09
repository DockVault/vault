"""Moving a link's expiry re-checks what making the link checked, offline on a real database.

Every link extend (public, note, upload) runs the shared check: the feature is on, the link's type (its tag)
is active, and the maker is still an account that may publish links and that the type admits. A link's
ceiling follows its type's maximum as it is now; a share keeps the maximum it was made under.
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

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.models import Group, RoleEnum, User, user_groups  # noqa: E402
from app.core.security import hash_password  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
LINK_ROUTES = {"extend_public_link": "public_file_links_enabled", "extend_note_link": "public_note_links_enabled",
               "extend_receiver": "public_receivers_enabled"}


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'links.db'}")
        copies = sa.MetaData()
        for table in (User.__table__, Group.__table__, user_groups):
            sa.Table(table.name, copies, *[sa.Column(c.name, c.type, primary_key=c.primary_key) for c in table.columns])
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _maker(db, **over):
    user = User(username="mia", email="mia@example.com", password_hash=hash_password("the-account-password-1"),
                role=RoleEnum.USER, is_active=True, is_locked=False)
    for k, v in over.items():
        setattr(user, k, v)
    db.add(user)
    db.commit()
    return user


def _tag(**over):
    tag = dict(is_active=True, blocked_user_ids=[], allowed_user_ids=[], allowed_department_ids=[],
               auto_enroll_new_users=True, max_ttl_hours=72)
    tag.update(over)
    return SimpleNamespace(**tag)


def _refused(db, tag, owner_id, enabled=True):
    with pytest.raises(HTTPException) as refused:
        api._link_type_for_extension(db, tag, "public link", owner_id, enabled)
    return refused.value


def test_a_link_still_makeable_passes(db):
    maker = _maker(db)
    tag = _tag()
    assert api._link_type_for_extension(db, tag, "public link", maker.id, True) is tag


def test_the_feature_switched_off_refuses(db):
    maker = _maker(db)
    refused = _refused(db, _tag(), maker.id, enabled=False)
    assert refused.status_code == 403 and "disabled on this deployment" in refused.detail


def test_a_gone_or_inactive_type_refuses(db):
    maker = _maker(db)
    assert "no longer exists" in _refused(db, None, maker.id).detail
    refused = _refused(db, _tag(is_active=False), maker.id)
    assert refused.status_code == 400 and "inactive" in refused.detail


def test_a_maker_who_may_no_longer_publish_refuses(db):
    locked = _maker(db, is_locked=True, locked_until=None)       # an administrator's lock
    assert "can no longer publish" in _refused(db, _tag(), locked.id).detail
    assert "can no longer publish" in _refused(db, _tag(), uuid.uuid4()).detail   # the account is gone


def test_a_maker_the_type_no_longer_admits_refuses(db):
    maker = _maker(db)
    refused = _refused(db, _tag(blocked_user_ids=[str(maker.id)]), maker.id)
    assert refused.status_code == 400 and "no longer admits" in refused.detail
    refused = _refused(db, _tag(auto_enroll_new_users=False), maker.id)   # nobody named, nobody enrolled
    assert "no longer admits" in refused.detail


def _function(name):
    for node in ast.walk(ast.parse(SOURCE)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(name)


@pytest.mark.parametrize("route,switch", sorted(LINK_ROUTES.items()))
def test_each_link_extend_runs_the_check_with_its_own_switch_and_the_live_tags_ceiling(route, switch):
    body = ast.unparse(_function(route))
    calls = [c for c in ast.walk(_function(route)) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Name) and c.func.id == "_link_type_for_extension"]
    assert len(calls) == 1 and len(calls[0].args) == 5, route
    assert switch in ast.unparse(calls[0].args[4]), route
    # The ceiling is the live tag's maximum, counted from the link's creation.
    assert "hours=tag.max_ttl_hours" in body, route


def test_a_share_keeps_the_maximum_it_was_made_under():
    made = datetime(2026, 1, 1, 12, 0)
    share = SimpleNamespace(created_at=made, expires_at=made + timedelta(days=1),
                            tag_policy_snapshot={"max_lifetime_minutes": 7 * 24 * 60})
    widened = SimpleNamespace(max_lifetime_minutes=90 * 24 * 60)
    assert api._share_ceiling(share, widened) == made + timedelta(days=7)
    assert "_share_ceiling" in {c.func.id for c in ast.walk(_function("extend_share"))
                                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
