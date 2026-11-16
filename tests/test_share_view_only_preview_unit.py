"""Whether a view-only share lets its recipient view files in the browser, offline on a real (SQLite) database.

A share copies its tag's switch (view_only_preview) when it is made. A view-only claim lets its recipient view a
file in the browser only when the share's own copy says so: the previewable scope stamped on the recipient
(app/core/authorization.py stamp_share_scope) and the preview's count (burn_share_preview) both read the share,
never the tag as it is now. A claim that allows downloads previews whatever the switch says, and no view-only
claim downloads. Every share made before the switch existed reads off: its maker was told a view-only recipient
cannot open the files. A tag made through the API has the switch on unless the request says otherwise, and so do
the tags seeded on a fresh install. tests/test_api_share_view_only_preview.py runs the same through the API.
"""
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import models as m  # noqa: E402
from app.core.authorization import PermissionService  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _people(db):
    owner = m.User(username="olga", email="olga@example.test", password_hash="x", role=m.RoleEnum.USER,
                   is_active=True, is_locked=False)
    reader = m.User(username="ravi", email="ravi@example.test", password_hash="x", role=m.RoleEnum.USER,
                    is_active=True, is_locked=False)
    db.add_all([owner, reader])
    db.commit()
    v = m.Vault(id=uuid.uuid4(), name="v", owner_id=owner.id, type="standard", file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    # The count of a preview reads only the file's id (and its folders, none here: the vault's root).
    f = SimpleNamespace(id=uuid.uuid4())
    return owner, reader, v, f


def _shared(db, owner, reader, v, *, view_only, tag_preview, share_preview=None, max_downloads=None):
    """A whole-vault share claimed by `reader`, under a tag whose switch is `tag_preview`. The share copies the
    switch as create_share does, unless `share_preview` says otherwise (None: the column's own default, as a
    share made before the switch existed reads)."""
    tag = m.ShareTag(name=f"t-{uuid.uuid4().hex[:8]}", view_only_preview=tag_preview)
    db.add(tag)
    db.commit()
    fields = dict(creator_id=owner.id, vault_id=v.id, tag_id=tag.id, target_type="vault",
                  claim_audience="anyone_internal", audience_user_ids=[], audience_department_ids=[],
                  expires_at=datetime.utcnow() + timedelta(days=1), view_only=view_only, status="active",
                  max_downloads=max_downloads)
    if share_preview is not None:
        fields["view_only_preview"] = share_preview
    s = m.Share(**fields)
    db.add(s)
    db.commit()
    db.add(m.ShareClaim(share_id=s.id, user_id=reader.id))
    db.commit()
    return tag, s


def _what_it_may_do(db, reader, v, f):
    ps = PermissionService(db)
    ps.stamp_share_scope(reader, v)
    preview_scope = reader._share_preview_scope[str(v.id)]
    previewed, _ = ps.burn_share_preview(reader, v, f, [])
    downloaded, _ = ps.burn_share_download(reader, v, f, [])
    return {"previewable": preview_scope is None or bool(preview_scope.get("files") or preview_scope.get("folders")),
            "previewed": previewed, "downloaded": downloaded}


@pytest.mark.parametrize("view_only, tag_preview, share_preview, expected", [
    # A view-only share made before the switch existed (the column's default): names and sizes only.
    (True, False, None, {"previewable": False, "previewed": False, "downloaded": False}),
    # A view-only share made under a tag with the switch off.
    (True, False, False, {"previewable": False, "previewed": False, "downloaded": False}),
    # A view-only share made under a tag with the switch on: viewed in the browser, never downloaded.
    (True, True, True, {"previewable": True, "previewed": True, "downloaded": False}),
    # A share that allows downloads previews whatever the switch says.
    (False, False, False, {"previewable": True, "previewed": True, "downloaded": True}),
    (False, False, None, {"previewable": True, "previewed": True, "downloaded": True}),
])
def test_a_view_only_claim_previews_only_when_its_share_says_so(db, view_only, tag_preview, share_preview,
                                                                 expected):
    owner, reader, v, f = _people(db)
    _shared(db, owner, reader, v, view_only=view_only, tag_preview=tag_preview, share_preview=share_preview)
    assert _what_it_may_do(db, reader, v, f) == expected


def test_switching_the_tag_on_later_does_not_open_a_share_made_before(db):
    # The share was made with the switch off; the tag is switched on since. The share keeps what it was made with.
    owner, reader, v, f = _people(db)
    tag, _ = _shared(db, owner, reader, v, view_only=True, tag_preview=False, share_preview=False)
    tag.view_only_preview = True
    db.commit()
    assert _what_it_may_do(db, reader, v, f) == {"previewable": False, "previewed": False, "downloaded": False}


def test_switching_the_tag_off_later_does_not_close_a_share_made_before(db):
    owner, reader, v, f = _people(db)
    tag, _ = _shared(db, owner, reader, v, view_only=True, tag_preview=True, share_preview=True)
    tag.view_only_preview = False
    db.commit()
    assert _what_it_may_do(db, reader, v, f) == {"previewable": True, "previewed": True, "downloaded": False}


def test_a_limited_view_only_share_that_does_not_preview_spends_nothing(db):
    owner, reader, v, f = _people(db)
    _, s = _shared(db, owner, reader, v, view_only=True, tag_preview=False, share_preview=False, max_downloads=3)
    _what_it_may_do(db, reader, v, f)
    claim = db.query(m.ShareClaim).filter(m.ShareClaim.share_id == s.id).one()
    db.refresh(claim)
    assert (claim.preview_count, claim.download_count) == (0, 0)


def test_a_new_tag_lets_view_only_recipients_view_files_unless_told_otherwise():
    from app.api.api_server import ShareTagCreate, ShareTagUpdate
    assert ShareTagCreate(name="a").view_only_preview is True
    assert ShareTagCreate(name="a", view_only_preview=False).view_only_preview is False
    # An update changes it only when given.
    assert "view_only_preview" not in ShareTagUpdate(name="a").model_dump(exclude_unset=True)


def test_the_columns_default_off_for_what_existed_before():
    # The model's own default, and the database default an upgrade gives every existing row.
    for table in (m.ShareTag.__table__, m.Share.__table__):
        col = table.c.view_only_preview
        assert col.nullable is False
        assert col.default.arg is False
        assert str(col.server_default.arg) == "false"


def test_the_tags_seeded_on_a_fresh_install_let_view_only_recipients_view_files():
    from app.api.api_server import _DEFAULT_SHARE_TAGS
    by_name = {t["name"]: t for t in _DEFAULT_SHARE_TAGS}
    assert by_name["Confidential (Read)"]["view_only_preview"] is True
    assert all(t.get("view_only_preview") is True for t in _DEFAULT_SHARE_TAGS)


def test_the_upgrade_adds_both_columns_off():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert "ALTER TABLE share_tags ADD COLUMN IF NOT EXISTS view_only_preview BOOLEAN NOT NULL DEFAULT FALSE" in src
    assert "ALTER TABLE shares ADD COLUMN IF NOT EXISTS view_only_preview BOOLEAN NOT NULL DEFAULT FALSE" in src
