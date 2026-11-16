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

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import models as m  # noqa: E402
from app.core.authorization import PermissionDeniedError, PermissionService  # noqa: E402
from app.services.vault_service import PREVIEW_NOT_SHARED, require_preview_scope  # noqa: E402

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
    # A file at the vault's root (no folders above it).
    f = m.File(id=uuid.uuid4(), vault_id=v.id, folder_id=None, size_bytes=5, storage_path="x")
    db.add(f)
    db.commit()
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
    """What the preview route asks (the previewable scope, with the sentence it refuses with) and what the count
    of a preview and of a download allow."""
    ps = PermissionService(db)
    ps.stamp_share_scope(reader, v)
    try:
        require_preview_scope(db, reader, v.id, f.id)
        previewable = True
    except PermissionDeniedError as e:
        assert str(e) == PREVIEW_NOT_SHARED
        previewable = False
    previewed, _ = ps.burn_share_preview(reader, v, f, [])
    downloaded, _ = ps.burn_share_download(reader, v, f, [])
    return {"previewable": previewable, "previewed": previewed, "downloaded": downloaded}


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



# --- Folder and file shares, the service's own gate, and claims of more than one kind ---

def _tree(db):
    """A vault with a folder, a subfolder in it holding a file, and a file at the root outside both."""
    owner, reader, v, root = _people(db)
    top = m.Folder(id=uuid.uuid4(), name="top", vault_id=v.id)
    db.add(top)
    db.commit()
    sub = m.Folder(id=uuid.uuid4(), name="sub", vault_id=v.id, parent_folder_id=top.id)
    db.add(sub)
    db.commit()
    deep = m.File(id=uuid.uuid4(), vault_id=v.id, folder_id=sub.id, size_bytes=5, storage_path="y")
    db.add(deep)
    db.commit()
    return owner, reader, v, top, deep, root


def _target(db, owner, reader, v, *, target, view_only, share_preview, folder=None, file=None, max_downloads=None):
    tag = m.ShareTag(name=f"t-{uuid.uuid4().hex[:8]}", view_only_preview=share_preview)
    db.add(tag)
    db.commit()
    s = m.Share(creator_id=owner.id, vault_id=v.id, tag_id=tag.id, target_type=target,
                target_folder_id=folder.id if folder is not None else None,
                target_file_id=file.id if file is not None else None,
                claim_audience="anyone_internal", audience_user_ids=[], audience_department_ids=[],
                expires_at=datetime.utcnow() + timedelta(days=1), view_only=view_only, status="active",
                view_only_preview=share_preview, max_downloads=max_downloads)
    db.add(s)
    db.commit()
    claim = m.ShareClaim(share_id=s.id, user_id=reader.id)
    db.add(claim)
    db.commit()
    return claim


def _previews(db, reader, v, f):
    """Whether the preview route lets `reader` view `f`, and the claims a preview of it spends."""
    from app.services.vault_service import folder_ancestry
    ps = PermissionService(db)
    ps.stamp_share_scope(reader, v)
    try:
        require_preview_scope(db, reader, v.id, f.id)
        allowed = True
    except PermissionDeniedError as e:
        assert str(e) == PREVIEW_NOT_SHARED
        allowed = False
    counted, burned = ps.burn_share_preview(reader, v, f, folder_ancestry(db, v.id, f.folder_id))
    return allowed, counted, burned


@pytest.mark.parametrize("target", ["folder", "file"])
@pytest.mark.parametrize("view_only, share_preview, expected", [
    (True, False, (False, False)),
    (True, True, (True, True)),
    (False, False, (True, True)),
])
def test_a_folder_or_file_share_previews_only_when_its_share_says_so(db, target, view_only, share_preview, expected):
    # The file sits in a subfolder of the shared folder: a folder share reaches it through its ancestry.
    owner, reader, v, top, deep, root = _tree(db)
    _target(db, owner, reader, v, target=target, view_only=view_only, share_preview=share_preview,
            folder=top if target == "folder" else None, file=deep if target == "file" else None)
    allowed, counted, _ = _previews(db, reader, v, deep)
    assert (allowed, counted) == expected
    # A file outside what is shared is not previewable, whatever the switch.
    with pytest.raises(PermissionDeniedError):
        require_preview_scope(db, reader, v.id, root.id)


def test_the_service_itself_refuses_a_preview_the_share_does_not_grant(db):
    from app.services.vault_service import VaultService
    owner, reader, v, top, deep, root = _tree(db)
    _target(db, owner, reader, v, target="vault", view_only=True, share_preview=False)
    service = VaultService(db, PermissionService(db))
    with pytest.raises(PermissionDeniedError) as refused:
        service._resolve_download(root.id, reader, None, allow_share=True, view_only_ok=True)
    assert str(refused.value) == PREVIEW_NOT_SHARED


def test_the_service_lets_a_viewable_view_only_share_preview_and_never_download(db):
    from app.services.vault_service import VaultService
    owner, reader, v, top, deep, root = _tree(db)
    _target(db, owner, reader, v, target="vault", view_only=True, share_preview=True)
    service = VaultService(db, PermissionService(db))
    got, _vault = service._resolve_download(root.id, reader, None, allow_share=True, view_only_ok=True)
    assert got.id == root.id
    with pytest.raises(PermissionDeniedError):
        service._resolve_download(root.id, reader, None, allow_share=True, view_only_ok=False)


def test_claims_of_more_than_one_kind_each_count_for_what_they_allow(db):
    from app.api.api_server import _via_share
    owner, reader, v, top, deep, root = _tree(db)
    # A names-only whole-vault share, and a share of one file that allows downloads.
    whole = _target(db, owner, reader, v, target="vault", view_only=True, share_preview=False, max_downloads=3)
    single = _target(db, owner, reader, v, target="file", view_only=False, share_preview=False, file=root,
                     max_downloads=3)
    allowed, counted, burned = _previews(db, reader, v, root)
    assert (allowed, counted) == (True, True)
    assert [str(c) for c in burned] == [str(single.id)], "the names-only claim spent a preview"
    allowed, counted, burned = _previews(db, reader, v, deep)
    assert (allowed, counted, burned) == (False, False, [])
    assert _via_share(reader, v.id) == {"view_only": False, "preview": True}
    db.refresh(whole)
    assert whole.preview_count == 0


def test_two_folder_shares_one_viewable_and_one_not(db):
    from app.api.api_server import _via_share
    owner, reader, v, top, deep, root = _tree(db)
    other = m.Folder(id=uuid.uuid4(), name="other", vault_id=v.id)
    db.add(other)
    db.commit()
    elsewhere = m.File(id=uuid.uuid4(), vault_id=v.id, folder_id=other.id, size_bytes=5, storage_path="z")
    db.add(elsewhere)
    db.commit()
    _target(db, owner, reader, v, target="folder", view_only=True, share_preview=False, folder=top)
    _target(db, owner, reader, v, target="folder", view_only=True, share_preview=True, folder=other)
    assert _previews(db, reader, v, deep)[:2] == (False, False)
    assert _previews(db, reader, v, elsewhere)[:2] == (True, True)
    assert _via_share(reader, v.id) == {"view_only": True, "preview": True}


def test_names_only_claims_alone_tell_the_web_app_there_is_nothing_to_view(db):
    from app.api.api_server import _via_share
    owner, reader, v, top, deep, root = _tree(db)
    _target(db, owner, reader, v, target="folder", view_only=True, share_preview=False, folder=top)
    PermissionService(db).stamp_share_scope(reader, v)
    assert _via_share(reader, v.id) == {"view_only": True, "preview": False}


# --- The switch a share is made with ---

def _create_share_call():
    import ast
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.AsyncFunctionDef) and n.name == "create_share")
    call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "Share")
    return {k.arg: ast.unparse(k.value) for k in call.keywords}


def test_a_share_copies_its_tags_switch_unless_its_maker_was_told_otherwise():
    # The tag as it is when the share is made, and what the share dialog showed its maker: the share is viewable
    # only when both allow it. A caller that says nothing gets the tag's switch.
    assert _create_share_call()["view_only_preview"] == (
        "bool(tag.view_only_preview) and payload.view_only_preview_shown is not False")
    from app.api.api_server import ShareCreate
    base = {"vault_id": str(uuid.uuid4()), "tag_id": str(uuid.uuid4()), "target_type": "vault",
            "claim_audience": "anyone_internal"}
    assert ShareCreate(**base).view_only_preview_shown is None
    assert ShareCreate(**base, view_only_preview_shown=False).view_only_preview_shown is False
