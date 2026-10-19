"""A brand image upload removes the slot's old image only after the new one is written and named.

The upload used to delete the slot's old image first and write the new one after, so a write that
failed (a full or read-only disk) left the setting pointing at an image that was gone: the login
screen and the header showed a broken image until someone uploaded again. Now the new image is
written and synced, the setting is pointed at it, and only then is the old one removed; a write or a
save that fails leaves the old image in place and still shown, and leaves nothing of the new one.

The real upload handler runs here against a directory of its own and a stand-in for the setting's
store. tests/test_brand_assets.py has the live half.
"""
import base64
import os
import types

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import durable_write  # noqa: E402

pytestmark = pytest.mark.unit

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC")
GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
OLD = "logo.0ldimage.png"


class _Upload:
    def __init__(self, data):
        self._data = data

    async def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]


class _DB:
    def __init__(self, fail_commit=False):
        self.fail_commit, self.committed, self.rolled_back = fail_commit, False, False

    def commit(self):
        if self.fail_commit:
            raise RuntimeError("the database went away")
        self.committed = True

    def rollback(self):
        self.rolled_back = True


@pytest.fixture
def brand(tmp_path, monkeypatch):
    folder = tmp_path / "brand"
    folder.mkdir()
    (folder / OLD).write_bytes(b"the old image")
    monkeypatch.setattr(S, "BRAND_ASSET_DIR", str(folder))
    setting = {"logo_url": f"/brand-assets/{OLD}"}
    seen = types.SimpleNamespace(at_update=None, set_map=None)

    def update(db, set_map=None, remove_keys=None):
        # What is on the disk when the setting is pointed at the new image.
        seen.at_update = sorted(os.listdir(folder))
        seen.set_map = set_map

    monkeypatch.setattr(S, "_update_brand_row", update)
    # raising=False: a handler that never reads the setting before it writes (as it was) still runs here.
    monkeypatch.setattr(S, "load_brand_overrides", lambda db: dict(setting), raising=False)

    class _Audit:
        def __init__(self, db):
            pass

        def log_action(self, **row):
            pass

    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.10")

    def upload(data, db=None):
        db = db or _DB()
        out = types.SimpleNamespace(db=db, result=None, error=None)
        try:
            out.result = run_coroutine(S.upload_brand_asset("logo", None, _Upload(data), object(), db))
        except Exception as exc:  # noqa: BLE001 -- the test reads what was raised
            out.error = exc
        out.files = sorted(os.listdir(folder))
        return out

    return types.SimpleNamespace(folder=folder, upload=upload, seen=seen, setting=setting)


def _name(data, ext):
    import hashlib
    return f"logo.{hashlib.sha256(data).hexdigest()[:8]}.{ext}"


def test_the_new_image_is_written_and_named_before_the_old_one_goes(brand):
    out = brand.upload(PNG)
    new = _name(PNG, "png")
    assert out.error is None and out.result["url"] == f"/brand-assets/{new}"
    # When the setting was pointed at the new image, both were on the disk.
    assert brand.seen.at_update == sorted([OLD, new])
    assert brand.seen.set_map == {"logo_url": f"/brand-assets/{new}", "logo_dark_url": f"/brand-assets/{new}",
                                  "logo_small_url": f"/brand-assets/{new}"}
    assert out.db.committed
    # After the save, only the new one is left, with exactly the bytes uploaded.
    assert out.files == [new]
    assert (brand.folder / new).read_bytes() == PNG


@pytest.mark.parametrize("where", ["open", "sync_file", "replace", "sync_directory"])
def test_a_write_that_fails_leaves_the_old_image_in_place(brand, monkeypatch, where):
    def fail(*args, **kwargs):
        raise OSError(28, "No space left on device")

    if where == "open":
        real_open = open

        def failing_open(path, mode="r", *args, **kwargs):
            if "w" in mode:
                raise OSError(28, "No space left on device")
            return real_open(path, mode, *args, **kwargs)
        monkeypatch.setattr("builtins.open", failing_open)
    elif where == "replace":
        monkeypatch.setattr(S.os, "replace", fail)
    else:
        monkeypatch.setattr(durable_write, where, fail)
    out = brand.upload(GIF)
    assert isinstance(out.error, HTTPException) and out.error.status_code == 503, out.error
    assert brand.seen.at_update is None, "the setting was changed for an image that was never written"
    assert not out.db.committed
    assert (brand.folder / OLD).read_bytes() == b"the old image"
    # Nothing of the new image is left behind, neither its temporary file nor its name.
    assert out.files == [OLD], out.files


def test_a_save_that_fails_leaves_the_old_image_and_drops_the_new_one(brand):
    out = brand.upload(GIF, db=_DB(fail_commit=True))
    assert isinstance(out.error, RuntimeError)
    assert out.db.rolled_back
    assert out.files == [OLD], "the old image must stay, and the new one no setting names must go"


def test_uploading_the_image_already_shown_keeps_it(brand):
    first = brand.upload(PNG)
    assert first.files == [_name(PNG, "png")]
    brand.setting["logo_url"] = first.result["url"]
    again = brand.upload(PNG, db=_DB(fail_commit=True))
    assert isinstance(again.error, RuntimeError)
    assert again.files == [_name(PNG, "png")], "a failed save removed the image the setting still names"
