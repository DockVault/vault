"""An upload link's stored copy of its address counts only while it is a copy of the present address, offline.

An upload link's address can be replaced. The replacement clears the stored copy, but a page opened before it
can still send a copy of the old address afterwards. The browser names the address its copy is of (the SHA-256
of the address, which the server keeps as the link's hash); the server keeps the first 16 characters beside the
copy, refuses a copy of an address the link no longer has, and treats a stored copy whose mark is not the
link's own as no copy at all.
"""
import base64
import hashlib
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

BLOB = base64.b64encode(b"DVZ2" + bytes([0x02, 0x06, 0, 0]) + b"\x00" * 140).decode()
OTHER_BLOB = base64.b64encode(b"DVZ2" + bytes([0x02, 0x06, 0, 0]) + b"\x01" * 140).decode()


def _hash(address):
    return hashlib.sha256(address.encode()).hexdigest()


class _Db:
    commits = 0

    def commit(self):
        self.commits += 1


def _link(address="first-address", **over):
    link = dict(token_hash=_hash(address), token_enc=None, token_enc_for=None, revoked=False, paused=False,
                expires_at=datetime.utcnow() + timedelta(days=1), max_uploads=None, upload_count=0)
    link.update(over)
    return SimpleNamespace(**link)


def _store(link, address, blob=BLOB):
    return api._store_receiver_token_copy(_Db(), link, api.LinkTokenCopyBody(token_enc=blob, token_hash=_hash(address)))


def _refused(link, body):
    with pytest.raises(HTTPException) as refused:
        api._store_receiver_token_copy(_Db(), link, body)
    return refused.value


def test_a_copy_of_the_present_address_is_kept_with_its_mark():
    link = _link()
    assert _store(link, "first-address") == {"stored": True}
    assert link.token_enc == BLOB and link.token_enc_for == _hash("first-address")[:16]
    assert api._receiver_copy_is_current(link)
    # Write-once while it is current.
    assert _refused(link, api.LinkTokenCopyBody(token_enc=OTHER_BLOB, token_hash=_hash("first-address"))).status_code == 409
    assert link.token_enc == BLOB


def test_a_copy_that_does_not_name_its_address_is_refused():
    link = _link()
    for token_hash in (None, "", "not-hex-at-all-xyz", "abc"):
        refused = _refused(link, api.LinkTokenCopyBody(token_enc=BLOB, token_hash=token_hash))
        assert refused.status_code == 400 and "address" in refused.detail
    assert link.token_enc is None


def test_a_copy_of_a_replaced_address_is_refused():
    link = _link(address="second-address")
    refused = _refused(link, api.LinkTokenCopyBody(token_enc=BLOB, token_hash=_hash("first-address")))
    assert refused.status_code == 409 and "no longer has" in refused.detail
    assert link.token_enc is None and link.token_enc_for is None


@pytest.mark.parametrize("mark", [None, _hash("first-address")[:16]])
def test_a_stored_copy_of_another_address_counts_as_none_and_gives_way(mark):
    # A copy stored with no mark, or with the mark of an address the link no longer has.
    link = _link(address="second-address", token_enc=OTHER_BLOB, token_enc_for=mark)
    assert not api._receiver_copy_is_current(link)
    assert _store(link, "second-address") == {"stored": True}
    assert link.token_enc == BLOB and api._receiver_copy_is_current(link)


def test_the_read_and_the_listing_go_by_the_mark():
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    def body(name):
        return next(ast.unparse(n) for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)

    assert "_receiver_copy_is_current(r)" in body("get_receiver_token_copy")
    assert "_store_receiver_token_copy(" in body("put_receiver_token_copy")
    assert "'has_token_copy': _receiver_copy_is_current(r)" in body("_receiver_public_dict")
    # Replacing the address clears the copy and its mark together.
    replace = body("replace_receiver_link")
    assert "r.token_enc = None" in replace and "r.token_enc_for = None" in replace
