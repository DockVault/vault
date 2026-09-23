"""Where every upload door takes, keeps and drops the same-name lock (app/core/upload_marker.py).

SFTP takes it at write-open and drops it at close. The web doors take the same lock: a resumable
upload holds it for as long as its session is live -- opening, each chunk, the commit -- and drops it
when the session ends; a direct upload holds it for the request. The rule itself (who may take over
whom) is pinned in test_upload_marker; the behaviour against a running stack is the live lane
(test_same_name_uploads_live). These pins hold the placement, which is what the rule depends on:
a lock taken before a refusal would outlive a request that never started, and one dropped on a
retryable failure would let another upload in while this one can still land.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_SRC = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
# Comment lines out, so no pin is satisfied by a comment.
API = "\n".join(line for line in _SRC.splitlines() if not line.lstrip().startswith("#"))


def _handler(signature: str) -> str:
    start = API.index(signature)
    return API[start:API.index("\n@app.", start)]


def test_opening_an_upload_takes_the_name_last():
    body = _handler("async def init_chunked_upload(")
    new = body.index("_web_upload_name_lock(db, vault_id, folder_uuid, body.file_name, current_user, _sid)")
    # Every refusal a NEW session can meet comes first, so a refused request leaves no lock behind.
    for refusal in ("open_sessions >= 25", "account_sessions >= 100", 'detail="File id already in use"'):
        assert body.index(refusal) < new, refusal
    assert new < body.index("db.add(session)")
    # A commit that fails leaves no lock in the session's place.
    failed = body[body.index("db.add(session)"):]
    failed = failed[:failed.index("db.refresh(session)")]
    assert "_release_web_upload_name(vault_id, [folder_uuid], body.file_name, _sid)" in failed
    # A CONTINUED session takes its name back after its binding checks.
    cont = body[body.index("    if session is not None:\n        for code, mine, theirs in ("):
                body.index("\n    if session is None:\n        if is_zk:")]
    assert cont.index('"key_epoch_mismatch"') < cont.index(
        "_web_upload_name_lock(db, vault_id, folder_uuid, body.file_name, current_user, session.id)")


def test_each_chunk_keeps_the_name_and_never_refuses_it():
    body = _handler("async def upload_chunk(")
    boundary = body.index("_release_db_before_streaming(db)")
    # The name is copied out with the rest BEFORE the boundary; the Redis round trip happens AFTER
    # it, so no pool connection waits on Redis.
    assert body.index("_filename = session.filename") < boundary
    keep = body[boundary:body.index("seal_stream_to_file(", boundary)]
    assert "_um.claim(vault_id, _folder_id, _filename, _user_id, _web_upload_lock_token(_sid))" in keep
    assert "HTTPException" not in keep and "isinstance" not in keep


def test_the_commit_claims_the_name_and_drops_it_whenever_the_session_ends():
    body = _handler("async def complete_chunked_upload(")
    claim = body.index("_web_upload_name_lock(db, vault_id, folder_uuid, _lock_name, current_user, _lock_session)")
    assert body.index("_reject_unreplaceable_upload(") < claim < body.index("finalize_streaming_upload(")
    assert "_lock_name = session.filename if not is_zk else None" in body
    release = "_release_web_upload_name(vault_id, _lock_folders, _lock_name, _lock_session)"
    # Dropped on success, on a lost replace race, and on both finalize failures ...
    assert body.count(release) == 4
    after_success = body[body.index("db.delete(session)\n    db.commit()"):]
    assert release in after_success
    # ... and NOT on a permission denial, which leaves the session open to be retried.
    denied = body[body.index("except PermissionDeniedError"):]
    denied = denied[:denied.index("except Exception")]
    assert release not in denied


def test_a_cancelled_upload_drops_its_name():
    body = _handler("async def cancel_chunked_upload(")
    cancelled = body[body.index("session.status = 'cancelled'"):]
    assert cancelled.index("db.commit()") < cancelled.index(
        "_release_web_upload_name(vault_id, [_cancelled_folder], _cancelled_name, session.id)")


def test_a_direct_upload_takes_over_nothing_and_always_lets_go():
    body = _handler("async def upload_file(")
    claim = body.index("_um.claim(vault_id, folder_uuid, upload_file.filename, current_user.id,")
    assert "_direct_lock, web=False)" in body[claim:claim + 200]
    assert claim < body.index("_reject_unreplaceable_upload(db, vault_id, folder_uuid, upload_file.filename")
    cleanup = body[body.index("finally:"):]
    assert "if _direct_locked:\n                    _um.remove(vault_id, folder_uuid, upload_file.filename, _direct_lock)" in cleanup


def test_the_listing_hides_only_the_viewers_own_browser_uploads():
    body = API[API.index("_marker_rows = _um.list_folder(vault_id, folder_uuid)"):]
    body = body[:body.index("response_data = {'items': items}")]
    assert 'if _r.get("web") and _r.get("member_id") == str(current_user.id):\n                        continue' in body
