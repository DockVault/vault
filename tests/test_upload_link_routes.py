"""The upload-link routes (app/api/api_server.py), offline: what each answers before anything is made or sent.

Creating a link makes a drop vault, and that vault is committed before the link's row is written. Every check of
the request therefore comes before the vault: a refusal after it would leave a vault with no link in the owner's
list, counting against their vault cap, on every retry. tests/test_api_upload_links_collect.py proves it on a
running stack.

The page route (GET /receivers/{token}/page) is driven in process in tests/test_link_owner_state.py; the pin here
holds that a protected link's message is returned by the session open, after its secret gate.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

API = Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py"


def _handler(src: str, signature: str) -> str:
    start = src.index(signature)
    nxt = re.search(r"^@app\.[a-z]+\(", src[start:], re.M)
    return src[start:start + nxt.start()] if nxt else src[start:]


def test_the_owner_message_is_checked_before_the_drop_vault_is_made():
    src = API.read_text(encoding="utf-8")
    body = _handler(src, "async def create_receiver(")
    checked = body.index("message = _link_message(payload.message)")
    made = body.index("vault_service.create_vault(")
    assert checked < made, "a message refused after create_vault leaves a vault with no link behind"
    # The row carries the checked value; nothing is checked a second time after the vault exists.
    assert "message=message)" in body and body.count("_link_message(") == 1


def test_the_session_open_returns_the_message_only_past_the_secret_gate():
    src = API.read_text(encoding="utf-8")
    body = _handler(src, "async def open_receiver_upload_session(")
    gate = body.index("verify_password(secret, receiver.password_hash)")
    assert gate < body.index('"message": receiver.message or None'), "the message must come after the code is checked"
    page = _handler(src, "async def receiver_upload_page_info(")
    assert "_receiver_resolve_live(db, receiver)" in page, "a dead owner or a gone drop vault must answer 404"
    assert 'if receiver.secret_kind == "none" else None' in page, "a protected link keeps its message behind the code"
