"""The upload-link routes (app/api/api_server.py), offline: what each answers before anything is made or sent.

Creating a link makes a drop vault, and that vault is committed before the link's row is written. Every check of
the request therefore comes before the vault: a refusal after it would leave a vault with no link in the owner's
list, counting against their vault cap, on every retry. tests/test_api_upload_links_collect.py proves it on a
running stack.
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
