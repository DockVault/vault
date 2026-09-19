"""The declared attempt token against the token chunk 0 actually carries.

A version-2 zero-knowledge file's 28-byte header travels in the clear at the front of transport
chunk 0, and its last 16 bytes are the attempt token the client also DECLARES when it opens the
session. A client whose two values drifted (a re-mint on resume; two reads) uploads a file that
completes and never opens. The server compares the two and refuses the chunk before publishing it.

The comparison is pure and the header is captured in passing (the body streams to sealed staging and
is never held whole), so both are tested without a request or a database; the route wiring is pinned
on the handler's source. The live behaviour -- a mismatched chunk 0 never lets the upload complete --
is the live lane.
"""
import asyncio
import threading
from pathlib import Path

import pytest

from app.core.upload_attempt_header import (
    HeadPeek, V2_CONTENT_HEADER_BYTES, header_token_mismatch,
)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"

TOKEN = bytes(range(16))
DECLARED = TOKEN.hex()
HEADER = b"DVZ2\x02\x04\x00\x00" + (1048576).to_bytes(4, "big") + TOKEN


def _run(coro):
    # A loop of its own, in a thread of its own: a unit test must not depend on ambient loop state
    # (a browser-driven module earlier in one process leaves a loop running in the main thread).
    out = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            out["v"] = loop.run_until_complete(coro)
        except BaseException as exc:                # noqa: BLE001 - re-raised on the caller
            out["e"] = exc
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join(timeout=30)
    assert not t.is_alive(), "the async body did not finish"
    if "e" in out:
        raise out["e"]
    return out.get("v")


def test_the_header_is_28_bytes_with_the_token_last():
    assert len(HEADER) == V2_CONTENT_HEADER_BYTES == 28
    assert HEADER[12:28] == TOKEN


@pytest.mark.parametrize("head, declared, mismatch", [
    (HEADER, DECLARED, False),                                  # one mint fed both: accepted
    (HEADER + b"frame bytes follow", DECLARED, False),
    (HEADER, (b"\xff" * 16).hex(), True),                       # declared one token, sealed another
    (HEADER[:27] + b"\x00", DECLARED, True),                    # last token byte differs
    (HEADER[:20], DECLARED, True),                              # v2 prefix but a split/short header
    (HEADER[:6], DECLARED, True),
    # The SMALLEST legacy body is a 12-byte nonce + a 16-byte tag = exactly 28, the same number as
    # the v2 header by arithmetic, not coincidence of design: if either the nonce or the tag length
    # ever changes, this row and the 28-byte bar in the module have to be re-examined together.
    (b"\x8a" * 28, DECLARED, False),
    (b"\x8a" * 4096, DECLARED, False),                          # legacy whole-file format: a random nonce
    (b"DVZ2\x02\x01" + b"\x00" * 22, DECLARED, False),          # another v2 purpose (a wrap), not content
    (b"DVZ1\x02\x04" + b"\x00" * 22, DECLARED, False),
    # A declared token needs a chunk 0 of at least 28 bytes WHATEVER it starts with: five bytes
    # cannot even be told from "some other format", and the header would ride in chunk 1 unseen.
    (b"DVZ2\x02", DECLARED, True),
    (b"\x8a" * 5, DECLARED, True),
    (b"\x8a" * 27, DECLARED, True),
    (b"", DECLARED, True),
    (HEADER, None, False),                                      # a Standard session declares no token
    (b"ab", None, False),                                       # ...and may send a chunk 0 of any size
    (HEADER, "", False),
    (HEADER, "not-hex", True),                                  # unparseable declaration: refuse
])
def test_the_comparison(head, declared, mismatch):
    assert header_token_mismatch(head, declared) is mismatch


def test_the_head_is_captured_in_passing_and_the_body_is_untouched():
    async def body(*pieces):
        for p in pieces:
            yield p

    async def drain(pieces):
        peek = HeadPeek(body(*pieces))
        got = [p async for p in peek]
        return got, bytes(peek.head)

    whole = HEADER + b"x" * 100
    # One piece, the header split across pieces, a leading empty piece, and a body shorter than 28.
    for pieces in ([whole], [whole[:5], whole[5:20], whole[20:]], [b"", whole], [whole[:10]]):
        got, head = _run(drain(pieces))
        assert b"".join(got) == b"".join(pieces), "the peek altered the stream"
        assert head == b"".join(pieces)[:28]


def _chunk_handler_src() -> str:
    s = API.read_text(encoding="utf-8")
    start = s.index("async def upload_chunk(")
    body = s[start:s.index("\n@app.", start)]
    return "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))


def test_the_chunk_route_refuses_a_mismatched_chunk_zero_before_publishing_it():
    src = _chunk_handler_src()
    # Only chunk 0 of a session that declared a token is peeked.
    assert src.count("HeadPeek(request.stream()) if (chunk_index == 0 and session.blob_id) else None") == 1
    # The comparison is the declared token against the captured head, exactly once.
    check = "if _peek is not None and header_token_mismatch(bytes(_peek.head), session.blob_id):"
    assert src.count(check) == 1
    # Refused BEFORE the staged chunk is renamed into place, so it is never counted as received and
    # the upload cannot complete on it. (mutation: move the check below the publish -> red; drop the
    # comparison -> red.)
    check_at = src.index(check)
    publish_at = src.index("os.replace(tmp_path, chunk_path)")
    assert check_at < publish_at, "the token check runs after the chunk is published"
    refusal = src[check_at:publish_at]
    assert "tmp_path.unlink()" in refusal and "status_code=409" in refusal
    assert '"code": "upload_attempt_mismatch"' in refusal
