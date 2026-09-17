"""Server-side contract for the owner-encrypted link re-copy (client-side wrap).

The server stores the re-copy blob OPAQUE: it cannot verify the blob is wrapped to the owner's key
(that needs the private key it never holds), so it enforces only that the blob is a V2 LINK-TOKEN
container within the size cap, and that the write/read is owner-only, interactive, write-once and
live-gated. The client wrap/unwrap round-trip and the live owner/cross-user/no-keypair/rotation cases
are the JS-pin and live-lane tests; here we pin the server shape check and the endpoint wiring.
"""
import base64
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

import _bare_api_env  # noqa: E402
_bare_api_env.set_bare_api_env()

import app.api.api_server as api  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"


def _v2_container(magic=b"DVZ2", ver=0x02, purpose=0x06, ct_len=17):
    body = magic + bytes([ver, purpose, 0x00, 0x00]) + os.urandom(97) + os.urandom(12) + os.urandom(ct_len)
    return base64.b64encode(body).decode()


def test_the_shape_check_accepts_a_well_formed_v2_container():
    assert api._valid_link_token_copy(_v2_container()) is True


def test_the_shape_check_refuses_plaintext_empty_and_oversized_blobs():
    assert api._valid_link_token_copy("just-a-plaintext-token") is False   # not base64 of a container
    assert api._valid_link_token_copy("") is False                          # empty
    assert api._valid_link_token_copy(None) is False
    # A base64 raw-plaintext (valid base64 but no V2 header) is refused.
    assert api._valid_link_token_copy(base64.b64encode(b"raw-token-not-a-container").decode()) is False
    # Oversized (past the size cap) is refused even with a valid header.
    big = base64.b64encode(b"DVZ2" + bytes([0x02, 0x06, 0, 0]) + os.urandom(api._LINK_TOKEN_COPY_MAX + 50)).decode()
    assert api._valid_link_token_copy(big) is False
    # Too short (below epk+nonce+tag+1) is refused.
    assert api._valid_link_token_copy(base64.b64encode(b"DVZ2" + bytes([0x02, 0x06, 0, 0]) + os.urandom(10)).decode()) is False


def test_the_shape_check_refuses_the_wrong_magic_version_or_purpose():
    assert api._valid_link_token_copy(_v2_container(magic=b"XXXX")) is False
    assert api._valid_link_token_copy(_v2_container(ver=0x01)) is False
    assert api._valid_link_token_copy(_v2_container(purpose=0x01)) is False   # a DEK wrap, not a link token


# ---- endpoint wiring (needs the full app + DB; the live lane exercises behaviour) ----
def _src():
    return API.read_text(encoding="utf-8")


def test_the_copy_is_owner_only_interactive_and_404s_for_everyone_else():
    src = _src()
    gate = src[src.index("def _link_owner_or_404("):src.index("def _link_is_live(")]
    assert "is_scoped(current_user)" in gate and '_is_temp_session' in gate   # no temp/scoped session
    assert "model.owner_id == current_user.id" in gate                        # owner-only
    assert gate.count("status_code=404") == 2                                 # temp AND non-owner -> 404 (no oracle)


def test_the_copy_is_write_once_live_gated_and_shape_checked():
    src = _src()
    store = src[src.index("def _store_link_token_copy("):src.index("def _read_link_token_copy(")]
    assert "link.token_enc is not None" in store and "status_code=409" in store  # write-once
    assert "_link_is_live(link)" in store                                        # live only
    assert "_valid_link_token_copy(blob)" in store and "status_code=400" in store  # shape checked


def test_the_read_path_is_liveness_gated_so_a_revoked_link_cannot_be_shown_again():
    # The GET must 404 on a non-live link (revoked / expired / max-uses) even though the blob row
    # still exists, so revoking makes the re-copy unrecoverable. (mutation: drop _link_is_live from
    # _read_link_token_copy -> a revoked link's blob is still returned -> red.)
    src = _src()
    read = src[src.index("def _read_link_token_copy("):src.index("@app.put(\"/note-links/{link_id}/token-copy\")")]
    assert "_link_is_live(link)" in read and "status_code=404" in read


def test_both_link_types_have_write_once_and_read_endpoints():
    src = _src()
    for route in ('@app.put("/note-links/{link_id}/token-copy")',
                  '@app.get("/note-links/{link_id}/token-copy")',
                  '@app.put("/public-links/{link_id}/token-copy")',
                  '@app.get("/public-links/{link_id}/token-copy")'):
        assert route in src, route
    # The read returns the opaque blob (token_enc), never a plaintext token.
    read = src[src.index("def _read_link_token_copy("):src.index("@app.put(\"/note-links/{link_id}/token-copy\")")]
    assert '"token_enc": link.token_enc' in read
    assert '"token":' not in read and "link.token\n" not in read   # never a plaintext token key/field


def test_the_blob_is_never_in_a_listing_and_creation_carries_owner_id_for_aad():
    src = _src()
    for dict_fn in ("def _notelink_public_dict(", "def _publiclink_public_dict("):
        body = src[src.index(dict_fn):src.index("\n\n", src.index(dict_fn) + 200)]
        assert '"token_enc":' not in body      # the owner list never carries the blob VALUE...
        # ...only a presence flag so the UI can show "Show link again" without a dead button.
        assert '"has_token_copy": link.token_enc is not None' in body
    # The create responses carry owner_id so the client can bind AAD = link id || owner id.
    assert src.count('["owner_id"] = str(current_user.id)') == 2
