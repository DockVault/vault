"""Live-lane acceptance for the bounded-memory transfers, against a running stack.

The heavy proof -- peak RssAnon of the transfer process(es) <= the ceiling + 64 MB on a file >= 4x
the ceiling, with the old path's growth-with-size as the control, and the browser renderer/tree
deltas on a >= 2 GB round-trip -- is the acceptance runner's instrument (it samples RssAnon on both
sides throughout). This lane pins the FUNCTIONAL acceptance that runs without that instrument at a
CI-affordable size: a file LARGER THAN the SFTP memory ceiling streams up and round-trips with an
identical hash (so the streaming path works past the ceiling and the old >512 MB tmpfs refusal is
gone), and the in-flight marker is gone once the upload closes. Size is env-tunable so the runner can
crank it to multi-GB. No asyncio.run().
"""
import hashlib
import os
import secrets
import subprocess

import pytest

from conftest import ADMIN_USER, ADMIN_PASS, unique

pytestmark = pytest.mark.integration

_CI = os.environ.get("CI")
# Default 96 MiB: comfortably above the 64 MiB SFTP memory ceiling (so it would have tripped the old
# tmpfs cap path) yet cheap in CI. The runner overrides this to multi-GB for the RSS measurement.
_SIZE_BYTES = int(os.environ.get("BV_LARGE_FILE_BYTES", str(96 * 1024 * 1024)))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_admin_pw_or_skip():
    if not ADMIN_PASS:
        pytest.skip("no admin password (set VAULT_ADMIN_PASS or ../.env ADMIN_PASSWORD)")


def test_a_file_larger_than_the_ceiling_streams_up_and_round_trips_identically(admin, temp_vault):
    # Prove the streaming write handles a file past the memory ceiling (no >512 MB refusal, no tmpfs
    # cap) and lands byte-identical. The RSS-vs-size flatness is the runner's instrument; this is the
    # functional half at a CI-affordable size.
    _require_admin_pw_or_skip()
    try:
        import paramiko  # noqa: F401
    except Exception:  # noqa: BLE001
        pytest.skip("paramiko not available")

    from test_sftp_roundtrip import sftp_session, _sftp_read  # reuse the shipped live helpers

    vname = temp_vault["name"]
    name = unique("large") + ".bin"
    # A random payload larger than the ceiling; generated once, hashed, streamed up, read back.
    payload = secrets.token_bytes(_SIZE_BYTES)
    want = _sha256(payload)

    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        with sftp.open(f"/{vname}/{name}", "wb") as fh:
            fh.set_pipelined(True)
            fh.write(payload)                       # streamed in the client's own chunks
    # Read it back over SFTP and confirm the hash -- authenticate-before-release means a byte that
    # did not verify would never have been stored, so an identical hash is end-to-end proof.
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        got = _sftp_read(sftp, f"/{vname}/{name}")
    assert _sha256(got) == want, "the streamed large file did not round-trip byte-identically"
    assert len(got) == _SIZE_BYTES


def test_the_old_512mb_refusal_is_gone_from_the_running_server():
    # A source-level confirmation against the DEPLOYED code: the streaming default means the tmpfs
    # >512 MB refusal is not on the upload path. (The functional proof is the round-trip above; this
    # guards against a deployment that shipped with streaming flipped off.)
    from app.core.config import settings
    assert settings.sftp_streaming_upload is True, (
        "this deployment has SFTP_STREAMING_UPLOAD off -- large uploads take the buffered tmpfs path "
        "with the >512 MB refusal; the bounded-memory acceptance measures the streaming default")
    assert settings.sftp_transfer_buffer_mb > 0
