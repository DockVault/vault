"""`StreamingUploadContext` and the terminal: the write half, offline.

The terminal is what makes a truncated file detectable, and the entire mechanism that emits it —
the clean-exit gate, the `hasattr` probe for codecs that have no terminal, the `try/finally` around
the write, and the re-raise — rested on a single integration test. A review showed that test
catches a missing terminal only as a download failure, never reaching its on-disk assertion, and
that renaming `terminal()` silently stops every Standard upload being terminated while the offline
suite stays green.

None of this needs a container. The context manager takes a path and a codec.
"""

import io
import os
import uuid

import pytest


pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _runtime_secrets():
    """The codec reads the deployment secret; the rest is bootstrap. Undone in teardown."""
    import base64
    import secrets as _secrets

    previous = {k: os.environ.get(k) for k in
                ("ENCRYPTION_KEY", "DATABASE_URL", "JWT_SECRET_KEY")}
    os.environ.setdefault("ENCRYPTION_KEY",
                          base64.urlsafe_b64encode(os.urandom(32)).decode())
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost/db")
    os.environ.setdefault("JWT_SECRET_KEY", _secrets.token_hex(32))
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                     # noqa: BLE001 - teardown must never fail the suite
        pass


@pytest.fixture
def parts():
    from app.core import security
    from app.services.streaming_upload import StreamingUploadContext
    return security, StreamingUploadContext, uuid.uuid4(), uuid.uuid4()


def test_a_clean_upload_produces_a_file_the_reader_accepts(parts, tmp_path):
    """End to end through the context manager, with the real codec and a real file."""
    security, Context, vault_id, file_id = parts
    path = tmp_path / "blob.bin"
    codec = security.GcmChunkStreamCodecV2(vault_id, file_id)

    with Context(file_id, path, codec) as ctx:
        ctx.write_chunk(b"first ")
        ctx.write_chunk(b"second")

    with open(path, "rb") as f:
        assert security.decrypt_gcm_chunk_stream(f, vault_id, file_id) == b"first second"


def test_a_failed_upload_is_not_terminated_and_leaves_nothing(parts, tmp_path):
    """A terminal asserts "this file is complete".

    Writing one over a partial upload would convert a detectable truncation into an object that
    authenticates as whole — the exact property this format exists to provide, inverted. The file
    is removed as well, but the ordering matters more than the removal, because the removal is
    best effort.
    """
    security, Context, vault_id, file_id = parts
    path = tmp_path / "doomed.bin"
    codec = security.GcmChunkStreamCodecV2(vault_id, file_id)

    with pytest.raises(RuntimeError):
        with Context(file_id, path, codec) as ctx:
            ctx.write_chunk(b"partial")
            raise RuntimeError("the upload failed")

    assert not path.exists(), "a failed upload left its blob behind"


def test_a_failed_upload_that_survives_cleanup_is_still_unreadable(parts, tmp_path):
    """Belt and braces, because the cleanup is best effort and can itself fail.

    Written by hand rather than through the context manager, so it models the file the cleanup
    failed to remove: records, no terminal.
    """
    security, _Context, vault_id, file_id = parts
    codec = security.GcmChunkStreamCodecV2(vault_id, file_id)
    orphan = codec.header() + codec.encrypt(b"partial", 0)
    with pytest.raises(security.EncryptionError, match="without a terminal"):
        security.decrypt_gcm_chunk_stream(io.BytesIO(orphan), vault_id, file_id)


def test_a_codec_with_no_terminal_writes_nothing_extra(parts, tmp_path):
    """Zero-knowledge vaults store the client's ciphertext verbatim.

    Their codec has no `terminal`, and the context manager probes for one with `hasattr`. That
    probe is also the silent-failure shape below, so both directions are pinned.
    """
    security, Context, _vault_id, _file_id = parts
    path = tmp_path / "zk.bin"

    with Context(uuid.uuid4(), path, security.IdentityChunkCodec()) as ctx:
        ctx.write_chunk(b"opaque ciphertext")

    assert path.read_bytes() == b"opaque ciphertext", "the passthrough codec gained a header"


def test_a_codec_whose_terminal_fails_re_raises_and_cleans_up(parts, tmp_path):
    """Out of disk on the last write.

    The failure happens when `exc_type` is still None, so without handling this the handle leaks,
    the cleanup branch never fires, and the error escapes before the close. The blob is unreadable
    either way — no terminal — but leaking a descriptor and a file is a poor way to say so.
    """
    security, Context, vault_id, file_id = parts
    path = tmp_path / "nospace.bin"

    class _Failing(security.GcmChunkStreamCodecV2):
        def terminal(self):
            raise OSError(28, "No space left on device")

    with pytest.raises(OSError):
        with Context(file_id, path, _Failing(vault_id, file_id)) as ctx:
            ctx.write_chunk(b"content")

    assert not path.exists(), "a failed terminal write left its blob behind"


def test_the_writer_is_reached_through_the_upload_service(parts):
    """The `hasattr` probe is a silent-failure shape, so name the coupling it depends on.

    Rename `terminal()` and every Standard upload quietly stops being terminated: the probe simply
    finds nothing, no error is raised, and only a download much later says otherwise. The
    integration test catches it as a 500; this catches it as what it is.
    """
    security, Context, _v, _f = parts
    assert hasattr(security.GcmChunkStreamCodecV2, "terminal"), (
        "the terminated codec has no `terminal` method, so the upload path's hasattr probe will "
        "skip it and every Standard file will be written unterminated")
    assert not hasattr(security.IdentityChunkCodec, "terminal")
    assert not hasattr(security.GcmChunkStreamCodec, "terminal"), (
        "the older codec must not grow a terminal; its files are read by the v1 path")


def test_no_terminal_is_written_on_the_error_path_even_if_cleanup_fails(parts, tmp_path,
                                                                        monkeypatch):
    """The ordering, isolated from the cleanup that usually hides it.

    Writing the terminal on the error path looks harmless because the file is unlinked immediately
    afterwards — a mutation doing exactly that passed every other test here. It is only harmless
    while the unlink succeeds, and the unlink is best effort: a locked or read-only file leaves the
    blob behind. Terminated, it would then read back as a complete, authentic, TRUNCATED file,
    which is precisely the outcome this format exists to make impossible.

    So the property is the ordering, not the cleanup, and it needs the cleanup taken away to be
    visible at all.
    """
    security, Context, vault_id, file_id = parts
    path = tmp_path / "survivor.bin"

    import pathlib
    real_unlink = pathlib.Path.unlink

    def _refuse(self, *a, **kw):
        if self == path:
            raise PermissionError("cleanup cannot remove this file")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "unlink", _refuse)

    with pytest.raises(RuntimeError):
        with Context(file_id, path, security.GcmChunkStreamCodecV2(vault_id, file_id)) as ctx:
            ctx.write_chunk(b"partial content")
            raise RuntimeError("the upload failed")

    assert path.exists(), "the test needs the cleanup to have failed to prove anything"
    with pytest.raises(security.EncryptionError, match="without a terminal"):
        with open(path, "rb") as f:
            security.decrypt_gcm_chunk_stream(f, vault_id, file_id)
