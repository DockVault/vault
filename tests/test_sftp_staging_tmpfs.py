"""SFTP upload staging on a size-capped tmpfs (RAM), not the persistent volume.

Each SFTP upload buffers its plaintext before encrypting it at close. The compose files back that
staging directory with a size-capped tmpfs so the plaintext never touches persistent disk. Two
consequences follow, and both are pinned here: a buffered upload cannot exceed the tmpfs, so the
per-file limit is clamped to it; and if a write fails part-way (the tmpfs filled under concurrent
uploads), the truncated buffer must be discarded rather than finalized as a whole file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import paramiko
import pytest

from app.sftp.sftp_server import VaultSFTPHandle, _staging_capped_max

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

_STAGING_TMPFS = "/app/storage/.sftp_tmp:mode=1777,size=${SFTP_STAGING_TMPFS_MB:-512}m"
_STAGING_ENV = "SFTP_STAGING_TMPFS_MB: ${SFTP_STAGING_TMPFS_MB:-512}"


def _service_block(compose_text, name):
    """The YAML text of one top-level service, from its `  <name>:` line up to the next top-level
    key. Text-based (PyYAML is deliberately absent from the test lock) but robust: a top-level
    service is exactly two-space-indented, and the block ends at the next such key or a column-0
    key (volumes:/networks:)."""
    lines = compose_text.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln == "  %s:" % name), None)
    assert start is not None, "service %s not found in compose" % name
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^\S", lines[j]) or re.match(r"^  [A-Za-z][\w-]*:\s*$", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# --- the per-file clamp -------------------------------------------------------------------------

def test_the_clamp_caps_an_upload_at_the_staging_budget():
    mb = 512
    budget = mb * 1024 * 1024
    assert _staging_capped_max(0, mb) == budget                    # unbounded -> the budget itself
    assert _staging_capped_max(100 * 1024 * 1024, mb) == 100 * 1024 * 1024   # smaller limit kept
    assert _staging_capped_max(2000 * 1024 * 1024, mb) == budget   # larger limit clamped down


def test_the_clamp_is_disabled_when_no_tmpfs_budget_is_set():
    # 0 means "staging is on the volume, not a tmpfs" -> leave the configured limit untouched.
    assert _staging_capped_max(2000 * 1024 * 1024, 0) == 2000 * 1024 * 1024
    assert _staging_capped_max(0, 0) == 0
    assert _staging_capped_max(2000 * 1024 * 1024, -1) == 2000 * 1024 * 1024


# --- the failed-write discard -------------------------------------------------------------------

class _FailingWriteFile:
    """A buffer whose write raises, as a full staging tmpfs would (ENOSPC)."""
    def __init__(self):
        self.bytes_written = 0

    def seek(self, offset):
        pass

    def write(self, data):
        raise OSError(28, "No space left on device")

    def flush(self):
        pass

    def close(self):
        pass


class _OkWriteFile:
    def __init__(self):
        self.buf = bytearray()

    def seek(self, offset):
        pass

    def write(self, data):
        self.buf.extend(data)

    def flush(self):
        pass

    def close(self):
        pass


class _FlushFailingWriteFile:
    """Writes succeed (a BufferedWriter holds the tail in memory) but the close-time flush raises,
    as a tmpfs that filled between the last write and close would -- the tail never reaches disk."""
    def seek(self, offset):
        pass

    def write(self, data):
        pass

    def flush(self):
        raise OSError(28, "No space left on device")

    def close(self):
        pass


def _handle_with(tmp_path, writefile):
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle.writepath = str(tmp_path / "up_buffer")
    Path(handle.writepath).write_bytes(b"")          # the on-disk buffer close() removes
    handle.writefile = writefile
    finalized = []
    handle.finalizer = lambda p: finalized.append(p)
    return handle, finalized


def test_a_failed_write_discards_the_upload_instead_of_finalizing_a_partial(tmp_path):
    handle, finalized = _handle_with(tmp_path, _FailingWriteFile())

    result = handle.write(0, b"some bytes")
    assert result == paramiko.SFTP_FAILURE
    assert handle.write_failed is True

    handle.close()
    assert finalized == [], "a truncated upload must NOT be finalized as a whole file"
    assert not os.path.exists(handle.writepath), "the plaintext buffer is removed"


def test_a_failed_close_flush_discards_the_upload(tmp_path):
    """The subtler path: individual writes succeed (buffered) but the tail only reaches the tmpfs at
    close-time flush, which then fails. The truncated buffer must be discarded, not finalized."""
    handle, finalized = _handle_with(tmp_path, _FlushFailingWriteFile())

    assert handle.write(0, b"a full chunk") == paramiko.SFTP_OK   # buffered, no failure yet
    assert handle.write_failed is False

    handle.close()   # flush() raises here
    assert handle.write_failed is True, "a failed close-flush must mark the upload for discard"
    assert finalized == [], "a tail that never flushed must NOT be finalized as a whole file"
    assert not os.path.exists(handle.writepath)


def test_a_clean_write_still_finalizes(tmp_path):
    """The control: without a write failure the upload is finalized as before."""
    handle, finalized = _handle_with(tmp_path, _OkWriteFile())

    assert handle.write(0, b"hello world") == paramiko.SFTP_OK
    assert handle.write_failed is False

    handle.close()
    assert finalized == [handle.writepath], "a complete upload is finalized"


def test_an_over_limit_upload_is_still_discarded(tmp_path):
    """The existing too-large path is unchanged: exceeding max_bytes marks overlimit and discards."""
    handle, finalized = _handle_with(tmp_path, _OkWriteFile())
    handle.max_bytes = 4

    assert handle.write(0, b"toolong") == paramiko.SFTP_FAILURE
    assert handle.overlimit is True

    handle.close()
    assert finalized == [], "an over-limit upload is discarded, not finalized"


# --- named error instead of a bare "Failure" ---------------------------------------------------

class _FakeProtocolServer:
    """Stand-in for the paramiko protocol handler the handle records a status description on."""
    def __init__(self):
        self._pending_status_desc = None


def test_over_limit_write_names_the_limit_instead_of_bare_failure(tmp_path):
    handle, _ = _handle_with(tmp_path, _OkWriteFile())
    handle.max_bytes = 4 * 1024 * 1024                       # 4 MiB
    handle._sftp_server = _FakeProtocolServer()
    assert handle.write(0, b"x" * (5 * 1024 * 1024)) == paramiko.SFTP_FAILURE
    desc = handle._sftp_server._pending_status_desc
    assert desc and "4 MB SFTP limit" in desc and "SFTP_STAGING_TMPFS_MB" in desc


def test_staging_full_write_names_the_buffer_instead_of_bare_failure(tmp_path):
    handle, _ = _handle_with(tmp_path, _FailingWriteFile())   # write raises ENOSPC
    handle._sftp_server = _FakeProtocolServer()
    assert handle.write(0, b"some bytes") == paramiko.SFTP_FAILURE
    desc = handle._sftp_server._pending_status_desc
    assert desc and "staging buffer is full" in desc


def test_no_status_desc_is_set_without_a_wired_server(tmp_path):
    # A read handle (no _sftp_server) must never crash setting a description.
    handle, _ = _handle_with(tmp_path, _OkWriteFile())
    handle.max_bytes = 2
    assert handle.write(0, b"toolong") == paramiko.SFTP_FAILURE   # no wired server -> just refuses


def test_message_server_substitutes_and_clears_pending_desc(monkeypatch):
    from app.sftp.sftp_server import _MessageSFTPServer
    srv = _MessageSFTPServer.__new__(_MessageSFTPServer)      # bypass paramiko's __init__
    srv._pending_status_desc = "upload rejected: file exceeds the 4 MB SFTP limit"
    sent = []
    monkeypatch.setattr(paramiko.SFTPServer, "_send_status",
                        lambda self, rn, code, desc=None: sent.append((rn, code, desc)))
    srv._send_status(7, paramiko.SFTP_FAILURE)
    assert sent[-1] == (7, paramiko.SFTP_FAILURE, "upload rejected: file exceeds the 4 MB SFTP limit")
    assert srv._pending_status_desc is None                  # consumed + cleared
    srv._send_status(8, paramiko.SFTP_OK)                     # nothing pending -> paramiko default
    assert sent[-1] == (8, paramiko.SFTP_OK, None)
    srv._pending_status_desc = "leftover"                    # an explicit desc still wins over pending
    srv._send_status(9, paramiko.SFTP_FAILURE, "explicit")
    assert sent[-1] == (9, paramiko.SFTP_FAILURE, "explicit") and srv._pending_status_desc is None


def test_env_example_file_size_agrees_with_sftp_staging():
    """The shipped defaults must agree so SFTP never silently refuses a file the web UI accepts:
    the effective SFTP per-file limit is min(MAX_FILE_SIZE_MB, SFTP_STAGING_TMPFS_MB)."""
    env = _read(".env.example")
    file_mb = int(re.search(r"^MAX_FILE_SIZE_MB=(\d+)", env, re.M).group(1))
    tmpfs_mb = int(re.search(r"^SFTP_STAGING_TMPFS_MB=(\d+)", env, re.M).group(1))
    assert file_mb <= tmpfs_mb, (
        "MAX_FILE_SIZE_MB (%d) must not exceed SFTP_STAGING_TMPFS_MB (%d), or SFTP refuses files the "
        "web UI accepts" % (file_mb, tmpfs_mb))


# --- the compose backing --------------------------------------------------------------------

def test_the_tmpfs_is_on_the_sftp_running_services_and_not_the_api_service():
    """Per-SERVICE placement, not a file-wide count: the staging tmpfs must back the process that
    actually buffers SFTP uploads (dev vault-sftp; secure combined vault + split vault-sftp) and
    must NOT sit on the HTTP-only vault-api, which never writes the staging dir."""
    dev = _read("deploy/docker-compose.yml")
    secure = _read("deploy/docker-compose.secure.yml")

    assert _STAGING_TMPFS in _service_block(dev, "vault-sftp"), "dev vault-sftp must stage on the tmpfs"
    assert _STAGING_TMPFS not in _service_block(dev, "vault-api"), "the HTTP API must not get the SFTP staging tmpfs"

    assert _STAGING_TMPFS in _service_block(secure, "vault"), "secure combined vault must stage on the tmpfs"
    assert _STAGING_TMPFS in _service_block(secure, "vault-sftp"), "secure split vault-sftp must stage on the tmpfs"
    assert _STAGING_TMPFS not in _service_block(secure, "vault-api"), "secure HTTP API must not get the staging tmpfs"


def test_the_clamp_size_is_exported_into_the_sftp_service_environment():
    """The app clamp is coupled to the real tmpfs: each SFTP-running service passes the tmpfs size
    into its environment, so the clamp matches. A service without the tmpfs (or an old compose)
    passes nothing and the app default (0, unclamped) applies -- no silent upgrade regression."""
    dev = _read("deploy/docker-compose.yml")
    secure = _read("deploy/docker-compose.secure.yml")
    assert _STAGING_ENV in _service_block(dev, "vault-sftp")
    assert _STAGING_ENV in _service_block(secure, "vault")
    assert _STAGING_ENV in _service_block(secure, "vault-sftp")
    # vault-api never runs SFTP, so it neither mounts the tmpfs nor exports its size.
    assert _STAGING_ENV not in _service_block(dev, "vault-api")
    assert _STAGING_ENV not in _service_block(secure, "vault-api")


def test_env_example_documents_the_staging_size_and_config_default_is_unclamped():
    assert "SFTP_STAGING_TMPFS_MB=512" in _read(".env.example")   # the shipped/recommended value
    # Read the default from source rather than instantiating Settings (which validates credentials).
    cfg = _read("app/core/config.py")
    m = re.search(r"sftp_staging_tmpfs_mb\s*:\s*int\s*=\s*Field\(default=(\d+)\)", cfg)
    assert m and m.group(1) == "0", (
        "the config default must be 0 (unclamped): a compose without the tmpfs (e.g. an in-place "
        "image upgrade) must not silently cap uploads; the compose exports the real size")


def test_the_clamp_is_wired_into_the_upload_open_path():
    """The clamp is exercised as a pure function above; this pins that it is actually APPLIED to the
    per-file limit in open(), so deleting the wiring line fails a test instead of silently shipping."""
    src = _read("app/sftp/sftp_server.py")
    assert "_staging_capped_max(_eff_max, settings.sftp_staging_tmpfs_mb)" in src, (
        "open() must clamp _eff_max to the staging budget; unwiring it must be caught here")
