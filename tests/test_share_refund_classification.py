"""Which failures return a burned share download, and which keep it spent.

A share download is burned before the bytes are served (to keep the cap atomic against concurrent
GETs), and returned only when the SERVER fails to serve the file. ``is_refundable_serve_failure``
draws that line, and it has to be exact: an ObjectChangedDuringRead subclasses EncryptionError, so a
bare ``isinstance(exc, EncryptionError)`` would refund a delete/replacement race a writer can trigger
on demand -- turning the download cap into a counter an attacker holds down. This is the deterministic
guard for that classification; the endpoint's live refund paths are exercised in test_api_share_downloads.
"""
import pytest

from app.services.vault_service import (
    is_refundable_serve_failure, FileServiceError, InvalidPasswordError,
    PasswordRequiredError, FileNotFoundError,
)
from app.core.security import EncryptionError, ObjectChangedDuringRead
from app.services.download_stream import ChecksumMismatch

pytestmark = pytest.mark.unit


def test_server_integrity_failures_are_refundable():
    """A rejected at-rest walk, a record that will not authenticate, or a whole-file checksum
    mismatch -- server-detected on stored bytes, none client-inducible -- return the burn."""
    assert is_refundable_serve_failure(ChecksumMismatch("stored bytes do not match the checksum"))
    assert is_refundable_serve_failure(EncryptionError("record failed to authenticate"))
    assert is_refundable_serve_failure(FileServiceError("walk rejected the blob"))


def test_object_changed_during_read_is_not_refundable():
    """The trap the guard exists for: ObjectChangedDuringRead IS an EncryptionError (so a bare
    isinstance would refund it), but a delete/same-name replacement mid-read is a race a writer can
    trigger at will -- refunding it would uncap the share. It must stay burned."""
    assert issubclass(ObjectChangedDuringRead, EncryptionError)          # documents why the exclusion is needed
    assert not is_refundable_serve_failure(ObjectChangedDuringRead("replaced while reading"))


def test_client_and_auth_failures_are_not_refundable():
    """InvalidPasswordError / PasswordRequiredError subclass FileServiceError, but the CLIENT caused
    them, so the burn stays spent -- else a wrong password could be used to uncap a share."""
    assert issubclass(InvalidPasswordError, FileServiceError)
    assert not is_refundable_serve_failure(InvalidPasswordError("wrong file password"))
    assert not is_refundable_serve_failure(PasswordRequiredError("file password required"))


def test_missing_blob_is_not_a_generic_serve_failure():
    """A missing blob IS refunded, but on its own 404 path -- so the generic classifier excludes it
    to avoid double-counting (FileNotFoundError also subclasses FileServiceError)."""
    assert issubclass(FileNotFoundError, FileServiceError)
    assert not is_refundable_serve_failure(FileNotFoundError("File data not found on disk"))


def test_unrelated_and_absent_failures_are_not_refundable():
    """A None failure (a completed transfer, or a client cancel/disconnect) and unrelated errors
    never refund."""
    assert not is_refundable_serve_failure(None)
    assert not is_refundable_serve_failure(ValueError("unrelated"))
    assert not is_refundable_serve_failure(KeyError("unrelated"))
