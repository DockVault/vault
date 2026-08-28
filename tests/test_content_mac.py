"""The file ETag is a KEYED tag over the content, not the plaintext checksum.

A file's ETag used to be the plaintext SHA-256 of its content, which let anyone who could request
the file confirm whether it held specific known content (hash a candidate, compare the tag). The
ETag is now `content_mac` -- HMAC-SHA256 of the checksum under a per-file key derived from the
deployment ENCRYPTION_KEY -- so it stays a stable, unique-per-version identifier but cannot be
reproduced or predicted without the deployment key. This checks those properties on the real helper.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid

import pytest

pytestmark = pytest.mark.unit


def _crypto_ok():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def _set_key(key_b64):
    os.environ["ENCRYPTION_KEY"] = key_b64
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost/db")
    os.environ.setdefault("JWT_SECRET_KEY", secrets.token_hex(32))
    from app.core import config as _config
    _config._runtime_initialized = False           # re-latch from the new env on next crypto call


@pytest.fixture(autouse=True)
def _runtime_secrets():
    previous = {k: os.environ.get(k) for k in ("ENCRYPTION_KEY", "DATABASE_URL", "JWT_SECRET_KEY")}
    _set_key(base64.urlsafe_b64encode(os.urandom(32)).decode())
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                               # noqa: BLE001
        pass


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_content_mac_is_deterministic_keyed_and_not_the_checksum():
    from app.core.security import content_mac
    fid = uuid.uuid4()
    sha = hashlib.sha256(b"the file content").hexdigest()

    mac = content_mac(fid, sha)
    assert content_mac(fid, sha) == mac, "same (file, checksum) -> same tag (a resume must match)"
    assert len(mac) == 64 and all(c in "0123456789abcdef" for c in mac), "hex-64"
    assert mac != sha, "the tag is not the plaintext checksum"

    # An attacker who knows the content (hence the checksum) cannot compute the tag without the key.
    guess = hmac.new(b"any key an attacker might try", sha.encode(), hashlib.sha256).hexdigest()
    assert guess != mac


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_content_mac_is_per_file_and_content_sensitive():
    from app.core.security import content_mac
    sha = hashlib.sha256(b"same content").hexdigest()
    a, b = uuid.uuid4(), uuid.uuid4()
    assert content_mac(a, sha) != content_mac(b, sha), "two files with identical content differ"
    other = hashlib.sha256(b"different content").hexdigest()
    assert content_mac(a, sha) != content_mac(a, other), "changed content -> changed tag"


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_content_mac_depends_on_the_deployment_key():
    """The whole point: without the deployment ENCRYPTION_KEY the tag is unpredictable. The same
    (file, checksum) under two different keys produces two different tags."""
    from app.core.security import content_mac
    fid = uuid.uuid4()
    sha = hashlib.sha256(b"content").hexdigest()

    _set_key(base64.urlsafe_b64encode(b"A" * 32).decode())
    mac_a = content_mac(fid, sha)
    _set_key(base64.urlsafe_b64encode(b"B" * 32).decode())
    mac_b = content_mac(fid, sha)
    assert mac_a != mac_b, "the tag is bound to the deployment key"
