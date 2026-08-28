"""Secrets can be supplied from a mounted file (<NAME>_FILE) instead of a plaintext value in .env.

The container entrypoint reads each supported <NAME>_FILE into <NAME> before dropping privileges and
exec'ing the app, so an operator can keep the master key, JWT secret, DB/redis passwords etc. out of
a plaintext .env (Docker/Kubernetes secrets). Read-old: the plain <NAME> still works and wins.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _load_entrypoint():
    spec = importlib.util.spec_from_file_location("dockvault_entrypoint", ROOT / "docker-entrypoint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_EP = _load_entrypoint()


@pytest.fixture
def clean_env():
    """Snapshot and restore every env var the tests touch (the function mutates os.environ)."""
    names = list(_EP._FILE_SECRETS) + [n + "_FILE" for n in _EP._FILE_SECRETS] + ["FOO", "FOO_FILE"]
    saved = {n: os.environ.get(n) for n in names}
    for n in names:
        os.environ.pop(n, None)
    try:
        yield
    finally:
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


def test_a_file_secret_is_read_into_the_plain_env_var(tmp_path, clean_env):
    secret = "gAAAAABhc2VjcmV0LWtleS12YWx1ZQ=="
    f = tmp_path / "encryption_key"
    f.write_text(secret + "\n", encoding="utf-8")   # printf-style trailing newline
    os.environ["ENCRYPTION_KEY_FILE"] = str(f)

    _EP._expand_file_secrets()

    assert os.environ.get("ENCRYPTION_KEY") == secret, "the trailing newline is stripped"


def test_the_plain_value_wins_when_both_are_set(tmp_path, clean_env):
    f = tmp_path / "jwt"
    f.write_text("from-file", encoding="utf-8")
    os.environ["JWT_SECRET_KEY_FILE"] = str(f)
    os.environ["JWT_SECRET_KEY"] = "from-env"    # read-old: an existing plaintext value is kept

    _EP._expand_file_secrets()

    assert os.environ["JWT_SECRET_KEY"] == "from-env"


def test_no_file_var_is_a_no_op(clean_env):
    _EP._expand_file_secrets()
    for name in _EP._FILE_SECRETS:
        assert name not in os.environ


def test_an_unreadable_file_leaves_the_var_unset_and_does_not_raise(tmp_path, clean_env):
    os.environ["REDIS_PASSWORD_FILE"] = str(tmp_path / "does-not-exist")
    _EP._expand_file_secrets()   # must not raise
    assert "REDIS_PASSWORD" not in os.environ


def test_a_non_utf8_file_leaves_the_var_unset_and_does_not_raise(tmp_path, clean_env):
    """Raw binary (e.g. `openssl rand 32 > file`) is not a valid UTF-8 env value. It must fail
    closed (var unset), never crash the entrypoint, and never echo the offending secret byte."""
    f = tmp_path / "enc"
    f.write_bytes(b"\x80\x81\x82 not utf-8")
    os.environ["ENCRYPTION_KEY_FILE"] = str(f)
    _EP._expand_file_secrets()   # must not raise
    assert "ENCRYPTION_KEY" not in os.environ


def test_a_non_allowlisted_file_var_is_not_expanded(tmp_path, clean_env):
    f = tmp_path / "foo"
    f.write_text("should-not-be-read", encoding="utf-8")
    os.environ["FOO_FILE"] = str(f)
    _EP._expand_file_secrets()
    assert "FOO" not in os.environ, "only the allowlisted secret names are expanded"


def test_internal_content_is_preserved_only_the_trailing_newline_is_stripped(tmp_path, clean_env):
    # A value with interior whitespace and no trailing newline must be read verbatim.
    f = tmp_path / "admin"
    f.write_text("p@ss w0rd-with spaces", encoding="utf-8")
    os.environ["ADMIN_PASSWORD_FILE"] = str(f)
    _EP._expand_file_secrets()
    assert os.environ["ADMIN_PASSWORD"] == "p@ss w0rd-with spaces"


def test_all_expected_secret_names_are_supported():
    for name in ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "REDIS_PASSWORD", "ADMIN_PASSWORD",
                 "LOG_TOKEN_PEPPER", "INVITE_TOKEN_PEPPER"):
        assert name in _EP._FILE_SECRETS
    # and the entrypoint calls the expansion before the privilege drop / exec
    src = (ROOT / "docker-entrypoint.py").read_text(encoding="utf-8")
    assert "_expand_file_secrets()" in src.split("def main(")[1].split("os.execvp")[0]
