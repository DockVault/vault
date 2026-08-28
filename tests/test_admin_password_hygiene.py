"""After the first admin is bootstrapped, the spent ADMIN_PASSWORD is dropped.

ADMIN_PASSWORD seeds the first admin exactly once; retaining it afterwards (a plaintext .env, a
mounted secret file, or the process environment) is a standing liability. Once the admin is
bootstrapped, scrub_bootstrap_password_source removes a writable mounted ADMIN_PASSWORD_FILE, clears
the value from the process environment, and warns about a source it cannot remove.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.core.admin_password_hygiene import scrub_bootstrap_password_source

pytestmark = pytest.mark.unit


def test_a_mounted_file_is_removed_and_the_env_is_cleared_after_bootstrap(tmp_path):
    f = tmp_path / "admin_password"
    f.write_text("the-bootstrap-secret\n", encoding="utf-8")
    env = {"ADMIN_PASSWORD": "the-bootstrap-secret", "ADMIN_PASSWORD_FILE": str(f)}

    result = scrub_bootstrap_password_source("seeded", environ=env)

    assert result == "file-removed"
    assert not f.exists(), "the mounted secret file is removed"
    assert "ADMIN_PASSWORD" not in env and "ADMIN_PASSWORD_FILE" not in env, "env is cleared"


@pytest.mark.parametrize("status", ["seeded", "already-bootstrapped", "marked-existing"])
def test_a_plaintext_env_value_is_cleared_and_warned_after_bootstrap(status):
    env = {"ADMIN_PASSWORD": "the-bootstrap-secret"}   # no file: a plaintext .env value
    result = scrub_bootstrap_password_source(status, environ=env)
    assert result == "warned"
    assert "ADMIN_PASSWORD" not in env, "the spent value is dropped from the process env"


@pytest.mark.parametrize("status", ["no-password", "error"])
def test_the_password_is_kept_when_no_admin_was_bootstrapped(status, tmp_path):
    """A boot that did NOT bootstrap an admin may need the password on a later boot -- keep it."""
    f = tmp_path / "admin_password"
    f.write_text("still-needed\n", encoding="utf-8")
    env = {"ADMIN_PASSWORD": "still-needed", "ADMIN_PASSWORD_FILE": str(f)}

    result = scrub_bootstrap_password_source(status, environ=env)

    assert result == "kept-not-bootstrapped"
    assert f.exists(), "the file is NOT removed while no admin is bootstrapped"
    assert env.get("ADMIN_PASSWORD") == "still-needed", "the value is NOT cleared"


def test_absent_password_is_a_noop_after_bootstrap():
    env = {}
    assert scrub_bootstrap_password_source("already-bootstrapped", environ=env) == "absent"
    assert env == {}


def test_an_unremovable_file_does_not_raise_and_still_clears_the_env(tmp_path, monkeypatch):
    """A read-only mount (e.g. a Kubernetes secret) fails the unlink; hygiene must not crash boot,
    and the spent value is still dropped from the process env with a warning."""
    f = tmp_path / "admin_password"
    f.write_text("secret\n", encoding="utf-8")
    env = {"ADMIN_PASSWORD": "secret", "ADMIN_PASSWORD_FILE": str(f)}

    import app.core.admin_password_hygiene as mod

    def _boom(_path):
        raise OSError("read-only file system")

    monkeypatch.setattr(mod.os, "remove", _boom)
    result = scrub_bootstrap_password_source("seeded", environ=env)   # must not raise

    assert result == "warned", "could not remove the file -> warn, do not crash"
    assert f.exists(), "the read-only file is left in place"
    assert "ADMIN_PASSWORD" not in env, "the process env is still cleared"


def test_the_lifespan_scrubs_the_password_right_after_seeding_the_admin():
    """Static guard: the lifespan must call scrub_bootstrap_password_source AFTER _seed_admin_user,
    with the bootstrap status. If seeding is not wired to the scrub, a spent password is retained."""
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    body = src.split("async def lifespan(")[1]
    seed_pos = body.index("_seed_admin_user()")
    scrub_pos = body.index("scrub_bootstrap_password_source(")
    assert seed_pos < scrub_pos, "the scrub must run after the admin is seeded"
    assert "_admin_bootstrap_status = _seed_admin_user()" in body, \
        "the bootstrap status must be captured and passed to the scrub"
