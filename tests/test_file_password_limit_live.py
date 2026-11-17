"""A file's own password is under the vault password's attempt limit, on the deployed stack.

No route sets a file password (a copy carries one over), so the test gives an uploaded file one directly in the
database, hashed by the server's own code. With the vault-password limit lowered to three in a ten-second window:
three wrong passwords at the download are refused one by one, then the right one is refused with 429 too, and once
the window has passed the right one downloads the file. tests/test_file_and_folder_password_limit.py covers the same
offline, with folders and the per-item, per-account count.
"""
import os
import subprocess
import time

import pytest

pytestmark = pytest.mark.integration

LIMIT, WINDOW = 3, 10
RIGHT = "the-files-own-password"


def _docker(*args, timeout=30):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")


@pytest.fixture
def small_vault_limits(admin):
    keys = ("rate_limit_vault_attempts", "rate_limit_vault_attempts_admin", "rate_limit_vault_window_seconds")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) or 0 for k in keys}
    r = admin.put("/settings", json={"rate_limit_vault_attempts": LIMIT, "rate_limit_vault_attempts_admin": LIMIT,
                                     "rate_limit_vault_window_seconds": WINDOW})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def _give_the_file_a_password(file_id):
    api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    hashed = _docker("exec", api, "python", "-c",
                     f"from app.core.security import hash_password; print(hash_password({RIGHT!r}))")
    assert hashed.returncode == 0 and hashed.stdout.strip(), hashed.stderr[-400:]
    db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    sql = f"UPDATE files SET password_hash = '{hashed.stdout.strip()}' WHERE id = '{file_id}'"
    updated = _docker("exec", db, "sh", "-c", 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$0"', sql)
    assert updated.returncode == 0 and "UPDATE 1" in updated.stdout, updated.stdout + updated.stderr


def test_a_files_password_is_refused_at_the_limit_even_when_right_until_the_window_ends(admin, temp_vault,
                                                                                          small_vault_limits):
    up = admin.post(f"/vaults/{temp_vault['id']}/files", files=[("files", ("guarded.txt", b"kept", "text/plain"))])
    assert up.status_code in (200, 201), up.text
    file_id = up.json()["files"][0]["id"]
    _give_the_file_a_password(file_id)
    url = f"/vaults/{temp_vault['id']}/files/{file_id}/download"

    def download(password):
        return admin.get(url, headers={"X-File-Password": password})

    assert [download("a-guess").status_code for _ in range(LIMIT)] == [401] * LIMIT
    refused = download(RIGHT)
    assert refused.status_code == 429, (refused.status_code, refused.text[:200])
    assert "Too many file password attempts" in refused.json()["detail"]
    time.sleep(WINDOW + 1)
    opened = download(RIGHT)
    assert opened.status_code == 200 and opened.content == b"kept", (opened.status_code, opened.text[:200])
