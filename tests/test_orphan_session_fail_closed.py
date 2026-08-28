"""A regular-user token whose session row is absent is rejected (fail closed).

Every regular login inserts an ActiveSession row (keyed by the hashed session_token) and commits
it BEFORE the token is minted, so a legitimate token always finds its row. A validly-signed token
that carries a session_token with NO matching row can therefore only be a forgery, a replayed token
whose session was hard-removed, or a token for a since-deleted user (its row cascade-deleted). The
durable revocation gate in get_current_user must deny all of these, not just rows explicitly marked
`revoked` -- an absent row is the strongest revocation there is.

Runs against the live deployment: it mints a validly-signed token INSIDE the container (real JWT
secret, real create_access_token) for a real admin user but with a random, never-inserted
session_token, then presents it to the API. Without the fail-closed check the missing row reads as
"not revoked" and the request would be admitted (200); with it, the request is denied (401).
"""
import os
import subprocess

import pytest
import requests

from conftest import BASE_URL

# Mint a validly-signed access token for a REAL user, but with a session_token that was never
# inserted into active_sessions. Printed as TOKEN:<jwt> on success, NOUSER if the DB has no user.
_FORGE_ORPHAN_SESSION = r'''
import secrets, sys
from app.core.database import SessionLocal
from app.core.models import User, RoleEnum
from app.core.security import create_access_token

db = SessionLocal()
try:
    user = (db.query(User).filter(User.role == RoleEnum.ADMIN).first()
            or db.query(User).first())
    if user is None:
        print("NOUSER"); sys.exit(0)
    token = create_access_token(data={
        "sub": str(user.id),
        "username": user.username,
        # Random => hash_session_token(...) matches no active_sessions row.
        "session_token": secrets.token_hex(32),
        "is_temporary": False,
    })
    print("TOKEN:" + token)
finally:
    db.close()
'''


def _mint_orphan_session_token():
    """A validly-signed token for a real user carrying a session with no DB row, or skip."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python", "-"],
            input=_FORGE_ORPHAN_SESSION, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable to mint the token in-container: {exc}")
    if proc.returncode != 0 and "No such container" in (proc.stderr or ""):
        pytest.skip(f"no {container} container on this host to mint the token in")
    assert proc.returncode == 0, f"minting failed (rc={proc.returncode})\n{proc.stdout}\n{proc.stderr}"
    if "NOUSER" in proc.stdout:
        pytest.skip("no user exists in the deployment to mint a token for")
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("TOKEN:")), None)
    assert line, f"no token minted; got:\n{proc.stdout}\n{proc.stderr}"
    return line[len("TOKEN:"):].strip()


def test_regular_token_with_missing_session_row_is_denied():
    """A validly-signed regular token whose session row is absent must be denied (fail closed)."""
    token = _mint_orphan_session_token()
    r = requests.get(
        f"{BASE_URL}/vaults",
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "203.0.113.201"},
        timeout=15,
    )
    assert r.status_code == 401, (
        "a regular token whose active_sessions row is absent must be rejected, not admitted "
        f"(got {r.status_code}: {r.text[:200]})"
    )


def test_a_real_login_token_is_still_accepted(admin):
    """Control: the same endpoint accepts a genuine session token, so the test above is not
    passing merely because /vaults rejects everything."""
    r = admin.get("/vaults")
    assert r.status_code == 200, (
        f"a genuine, unrevoked session must still be accepted (got {r.status_code}: {r.text[:200]})"
    )
