"""Live: the challenges of key registration and envelope replacement are stored sealed.

A row's one-time key is in the database only as a value sealed with the deployment key. A row holding a
key in the clear -- what an older release wrote before an upgrade -- cannot be answered, even with the MAC
that key gives, and a fresh challenge then goes through. Rows past their lifetime are swept.
test_possession_challenges_sealed.py pins the same offline.
"""
import base64
import hashlib
import hmac
import os
import subprocess
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import ApiClient, ensure_ecc_keypair
from _account_change_helpers import in_api_container

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    result = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


def _signed_in(admin):
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    return user, client


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def test_a_registration_challenge_is_sealed_and_one_written_in_the_clear_cannot_be_answered(admin):
    user, client = _signed_in(admin)
    try:
        ch = client.post("/ecc/keys/register/challenge").json()
        stored = _psql(f"SELECT server_private_key FROM ecc_registration_challenges WHERE id = '{ch['challenge_id']}'")
        assert stored and "BEGIN" not in stored and stored.startswith("gAAAAA"), stored[:20]

        # The row as an older release wrote it: the key in the clear. The MAC is the right one for it.
        server = ec.generate_private_key(ec.SECP384R1())
        clear = server.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode()
        _psql(f"UPDATE ecc_registration_challenges SET server_private_key = '{clear}' "
              f"WHERE id = '{ch['challenge_id']}'")
        key = ec.generate_private_key(ec.SECP384R1())
        shared = key.exchange(ec.ECDH(), server.public_key())
        mac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"dv-ecc-pop-v1",
                       info=b"registration-pop").derive(shared)
        mac = base64.b64encode(hmac.new(mac_key, base64.b64decode(ch["nonce"]) + _pem(key).encode(),
                                        hashlib.sha256).digest()).decode()
        r = client.post("/ecc/keys/register", json={
            "public_key": _pem(key), "encrypted_private_key": "{}",
            "pop": {"challenge_id": ch["challenge_id"], "mac": mac}})
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == "Invalid or expired proof-of-possession challenge."
        assert _psql(f"SELECT count(*) FROM ecc_registration_challenges WHERE id = '{ch['challenge_id']}'") == "0"
        assert client.get("/ecc/keys/public").json()["has_keypair"] is False

        # A fresh challenge goes through, as the web app's one retry does.
        ensure_ecc_keypair(client)
        assert client.get("/ecc/keys/public").json()["has_keypair"] is True
    finally:
        admin.delete_user(user["id"])


def test_an_envelope_replacement_challenge_is_sealed(admin):
    user, client = _signed_in(admin)
    try:
        ensure_ecc_keypair(client)
        ch = client.post("/ecc/keys/private/challenge").json()
        stored = _psql(f"SELECT server_private_key FROM ecc_key_update_challenges WHERE id = '{ch['challenge_id']}'")
        assert stored and "BEGIN" not in stored and stored.startswith("gAAAAA"), stored[:20]
    finally:
        admin.delete_user(user["id"])


def test_expired_challenges_are_swept(admin):
    user, client = _signed_in(admin)
    try:
        ids = {}
        for table in ("ecc_registration_challenges", "ecc_key_update_challenges"):
            old, fresh = str(uuid.uuid4()), str(uuid.uuid4())
            _psql(f"INSERT INTO {table} (id, user_id, server_private_key, nonce, created_at) VALUES "
                  f"('{old}', '{user['id']}', 'x', 'n', (now() AT TIME ZONE 'utc') - interval '1 hour'), "
                  f"('{fresh}', '{user['id']}', 'x', 'n', now() AT TIME ZONE 'utc')")
            ids[table] = (old, fresh)
        in_api_container(
            "from app.core import retention\n"
            "from app.core.database import SessionLocal\n"
            "print(retention.prune_possession_challenges(retention.Pass(SessionLocal)).deleted)\n")
        for table, (old, fresh) in ids.items():
            assert _psql(f"SELECT count(*) FROM {table} WHERE id = '{old}'") == "0", table
            assert _psql(f"SELECT count(*) FROM {table} WHERE id = '{fresh}'") == "1", table
    finally:
        admin.delete_user(user["id"])
