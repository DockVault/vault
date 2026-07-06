"""Registration proof-of-possession (ECDH key-confirmation).

Registration must prove the caller holds the private key matching the public key they
register. These cover the security properties: a valid PoP registers; a missing / wrong /
mismatched PoP is refused; and a challenge is single-use (a failed attempt consumes it, so
it can't be brute-forced or replayed).
"""
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import ApiClient, compute_registration_pop


def _fresh_client(admin):
    u = admin.create_user(role="user")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    return u, c


def _keypair():
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def _mac_for(priv, public_key_pem, challenge) -> str:
    """The correct MAC for a GIVEN challenge dict (lets a test reuse one challenge_id)."""
    server_pub = serialization.load_pem_public_key(challenge["server_ephemeral_public_key"].encode())
    shared = priv.exchange(ec.ECDH(), server_pub)
    mac_key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=b"dv-ecc-pop-v1", info=b"registration-pop").derive(shared)
    msg = base64.b64decode(challenge["nonce"]) + public_key_pem.encode()
    return base64.b64encode(hmac.new(mac_key, msg, hashlib.sha256).digest()).decode()


def test_register_with_valid_pop_succeeds(admin):
    u, c = _fresh_client(admin)
    try:
        priv, pub = _keypair()
        r = c.post("/ecc/keys/register", json={
            "public_key": pub, "encrypted_private_key": "opaque",
            "pop": compute_registration_pop(c, priv, pub)})
        assert r.status_code == 201, r.text
    finally:
        admin.delete_user(u["id"])


def test_register_without_pop_rejected(admin):
    u, c = _fresh_client(admin)
    try:
        _, pub = _keypair()
        r = c.post("/ecc/keys/register", json={"public_key": pub, "encrypted_private_key": "opaque"})
        assert r.status_code == 400, r.text
        assert "possession" in r.text.lower()
        assert c.get("/ecc/keys/public").json().get("has_keypair") is False  # nothing registered
    finally:
        admin.delete_user(u["id"])


def test_register_with_bad_mac_rejected(admin):
    u, c = _fresh_client(admin)
    try:
        priv, pub = _keypair()
        pop = compute_registration_pop(c, priv, pub)
        pop["mac"] = base64.b64encode(b"\x00" * 32).decode()  # wrong MAC
        r = c.post("/ecc/keys/register", json={
            "public_key": pub, "encrypted_private_key": "opaque", "pop": pop})
        assert r.status_code == 400, r.text
        assert c.get("/ecc/keys/public").json().get("has_keypair") is False
    finally:
        admin.delete_user(u["id"])


def test_register_pop_requires_the_matching_private_key(admin):
    """The core property: the MAC must be produced with the PRIVATE key of the PUBLIC key
    being registered. A MAC over the right public key but from an UNRELATED private key fails."""
    u, c = _fresh_client(admin)
    try:
        _, pub = _keypair()
        priv_other, _ = _keypair()                       # not pub's private half
        pop = compute_registration_pop(c, priv_other, pub)  # MAC over `pub`, wrong ECDH key
        r = c.post("/ecc/keys/register", json={
            "public_key": pub, "encrypted_private_key": "opaque", "pop": pop})
        assert r.status_code == 400, r.text
        assert c.get("/ecc/keys/public").json().get("has_keypair") is False
    finally:
        admin.delete_user(u["id"])


def test_register_pop_is_bound_to_the_public_key(admin):
    """A valid PoP for one public key can't register a DIFFERENT public key."""
    u, c = _fresh_client(admin)
    try:
        priv_a, pub_a = _keypair()
        _, pub_b = _keypair()
        pop = compute_registration_pop(c, priv_a, pub_a)  # valid for pub_a
        r = c.post("/ecc/keys/register", json={
            "public_key": pub_b, "encrypted_private_key": "opaque", "pop": pop})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(u["id"])


def test_challenge_is_single_use(admin):
    """A challenge is consumed even on a FAILED attempt, so a correct MAC replayed against the
    same challenge afterwards still fails — it can't be brute-forced or reused."""
    u, c = _fresh_client(admin)
    try:
        priv, pub = _keypair()
        ch = c.post("/ecc/keys/register/challenge").json()
        good_mac = _mac_for(priv, pub, ch)
        # 1) a WRONG mac against this challenge -> 400, and consumes the challenge
        bad = {"challenge_id": ch["challenge_id"], "mac": base64.b64encode(b"\x00" * 32).decode()}
        assert c.post("/ecc/keys/register", json={
            "public_key": pub, "encrypted_private_key": "opaque", "pop": bad}).status_code == 400
        # 2) the CORRECT mac reusing the SAME challenge -> still 400 (already consumed)
        r = c.post("/ecc/keys/register", json={
            "public_key": pub, "encrypted_private_key": "opaque",
            "pop": {"challenge_id": ch["challenge_id"], "mac": good_mac}})
        assert r.status_code == 400, r.text
        assert c.get("/ecc/keys/public").json().get("has_keypair") is False
    finally:
        admin.delete_user(u["id"])
