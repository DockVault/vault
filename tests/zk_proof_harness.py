"""Test-side client for the key proof that zero-knowledge key changes carry.

Four requests change a zero-knowledge vault's keys: creating a zero-knowledge vault, sharing one, rotating
its key and setting its name-index key. A server that asks for a key proof wants, with each of them, MACs
over a one-time challenge and over the exact bytes of the request body. This module makes those requests
the way the web client does, so the HTTP suite keeps exercising the real routes:

* **Identity keys are derived, not generated.** An account's P-384 identity key comes from
  ``sha384(seed || 0x00 || username)``, so any test -- and a later run against the same stack -- can
  recompute the private key of an account it did not register itself. ``ensure_ecc_keypair`` in
  ``conftest.py`` registers this key. An account whose registered key is not the derived one cannot be
  proved for; :func:`identity_key_for` refuses such an account with a message rather than letting the
  server's refusal read like a product bug. Fresh users always match.
* **Every private key the harness makes is remembered by the SHA-256 of its public point** (see
  :func:`remember` and :func:`private_key_for`). A challenge names the verifier it expects a proof
  against, and the point identifies the private key to prove with, so no test has to thread key material
  through its own code. :func:`team_public_key` hands out a remembered team key for hierarchical vaults.
* **The body is serialized once.** :func:`post_zk` turns the body into one string, and the same bytes are
  what it hashes and what it sends.
* **No challenge, no proof.** A server that predates the challenge route answers it with its default 404
  (no ``reason``); a server that refuses the challenge answers with its refusal. Either way the request is
  then sent without a proof, as the web client sends it to an old server, so what the test sees is the
  guarded route's own answer.

Nothing here imports the application.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# The derivation's domain. Public on purpose: these are test identities, never a deployment's.
IDENTITY_SEED = b"dockvault-test-identity-key-v1"

# The order of the P-384 group. A scalar must lie in [1, n - 1].
_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16
)

CHALLENGE_PATH = "/ecc/vaults/{vault_id}/key-proof/challenge"
PROOF_HEADER = "X-ZK-Key-Proof"

# (method, path pattern, operation). The operation names are the challenge's `op` values.
_GUARDED_ROUTES = (
    ("POST", re.compile(r"^/ecc/vaults/(?P<vid>[^/?#]+)/rekey$"), "rekey"),
    ("POST", re.compile(r"^/ecc/vaults/(?P<vid>[^/?#]+)/members$"), "share"),
    ("PUT", re.compile(r"^/ecc/vaults/(?P<vid>[^/?#]+)/index-key$"), "index_key"),
    ("PUT", re.compile(r"^/ecc/vaults/(?P<vid>[^/?#]+)/key-proof$"), "bootstrap"),
    ("POST", re.compile(r"^/vaults$"), "create"),
)

_KEYS: dict = {}


class HarnessError(AssertionError):
    """The harness cannot make the request the test asked for. An AssertionError, so pytest reports it
    as the test's failure with the harness's own explanation."""


# ------------------------------------------------------------------------------------------------ keys

def public_point(key_or_pem) -> bytes:
    """The 97-byte uncompressed P-384 point of a public key, a private key, or a public-key PEM."""
    if isinstance(key_or_pem, str):
        key = serialization.load_pem_public_key(key_or_pem.strip().encode())
    elif isinstance(key_or_pem, ec.EllipticCurvePrivateKey):
        key = key_or_pem.public_key()
    else:
        key = key_or_pem
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError("not a P-384 public key")
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def remember(key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePrivateKey:
    """Record a private key so a later proof against its public key can find it."""
    _KEYS[hashlib.sha256(public_point(key)).digest()] = key
    return key


def private_key_for(public_key_pem: Optional[str]) -> Optional[ec.EllipticCurvePrivateKey]:
    """The remembered private key for a public-key PEM, or None (unknown key, or not a P-384 key)."""
    if not public_key_pem:
        return None
    try:
        return _KEYS.get(hashlib.sha256(public_point(public_key_pem)).digest())
    except (ValueError, TypeError):
        return None


def new_private_key() -> ec.EllipticCurvePrivateKey:
    """A fresh, remembered P-384 key."""
    return remember(ec.generate_private_key(ec.SECP384R1()))


def team_public_key() -> str:
    """A fresh team public key (PEM) for a hierarchical vault. Its private half is remembered, so the
    harness can prove it holds the team key whenever a challenge names this key as the verifier."""
    return public_pem(new_private_key())


def identity_private_key(username: str) -> ec.EllipticCurvePrivateKey:
    """The derived identity key of `username`, remembered."""
    digest = hashlib.sha384(IDENTITY_SEED + b"\x00" + username.encode("utf-8")).digest()
    scalar = int.from_bytes(digest, "big") % (_P384_ORDER - 1) + 1
    return remember(ec.derive_private_key(scalar, ec.SECP384R1()))


# ------------------------------------------------------------------------------------------ accounts

def token_claims(client) -> dict:
    """The claims of the client's bearer token, read without verification (the client reading its own
    token is not a trust decision)."""
    claims = getattr(client, "_token_claims", None)
    return claims() if callable(claims) else {}


def client_username(client) -> Optional[str]:
    """The account a client acts as: from its token, else from the login response."""
    name = token_claims(client).get("username")
    if name:
        return name
    user = getattr(client, "user", None) or {}
    return user.get("username")


def client_user_id(client) -> Optional[str]:
    sub = token_claims(client).get("sub")
    if sub:
        return str(sub).lower()
    user = getattr(client, "user", None) or {}
    return str(user["id"]).lower() if user.get("id") else None


def identity_key_for(client) -> ec.EllipticCurvePrivateKey:
    """The identity private key registered for the client's account.

    Refuses an account whose registered key is not the harness's derived key: no proof for it can
    verify, and a test that ran on anyway would report the server's refusal as a product failure.
    """
    username = client_username(client)
    if not username:
        raise HarnessError("the client has no signed-in account to prove for")
    key = identity_private_key(username)
    registered = client.get("/ecc/keys/public").json()
    if not registered.get("has_keypair") or not registered.get("public_key"):
        raise HarnessError(f"{username!r} has no encryption key registered; call ensure_ecc_keypair first")
    if public_point(registered["public_key"]) != public_point(key):
        raise HarnessError(
            f"the key registered for {username!r} is not the test harness's derived key, so no proof "
            "for it can be made. Use a fresh user, or a fresh stack if this is a long-lived one."
        )
    return key


# ------------------------------------------------------------------------------------------ requests

def guarded_operation(method: str, path: str, body) -> Optional[tuple]:
    """(op, vault id or None) when this request is one that takes a key proof, else None.

    Only a zero-knowledge create is guarded; a standard vault create is an ordinary request. A create
    names its vault id in the body (None when the body has none yet).
    """
    route = path.split("?", 1)[0]
    for verb, pattern, op in _GUARDED_ROUTES:
        m = pattern.match(route)
        if verb != method.upper() or not m:
            continue
        if op == "create":
            if not (isinstance(body, dict) and body.get("type") == "zero_knowledge"):
                return None
            return op, body.get("id")
        if op == "rekey" and isinstance(body, dict) and body.get("owner_reset") is True:
            return "owner_reset", m.group("vid")
        return op, m.group("vid")
    return None


def serialize(body) -> str:
    """The one serialization of a request body; the string hashed is the string sent."""
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def _json_or_empty(response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _prove(client, op, vault_id, challenge, body):
    """Complete a body with the material the operation installs and return (body, header value)."""
    raise HarnessError(
        "the server issued a key-proof challenge, but this harness cannot compute key proofs yet"
    )


def _send(client, method, path, raw: Optional[str], extra_headers: dict):
    verb = getattr(client, method.lower())
    if raw is None:
        return verb(path, headers=extra_headers)
    headers = {"Content-Type": "application/json", **extra_headers}
    return verb(path, data=raw.encode("utf-8"), headers=headers)


def post_zk(client, path, json=None, *, method="POST", headers=None):
    """Send one request to a route that may take a key proof, the way the web client does.

    Not a guarded request (for example a standard vault create): sent as is. Otherwise: ask for a
    challenge; if the server issues none (it predates the route, or refuses), send the body without a
    proof; if it issues one, prove and send. The body is serialized exactly once and those bytes are what
    is sent.

    The response carries `zk_challenge_status`: the challenge's status code, or None when no challenge
    was asked for.
    """
    body = json
    headers = dict(headers or {})
    guarded = guarded_operation(method, path, body)
    if guarded is None:
        response = _send(client, method, path, None if body is None else serialize(body), headers)
        response.zk_challenge_status = None
        return response
    op, vault_id = guarded
    challenge_vault = vault_id or str(uuid.uuid4())
    challenge = client.post(CHALLENGE_PATH.format(vault_id=challenge_vault), json={"op": op})
    if challenge.status_code == 200:
        if op == "create" and isinstance(body, dict) and not body.get("id"):
            body = {**body, "id": challenge_vault}
        body, proof = _prove(client, op, challenge_vault, _json_or_empty(challenge), body)
        headers[PROOF_HEADER] = proof
    response = _send(client, method, path, serialize(body), headers)
    response.zk_challenge_status = challenge.status_code
    return response


def put_zk(client, path, json=None, *, headers=None):
    """`post_zk` for the guarded PUT routes (the name-index key, the proof bootstrap)."""
    return post_zk(client, path, json, method="PUT", headers=headers)
