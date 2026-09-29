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

The proofs themselves are computed by the independent reference (``zk_key_proof_reference``). The
material a request installs (a direct vault's proof key and its seal, the key check, the lineage tag) is
generated here when the test's body does not carry it; the server checks only its shape, so a stand-in
DEK the harness remembers per vault and epoch is enough for the HTTP suite.

Nothing here imports the application.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import zk_key_proof_reference as reference

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
# Stand-in DEKs by (vault id, DEK epoch): the harness seals proof keys and computes key checks and
# lineage tags under these, so its material is consistent with itself. The server never sees a DEK.
_DEKS: dict = {}


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


def stand_in_dek(vault_id: str, dek_epoch: int) -> bytes:
    """The harness's DEK for a vault's epoch (random, remembered)."""
    return _DEKS.setdefault((str(vault_id).lower(), int(dek_epoch)), os.urandom(32))


def direct_proof_material(vault_id: str, dek_epoch: int) -> tuple:
    """(proof key, {public_key, sealed_private_key, dek_check}) for a direct vault's epoch: a fresh,
    remembered proof keypair, sealed under the harness's stand-in DEK for that epoch."""
    key = new_private_key()
    pem = public_pem(key)
    dek = stand_in_dek(vault_id, dek_epoch)
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    sealed = reference.seal_key_proof_key(dek, vault_id, dek_epoch, pem, pkcs8, os.urandom(12))
    return key, {
        "public_key": pem,
        "sealed_private_key": base64.b64encode(sealed).decode(),
        "dek_check": base64.b64encode(reference.dek_check(dek, vault_id, dek_epoch)).decode(),
    }


def _epoch(value, fallback: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else fallback


def _lineage(vault_id, prev_epoch, mode, next_team_epoch, next_verifier_pem, next_check, team_wrap):
    """A lineage tag under the harness's stand-in DEK for the previous epoch, or random bytes when the
    inputs are not well-formed (the server checks only the tag's length)."""
    try:
        return base64.b64encode(reference.lineage_tag(
            stand_in_dek(vault_id, prev_epoch), vault_id=vault_id, prev_epoch=prev_epoch, mode=mode,
            next_team_epoch=next_team_epoch, next_verifier_pem=next_verifier_pem,
            next_dek_check=next_check, next_team_wrap_b64=team_wrap)).decode()
    except (ValueError, TypeError, KeyError):
        return base64.b64encode(os.urandom(32)).decode()


def _complete(op, vault_id, challenge, body, current_pem):
    """Add the material the operation installs, when the body does not carry it; return (body, the
    public key the request installs or None)."""
    if not isinstance(body, dict):
        return body, None
    body = dict(body)
    mode = challenge.get("mode") or "direct"
    de = _epoch(challenge.get("dek_epoch"), 1)
    te = _epoch(challenge.get("team_epoch"), 1)
    if op == "create":
        if body.get("key_wrapping_mode") == "hierarchical":
            return body, body.get("team_public_key")
        if "key_proof" not in body:
            _, body["key_proof"] = direct_proof_material(vault_id, 1)
        return body, (body.get("key_proof") or {}).get("public_key")
    if op in ("rekey", "owner_reset"):
        to = _epoch(body.get("to_version"), de + 1)
        if mode == "hierarchical":
            new_pem = body.get("team_public_key")
            if "lineage_tag" not in body:
                body["lineage_tag"] = _lineage(vault_id, de, mode, te + 1 if new_pem else te,
                                               new_pem or current_pem, None, body.get("team_dek_wrapped"))
            return body, new_pem
        if "next_key_proof" not in body:
            _, body["next_key_proof"] = direct_proof_material(vault_id, to)
        nkp = body.get("next_key_proof") or {}
        if "lineage_tag" not in body:
            try:
                check = base64.b64decode(nkp.get("dek_check") or "", validate=True)
            except (ValueError, TypeError):
                check = None
            body["lineage_tag"] = _lineage(vault_id, de, mode, te, nkp.get("public_key"), check, None)
        return body, nkp.get("public_key")
    if op == "share":
        if mode == "direct" and "dek_version" not in body:
            body["dek_version"] = de
        return body, None
    if op == "bootstrap":
        return body, body.get("public_key")
    return body, None


# `roles` in _prove / prepare_zk / post_zk: prove a role with a key other than the harness's own, or not at
# all. A missing entry means the harness's usual key; a key means that key; None means the role's MAC is left
# out ("-"). The public keys the transcript names stay the ones the challenge and the body name, as a client
# that does not hold a key would have to name them.
_ROLE_NAMES = ("identity", "current", "new")


def _prove(client, op, vault_id, challenge, body, augment=True, roles=None):
    """Complete the body, serialize it once and prove it. Returns (the exact string to send, header)."""
    roles = dict(roles or {})
    unknown = set(roles) - set(_ROLE_NAMES)
    if unknown:
        raise HarnessError(f"unknown roles {sorted(unknown)}; use {_ROLE_NAMES}")
    identity = identity_key_for(client)
    verifier = challenge.get("verifier") or {}
    current_pem = None if op in reference.OPS_WITHOUT_CURRENT_KEY else verifier.get("public_key")
    if augment:
        body, new_pem = _complete(op, vault_id, challenge, body, current_pem)
    else:
        _, new_pem = _complete(op, vault_id, challenge, body, current_pem)
    raw = serialize(body)

    def valid(pem):
        try:
            reference.point(pem)
            return pem
        except (ValueError, TypeError, AttributeError):
            return None

    new_pem, current_pem = valid(new_pem), valid(current_pem)
    digest = reference.transcript(
        op=op, challenge_id=challenge["challenge_id"], nonce_b64=challenge["nonce"],
        user_id=client_user_id(client), vault_id=vault_id, mode=challenge.get("mode") or "direct",
        dek_epoch=_epoch(challenge.get("dek_epoch"), 1), team_epoch=_epoch(challenge.get("team_epoch"), 1),
        identity_pem=public_pem(identity), current_pem=current_pem, new_pem=new_pem,
        body=raw.encode("utf-8"),
    )
    server = challenge["server_ephemeral_public_key"]
    current_key = roles["current"] if "current" in roles else private_key_for(current_pem)
    new_key = roles["new"] if "new" in roles else private_key_for(new_pem)
    identity = roles["identity"] if "identity" in roles else identity
    header = reference.proof_header(
        challenge["challenge_id"],
        reference.role_mac("identity", identity, server, digest) if identity else bytes(32),
        reference.role_mac("current-key", current_key, server, digest) if current_key else None,
        reference.role_mac("new-key", new_key, server, digest) if new_key else None,
    )
    return raw, header


def _send(client, method, path, raw: Optional[str], extra_headers: dict):
    verb = getattr(client, method.lower())
    if raw is None:
        return verb(path, headers=extra_headers)
    headers = {"Content-Type": "application/json", **extra_headers}
    return verb(path, data=raw.encode("utf-8"), headers=headers)


def prepare_zk(client, path, json=None, *, method="POST", augment=True, roles=None) -> dict:
    """Everything post_zk would send, without sending it: {"raw": the body string, "header": the proof
    header or None, "challenge": the challenge's answer or None, "challenge_status", "op", "vault_id"}.
    For tests that replay a request, edit it, or send it later."""
    body = json
    guarded = guarded_operation(method, path, body)
    if guarded is None:
        return {"raw": None if body is None else serialize(body), "header": None, "challenge": None,
                "challenge_status": None, "op": None, "vault_id": None}
    op, vault_id = guarded
    challenge_vault = vault_id or str(uuid.uuid4())
    request = {"op": op}
    if op == "create":
        request["mode"] = body.get("key_wrapping_mode") or "direct"
    challenge = client.post(CHALLENGE_PATH.format(vault_id=challenge_vault), json=request)
    answer, header = None, None
    if challenge.status_code == 200:
        if op == "create" and augment and isinstance(body, dict) and "id" not in body:
            body = {**body, "id": challenge_vault}
        answer = _json_or_empty(challenge)
        raw, header = _prove(client, op, challenge_vault, answer, body, augment=augment, roles=roles)
    else:
        raw = serialize(body)
    return {"raw": raw, "header": header, "challenge": answer, "challenge_status": challenge.status_code,
            "op": op, "vault_id": challenge_vault}


def send_prepared(client, path, prepared: dict, *, method="POST", headers=None, header=...):
    """Send what prepare_zk made. `header` replaces its proof header (None sends none)."""
    extra = dict(headers or {})
    proof = prepared["header"] if header is ... else header
    if proof is not None:
        extra[PROOF_HEADER] = proof
    response = _send(client, method, path, prepared["raw"], extra)
    response.zk_challenge_status = prepared["challenge_status"]
    return response


def post_zk(client, path, json=None, *, method="POST", headers=None, augment=True, roles=None):
    """Send one request to a route that may take a key proof, the way the web client does.

    Not a guarded request (for example a standard vault create): sent as is. Otherwise: ask for a
    challenge; if the server issues none (it predates the route, or refuses), send the body without a
    proof; if it issues one, prove and send. The body is serialized exactly once and those bytes are what
    is sent.

    With a challenge, the body gains the material its operation installs when it does not carry it
    already (a create's `key_proof` and `id`, a rotation's `next_key_proof` and `lineage_tag`, a direct
    share's `dek_version`); `augment=False` sends the test's body exactly as given.

    The response carries `zk_challenge_status`: the challenge's status code, or None when no challenge
    was asked for. `roles` proves a role with another key, or leaves it out (see _ROLE_NAMES).

    The vault a create makes does not exist yet, so its challenge names the mode the body creates it in,
    which the proof then binds; every other operation's mode is the vault's own. A create names its
    vault: only a body with no `id` at all gets one, so a test that sends an empty or malformed id keeps it.
    """
    prepared = prepare_zk(client, path, json, method=method, augment=augment, roles=roles)
    return send_prepared(client, path, prepared, method=method, headers=headers)


def put_zk(client, path, json=None, *, headers=None, augment=True, roles=None):
    """`post_zk` for the guarded PUT routes (the name-index key, the proof bootstrap)."""
    return post_zk(client, path, json, method="PUT", headers=headers, augment=augment, roles=roles)
