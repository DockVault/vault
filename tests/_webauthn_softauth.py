"""A software WebAuthn authenticator on ``cryptography``, for the offline tests of the passkey service.

It produces the WebAuthn Level 3 JSON shapes a browser's ``PublicKeyCredential.toJSON()`` returns (camelCase keys,
bytes as base64url without padding), with every knob a test needs to be hostile: the flags, the sign count, the
relying-party id and challenge it signs for, a bad signature, another credential id, a missing user handle, the
attestation format and statement.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from fido2.cose import CoseKey
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

FLAG = AuthenticatorData.FLAG

ES256 = -7
RS256 = -257
EDDSA = -8


class SoftAuthenticator:
    """One credential per instance."""

    def __init__(self, alg: int = ES256, aaguid: bytes = b"\x00" * 16, cose_alg_override: Optional[int] = None):
        self.alg = alg
        self.aaguid = aaguid
        self.credential_id = os.urandom(32)
        if alg == ES256:
            self._priv = ec.generate_private_key(ec.SECP256R1())
        elif alg == RS256:
            self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif alg == EDDSA:
            self._priv = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"unsupported alg {alg}")
        self.cose_public_key = CoseKey.for_alg(alg).from_cryptography_key(self._priv.public_key())
        if cose_alg_override is not None:
            # Lie about the algorithm in the COSE key (to probe the server's algorithm checks).
            d = dict(self.cose_public_key)
            d[3] = cose_alg_override
            self.cose_public_key = CoseKey.for_alg(cose_alg_override)(d)
        self.user_handle: Optional[bytes] = None

    def sign(self, message: bytes) -> bytes:
        if self.alg == ES256:
            return self._priv.sign(message, ec.ECDSA(hashes.SHA256()))
        if self.alg == RS256:
            return self._priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return self._priv.sign(message)

    @staticmethod
    def client_data(typ: str, challenge_b64url: str, origin: str, cross_origin: bool = False) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64url, "origin": origin, "crossOrigin": cross_origin},
                          separators=(",", ":")).encode()

    @staticmethod
    def rp_id_hash(rp_id: str) -> bytes:
        return hashlib.sha256(rp_id.encode()).digest()

    def make_credential(self, creation_options: dict, origin: str, *, flags: int = FLAG.UP | FLAG.UV,
                        sign_count: int = 0, fmt: str = "none", rp_id_override: Optional[str] = None,
                        challenge_override: Optional[str] = None, att_stmt_override: Optional[dict] = None,
                        bad_signature: bool = False, x5c: Optional[list] = None, att_signer=None,
                        transports: Optional[list] = None, credential_type: str = "public-key",
                        extensions: Optional[dict] = None) -> dict:
        pk = creation_options["publicKey"]
        rp_id = rp_id_override or pk["rp"]["id"]
        challenge = challenge_override or pk["challenge"]
        self.user_handle = websafe_decode(pk["user"]["id"])
        cdj = self.client_data("webauthn.create", challenge, origin)
        cd_hash = hashlib.sha256(cdj).digest()
        acd = AttestedCredentialData.create(self.aaguid, self.credential_id, self.cose_public_key)
        auth_data = AuthenticatorData.create(self.rp_id_hash(rp_id), flags | FLAG.AT, sign_count, acd)
        if att_stmt_override is not None:
            att_stmt = att_stmt_override
        elif fmt == "none":
            att_stmt = {}
        elif fmt == "packed":
            signer = att_signer or self.sign
            sig = signer(auth_data + cd_hash)
            if bad_signature:
                sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            att_stmt = {"alg": self.alg, "sig": sig}
            if x5c:
                att_stmt["x5c"] = x5c
        else:
            raise ValueError(fmt)
        att_obj = AttestationObject.create(fmt, auth_data, att_stmt)
        resp = {
            "clientDataJSON": websafe_encode(cdj),
            "attestationObject": websafe_encode(att_obj),
            "transports": transports if transports is not None else ["internal", "hybrid"],
            "publicKeyAlgorithm": self.alg,
            "authenticatorData": websafe_encode(auth_data),
        }
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": credential_type,
            "authenticatorAttachment": "platform",
            "clientExtensionResults": extensions if extensions is not None else {},
            "response": resp,
        }

    def get_assertion(self, request_options: dict, origin: str, *, flags: int = FLAG.UP | FLAG.UV, sign_count: int = 1,
                      rp_id_override: Optional[str] = None, challenge_override: Optional[str] = None,
                      bad_signature: bool = False, credential_id_override: Optional[bytes] = None,
                      include_user_handle: bool = True, user_handle_override: Optional[bytes] = None) -> dict:
        pk = request_options["publicKey"]
        rp_id = rp_id_override or pk["rpId"]
        challenge = challenge_override or pk["challenge"]
        cdj = self.client_data("webauthn.get", challenge, origin)
        cd_hash = hashlib.sha256(cdj).digest()
        auth_data = AuthenticatorData.create(self.rp_id_hash(rp_id), flags, sign_count)
        sig = self.sign(auth_data + cd_hash)
        if bad_signature:
            sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        cid = credential_id_override or self.credential_id
        resp = {"clientDataJSON": websafe_encode(cdj), "authenticatorData": websafe_encode(auth_data),
                "signature": websafe_encode(sig)}
        handle = user_handle_override if user_handle_override is not None else self.user_handle
        if include_user_handle and handle is not None:
            resp["userHandle"] = websafe_encode(handle)
        return {"id": websafe_encode(cid), "rawId": websafe_encode(cid), "type": "public-key",
                "authenticatorAttachment": "platform", "clientExtensionResults": {}, "response": resp}
