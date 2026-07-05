"""
ECC Crypto Service — server-side PUBLIC-key validation only.

Zero-knowledge invariant: the server NEVER handles ECC PRIVATE keys or plaintext vault DEKs.
Keypair generation, private-key password-encrypt/decrypt, and DEK wrap/unwrap all happen ONLY in
the browser (static/js/ecc_crypto.js); the server stores just the public key plus the
browser-produced opaque ciphertext (POST /ecc/keys/register and the /ecc key blobs).

This module historically also carried a full server-side crypto suite — keypair generation,
unencrypted private-key export, private-key import, password encrypt/decrypt of a private key,
ECDH+AES-KW DEK wrap/unwrap, server-side DEK generation, and a member-add helper that wrapped a
plaintext DEK server-side. NONE had a live caller, and any of them, if ever wired into a route,
would have broken the zero-knowledge guarantee (the server would see a private key or a plaintext
DEK). They have been removed. Do NOT re-add a server-side private-key or plaintext-DEK path; a
static guard test asserts no live server code contains such a helper.
"""
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# P-384 (SECP384R1) — the curve used for public keys registered by clients.
ECC_CURVE = ec.SECP384R1()


class ECCCryptoService:
    """Server-side PUBLIC-key utilities only. No private-key or DEK operations exist here."""

    @staticmethod
    def import_public_key(pem_str: str) -> ec.EllipticCurvePublicKey:
        """Import (and thereby validate) a PEM-encoded ECC public key. Used at
        POST /ecc/keys/register to reject malformed keys. Public keys are not secret; the server
        never sees or handles the matching private key."""
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8'),
            backend=default_backend(),
        )


__all__ = ['ECCCryptoService']
