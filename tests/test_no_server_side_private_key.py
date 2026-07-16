"""Guard: the vault server must never handle ECC PRIVATE keys or plaintext vault DEKs.

Zero-knowledge requires ALL private-key and DEK crypto to run in the browser (static/js/
ecc_crypto.js); the server only ever stores a public key and browser-produced opaque ciphertext.
This is a STATIC test — it scans the live server source as text (no imports, so it runs anywhere)
and fails if a server-side private-key / plaintext-DEK helper is (re)introduced. It exists because
such helpers previously lived in app/services/ecc_crypto_service.py with no live caller — a foot-gun a future
wiring mistake could turn into a zero-knowledge-breaking server-side key path.
"""
import re
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent.parent

# Server-side private-key / plaintext-DEK helper names that must NOT appear in live server code.
_FORBIDDEN = [
    "generate_ecc_keypair",
    "export_private_key",
    "import_private_key",
    "encrypt_private_key",         # server-side private-key password encryption
    "decrypt_private_key",         # server-side private-key decryption
    "wrap_vault_dek_for_member",
    "unwrap_vault_dek_for_member",
    "add_member_to_vault",
    "generate_vault_dek",          # server-side DEK generation
]

# Not live server code (tests, deps, caches, browser assets).
_SKIP_PARTS = {"tests", ".venv", "venv", "__pycache__", "node_modules", ".git", "static"}


def _live_py_files():
    for p in _APP_DIR.rglob("*.py"):
        if any(part in _SKIP_PARTS for part in p.parts):
            continue
        yield p


def test_no_server_side_private_key_helpers_in_live_code():
    offenders = {}
    for p in _live_py_files():
        text = p.read_text(encoding="utf-8", errors="ignore")
        hits = [name for name in _FORBIDDEN if re.search(rf"\b{name}\b", text)]
        if hits:
            offenders[str(p.relative_to(_APP_DIR))] = hits
    assert not offenders, (
        "server-side private-key / plaintext-DEK helper(s) reappeared in live code — the "
        "zero-knowledge model requires these to run ONLY in the browser: " + repr(offenders)
    )


def test_ecc_crypto_service_does_no_private_key_or_dek_crypto():
    """The ECC service must not generate, import, serialize, encrypt, or decrypt any private key,
    nor wrap/unwrap a DEK — it is a public-key-only module."""
    text = (_APP_DIR / "app/services/ecc_crypto_service.py").read_text(encoding="utf-8", errors="ignore")
    for forbidden in ("private_bytes", "generate_private_key", "load_pem_private_key",
                      "PBKDF2HMAC", "aes_key_wrap", "aes_key_unwrap", "AESGCM"):
        assert forbidden not in text, f"ecc_crypto_service must not use {forbidden} (private-key/DEK crypto)"
