"""Credential unlocking primitives used by explicit runtime bootstrap.

Importing this module is inert: it never reads a dotenv, prompts, prints, exits,
connects to a keychain, or writes. Entry points opt into those operations by calling
``CredentialManager.unlock_or_raise`` through ``app.core.config``.
"""

import base64
import getpass
import os
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    keyring = None
    KEYRING_AVAILABLE = False


class CredentialUnlockError(RuntimeError):
    """Typed credential failure with a message safe for startup logs."""

    def __init__(self, code: str, safe_message: str):
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


# bcrypt hashes at most the first 72 BYTES of its input. Clamp verification input
# for compatibility with hashes created by older bcrypt releases that truncated it.
BCRYPT_MAX_PASSWORD_BYTES = 72


def bcrypt_password_bytes(password: str) -> bytes:
    """UTF-8 encode a password and clamp it to bcrypt's 72-byte input limit."""
    return password.encode("utf-8")[:BCRYPT_MAX_PASSWORD_BYTES]


class CredentialManager:
    """Own plaintext or decrypted credentials for one initialized process."""

    _CREDENTIAL_NAMES = (
        "ENCRYPTION_KEY",
        "DATABASE_URL",
        "REDIS_PASSWORD",
        "JWT_SECRET_KEY",
        "ADMIN_PASSWORD",
    )

    def __init__(self):
        self.credentials = {}
        self.is_unlocked = False
        self._fernet_cipher = None

    def derive_key_from_password(self, password: str, salt: str) -> bytes:
        """Derive the optional encrypted-dotenv key with PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=600000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def get_password_from_keychain(self) -> Optional[str]:
        """Retrieve a saved password at runtime; keychain failures stay silent."""
        if not KEYRING_AVAILABLE:
            return None
        try:
            return keyring.get_password("DockVault", "master_password")
        except Exception:
            return None

    def save_password_to_keychain(self, password: str) -> bool:
        """Save a password when an explicit caller requests it."""
        if not KEYRING_AVAILABLE:
            return False
        try:
            keyring.set_password("DockVault", "master_password", password)
            return True
        except Exception:
            return False

    def prompt_for_password(self) -> str:
        """Prompt only from the explicit interactive startup path."""
        try:
            return getpass.getpass("DockVault master password: ")
        except (EOFError, KeyboardInterrupt):
            raise CredentialUnlockError(
                "master-password-unavailable",
                "The encrypted credential store could not obtain a master password.",
            ) from None

    def verify_password(self, password: str) -> bool:
        """Verify a password without logging hash material or exception details."""
        password_hash = os.getenv("MASTER_PASSWORD_HASH")
        if not password_hash:
            return False
        try:
            return bcrypt.checkpw(
                bcrypt_password_bytes(password),
                password_hash.encode(),
            )
        except Exception:
            return False

    def check_legacy_mode(self) -> bool:
        """Return whether credentials are supplied directly by the environment."""
        return bool(
            os.getenv("ENCRYPTION_KEY")
            and not os.getenv("ENCRYPTED_ENCRYPTION_KEY")
            and not os.getenv("MASTER_PASSWORD_HASH")
        )

    def load_legacy_credentials(self) -> None:
        """Load plaintext process-environment credentials without output or I/O."""
        values = {name: os.getenv(name) for name in self._CREDENTIAL_NAMES}
        try:
            cipher = Fernet((values["ENCRYPTION_KEY"] or "").encode())
        except Exception:
            raise CredentialUnlockError(
                "encryption-key-invalid",
                "The configured file-encryption key is invalid.",
            ) from None
        self.credentials = values
        self._fernet_cipher = cipher
        self.is_unlocked = True

    def decrypt_credential(self, encrypted_value: str, fernet: Fernet) -> str:
        """Decrypt one credential without exposing ciphertext or exception detail."""
        try:
            return fernet.decrypt(encrypted_value.encode()).decode()
        except Exception:
            raise CredentialUnlockError(
                "credential-decryption-failed",
                "Encrypted credentials could not be decrypted.",
            ) from None

    def unlock_or_raise(
        self,
        max_attempts: int = 25,
        *,
        master_password: Optional[str] = None,
        interactive: bool = True,
    ) -> None:
        """Unlock once or raise a typed, sanitized startup failure."""
        if self.is_unlocked:
            return

        if self.check_legacy_mode():
            self.load_legacy_credentials()
            return

        if not os.getenv("ENCRYPTED_ENCRYPTION_KEY"):
            raise CredentialUnlockError(
                "required-secret-missing",
                "No complete plaintext or encrypted credential set is configured.",
            )
        if not os.getenv("MASTER_PASSWORD_HASH"):
            raise CredentialUnlockError(
                "encrypted-credentials-incomplete",
                "The encrypted credential set is incomplete.",
            )

        encrypted_values = {
            name: os.getenv(f"ENCRYPTED_{name}") for name in self._CREDENTIAL_NAMES
        }
        salt = os.getenv("MASTER_KEY_SALT")
        if not salt or any(not value for value in encrypted_values.values()):
            raise CredentialUnlockError(
                "encrypted-credentials-incomplete",
                "The encrypted credential set is incomplete.",
            )

        explicit_password = master_password is not None
        password = master_password if explicit_password else self.get_password_from_keychain()
        attempts = max(1, int(max_attempts))
        for attempt in range(attempts):
            if password is None:
                if not interactive:
                    raise CredentialUnlockError(
                        "master-password-unavailable",
                        "The encrypted credential store requires a master password.",
                    )
                password = self.prompt_for_password()

            if self.verify_password(password):
                break

            if explicit_password or not interactive or attempt == attempts - 1:
                raise CredentialUnlockError(
                    "master-password-invalid",
                    "The encrypted credential store rejected the master password.",
                )
            password = None
        else:  # defensive; the loop either breaks or raises
            raise CredentialUnlockError(
                "master-password-invalid",
                "The encrypted credential store rejected the master password.",
            )

        try:
            wrapping_key = self.derive_key_from_password(password, salt)
            wrapping_fernet = Fernet(wrapping_key)
            decrypted = {
                name: self.decrypt_credential(value, wrapping_fernet)
                for name, value in encrypted_values.items()
            }
            content_fernet = Fernet(decrypted["ENCRYPTION_KEY"].encode())
        except CredentialUnlockError:
            raise
        except Exception:
            raise CredentialUnlockError(
                "credential-decryption-failed",
                "Encrypted credentials could not be decrypted.",
            ) from None

        self.credentials = decrypted
        self._fernet_cipher = content_fernet
        self.is_unlocked = True

    def unlock(
        self,
        max_attempts: int = 25,
        *,
        master_password: Optional[str] = None,
        interactive: bool = True,
    ) -> bool:
        """Backward-compatible boolean wrapper around ``unlock_or_raise``."""
        try:
            self.unlock_or_raise(
                max_attempts,
                master_password=master_password,
                interactive=interactive,
            )
            return True
        except CredentialUnlockError:
            return False

    def get(self, key: str) -> Optional[str]:
        if not self.is_unlocked:
            raise RuntimeError("Credentials are not initialized")
        return self.credentials.get(key)

    def get_fernet(self) -> Fernet:
        if not self.is_unlocked or not self._fernet_cipher:
            raise RuntimeError("Credentials are not initialized")
        return self._fernet_cipher

    def is_legacy_mode(self) -> bool:
        return not os.getenv("ENCRYPTED_ENCRYPTION_KEY")


credential_manager = CredentialManager()


def require_unlock():
    """Decorator that guards functions requiring initialized credentials."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not credential_manager.is_unlocked:
                raise RuntimeError(
                    f"Cannot call {func.__name__}: credentials are not initialized"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
