"""
Security utilities for password hashing, encryption, and credential generation.
Implements industry-standard security practices.
"""
import secrets
import hashlib
import hmac
import base64
import struct
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jose import JWTError, jwt

from config import settings


# Argon2 password hasher (winner of Password Hashing Competition)
password_hasher = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # Memory usage in KiB (64 MB)
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of hash in bytes
    salt_len=16  # Length of salt in bytes
)

# Fernet encryption for files at rest
fernet = Fernet(settings.encryption_key.encode())

# --- AES-256-GCM chunked at-rest stream (format version 0x10) ---------------
# The legacy at-rest format is a global-key Fernet chunk stream (encrypt_chunk /
# decrypt_chunk_stream). Fernet has no AAD, so a stored blob is not bound to the
# vault/file it belongs to — an operator with disk access could swap one file's blob
# for another's. This new format uses AES-256-GCM with a per-chunk AAD = domain ||
# vault_id || file_id || chunk_index, binding every chunk to its vault+file (no
# cross-file/vault swap) and its position (no reorder). Whole-file truncation/tamper is
# independently caught by the stored plaintext SHA-256 that download_file verifies, so
# the chunk stream itself does not need a length/EOF marker.
#
# Keying: a deployment ROOT key is derived from settings.encryption_key (same secret
# lifecycle as the Fernet stream), and each FILE gets its own subkey via
# HKDF(root, info=vault_id||file_id). Per-file subkeys keep the AES-GCM random-nonce
# collision budget per-file (~2^32 chunks) instead of deployment-wide, and add a
# key-level vault+file binding on top of the AAD.
#
# Backward compatibility: NEW Standard-vault writes use this format; OLD Fernet-stream
# files keep being read by decrypt_chunk_stream (detected by the absence of the magic
# header). Zero-knowledge vaults are unaffected (their blobs are stored verbatim);
# their swap-resistance is the client's own AEAD + the server-stored checksum, not this
# AAD (the server holds no key for a ZK vault).
_GCM_STREAM_ROOT_KEY = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'dockvault-gcm-chunk-stream-key-v1',
    info=b'at-rest-content',
).derive(settings.encryption_key.encode())

# Full magic (the legacy EncryptedFileStorage compares only header[:5] to a 9-byte
# constant, so its detector never matches; we compare the FULL magic here).
GCM_STREAM_MAGIC = b'DockVault'
GCM_STREAM_VERSION = 0x10  # distinct from the (dead) whole-file GCM version 0x01
_GCM_STREAM_HEADER = GCM_STREAM_MAGIC + bytes([GCM_STREAM_VERSION]) + b'\x00\x00'  # +2 reserved
_GCM_NONCE_SIZE = 12
_CHUNK_AAD_DOMAIN = b'dockvault-chunk-aad-v1'


def _uuid_bytes(value) -> bytes:
    """16 raw bytes of a UUID, accepting a uuid.UUID or its string form."""
    return value.bytes if isinstance(value, uuid.UUID) else uuid.UUID(str(value)).bytes


def _chunk_stream_aad(vault_id, file_id, index: int) -> bytes:
    """Per-chunk associated data binding a chunk to its vault, file, and position."""
    return _CHUNK_AAD_DOMAIN + _uuid_bytes(vault_id) + _uuid_bytes(file_id) + struct.pack('>Q', index)


def _gcm_stream_subkey(vault_id, file_id) -> bytes:
    """Per-file 32-byte AES key derived from the deployment root key. Each file having
    its own key makes the AES-GCM random-nonce collision budget per-file (~2^32 chunks)
    rather than deployment-wide, and binds the blob to its vault+file at the KEY level
    (defense in depth on top of the per-chunk AAD). Same encryption_key lifecycle."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dockvault-gcm-chunk-subkey-v1',
        info=_uuid_bytes(vault_id) + _uuid_bytes(file_id),
    ).derive(_GCM_STREAM_ROOT_KEY)


class GcmChunkStreamCodec:
    """Stateless-per-chunk writer codec for the AES-256-GCM chunked at-rest stream.

    On-disk: [header][record]* where header = MAGIC + 0x10 + 2 reserved and each
    record = [4-byte BE len of (nonce+ct)][12-byte nonce][ciphertext+16-byte tag].
    Each record is encrypted under this file's subkey with AAD =
    _chunk_stream_aad(vault_id, file_id, index).
    """

    def __init__(self, vault_id, file_id):
        self._aesgcm = AESGCM(_gcm_stream_subkey(vault_id, file_id))
        self._vault_id = vault_id
        self._file_id = file_id

    def header(self) -> bytes:
        return _GCM_STREAM_HEADER

    def encrypt(self, chunk: bytes, index: int) -> bytes:
        nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
        aad = _chunk_stream_aad(self._vault_id, self._file_id, index)
        ct = self._aesgcm.encrypt(nonce, chunk, aad)
        return struct.pack('>I', _GCM_NONCE_SIZE + len(ct)) + nonce + ct


class IdentityChunkCodec:
    """Passthrough codec for zero-knowledge vaults: store the client's ciphertext
    verbatim with no header (parity with the previous identity-lambda behaviour)."""

    def header(self) -> bytes:
        return b''

    def encrypt(self, chunk: bytes, index: int) -> bytes:
        return chunk


def is_gcm_chunk_stream(storage_path) -> bool:
    """Cheap, non-decrypting peek: True iff the file begins with the GCM chunked-stream
    magic + version. Legacy Fernet streams start with a 4-byte chunk length (no magic),
    so they return False and route to decrypt_chunk_stream."""
    try:
        prefix_len = len(GCM_STREAM_MAGIC) + 1
        with open(storage_path, 'rb') as f:
            head = f.read(prefix_len)
        return (len(head) == prefix_len
                and head[:len(GCM_STREAM_MAGIC)] == GCM_STREAM_MAGIC
                and head[len(GCM_STREAM_MAGIC)] == GCM_STREAM_VERSION)
    except Exception:
        return False


def decrypt_gcm_chunk_stream(file_handle, vault_id, file_id) -> bytes:
    """Decrypt an AES-256-GCM chunked stream, authenticating each chunk against its
    per-chunk AAD (vault_id, file_id, index). Raises EncryptionError on any mismatch —
    e.g. a blob swapped in from another file/vault (file_id/vault_id differ) or reordered
    chunks (index differs)."""
    header = file_handle.read(len(_GCM_STREAM_HEADER))
    if (len(header) < len(_GCM_STREAM_HEADER)
            or header[:len(GCM_STREAM_MAGIC)] != GCM_STREAM_MAGIC
            or header[len(GCM_STREAM_MAGIC)] != GCM_STREAM_VERSION):
        raise EncryptionError("Not a valid AES-GCM chunk stream")
    aesgcm = AESGCM(_gcm_stream_subkey(vault_id, file_id))
    out = []
    index = 0
    try:
        while True:
            length_header = file_handle.read(4)
            if not length_header or len(length_header) < 4:
                break
            rec_len = struct.unpack('>I', length_header)[0]
            record = file_handle.read(rec_len)
            if len(record) != rec_len:
                raise EncryptionError("Incomplete chunk in encrypted file")
            nonce, ct = record[:_GCM_NONCE_SIZE], record[_GCM_NONCE_SIZE:]
            aad = _chunk_stream_aad(vault_id, file_id, index)
            out.append(aesgcm.decrypt(nonce, ct, aad))
            index += 1
    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt AES-GCM chunk stream: {e}")
    return b''.join(out)


# --- Filename / MIME encryption at rest (Standard vaults) -------------------
# Names/MIME were stored plaintext. Encrypt them at rest under the SAME deployment
# secret that protects file CONTENT (the vault password is only an access gate, not the
# content key — see the SFTP design), so the server can always derive these keys and
# backfill is EAGER for every vault (no password needed, no lazy migration).
#
#  * Per-OBJECT cipher key: HKDF(name-root, vault_id||obj_id) -> AES-256-GCM. Names are
#    short, so each (filename, mime) is a single GCM blob with AAD = field||vault||obj.
#  * Per-VAULT blind index: HMAC(name) under a per-vault key, so the same name in a vault
#    maps to the same digest. This preserves the server-side EXACT-match the app relies
#    on (SFTP path resolution, no-clobber, rename uniqueness, dedup) without storing the
#    plaintext. (No server-side substring search exists today, so exact-match suffices.)
# Zero-knowledge vaults are NOT sealed with these server-held keys — their names are
# encrypted IN THE BROWSER under the per-vault DEK (which the server never holds). Such
# blobs are stored verbatim in the SAME enc_name/enc_mime columns but carry the marker
# prefix below so the server can tell them apart and never tries (and fails) to decrypt
# them. See docs/vault-zk-name-encryption.md and static/js/ecc_crypto.js.
#
# ZK_NAME_PREFIX MUST match the prefix the browser writes (ecc_crypto.js encryptName):
# enc_name/enc_mime for a ZK object = ZK_NAME_PREFIX + base64(iv||ciphertext+tag).
ZK_NAME_PREFIX = 'zk1:'


def is_zk_sealed_name(token) -> bool:
    """True if an enc_name/enc_mime blob was sealed CLIENT-SIDE for a zero-knowledge
    vault (the server has no key for it). Lets the transparent-decrypt load events and
    any server reader skip ZK blobs instead of treating them as server-decryptable."""
    return bool(token) and str(token).startswith(ZK_NAME_PREFIX)


_NAME_ENC_ROOT = HKDF(
    algorithm=hashes.SHA256(), length=32,
    salt=b'dockvault-name-enc-key-v1', info=b'filename-mime',
).derive(settings.encryption_key.encode())
_NAME_BI_ROOT = HKDF(
    algorithm=hashes.SHA256(), length=32,
    salt=b'dockvault-name-bi-key-v1', info=b'filename-blind-index',
).derive(settings.encryption_key.encode())


def _name_object_key(vault_id, obj_id) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-obj-v1',
        info=_uuid_bytes(vault_id) + _uuid_bytes(obj_id),
    ).derive(_NAME_ENC_ROOT)


def _name_field_aad(field: str, vault_id, obj_id) -> bytes:
    return b'dockvault-field:' + field.encode() + b':' + _uuid_bytes(vault_id) + _uuid_bytes(obj_id)


def encrypt_object_field(vault_id, obj_id, plaintext: str, field: str) -> str:
    """Encrypt a small per-object string (filename or MIME) at rest. Returns base64 of
    nonce||ciphertext+tag. `field` ('name'/'mime') is bound via AAD so the two fields of
    one object aren't interchangeable."""
    aesgcm = AESGCM(_name_object_key(vault_id, obj_id))
    nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), _name_field_aad(field, vault_id, obj_id))
    return base64.b64encode(nonce + ct).decode('ascii')


def decrypt_object_field(vault_id, obj_id, token: str, field: str) -> str:
    """Inverse of encrypt_object_field. Raises on tamper / wrong object."""
    raw = base64.b64decode(token)
    nonce, ct = raw[:_GCM_NONCE_SIZE], raw[_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(_name_object_key(vault_id, obj_id))
    return aesgcm.decrypt(nonce, ct, _name_field_aad(field, vault_id, obj_id)).decode('utf-8')


def name_blind_index(vault_id, name: str) -> str:
    """Deterministic per-vault HMAC-SHA256 of an EXACT name, for server-side equality
    lookup without storing plaintext. Same (vault_id, name) -> same hex digest."""
    key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-bi-vault-v1', info=_uuid_bytes(vault_id),
    ).derive(_NAME_BI_ROOT)
    return hmac.new(key, name.encode('utf-8'), hashlib.sha256).hexdigest()


def vault_password_fingerprint(password_hash: str) -> str:
    """A stable, non-reversible fingerprint of a vault's stored password hash.

    Captured when a temporary credential proves a vault's password, and re-checked on
    every SFTP access. If the vault's password is later added, changed, or rotated, its
    stored hash string changes, this fingerprint no longer matches, and the credential's
    standing proof is void — so SFTP tracks the live password exactly as the web's
    per-request check does (no proof frozen at mint outliving a rotation)."""
    return hashlib.sha256((password_hash or "").encode()).hexdigest()


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class PasswordHashingError(SecurityError):
    """Exception raised when password hashing fails."""
    pass


class PasswordVerificationError(SecurityError):
    """Exception raised when password verification fails."""
    pass


class EncryptionError(SecurityError):
    """Exception raised when encryption operations fail."""
    pass


# Password Hashing Functions
def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hashed password string
        
    Raises:
        PasswordHashingError: If hashing fails
    """
    try:
        return password_hasher.hash(password)
    except Exception as e:
        raise PasswordHashingError(f"Failed to hash password: {str(e)}")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Hashed password to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        password_hasher.verify(password_hash, password)
        
        # Check if hash needs rehashing (parameters changed)
        if password_hasher.check_needs_rehash(password_hash):
            # In production, you should rehash and update the database
            pass
        
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
    except Exception:
        return False


# Temporary Credential Generation
def generate_temporary_credentials() -> Tuple[str, str, str]:
    """
    Generate temporary one-time credentials.
    
    Returns:
        Tuple of (username, credential_string, credential_hash)
    """
    # Generate a unique username for temporary access
    temp_username = f"temp_{uuid.uuid4().hex[:12]}"
    
    # Generate a 16-character alphanumeric password (enhanced security)
    # Using letters (uppercase + lowercase) and digits = 62 characters
    # 16 characters from 62-char alphabet = 62^16 ≈ 4.8×10^28 possibilities
    # (vs 12 chars = 62^12 ≈ 3.2×10^21 possibilities)
    import string
    alphabet = string.ascii_letters + string.digits
    credential_string = ''.join(secrets.choice(alphabet) for _ in range(16))
    
    # Hash the credential for storage (bcrypt - one-way hashing)
    credential_hash = hash_password(credential_string)
    
    return temp_username, credential_string, credential_hash


def verify_temporary_credential(credential: str, credential_hash: str) -> bool:
    """
    Verify a temporary credential against its hash.
    
    Args:
        credential: Plain text credential to verify
        credential_hash: Hashed credential to verify against
        
    Returns:
        True if credential matches, False otherwise
    """
    return verify_password(credential, credential_hash)


# File Encryption Functions
def encrypt_file_content(content: bytes) -> bytes:
    """
    Encrypt file content using Fernet (AES-128 in CBC mode).
    
    Args:
        content: Plain file content as bytes
        
    Returns:
        Encrypted content as bytes
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        return fernet.encrypt(content)
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt content: {str(e)}")


def encrypt_chunk(chunk: bytes) -> bytes:
    """
    Encrypt a single chunk of data.
    Each chunk is encrypted independently for streaming support.
    
    Args:
        chunk: Chunk of data to encrypt
        
    Returns:
        Encrypted chunk with 4-byte length header
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        encrypted = fernet.encrypt(chunk)
        # Prepend chunk length for streaming decryption (4 bytes, big-endian)
        import struct
        length_header = struct.pack('>I', len(encrypted))
        return length_header + encrypted
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt chunk: {str(e)}")


def decrypt_chunk_stream(file_handle):
    """
    Generator that decrypts chunks from a file handle.
    Reads 4-byte length header, then encrypted chunk, decrypts and yields.
    
    Args:
        file_handle: File handle opened in binary read mode
        
    Yields:
        Decrypted chunks
        
    Raises:
        EncryptionError: If decryption fails
    """
    import struct
    try:
        while True:
            # Read 4-byte length header
            length_header = file_handle.read(4)
            if not length_header or len(length_header) < 4:
                break
            
            chunk_length = struct.unpack('>I', length_header)[0]
            
            # Read encrypted chunk
            encrypted_chunk = file_handle.read(chunk_length)
            if len(encrypted_chunk) != chunk_length:
                raise EncryptionError("Incomplete chunk in encrypted file")
            
            # Decrypt and yield
            decrypted = fernet.decrypt(encrypted_chunk)
            yield decrypted
    except Exception as e:
        if "Incomplete chunk" in str(e):
            raise
        raise EncryptionError(f"Failed to decrypt chunk: {str(e)}")


def decrypt_file_content(encrypted_content: bytes) -> bytes:
    """
    Decrypt file content using Fernet.
    
    Args:
        encrypted_content: Encrypted file content as bytes
        
    Returns:
        Decrypted content as bytes
        
    Raises:
        EncryptionError: If decryption fails
    """
    try:
        return fernet.decrypt(encrypted_content)
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt content: {str(e)}")


def encrypt_string(plain_text: str) -> str:
    """
    Encrypt a string value.
    
    Args:
        plain_text: Plain text string
        
    Returns:
        Encrypted string (base64 encoded)
    """
    try:
        encrypted = fernet.encrypt(plain_text.encode())
        return encrypted.decode()
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt string: {str(e)}")


def decrypt_string(encrypted_text: str) -> str:
    """
    Decrypt an encrypted string value.
    
    Args:
        encrypted_text: Encrypted string (base64 encoded)
        
    Returns:
        Decrypted plain text string
    """
    try:
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt string: {str(e)}")


# File Integrity Functions
def calculate_file_checksum(content: bytes) -> str:
    """
    Calculate SHA-256 checksum of file content.
    
    Args:
        content: File content as bytes
        
    Returns:
        Hexadecimal checksum string
    """
    return hashlib.sha256(content).hexdigest()


def verify_file_integrity(content: bytes, expected_checksum: str) -> bool:
    """
    Verify file integrity using checksum.
    
    Args:
        content: File content as bytes
        expected_checksum: Expected SHA-256 checksum
        
    Returns:
        True if checksums match, False otherwise
    """
    actual_checksum = calculate_file_checksum(content)
    return secrets.compare_digest(actual_checksum, expected_checksum)


# JWT Token Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        )
    
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


def verify_access_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token data if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError:
        return None


# Session Token Generation
def generate_session_token() -> str:
    """
    Generate a secure session token.
    
    Returns:
        URL-safe session token string
    """
    return secrets.token_urlsafe(32)


# Secure Random String Generation
def generate_secure_random_string(length: int = 32) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length: Length of the string in bytes (default 32)
        
    Returns:
        URL-safe random string
    """
    return secrets.token_urlsafe(length)


# Input Sanitization
def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove any path separators and null bytes
    filename = filename.replace('/', '').replace('\\', '').replace('\0', '')
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        # Preserve extension if present
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        if ext:
            filename = name[:255-len(ext)-1] + '.' + ext
        else:
            filename = filename[:255]
    
    # Ensure filename is not empty
    if not filename:
        filename = f"file_{uuid.uuid4().hex[:8]}"
    
    return filename


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a path component (folder/vault name).
    
    Args:
        component: Original path component
        
    Returns:
        Sanitized path component
    """
    return sanitize_filename(component)
