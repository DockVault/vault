"""
Vault Key Management Utilities
===============================

Handles vault-specific encryption key generation, derivation, and encryption.

This module provides cryptographic functions for implementing per-vault encryption keys:
1. Each vault has a unique encryption key
2. Vault keys are encrypted with either vault password or master key
3. Password-protected vaults use PBKDF2 key derivation
4. Non-password-protected vaults are encrypted with master ENCRYPTION_KEY

Security Benefits:
- Vault isolation: Compromising one vault doesn't expose others
- Defense in depth: Password + encryption layers
- Key rotation: Can rotate keys per-vault
- Least privilege: Each vault has minimum necessary access
"""

import os
import json
import base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class VaultKeyError(Exception):
    """Base exception for vault key operations."""
    pass


class InvalidVaultKeyError(VaultKeyError):
    """Raised when vault key decryption fails."""
    pass


def generate_vault_key() -> bytes:
    """
    Generate a new random vault encryption key.
    
    Uses Fernet.generate_key() which creates a URL-safe base64-encoded
    32-byte key suitable for Fernet symmetric encryption.
    
    Returns:
        bytes: 32-byte random key (URL-safe base64-encoded)
    
    Example:
        >>> key = generate_vault_key()
        >>> len(base64.urlsafe_b64decode(key))
        32
    """
    return Fernet.generate_key()


def generate_salt() -> str:
    """
    Generate a random salt for PBKDF2 key derivation.
    
    Creates a cryptographically secure 16-byte random salt,
    encoded as URL-safe base64 for storage.
    
    Returns:
        str: Base64-encoded 16-byte salt
    
    Example:
        >>> salt = generate_salt()
        >>> isinstance(salt, str)
        True
        >>> len(base64.urlsafe_b64decode(salt.encode()))
        16
    """
    return base64.urlsafe_b64encode(os.urandom(16)).decode()


def derive_key_encryption_key(
    password: str,
    salt: str,
    iterations: int = 100000
) -> bytes:
    """
    Derive a key encryption key (KEK) from vault password using PBKDF2.
    
    Uses PBKDF2-HMAC-SHA256 with 100,000 iterations (OWASP recommended minimum).
    The derived key is suitable for use with Fernet encryption.
    
    Args:
        password: Vault password (plaintext)
        salt: Base64-encoded salt
        iterations: PBKDF2 iteration count (default 100,000)
    
    Returns:
        bytes: 32-byte key encryption key (URL-safe base64-encoded)
    
    Raises:
        ValueError: If password is empty or salt is invalid
    
    Example:
        >>> password = "my_vault_password"
        >>> salt = generate_salt()
        >>> kek = derive_key_encryption_key(password, salt)
        >>> len(base64.urlsafe_b64decode(kek))
        32
    
    Security Notes:
        - 100,000 iterations provides ~100ms delay on modern hardware
        - Salt must be unique per vault to prevent rainbow table attacks
        - KEK is used to encrypt/decrypt the vault's encryption key
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if not salt:
        raise ValueError("Salt cannot be empty")
    
    try:
        salt_bytes = base64.urlsafe_b64decode(salt.encode())
    except Exception as e:
        raise ValueError(f"Invalid salt encoding: {e}")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=iterations
    )
    
    derived_key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(derived_key)


def encrypt_vault_key(
    vault_key: bytes,
    password: Optional[str] = None,
    master_key: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Encrypt a vault key with either password-derived key or master key.
    
    Password-Protected Vaults:
        1. Generate random salt
        2. Derive KEK from password using PBKDF2
        3. Encrypt vault_key with KEK using Fernet
    
    Non-Password-Protected Vaults:
        1. Encrypt vault_key with master_key using Fernet
    
    Args:
        vault_key: The vault's encryption key (32 bytes from generate_vault_key())
        password: Optional vault password (for password-protected vaults)
        master_key: Optional master key (for non-password-protected vaults)
    
    Returns:
        Dictionary with encrypted key and metadata:
        {
            'encrypted_key': str,     # Base64-encoded encrypted vault key
            'salt': Optional[str],    # Base64-encoded salt (if password-protected)
            'method': str,            # 'password' or 'master_key'
            'iterations': Optional[int],  # PBKDF2 iterations (if password-protected)
            'version': int            # Key version (1)
        }
    
    Raises:
        ValueError: If neither password nor master_key provided
        VaultKeyError: If encryption fails
    
    Example (password-protected):
        >>> vault_key = generate_vault_key()
        >>> result = encrypt_vault_key(vault_key, password="my_password")
        >>> result['method']
        'password'
        >>> 'salt' in result
        True
    
    Example (non-password-protected):
        >>> vault_key = generate_vault_key()
        >>> result = encrypt_vault_key(vault_key, master_key=MASTER_KEY)
        >>> result['method']
        'master_key'
        >>> result['salt']
        None
    """
    if not password and not master_key:
        raise ValueError("Either password or master_key must be provided")
    
    if password and master_key:
        # Prefer password over master_key if both provided
        master_key = None
    
    try:
        if password:
            # Password-protected vault: derive KEK from password
            salt = generate_salt()
            kek = derive_key_encryption_key(password, salt)
            fernet_kek = Fernet(kek)
            encrypted_key = fernet_kek.encrypt(vault_key)
            
            return {
                'encrypted_key': base64.urlsafe_b64encode(encrypted_key).decode(),
                'salt': salt,
                'method': 'password',
                'iterations': 100000,
                'version': 1
            }
        
        else:  # master_key
            # Non-password-protected vault: encrypt with master key
            if not master_key:
                raise ValueError("Master key is required but was not provided")
            fernet_master = Fernet(master_key)
            encrypted_key = fernet_master.encrypt(vault_key)
            
            return {
                'encrypted_key': base64.urlsafe_b64encode(encrypted_key).decode(),
                'salt': None,
                'method': 'master_key',
                'iterations': None,
                'version': 1
            }
    
    except Exception as e:
        raise VaultKeyError(f"Failed to encrypt vault key: {str(e)}")


def decrypt_vault_key(
    encrypted_data: Dict[str, Any],
    password: Optional[str] = None,
    master_key: Optional[bytes] = None
) -> bytes:
    """
    Decrypt a vault key.
    
    Uses the encryption method from encrypted_data to determine
    whether to use password-derived KEK or master key.
    
    Args:
        encrypted_data: Dictionary with encrypted key and metadata
            {
                'encrypted_key': str,
                'salt': Optional[str],
                'method': str,  # 'password' or 'master_key'
                'iterations': Optional[int],
                'version': int
            }
        password: Optional vault password (required if method='password')
        master_key: Optional master key (required if method='master_key')
    
    Returns:
        bytes: Decrypted vault key (32-byte URL-safe base64-encoded)
    
    Raises:
        ValueError: If required decryption credential not provided
        InvalidVaultKeyError: If decryption fails (wrong password/key)
        VaultKeyError: If metadata is invalid
    
    Example (password-protected):
        >>> encrypted_data = encrypt_vault_key(vault_key, password="my_password")
        >>> decrypted_key = decrypt_vault_key(encrypted_data, password="my_password")
        >>> decrypted_key == vault_key
        True
    
    Example (wrong password):
        >>> encrypted_data = encrypt_vault_key(vault_key, password="my_password")
        >>> decrypt_vault_key(encrypted_data, password="wrong_password")
        InvalidVaultKeyError: Invalid vault password or corrupted key
    """
    if 'encrypted_key' not in encrypted_data:
        raise VaultKeyError("Missing 'encrypted_key' in encrypted_data")
    
    if 'method' not in encrypted_data:
        raise VaultKeyError("Missing 'method' in encrypted_data")
    
    try:
        encrypted_key_b64 = encrypted_data['encrypted_key']
        encrypted_key = base64.urlsafe_b64decode(encrypted_key_b64.encode())
        method = encrypted_data['method']
        
        if method == 'password':
            if not password:
                raise ValueError("Password required to decrypt vault key (vault is password-protected)")
            
            if 'salt' not in encrypted_data or not encrypted_data['salt']:
                raise VaultKeyError("Missing salt for password-protected vault")
            
            salt = encrypted_data['salt']
            iterations = encrypted_data.get('iterations', 100000)
            
            kek = derive_key_encryption_key(password, salt, iterations)
            fernet_kek = Fernet(kek)
            
            try:
                return fernet_kek.decrypt(encrypted_key)
            except InvalidToken:
                raise InvalidVaultKeyError(
                    "Invalid vault password or corrupted key"
                )
        
        elif method == 'master_key':
            if not master_key:
                raise ValueError("Master key required to decrypt vault key")
            
            fernet_master = Fernet(master_key)
            
            try:
                return fernet_master.decrypt(encrypted_key)
            except InvalidToken:
                raise InvalidVaultKeyError(
                    "Invalid master key or corrupted vault key"
                )
        
        else:
            raise VaultKeyError(f"Unknown encryption method: {method}")
    
    except InvalidVaultKeyError:
        # Re-raise as-is
        raise
    except ValueError:
        # Re-raise as-is
        raise
    except VaultKeyError:
        # Re-raise as-is
        raise
    except Exception as e:
        raise VaultKeyError(f"Failed to decrypt vault key: {str(e)}")


def get_vault_fernet(
    vault,
    password: Optional[str] = None,
    master_key: Optional[bytes] = None
) -> Fernet:
    """
    Get a Fernet instance for vault-specific encryption/decryption.
    
    This is the main entry point for file encryption/decryption operations.
    It handles:
    1. Loading vault's encrypted key metadata
    2. Decrypting vault key with appropriate method
    3. Creating Fernet instance with vault key
    
    Args:
        vault: Vault model instance with encryption key columns:
            - encrypted_vault_key: Base64-encoded encrypted key
            - key_salt: Salt for PBKDF2 (if password-protected)
            - key_version: Key version number
            - key_encryption_metadata: JSON metadata
            - password_hash: Indicates if password-protected
        password: Optional vault password (required for password-protected vaults)
        master_key: Optional master key (for non-password-protected vaults)
    
    Returns:
        Fernet: Fernet instance configured with vault's encryption key
    
    Raises:
        ValueError: If vault has no encryption key or password required but not provided
        InvalidVaultKeyError: If password is incorrect
        VaultKeyError: If metadata is corrupted
    
    Example:
        >>> vault_fernet = get_vault_fernet(vault, password="my_password")
        >>> encrypted_file = vault_fernet.encrypt(file_content)
        >>> decrypted_file = vault_fernet.decrypt(encrypted_file)
    
    Usage in vault_service.py:
        # Upload file
        vault_fernet = get_vault_fernet(vault, password=vault_password)
        encrypted_content = vault_fernet.encrypt(file_content)
        
        # Download file
        vault_fernet = get_vault_fernet(vault, password=vault_password)
        file_content = vault_fernet.decrypt(encrypted_content)
    """
    if not vault.encrypted_vault_key:
        raise ValueError(f"Vault {vault.id} has no encryption key")
    
    # Load encryption metadata
    try:
        if vault.key_encryption_metadata:
            if isinstance(vault.key_encryption_metadata, str):
                metadata = json.loads(vault.key_encryption_metadata)
            else:
                metadata = vault.key_encryption_metadata
        else:
            # Fallback for legacy vaults
            metadata = {}
    except (json.JSONDecodeError, TypeError) as e:
        raise VaultKeyError(f"Invalid key encryption metadata: {e}")
    
    # Build encrypted data structure
    encrypted_data = {
        'encrypted_key': vault.encrypted_vault_key,
        'salt': vault.key_salt,
        'method': metadata.get('method', 'password' if vault.password_hash else 'master_key'),
        'iterations': metadata.get('iterations', 100000),
        'version': vault.key_version or 1
    }
    
    # Decrypt vault key
    vault_key = decrypt_vault_key(
        encrypted_data,
        password=password,
        master_key=master_key
    )
    
    # Create and return Fernet instance
    return Fernet(vault_key)


def validate_vault_key_setup(vault) -> Dict[str, Any]:
    """
    Validate that a vault has proper encryption key setup.
    
    Checks:
    - encrypted_vault_key exists
    - key_salt exists (if password-protected)
    - key_encryption_metadata is valid JSON
    - key_version is set
    
    Args:
        vault: Vault model instance
    
    Returns:
        Dictionary with validation results:
        {
            'valid': bool,
            'has_encrypted_key': bool,
            'has_salt': bool,
            'has_metadata': bool,
            'method': str,
            'issues': List[str]
        }
    
    Example:
        >>> result = validate_vault_key_setup(vault)
        >>> if not result['valid']:
        >>>     print(f"Issues: {result['issues']}")
    """
    issues = []
    
    has_encrypted_key = bool(vault.encrypted_vault_key)
    if not has_encrypted_key:
        issues.append("Missing encrypted_vault_key")
    
    has_salt = bool(vault.key_salt)
    has_metadata = bool(vault.key_encryption_metadata)
    
    # Determine method
    method = None
    if has_metadata:
        try:
            if isinstance(vault.key_encryption_metadata, str):
                metadata = json.loads(vault.key_encryption_metadata)
            else:
                metadata = vault.key_encryption_metadata
            method = metadata.get('method')
        except json.JSONDecodeError:
            issues.append("Invalid key_encryption_metadata JSON")
    
    # Validate based on method
    if method == 'password':
        if not has_salt:
            issues.append("Password-protected vault missing key_salt")
    
    if not vault.key_version:
        issues.append("Missing key_version")
    
    return {
        'valid': len(issues) == 0,
        'has_encrypted_key': has_encrypted_key,
        'has_salt': has_salt,
        'has_metadata': has_metadata,
        'method': method,
        'issues': issues
    }


def get_vault_key_bytes(
    vault,
    password: Optional[str] = None,
    master_key: Optional[bytes] = None,
    key_version: Optional[int] = None
) -> bytes:
    """
    Get raw 32-byte encryption key for a vault.
    
    This function extracts the actual encryption key bytes without wrapping
    in Fernet. Useful for AES-GCM or other encryption schemes.
    
    Args:
        vault: Vault model instance with encryption key columns
        password: Optional vault password (required for password-protected vaults)
        master_key: Optional master key (for non-password-protected vaults)
        key_version: Optional specific key version to retrieve (default: current)
    
    Returns:
        bytes: 32-byte encryption key
    
    Raises:
        ValueError: If vault has no encryption key or password required but not provided
        InvalidVaultKeyError: If password is incorrect
        VaultKeyError: If metadata is corrupted
    
    Example:
        >>> vault_key = get_vault_key_bytes(vault, password="my_password")
        >>> print(len(vault_key))  # 32
        >>> # Use with AES-GCM
        >>> from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        >>> aesgcm = AESGCM(vault_key)
        >>> encrypted = aesgcm.encrypt(nonce, plaintext, None)
    """
    import json
    import base64
    
    if not vault.encrypted_vault_key:
        raise ValueError(f"Vault {vault.id} has no encryption key")
    
    # Parse encryption metadata
    try:
        if vault.key_encryption_metadata:
            if isinstance(vault.key_encryption_metadata, str):
                metadata = json.loads(vault.key_encryption_metadata)
            else:
                metadata = vault.key_encryption_metadata
        else:
            # Default to master key method if no metadata
            metadata = {'method': 'master_key'}
    except json.JSONDecodeError as e:
        raise VaultKeyError(f"Invalid key encryption metadata: {e}")
    
    # Build encrypted_data dict for decrypt_vault_key function
    encrypted_data = {
        'encrypted_key': vault.encrypted_vault_key,
        'method': metadata.get('method', 'master_key'),
        'version': vault.key_version or 1
    }
    
    # Add salt if available (for password method)
    if vault.key_salt:
        encrypted_data['salt'] = vault.key_salt
    
    # Add iterations if in metadata
    if 'iterations' in metadata:
        encrypted_data['iterations'] = metadata['iterations']
    
    # Decrypt the vault key using existing function
    vault_key_b64 = decrypt_vault_key(encrypted_data, password=password, master_key=master_key)
    
    # vault_key_b64 is base64-encoded Fernet key, decode it to get raw bytes
    vault_key_bytes = base64.urlsafe_b64decode(vault_key_b64)
    
    # Fernet keys are 32 bytes
    if len(vault_key_bytes) != 32:
        raise VaultKeyError(f"Invalid vault key length: {len(vault_key_bytes)} bytes")
    
    return vault_key_bytes


def rotate_vault_key(vault, master_key: bytes, db) -> int:
    """
    Rotate a vault's encryption key to a new version.
    
    This function performs the following steps:
    1. Archives the current key to VaultKeyHistory
    2. Generates a new random 32-byte key
    3. Encrypts the new key with the master key
    4. Increments the vault's key_version
    5. Updates the vault with the new encrypted key
    
    After rotation:
    - New file uploads use the new key version
    - Old files can still be decrypted using historical keys
    - No re-encryption of existing files is required
    
    Args:
        vault: Vault model instance to rotate key for
        master_key: Master encryption key (from settings.encryption_key)
        db: SQLAlchemy database session
    
    Returns:
        int: New key version number
    
    Raises:
        VaultKeyError: If rotation fails
    
    Example:
        >>> from app.core.config import settings
        >>> master_key = settings.encryption_key.encode()
        >>> new_version = rotate_vault_key(vault, master_key, db)
        >>> print(f"Key rotated to version {new_version}")
    """
    from app.core.models import VaultKeyHistory
    from datetime import datetime
    import secrets
    
    try:
        # Step 1: Archive current key to history
        old_key_history = VaultKeyHistory(
            vault_id=vault.id,
            key_version=vault.key_version,
            encrypted_key=vault.encrypted_vault_key,
            key_salt=vault.key_salt,
            key_encryption_metadata=vault.key_encryption_metadata,
            created_at=vault.key_created_at or datetime.now(timezone.utc),
            retired_at=datetime.now(timezone.utc)
        )
        db.add(old_key_history)
        
        # Step 2: Generate new random 32-byte key
        new_key_bytes = secrets.token_bytes(32)
        new_key_b64 = base64.urlsafe_b64encode(new_key_bytes).decode()
        
        # Step 3: Encrypt new key with master key
        # Fernet.generate_key() returns base64-encoded key, but we have raw bytes
        # We need to create a Fernet key format
        new_fernet_key = base64.urlsafe_b64encode(new_key_bytes)
        
        encrypted_result = encrypt_vault_key(
            vault_key=new_fernet_key,
            master_key=master_key
        )
        
        # Step 4: Increment version
        new_version = vault.key_version + 1
        
        # Step 5: Update vault
        vault.key_version = new_version
        vault.encrypted_vault_key = encrypted_result['encrypted_key']
        vault.key_salt = encrypted_result.get('salt')
        
        # Store metadata with method
        metadata = encrypted_result.get('metadata', {})
        metadata['method'] = encrypted_result['method']
        vault.key_encryption_metadata = json.dumps(metadata)
        vault.key_created_at = datetime.now(timezone.utc)
        
        # Commit changes
        db.commit()
        
        print(f"✅ Vault {vault.id} key rotated: v{vault.key_version - 1} → v{new_version}")
        
        return new_version
        
    except Exception as e:
        db.rollback()
        raise VaultKeyError(f"Key rotation failed: {str(e)}")


def get_vault_key_for_version(vault, key_version: int, master_key: bytes, 
                               password: Optional[str], db) -> bytes:
    """
    Retrieve vault encryption key for a specific version.
    
    This function supports multi-version key access:
    - If requested version matches current: returns current key
    - If requested version is historical: queries VaultKeyHistory
    - Decrypts and returns the raw 32-byte key
    
    This enables decryption of files encrypted with older key versions
    after key rotation, without requiring file re-encryption.
    
    Args:
        vault: Vault model instance
        key_version: Key version number to retrieve (1, 2, 3, etc.)
        master_key: Master encryption key
        password: Optional vault password (for password-protected vaults)
        db: SQLAlchemy database session
    
    Returns:
        bytes: Raw 32-byte encryption key for the specified version
    
    Raises:
        VaultKeyError: If key version not found or decryption fails
    
    Example:
        >>> # Download file encrypted with old key version
        >>> file_key_version = 1  # From file header
        >>> vault_key = get_vault_key_for_version(vault, file_key_version, master_key, None, db)
        >>> decrypted_content = decrypt_file(encrypted_content, vault_key)
    """
    from app.core.models import VaultKeyHistory
    
    # Case 1: Requested version is current
    if key_version == vault.key_version:
        return get_vault_key_bytes(vault, password=password, master_key=master_key)
    
    # Case 2: Requested version is historical
    historical_key = db.query(VaultKeyHistory).filter(
        VaultKeyHistory.vault_id == vault.id,
        VaultKeyHistory.key_version == key_version
    ).first()
    
    if not historical_key:
        raise VaultKeyError(
            f"Key version {key_version} not found for vault {vault.id}. "
            f"Current version: {vault.key_version}"
        )
    
    # Decrypt historical key
    metadata = json.loads(historical_key.key_encryption_metadata) if historical_key.key_encryption_metadata else {}
    
    encrypted_data = {
        'encrypted_key': historical_key.encrypted_key,
        'method': metadata.get('method', 'master_key'),
        'version': key_version
    }
    
    if historical_key.key_salt:
        encrypted_data['salt'] = historical_key.key_salt
    
    if 'iterations' in metadata:
        encrypted_data['iterations'] = metadata['iterations']
    
    # Decrypt and return raw bytes
    vault_key_b64 = decrypt_vault_key(encrypted_data, password=password, master_key=master_key)
    vault_key_bytes = base64.urlsafe_b64decode(vault_key_b64)
    
    if len(vault_key_bytes) != 32:
        raise VaultKeyError(f"Invalid historical key length: {len(vault_key_bytes)} bytes")
    
    print(f"📜 Retrieved historical key version {key_version} for vault {vault.id}")
    
    return vault_key_bytes


def get_vault_key_history(vault_id, db) -> List[Dict[str, Any]]:
    """
    Get the key rotation history for a vault.
    
    Returns a list of all key versions with their lifecycle information.
    Useful for auditing, compliance, and understanding rotation timeline.
    
    Args:
        vault_id: UUID of the vault
        db: SQLAlchemy database session
    
    Returns:
        List of dicts containing key version history:
        [
            {
                'key_version': 1,
                'created_at': datetime,
                'retired_at': datetime,
                'active_duration_days': 90
            },
            ...
        ]
    
    Example:
        >>> history = get_vault_key_history(vault.id, db)
        >>> for entry in history:
        >>>     print(f"Version {entry['key_version']}: {entry['active_duration_days']} days active")
    """
    from app.core.models import VaultKeyHistory
    
    history_entries = db.query(VaultKeyHistory).filter(
        VaultKeyHistory.vault_id == vault_id
    ).order_by(VaultKeyHistory.key_version).all()
    
    result = []
    for entry in history_entries:
        duration = (entry.retired_at - entry.created_at).days if entry.retired_at else None
        result.append({
            'key_version': entry.key_version,
            'created_at': entry.created_at,
            'retired_at': entry.retired_at,
            'active_duration_days': duration
        })
    
    return result

