"""
Enhanced Encrypted File Storage

Provides filesystem-level encryption for vault files with:
- AES-256-GCM authenticated encryption
- Per-vault encryption keys (already implemented)
- Encryption metadata for key rotation
- File format verification
- Secure file deletion
"""

import os
import struct
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

# File format constants
MAGIC_BYTES = b'DockVault'  # File format identifier
VERSION = 1  # Encryption format version
NONCE_SIZE = 12  # AES-GCM nonce size (96 bits)
TAG_SIZE = 16  # AES-GCM authentication tag size (128 bits)

# Header structure:
# - Magic bytes (5 bytes): 'DockVault'
# - Version (1 byte): format version
# - Key version (2 bytes): which key version was used
# - Nonce (12 bytes): AES-GCM nonce
# - Total: 20 bytes
HEADER_SIZE = 5 + 1 + 2 + NONCE_SIZE


class EncryptedFileStorage:
    """
    Handles encrypted storage and retrieval of files.
    
    Uses AES-256-GCM for authenticated encryption with per-vault keys.
    Stores metadata in file header for key rotation support.
    """
    
    def __init__(self, base_storage_path: Path):
        """
        Initialize encrypted file storage.
        
        Args:
            base_storage_path: Base directory for file storage
        """
        self.storage_path = Path(base_storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def encrypt_and_save(
        self,
        file_content: bytes,
        vault_key: bytes,
        storage_path: Path,
        key_version: int = 1,
        associated_data: Optional[bytes] = None
    ) -> int:
        """
        Encrypt file content and save to disk with metadata.
        
        Args:
            file_content: Raw file bytes to encrypt
            vault_key: 32-byte vault encryption key
            storage_path: Path where encrypted file will be saved
            key_version: Version of the key being used (for rotation)
            associated_data: Optional additional authenticated data (AAD)
            
        Returns:
            Size of encrypted file in bytes
            
        Raises:
            ValueError: If vault_key is not 32 bytes
        """
        if len(vault_key) != 32:
            raise ValueError("Vault key must be 32 bytes")
        
        # Generate random nonce (must be unique per encryption)
        nonce = secrets.token_bytes(NONCE_SIZE)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(vault_key)
        
        # Encrypt with authentication
        # If associated_data provided, it will be authenticated but not encrypted
        encrypted_content = aesgcm.encrypt(nonce, file_content, associated_data)
        
        # Build header with metadata
        header = self._build_header(nonce, key_version)
        
        # Write header + encrypted content to disk
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(storage_path, 'wb') as f:
            f.write(header)
            f.write(encrypted_content)
        
        # Return total file size
        return len(header) + len(encrypted_content)
    
    def load_and_decrypt(
        self,
        storage_path: Path,
        vault_key: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, int]:
        """
        Load encrypted file from disk and decrypt.
        
        Args:
            storage_path: Path to encrypted file
            vault_key: 32-byte vault encryption key
            associated_data: Optional additional authenticated data (must match encryption AAD)
            
        Returns:
            Tuple of (decrypted_content, key_version)
            
        Raises:
            ValueError: If file format is invalid or decryption fails
            FileNotFoundError: If file doesn't exist
        """
        if not storage_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {storage_path}")
        
        # Read file
        with open(storage_path, 'rb') as f:
            data = f.read()
        
        # Validate minimum size
        if len(data) < HEADER_SIZE + TAG_SIZE:
            raise ValueError("File too small to be valid encrypted file")
        
        # Parse header
        header = data[:HEADER_SIZE]
        encrypted_content = data[HEADER_SIZE:]
        
        nonce, key_version = self._parse_header(header)
        
        # Decrypt with authentication
        aesgcm = AESGCM(vault_key)
        try:
            decrypted_content = aesgcm.decrypt(nonce, encrypted_content, associated_data)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
        
        return decrypted_content, key_version
    
    def _build_header(self, nonce: bytes, key_version: int) -> bytes:
        """
        Build file header with encryption metadata.
        
        Format:
        - Magic bytes (5): 'DockVault'
        - Version (1): format version
        - Key version (2): key version number (big-endian)
        - Nonce (12): AES-GCM nonce
        
        Args:
            nonce: 12-byte nonce
            key_version: Key version number (0-65535)
            
        Returns:
            20-byte header
        """
        header = bytearray()
        header.extend(MAGIC_BYTES)  # 5 bytes
        header.append(VERSION)  # 1 byte
        header.extend(struct.pack('>H', key_version))  # 2 bytes (big-endian uint16)
        header.extend(nonce)  # 12 bytes
        return bytes(header)
    
    def _parse_header(self, header: bytes) -> Tuple[bytes, int]:
        """
        Parse file header and extract metadata.
        
        Args:
            header: 20-byte header
            
        Returns:
            Tuple of (nonce, key_version)
            
        Raises:
            ValueError: If header is invalid
        """
        if len(header) != HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header)} bytes")
        
        # Verify magic bytes
        magic = header[:5]
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid file format (magic bytes: {magic})")
        
        # Check version
        version = header[5]
        if version != VERSION:
            raise ValueError(f"Unsupported file format version: {version}")
        
        # Extract key version (big-endian uint16)
        key_version = struct.unpack('>H', header[6:8])[0]
        
        # Extract nonce
        nonce = header[8:20]
        
        return nonce, key_version
    
    def secure_delete(self, storage_path: Path) -> None:
        """
        Securely delete encrypted file by overwriting before removal.
        
        Performs a single-pass overwrite with random data before deletion.
        For compliance with data protection regulations.
        
        Args:
            storage_path: Path to file to delete
        """
        if not storage_path.exists():
            return
        
        try:
            # Get file size
            file_size = storage_path.stat().st_size
            
            # Overwrite with random data
            with open(storage_path, 'wb') as f:
                # Write random data in 1MB chunks to avoid memory issues
                chunk_size = 1024 * 1024
                remaining = file_size
                while remaining > 0:
                    chunk = secrets.token_bytes(min(chunk_size, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)
            
            # Flush to disk
            with open(storage_path, 'rb') as f:
                os.fsync(f.fileno())
            
            # Finally, delete the file
            storage_path.unlink()
            
        except Exception as e:
            # If secure deletion fails, still try to delete normally
            print(f"Warning: Secure deletion failed: {e}")
            try:
                storage_path.unlink()
            except Exception:
                pass
    
    def verify_file_format(self, storage_path: Path) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Verify that a file has valid encrypted format without decrypting.
        
        Args:
            storage_path: Path to file to verify
            
        Returns:
            Tuple of (is_valid, format_version, key_version)
            Returns (False, None, None) if invalid
        """
        if not storage_path.exists():
            return False, None, None
        
        try:
            with open(storage_path, 'rb') as f:
                header = f.read(HEADER_SIZE)
            
            if len(header) < HEADER_SIZE:
                return False, None, None
            
            # Verify magic bytes
            if header[:5] != MAGIC_BYTES:
                return False, None, None
            
            # Get versions
            format_version = header[5]
            key_version = struct.unpack('>H', header[6:8])[0]
            
            return True, format_version, key_version
            
        except Exception:
            return False, None, None
    
    def get_file_key_version(self, storage_path: Path) -> Optional[int]:
        """
        Get the key version used to encrypt a file.
        
        Useful for identifying files that need re-encryption during key rotation.
        
        Args:
            storage_path: Path to encrypted file
            
        Returns:
            Key version number, or None if file is invalid
        """
        is_valid, _, key_version = self.verify_file_format(storage_path)
        return key_version if is_valid else None


def derive_file_encryption_key(vault_key: bytes, vault_id: str) -> bytes:
    """
    Derive a file encryption key from vault key.
    
    Uses HKDF to derive a key specific to this vault.
    This is already done in vault_key_utils.py, but provided here for completeness.
    
    Args:
        vault_key: Master or vault-specific key
        vault_id: Vault UUID as string
        
    Returns:
        32-byte derived key for AES-256
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dockvault-file-encryption',
        info=vault_id.encode()
    )
    return hkdf.derive(vault_key)


# Example usage:
if __name__ == "__main__":
    # Demo encryption and decryption
    import uuid
    
    # Simulate vault key (normally from vault_key_utils)
    vault_id = str(uuid.uuid4())
    master_key = secrets.token_bytes(32)
    vault_key = derive_file_encryption_key(master_key, vault_id)
    
    # Initialize storage
    storage = EncryptedFileStorage(Path("./test_encrypted_storage"))
    
    # Encrypt and save
    test_file = b"This is sensitive file content!"
    storage_path = Path("./test_encrypted_storage/test_file.enc")
    
    print("Encrypting file...")
    size = storage.encrypt_and_save(test_file, vault_key, storage_path)
    print(f"Encrypted file size: {size} bytes")
    
    # Verify format
    is_valid, fmt_ver, key_ver = storage.verify_file_format(storage_path)
    print(f"Valid format: {is_valid}, Format version: {fmt_ver}, Key version: {key_ver}")
    
    # Decrypt and load
    print("\nDecrypting file...")
    decrypted, key_version = storage.load_and_decrypt(storage_path, vault_key)
    print(f"Decrypted content: {decrypted.decode()}")
    print(f"Key version used: {key_version}")
    
    # Secure delete
    print("\nSecurely deleting file...")
    storage.secure_delete(storage_path)
    print(f"File deleted: {not storage_path.exists()}")
