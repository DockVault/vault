"""
DockVault Startup Security Module
------------------------------
Handles master password validation and credential decryption on startup.

This module must be initialized BEFORE any other modules that need credentials.
"""

import os
import sys
import base64
import getpass
import bcrypt
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    print("⚠️  keyring not installed. Install with: pip install keyring")
    print("⚠️  System keychain integration will be unavailable")


class CredentialManager:
    """
    Manages encrypted credentials and master password authentication.
    
    Usage:
        credential_manager = CredentialManager()
        if credential_manager.unlock():
            # Credentials are now available
            encryption_key = credential_manager.get('ENCRYPTION_KEY')
            db_url = credential_manager.get('DATABASE_URL')
    """
    
    def __init__(self):
        self.credentials = {}
        self.is_unlocked = False
        self._fernet_cipher = None
    
    def derive_key_from_password(self, password: str, salt: str) -> bytes:
        """Derive encryption key from password using PBKDF2.

        600k iterations per current OWASP guidance for PBKDF2-HMAC-SHA256 (was 100k). This KDF only
        guards the OPTIONAL encrypted-.env master-password mode (not the Docker/SaaS plaintext-env
        path, not user login which uses argon2/bcrypt), so raising it costs one extra ~0.5s unlock at
        startup for that mode and nothing for the common deployments."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=600000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def get_password_from_keychain(self) -> Optional[str]:
        """Try to retrieve master password from system keychain"""
        if not KEYRING_AVAILABLE:
            return None
        
        try:
            import keyring as kr
            password = kr.get_password("DockVault", "master_password")
            if password:
                print("✅ Retrieved master password from system keychain")
            return password
        except Exception as e:
            print(f"⚠️  Could not access keychain: {e}")
            return None
    
    def save_password_to_keychain(self, password: str) -> bool:
        """Save master password to system keychain"""
        if not KEYRING_AVAILABLE:
            return False
        
        try:
            import keyring as kr
            kr.set_password("DockVault", "master_password", password)
            print("✅ Saved master password to system keychain")
            return True
        except Exception as e:
            print(f"⚠️  Could not save to keychain: {e}")
            return False
    
    def prompt_for_password(self) -> str:
        """Prompt user for master password"""
        print("\n" + "="*60)
        print("🔐 DockVault Master Password Required")
        print("="*60)
        print("Enter the master password to unlock encrypted credentials.")
        print()
        
        password = getpass.getpass("Master password: ")
        return password
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored bcrypt hash"""
        password_hash = os.getenv("MASTER_PASSWORD_HASH")
        
        if not password_hash:
            return False

        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except Exception:
            # Do not log hash bytes or exception detail — the master-password hash /
            # its salt must never reach container stdout.
            return False
    
    def check_legacy_mode(self) -> bool:
        """Check if using legacy unencrypted .env"""
        # If ENCRYPTION_KEY exists as plaintext, we're in legacy mode
        encryption_key = os.getenv("ENCRYPTION_KEY")
        encrypted_key = os.getenv("ENCRYPTED_ENCRYPTION_KEY")
        master_password_hash = os.getenv("MASTER_PASSWORD_HASH")
        
        # Plain environment mode: no encryption, no master password
        # This is typical for Docker/test/development environments
        return bool(encryption_key and not encrypted_key and not master_password_hash)
    
    def load_legacy_credentials(self):
        """Load credentials from legacy unencrypted .env"""
        # Check if this is a Docker/test environment (no master password warning needed)
        is_plain_env = not os.getenv("MASTER_PASSWORD_HASH")
        
        if is_plain_env:
            print("\n" + "="*60)
            print("ℹ️  Using plaintext environment variables")
            print("="*60)
            print()
            print("Running in plain configuration mode (Docker/test/dev).")
            print("All credentials loaded directly from environment.")
            print()
        else:
            print("\n" + "="*60)
            print("⚠️  WARNING: Using LEGACY UNENCRYPTED credentials!")
            print("="*60)
            print()
            print("Your .env file contains plaintext secrets.")
            print("This is a SECURITY RISK!")
            print()
            print("🔒 To enable encryption protection:")
            print("   python setup_master_password.py")
            print()
            print("Continuing with plaintext credentials...")
            print()
        
        self.credentials = {
            'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),
            'DATABASE_URL': os.getenv('DATABASE_URL'),
            'REDIS_PASSWORD': os.getenv('REDIS_PASSWORD'),
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
            'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD')
        }
        
        # Create Fernet cipher for file encryption
        if self.credentials['ENCRYPTION_KEY']:
            self._fernet_cipher = Fernet(self.credentials['ENCRYPTION_KEY'].encode())
        
        self.is_unlocked = True
    
    def decrypt_credential(self, encrypted_value: str, fernet: Fernet) -> str:
        """Decrypt a single credential"""
        try:
            return fernet.decrypt(encrypted_value.encode()).decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt credential: {e}")
    
    def unlock(self, max_attempts: int = 25) -> bool:
        """
        Unlock encrypted credentials with master password.
        
        Args:
            max_attempts: Maximum number of password attempts (default: 25)
        
        Returns:
            True if successfully unlocked, False otherwise
        """
        
        # Check if already unlocked
        if self.is_unlocked:
            return True
        
        # Check for legacy/plain mode FIRST
        if self.check_legacy_mode():
            self.load_legacy_credentials()
            return True
        
        # Check for encrypted credentials
        if not os.getenv("ENCRYPTED_ENCRYPTION_KEY"):
            print("\n" + "="*60)
            print("❌ ERROR: No credentials found!")
            print("="*60)
            print()
            print("Your .env file doesn't have credentials configured.")
            print()
            print("Available environment variables:")
            print(f"  ENCRYPTION_KEY: {'SET' if os.getenv('ENCRYPTION_KEY') else 'NOT SET'}")
            print(f"  ENCRYPTED_ENCRYPTION_KEY: {'SET' if os.getenv('ENCRYPTED_ENCRYPTION_KEY') else 'NOT SET'}")
            print(f"  MASTER_PASSWORD_HASH: {'SET' if os.getenv('MASTER_PASSWORD_HASH') else 'NOT SET'}")
            print()
            print("To set up encrypted credentials:")
            print("   python setup_master_password.py")
            print()
            return False
        
        # Try keychain first
        password = self.get_password_from_keychain()
        
        # Attempt to unlock
        for attempt in range(max_attempts):
            # Prompt if no password from keychain
            if not password:
                password = self.prompt_for_password()
            
            # Verify password
            print(f"🔍 Verifying password (attempt {attempt + 1}/{max_attempts})...")
            if not self.verify_password(password):
                remaining = max_attempts - attempt - 1
                print(f"❌ Invalid master password!")
                
                if remaining > 0:
                    print(f"   {remaining} attempt(s) remaining\n")
                    password = None  # Force re-prompt
                    continue
                else:
                    print("🔒 Maximum attempts exceeded.")
                    print("   Cannot start server without valid credentials.")
                    return False
            
            print("✅ Password verified successfully!")
            
            # Password is correct - decrypt credentials
            try:
                salt = os.getenv("MASTER_KEY_SALT")
                if not salt:
                    print("❌ Missing MASTER_KEY_SALT in .env file")
                    return False
                
                password_key = self.derive_key_from_password(password, salt)
                fernet = Fernet(password_key)
                
                # Decrypt all credentials
                encrypted_values = {
                    'ENCRYPTION_KEY': os.getenv("ENCRYPTED_ENCRYPTION_KEY"),
                    'DATABASE_URL': os.getenv("ENCRYPTED_DATABASE_URL"),
                    'REDIS_PASSWORD': os.getenv("ENCRYPTED_REDIS_PASSWORD"),
                    'JWT_SECRET_KEY': os.getenv("ENCRYPTED_JWT_SECRET_KEY"),
                    'ADMIN_PASSWORD': os.getenv("ENCRYPTED_ADMIN_PASSWORD")
                }
                
                # Check all encrypted values are present
                missing = [k for k, v in encrypted_values.items() if not v]
                if missing:
                    print(f"❌ Missing encrypted values: {', '.join(missing)}")
                    return False
                
                # Now we know all values are non-None, decrypt them
                self.credentials = {}
                for k, v in encrypted_values.items():
                    if v:  # Type guard - should always be true due to check above
                        self.credentials[k] = self.decrypt_credential(v, fernet)
                
                # Create Fernet cipher for file encryption
                self._fernet_cipher = Fernet(self.credentials['ENCRYPTION_KEY'].encode())
                
                self.is_unlocked = True
                
                print("\n✅ Master password verified!")
                print("✅ All credentials decrypted successfully")
                
                # Offer to save to keychain
                if not self.get_password_from_keychain():
                    print()
                    save = input("💾 Save password to system keychain? (y/n): ").strip().lower()
                    if save == 'y':
                        self.save_password_to_keychain(password)
                
                print()
                return True
                
            except Exception as e:
                print(f"❌ Failed to decrypt credentials: {e}")
                print("   This might indicate:")
                print("     • Corrupted .env file")
                print("     • Modified encrypted values")
                print("     • Wrong password (despite hash match)")
                return False
        
        return False
    
    def get(self, key: str) -> Optional[str]:
        """
        Get a decrypted credential value.
        
        Args:
            key: Credential name (e.g., 'ENCRYPTION_KEY', 'DATABASE_URL')
            
        Returns:
            Decrypted credential value, or None if not found/not unlocked
        """
        if not self.is_unlocked:
            raise RuntimeError("Credentials not unlocked! Call unlock() first.")
        
        return self.credentials.get(key)
    
    def get_fernet(self) -> Fernet:
        """
        Get Fernet cipher for file encryption/decryption.
        
        Returns:
            Fernet cipher instance
            
        Raises:
            RuntimeError: If credentials not unlocked
        """
        if not self.is_unlocked:
            raise RuntimeError("Credentials not unlocked! Call unlock() first.")
        
        if not self._fernet_cipher:
            raise RuntimeError("Fernet cipher not initialized!")
        
        return self._fernet_cipher
    
    def is_legacy_mode(self) -> bool:
        """Check if running in legacy unencrypted mode"""
        return not os.getenv("ENCRYPTED_ENCRYPTION_KEY")


# Global instance
credential_manager = CredentialManager()


def require_unlock():
    """Decorator to ensure credentials are unlocked before function runs"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not credential_manager.is_unlocked:
                raise RuntimeError(
                    f"Cannot call {func.__name__}: credentials not unlocked! "
                    "Call credential_manager.unlock() first."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
