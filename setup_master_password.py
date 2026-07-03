#!/usr/bin/env python3
"""
DockVault Master Password Setup
---------------------------
This script encrypts ALL sensitive credentials with a master password.

Usage:
    python setup_master_password.py

What it does:
    1. Prompts for a master password (min 16 chars)
    2. Encrypts all sensitive .env variables
    3. Generates new .env.secure file
    4. Original credentials are encrypted and safe

Security:
    - Password is never stored (only bcrypt hash for verification)
    - All secrets encrypted with PBKDF2-derived key
    - 100,000 iterations (OWASP recommended)
    - Unique salt generated
"""

import os
import sys
import base64
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt
from dotenv import load_dotenv

def generate_salt() -> str:
    """Generate a random salt for PBKDF2"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()

def derive_key_from_password(password: str, salt: str) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000  # OWASP recommended minimum
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_value(value: str, fernet: Fernet) -> str:
    """Encrypt a single value"""
    return fernet.encrypt(value.encode()).decode()

def get_master_password() -> str:
    """Prompt for master password with confirmation"""
    print("="*60)
    print("🔐 DockVault Master Password Setup")
    print("="*60)
    print("\nThis password will protect ALL sensitive credentials.")
    print("⚠️  WARNING: If you forget this password, data is UNRECOVERABLE!")
    print("\nRequirements:")
    print("  • Minimum 16 characters")
    print("  • Use a password manager to store it securely")
    print("  • Never share this password")
    print()
    
    while True:
        password = getpass.getpass("Enter master password: ")
        
        if len(password) < 16:
            print("❌ Password must be at least 16 characters!\n")
            continue
        
        password_confirm = getpass.getpass("Confirm master password: ")
        
        if password != password_confirm:
            print("❌ Passwords don't match!\n")
            continue
        
        # Password strength check
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        strength = sum([has_upper, has_lower, has_digit, has_special])
        
        if strength < 3:
            print("⚠️  Weak password! Recommended: mix of uppercase, lowercase, digits, and symbols")
            confirm = input("Continue anyway? (yes/no): ")
            if confirm.lower() != 'yes':
                continue
        
        return password

def load_current_env() -> dict:
    """Load current .env file"""
    env_path = Path(".env")
    
    if not env_path.exists():
        print("❌ .env file not found!")
        sys.exit(1)
    
    load_dotenv()
    
    # Extract values that need encryption
    secrets = {
        'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY', ''),
        'DATABASE_URL': os.getenv('DATABASE_URL', ''),
        'REDIS_PASSWORD': os.getenv('REDIS_PASSWORD', ''),
        'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', ''),
        'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD', '')
    }
    
    # Validate all secrets are present
    missing = [k for k, v in secrets.items() if not v]
    if missing:
        print(f"⚠️  Warning: Missing values for: {', '.join(missing)}")
        print("    These will be left empty (you can add them later)")
    
    return secrets

def create_secure_env(password: str, secrets: dict) -> tuple[str, str, str]:
    """Create encrypted .env file content"""
    
    # Generate salt
    salt = generate_salt()
    
    # Derive key from password
    password_key = derive_key_from_password(password, salt)
    fernet = Fernet(password_key)
    
    # Hash password for verification
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Encrypt all secrets
    encrypted_secrets = {}
    for key, value in secrets.items():
        if value:
            encrypted_secrets[key] = encrypt_value(value, fernet)
    
    # Build .env.secure content
    content = [
        "# DockVault Secure Configuration",
        "# =============================",
        "# All sensitive credentials are encrypted with master password",
        "# App will prompt for password on startup",
        "",
        "# Master Password Protection",
        f"MASTER_PASSWORD_HASH={password_hash}",
        f"MASTER_KEY_SALT={salt}",
        "",
        "# Encrypted Secrets (DO NOT EDIT MANUALLY)",
        f"ENCRYPTED_ENCRYPTION_KEY={encrypted_secrets.get('ENCRYPTION_KEY', '')}",
        f"ENCRYPTED_DATABASE_URL={encrypted_secrets.get('DATABASE_URL', '')}",
        f"ENCRYPTED_REDIS_PASSWORD={encrypted_secrets.get('REDIS_PASSWORD', '')}",
        f"ENCRYPTED_JWT_SECRET_KEY={encrypted_secrets.get('JWT_SECRET_KEY', '')}",
        f"ENCRYPTED_ADMIN_PASSWORD={encrypted_secrets.get('ADMIN_PASSWORD', '')}",
        "",
        "# Non-sensitive configuration (kept as plaintext)",
        f"REDIS_HOST={os.getenv('REDIS_HOST', 'localhost')}",
        f"REDIS_PORT={os.getenv('REDIS_PORT', '6379')}",
        f"REDIS_DB={os.getenv('REDIS_DB', '0')}",
        "",
        f"SFTP_HOST={os.getenv('SFTP_HOST', '0.0.0.0')}",
        f"SFTP_PORT={os.getenv('SFTP_PORT', '2222')}",
        f"SFTP_HOST_KEY_PATH={os.getenv('SFTP_HOST_KEY_PATH', './keys/ssh_host_rsa_key')}",
        "",
        f"API_HOST={os.getenv('API_HOST', '0.0.0.0')}",
        f"API_PORT={os.getenv('API_PORT', '8000')}",
        f"API_USE_HTTPS={os.getenv('API_USE_HTTPS', 'true')}",
        f"API_SSL_CERTFILE={os.getenv('API_SSL_CERTFILE', './certs/cert.pem')}",
        f"API_SSL_KEYFILE={os.getenv('API_SSL_KEYFILE', './certs/key.pem')}",
        "",
        f"ENVIRONMENT={os.getenv('ENVIRONMENT', 'development')}",
        "",
        f"JWT_ALGORITHM={os.getenv('JWT_ALGORITHM', 'HS256')}",
        f"JWT_ACCESS_TOKEN_EXPIRE_MINUTES={os.getenv('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', '30')}",
        "",
        f"TEMP_CRED_VALIDITY_MINUTES={os.getenv('TEMP_CRED_VALIDITY_MINUTES', '65')}",
        f"TEMP_CRED_SESSION_GRACE_MINUTES={os.getenv('TEMP_CRED_SESSION_GRACE_MINUTES', '65')}",
        f"TEMP_CRED_TOTAL_LIFETIME_MINUTES={os.getenv('TEMP_CRED_TOTAL_LIFETIME_MINUTES', '65')}",
        "",
        f"FILE_STORAGE_PATH={os.getenv('FILE_STORAGE_PATH', './storage')}",
        f"MAX_FILE_SIZE_MB={os.getenv('MAX_FILE_SIZE_MB', '15360')}",
        f"TRANSFER_SPEED_LIMIT_KB={os.getenv('TRANSFER_SPEED_LIMIT_KB', '0')}",
        "",
        f"RATE_LIMIT_LOGIN_ATTEMPTS={os.getenv('RATE_LIMIT_LOGIN_ATTEMPTS', '5')}",
        f"RATE_LIMIT_LOGIN_WINDOW_SECONDS={os.getenv('RATE_LIMIT_LOGIN_WINDOW_SECONDS', '300')}",
        f"RATE_LIMIT_VAULT_ATTEMPTS={os.getenv('RATE_LIMIT_VAULT_ATTEMPTS', '5')}",
        f"RATE_LIMIT_VAULT_ATTEMPTS_ADMIN={os.getenv('RATE_LIMIT_VAULT_ATTEMPTS_ADMIN', '20')}",
        f"RATE_LIMIT_VAULT_WINDOW_SECONDS={os.getenv('RATE_LIMIT_VAULT_WINDOW_SECONDS', '300')}",
        "",
        f"LOG_LEVEL={os.getenv('LOG_LEVEL', 'INFO')}",
        f"LOG_FILE_PATH={os.getenv('LOG_FILE_PATH', './logs/sftp_server.log')}",
        "",
        f"ADMIN_USERNAME={os.getenv('ADMIN_USERNAME', 'admin')}",
        f"ADMIN_EMAIL={os.getenv('ADMIN_EMAIL', 'admin@example.com')}",
        ""
    ]
    
    return "\n".join(content), salt, password_hash

def main():
    """Main setup flow"""
    
    # Load current .env
    print("\n📂 Loading current .env file...")
    secrets = load_current_env()
    print(f"✅ Found {len([v for v in secrets.values() if v])} credentials to encrypt")
    
    # Get master password
    print()
    password = get_master_password()
    
    # Create encrypted content
    print("\n🔒 Encrypting credentials...")
    secure_content, salt, password_hash = create_secure_env(password, secrets)
    
    # Backup current .env
    backup_path = Path(".env.backup")
    if Path(".env").exists():
        print(f"\n💾 Backing up current .env to {backup_path}")
        Path(".env").rename(backup_path)
    
    # Write new .env.secure
    secure_path = Path(".env.secure")
    with open(secure_path, 'w') as f:
        f.write(secure_content)
    
    print(f"✅ Created {secure_path}")
    
    # Write new .env (same as .env.secure)
    with open(".env", 'w') as f:
        f.write(secure_content)
    
    print(f"✅ Created new .env")
    
    # Summary
    print("\n" + "="*60)
    print("✅ SETUP COMPLETE!")
    print("="*60)
    print("\n📋 What was done:")
    print("  1. ✅ Encrypted all sensitive credentials")
    print("  2. ✅ Created .env.secure (encrypted version)")
    print("  3. ✅ Updated .env with encrypted values")
    print("  4. ✅ Backed up old .env to .env.backup")
    print("\n⚠️  IMPORTANT:")
    print("  • SAVE YOUR MASTER PASSWORD SECURELY!")
    print("  • Without it, encrypted data is UNRECOVERABLE")
    print("  • Use a password manager (LastPass, 1Password, etc.)")
    print("  • DO NOT commit .env.backup to git")
    print("\n🚀 Next steps:")
    print("  1. Test the app: python api_server.py")
    print("  2. It will prompt for your master password")
    print("  3. If successful, you can delete .env.backup")
    print("\n🔧 To store password in system keychain (optional):")
    print("     python -c \"import keyring; keyring.set_password('DockVault', 'master_password', 'YOUR_PASSWORD')\"")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
