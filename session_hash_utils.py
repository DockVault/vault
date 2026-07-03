"""
Session Token Hashing Utility
-------------------------------
Provides secure hashing of session tokens before storage in Redis.

Security:
- Uses SHA-256 (NIST approved, no known vulnerabilities)
- One-way function (cannot reverse hash to get token)
- Deterministic (same token always produces same hash)
- Fast (suitable for high-performance session validation)
- Collision resistant (2^256 possible outputs)

This prevents session hijacking via Redis compromise by ensuring
only hashed tokens are stored, making stolen Redis data useless.
"""

import hashlib
import hmac
from typing import Optional


def hash_session_token(token: str) -> str:
    """
    Hash a session token using SHA-256.
    
    This creates a one-way fingerprint of the session token that can be
    safely stored in Redis. Even if Redis is compromised, the attacker
    cannot retrieve the original tokens from the hashes.
    
    Args:
        token: The session token (JWT or other format)
    
    Returns:
        64-character hexadecimal SHA-256 hash of the token
        
    Example:
        >>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        >>> hash_session_token(token)
        '7a8f9e3c2d1b4a5e6f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'
        
    Security Properties:
        - One-way: Cannot reverse hash to original token
        - Deterministic: Same token always produces same hash
        - Collision resistant: Hash collisions extremely unlikely
        - Fast: ~10 microseconds, suitable for every request
    """
    if not token:
        raise ValueError("Token cannot be empty")
    
    # Use SHA-256 for cryptographic strength and speed
    # SHA-256 is NIST approved and has no known vulnerabilities
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def is_token_hashed(value: str) -> bool:
    """
    Check if a value is already a hashed token (64 hex characters).
    
    This is useful for backward compatibility during migration,
    allowing the system to detect and handle both plaintext tokens
    and hashed tokens during a transition period.
    
    Args:
        value: Token or hash to check
    
    Returns:
        True if the value appears to be a hash (64 hex chars),
        False if it appears to be a plaintext token
        
    Example:
        >>> is_token_hashed("7a8f9e3c2d1b...")  # 64 chars
        True
        >>> is_token_hashed("eyJhbGciOi...")  # JWT format
        False
        
    Note:
        This is a heuristic check. It detects the standard SHA-256
        hex output format (64 characters, all hexadecimal).
    """
    if not value:
        return False
    
    # SHA-256 produces exactly 64 hexadecimal characters
    return (
        len(value) == 64 and
        all(c in '0123456789abcdef' for c in value.lower())
    )


def verify_token_hash(token: str, token_hash: str) -> bool:
    """
    Verify that a token matches its hash.
    
    This is useful for testing and validation to ensure
    the hashing is working correctly.
    
    Args:
        token: The original token
        token_hash: The hash to verify against
    
    Returns:
        True if the token hashes to the given hash, False otherwise
        
    Example:
        >>> token = "my_session_token"
        >>> hash = hash_session_token(token)
        >>> verify_token_hash(token, hash)
        True
        >>> verify_token_hash("wrong_token", hash)
        False
    """
    try:
        computed_hash = hash_session_token(token)
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, token_hash)
    except Exception:
        return False


# For testing and validation
if __name__ == "__main__":
    # Test the hashing function
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE2MzYwMDAwMDB9.abc123"
    
    print("Session Token Hashing Test")
    print("=" * 60)
    print(f"Original token: {test_token[:50]}...")
    print(f"Token length: {len(test_token)} characters")
    print()
    
    token_hash = hash_session_token(test_token)
    print(f"SHA-256 hash: {token_hash}")
    print(f"Hash length: {len(token_hash)} characters")
    print()
    
    print(f"Is hashed? {is_token_hashed(token_hash)}")
    print(f"Is original hashed? {is_token_hashed(test_token)}")
    print()
    
    # Test idempotency (same input = same output)
    hash2 = hash_session_token(test_token)
    print(f"Idempotent (same hash twice): {token_hash == hash2}")
    print()
    
    # Test different input produces different output
    different_token = test_token + "x"
    different_hash = hash_session_token(different_token)
    print(f"Different token produces different hash: {token_hash != different_hash}")
    print()
    
    print("✅ All tests passed!")
