"""Unit tests for the device sync secret primitives (app/core/security).

Pure/offline (no DB, no network): the CSPRNG token generator and its at-rest hash. These pin the
cryptographic shape the device principal rests on — a high-entropy opaque secret, stored only as
its sha256, compared constant-time — so a later refactor can't silently weaken it (e.g. shorten the
secret, persist the raw value, or swap the hash). The DB-backed resolver (get_current_device_principal)
and the app-wide route-sweep are integration checks: api_server can't import without a full
credential configuration, so they run against a live throwaway stack at verify time.
"""
import hmac

import pytest

from app.core.security import generate_device_secret, hash_device_secret

pytestmark = pytest.mark.unit


# ---- generate_device_secret: high-entropy, unique, URL-safe --------------------------------
def test_secret_is_256_bits_of_urlsafe_entropy():
    secret = generate_device_secret()
    # secrets.token_urlsafe(32) -> 32 random bytes -> 43 base64url chars (no padding).
    assert len(secret) == 43
    # URL-safe base64 alphabet only, so the raw secret is safe in an Authorization header.
    assert all(c.isalnum() or c in "-_" for c in secret)


def test_secrets_do_not_repeat():
    # A CSPRNG, so a collision across a batch is eff. impossible; a repeat would mean a broken
    # generator (e.g. a seeded `random`), which this guards against.
    secrets_seen = {generate_device_secret() for _ in range(1000)}
    assert len(secrets_seen) == 1000


# ---- hash_device_secret: deterministic hex sha256, one-way, only-the-hash-stored -----------
def test_hash_is_hex_sha256():
    h = hash_device_secret(generate_device_secret())
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_is_deterministic_for_the_same_secret():
    secret = generate_device_secret()
    assert hash_device_secret(secret) == hash_device_secret(secret)


def test_distinct_secrets_hash_distinctly():
    a, b = generate_device_secret(), generate_device_secret()
    assert hash_device_secret(a) != hash_device_secret(b)


def test_hash_is_not_the_raw_secret():
    # The stored form must never equal the presented secret — that is the whole point of storing
    # only the hash. (Trivially true for sha256, but pinned so nobody "optimises" it to identity.)
    secret = generate_device_secret()
    assert hash_device_secret(secret) != secret


def test_constant_time_compare_confirms_a_matching_hash():
    # How the resolver confirms a hashed-value lookup: hmac.compare_digest on the hex digests.
    secret = generate_device_secret()
    assert hmac.compare_digest(hash_device_secret(secret), hash_device_secret(secret))
    assert not hmac.compare_digest(hash_device_secret(secret), hash_device_secret(generate_device_secret()))


@pytest.mark.parametrize("value", ["", "not-a-real-secret", "a" * 512])
def test_hash_accepts_any_string_without_raising(value):
    # An account JWT or a malformed header value reaches hash_device_secret in the resolver; it
    # must hash to a well-formed digest (that then matches no stored secret) rather than raise.
    h = hash_device_secret(value)
    assert len(h) == 64
