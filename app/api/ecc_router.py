"""
ECC Router - FastAPI router for ECC Zero-Trust encryption endpoints
Implements ECC P-384 based key management and vault wrapping.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field
from typing import Optional, List
import hashlib
import base64
import os
import json
import uuid
from app.core.database import get_db
from app.core.models import User, Vault, UserKeyPair, VaultMemberKey, VaultMemberIndexKey, ZKShareInvite, ECCRegistrationChallenge, ECCKeyUpdateChallenge, vault_members, RoleEnum
from app.services import ecc_pop, ecc_update_pop
from app.services.ecc_crypto_service import ECCCryptoService
from app.services.audit_logger import AuditLogger
from app.core.rate_limiter import rate_limiter as _rate_limiter
from app.core.endpoint_permissions import require_endpoint_permission
from app.core.temp_scope import (
    require_vault_cap, enforce_vault, is_scoped, has_scoped_vault_cap, effective_vault_caps,
)
# The vault_member_keys table holds two different kinds of row -- a wrapped team PRIVATE key
# (hierarchical) and a wrapped DEK (direct) -- and wrapping_algorithm is the only thing that
# tells them apart. Every query that touches one kind MUST filter on it, by membership rather
# than equality, so a next-generation label is not silently invisible.
from app.core.key_wrap_algorithms import (
    DIRECT_DEK_ALGO,
    DIRECT_DEK_ALGOS,
    classify as _classify_algo,
)
from app.core.zk_temp_access import (
    TEAMPRIV_ALGO,
    TEAMPRIV_ALGOS,
    TEMP_ZK_KEY_ACCESS_DENIED,
    may_release_private_envelope,
    may_release_vault_key,
)
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta

router = APIRouter(tags=["ECC - Elliptic Curve Cryptography"])
security_scheme = HTTPBearer()


# =============================================================================
# Pydantic Models
# =============================================================================

class RegistrationPoP(BaseModel):
    """Proof-of-possession for key registration: the challenge id + the client's ECDH
    key-confirmation MAC over (nonce || public_key). See app/services/ecc_pop.py."""
    challenge_id: str
    mac: str


class KeypairRegisterRequest(BaseModel):
    """Request to register user's public key."""
    public_key: str = Field(..., description="PEM-encoded ECC P-384 public key")
    encrypted_private_key: Optional[str] = None  # Password-encrypted for recovery
    key_salt: Optional[str] = None  # Salt for password-derived encryption
    key_iterations: int = 600000  # PBKDF2 iterations
    pop: Optional[RegistrationPoP] = None  # ECDH key-confirmation proof-of-possession


class KeypairRegisterResponse(BaseModel):
    """Response after registering public key."""
    message: str
    user_id: str
    fingerprint: str
    key_id: str


class PublicKeyResponse(BaseModel):
    """Response with user's public key info."""
    user_id: str
    public_key: Optional[str] = None
    fingerprint: Optional[str] = None
    has_keypair: bool = False


class DecompressPointRequest(BaseModel):
    """Request to decompress an ECC point."""
    # A compressed P-384 point is 49 bytes (~68 chars base64); cap the field so an authenticated
    # caller can't post an unbounded body to force a large allocation before validation.
    compressed_point: str = Field(..., max_length=256, description="Base64-encoded compressed point")
    curve: str = Field(default="P-384", max_length=16, description="ECC curve name")


class DecompressPointResponse(BaseModel):
    """Response with decompressed point."""
    uncompressed_point: str = Field(..., description="Base64-encoded uncompressed point")


class VaultKeysResponse(BaseModel):
    """Response with encrypted vault keys."""
    vault_id: str
    mode: str
    has_access: bool
    wrapped_dek: Optional[str] = None  # DEK wrapped to the caller (direct) or to the team pubkey (hierarchical)
    ephemeral_public_key: Optional[str] = None
    # DEK epoch of the returned wrapped_dek, and the vault's CURRENT epoch. A
    # version-aware client uses key_version to decrypt old files and current_dek_version
    # to know which epoch new uploads must use. Both default to 1, so a legacy client
    # (which ignores these fields) keeps working against a never-rotated vault.
    key_version: Optional[int] = None
    current_dek_version: int = 1
    # The account this row was selected for, echoed so a reader binding the recipient into a
    # transcript has an authenticated source for it rather than reconstructing it from local
    # state whose population order it would have to reason about.
    #
    # Nothing consumes this yet, deliberately: the transcript that needs it belongs to a
    # format whose reader ships before its writer, and an authenticated field has to be
    # available on the server for a while before a client may depend on it.
    recipient_user_id: Optional[str] = None
    # Hierarchical mode only: the team PUBLIC key, the caller's wrap of the team PRIVATE key
    # (to unwrap with their identity key), its ephemeral, and the team-keypair epoch the DEK
    # above was wrapped under. The client unwraps team_priv (@ team_key_version) then the DEK.
    # All null in direct mode. `mode` is ADVISORY — the crypto fails closed regardless.
    team_public_key: Optional[str] = None
    wrapped_team_privkey: Optional[str] = None
    team_ephemeral_public_key: Optional[str] = None
    team_key_version: Optional[int] = None
    # True when a member was removed (revoke / reconciler sweep / offboarding blacklist) WITHOUT
    # a DEK rotation — a manager should rotate the vault key for forward secrecy on new content.
    # Derived, so it clears automatically once a rekey advances the epoch. Only reported to a
    # caller who holds a key (the no-access response leaves it at the default).
    rekey_owed: bool = False


# =============================================================================
# Dependencies
# =============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get the current authenticated user for the /ecc ZK-crypto plane.

    SECURITY: this MUST enforce the exact same hardening as the rest of the
    API, otherwise the ZK crypto mutators (grant/revoke/rekey/retire/register) are a weaker
    authentication surface than a plain vault write. The previous bespoke implementation only
    did verify_access_token + user lookup + is_active — it OMITTED the token denylist, the
    durable ActiveSession.revoked check, temp-session is_active/grace validation, the
    account_locked check, and attach_scope (temp-credential least-privilege). So a
    logged-out / revoked / locked JWT drove crypto mutations until it expired, and an
    admin-minted, tightly-scoped temp credential acted as a full Manager on every ZK vault.

    We now delegate to the ONE hardened dependency (api_server.get_current_user) so there is a
    single source of truth for authentication. The import is LAZY (inside the function body)
    because api_server imports this module at load time to mount the router
    (api_server.include_router(ecc_router)); a module-level import would be circular. By
    request time api_server is fully loaded, so the lazy import is a cheap dict lookup.
    """
    from app.api.api_server import get_current_user as _hardened_get_current_user
    return await _hardened_get_current_user(credentials, db)


# =============================================================================
# Membership / authorization helpers (the ZK DEK layer)
# =============================================================================
# Window during which a freshly-granted wrapped DEK is exempt from the orphan
# reconciler. ZK sharing happens in two steps (wrap the DEK, then grant authz) and
# uploads can race a rotation, so a key that is briefly "active but not yet a
# vault_members row" is normal. Only keys orphaned for longer than this — the
# hallmark of a revoke that removed authz but failed to drop the crypto key — are
# swept. Comfortably longer than any share/upload round-trip (and than the test suite).
ZK_ORPHAN_GRACE_SECONDS = 300


def _is_owner_or_admin(vault: Vault, user: User) -> bool:
    return str(vault.owner_id) == str(user.id) or getattr(user, 'role', None) == RoleEnum.ADMIN


def _member_row(db: Session, vault_id, user_id):
    return db.execute(
        select(vault_members.c.manage_permission).where(
            vault_members.c.vault_id == vault_id,
            vault_members.c.user_id == user_id,
        )
    ).first()


def _is_member(db: Session, vault: Vault, user_id) -> bool:
    """True if user_id is the owner or has a direct vault_members row. ZK vaults
    cannot be shared to groups (a group has no key), so direct membership + owner
    is the complete access set — no group fan-out to consider here."""
    if str(vault.owner_id) == str(user_id):
        return True
    return _member_row(db, vault.id, user_id) is not None


def _can_manage_vault(db: Session, vault: Vault, user: User) -> bool:
    """Owner, global admin, or a Manager (member with manage_permission). Mirrors
    api_server._can_manage_vault so the security-critical rekey is gated no weaker
    than a plain permission change on /vaults."""
    if _is_owner_or_admin(vault, user):
        return True
    row = _member_row(db, vault.id, user.id)
    return bool(row and row.manage_permission)


def _age_seconds(ts) -> Optional[float]:
    """Seconds since a stored timestamp, tolerating both naive (model default
    datetime.utcnow) and aware (datetime.now(timezone.utc)) values that coexist in
    this table. Returns None when unknown so callers can treat it conservatively."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds()


def _reconcile_orphan_member_keys(db: Session, vault: Vault) -> bool:
    """DIVERGENCE-2 reconciler: deactivate any ACTIVE wrapped DEK held by a user who
    is no longer a member of the vault (and isn't the owner). This closes the legacy
    best-effort-revoke hole where DELETE /vaults/{id}/permissions removed authz but the
    matching VaultMemberKey was left active — letting a removed user still fetch and
    unwrap their DEK via GET /ecc/vaults/{id}/keys.

    Deliberately conservative: it ONLY removes keys orphaned for longer than
    ZK_ORPHAN_GRACE_SECONDS (so an in-flight share — wrap-then-grant — or a key minted
    seconds ago is never swept), and it NEVER touches the inverse case (a member with no
    key yet = a pending share). Called on vault-open (get_vault_keys / member-keys) and
    before a rekey computes its target set. Returns True if anything changed."""
    rows = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault.id,
        VaultMemberKey.is_active == True,  # noqa: E712
    ).all()
    changed = False
    for mk in rows:
        if str(mk.user_id) == str(vault.owner_id):
            continue
        if _is_member(db, vault, mk.user_id):
            continue
        age = _age_seconds(mk.granted_at)
        if age is None or age < ZK_ORPHAN_GRACE_SECONDS:
            continue  # too fresh to be a confirmed orphan — leave it
        mk.is_active = False
        mk.revoked_at = datetime.now(timezone.utc)
        changed = True
    if changed:
        db.commit()
    return changed


def _audit_zk(db: Session, actor: User, action: str, *, resource_id,
              resource_type: str = "vault", details: Optional[dict] = None,
              status: str = "success") -> None:
    """Best-effort audit row for a /ecc ZK-crypto mutation.

    Called AFTER the mutation has committed (AuditLogger.log_action commits its own row), so a
    failure to record the audit never rolls back or 500s the crypto change it documents — it
    only drops the audit entry. The /ecc plane previously wrote ZERO audit rows, a forensic
    blind spot for the security-critical key grant / revoke / rekey / retire / register
    operations (standard vault create/delete are audited)."""
    try:
        AuditLogger(db).log_action(
            action=action,
            status=status,
            user=actor,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details or None,
        )
    except Exception:  # noqa: BLE001 — audit must never break the mutation it records
        db.rollback()


# Per-user sliding-window throttles for the /ecc key endpoints, so the key-management plane
# can't be driven as a brute-force / key-enumeration engine. Limits are generous — far above
# any legitimate interactive rate — and keyed per user. Fail OPEN on a Redis outage (these are
# availability-sensitive crypto operations, not an auth gate) — check_rate_limit's default.
_ECC_RATELIMIT = {
    "register": (15, 60),      # a user registers a keypair once (idempotent); no burst is legit
    "public_key": (100, 60),   # resolving recipients' keys while sharing to a team
    "mutate": (400, 60),       # grant / revoke / rekey / retire
    "decompress": (200, 60),   # point-format conversion during key ops (bounded compute)
    # Replacing the private-key envelope. Separate buckets from "register" so exhausting one
    # cannot lock out the other, and deliberately generous against legitimate use (a passphrase
    # change or a recovery restore is rare) while tight against guessing: combined with one-time
    # consumption, an attacker gets at most 10 proof attempts per 15 minutes, each needing a fresh
    # issuance, against a 256-bit MAC.
    "key_update_challenge": (10, 900),
    "key_update": (10, 900),
}


def _ecc_rate_limit(user: User, bucket: str) -> None:
    limit, window = _ECC_RATELIMIT[bucket]
    allowed, _, reset = _rate_limiter.check_rate_limit(
        identifier=str(user.id), limit=limit, window=window, prefix=f"ecc:{bucket}")
    if not allowed:
        import time as _time
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many key-management requests; please slow down.",
            headers={"Retry-After": str(max(1, reset - int(_time.time())))},
        )


def _manages_any_vault(db: Session, user: User) -> bool:
    """True if the user is a global admin, owns any vault, or is a Manager (manage_permission)
    of any vault — i.e. is a potential SHARER who could legitimately add a member to some vault.
    Scopes the public-key lookup so it is not a has-a-keypair enumeration oracle for arbitrary
    accounts. Does NOT break onboarding: the browser share/rekey flows always run as a manager
    of the vault they're sharing, and they fetch a not-yet-member recipient's key from here."""
    # A SCOPED temp credential is confined to its scope, NOT the underlying admin's blanket
    # role/ownership: it counts as a potential sharer (and may look up a recipient's public key) only
    # if it actually holds a permissions-management capability on some granted vault. This stops the
    # public-key lookup from being a has-a-keypair enumeration oracle any scoped credential could sweep.
    if is_scoped(user):
        return has_scoped_vault_cap(user, "vault.change_permissions")
    if getattr(user, 'role', None) == RoleEnum.ADMIN:
        return True
    if db.query(Vault.id).filter(Vault.owner_id == user.id).first():
        return True
    row = db.execute(
        select(vault_members.c.vault_id).where(
            vault_members.c.user_id == user.id,
            vault_members.c.manage_permission == True,  # noqa: E712
        )
    ).first()
    return row is not None


# =============================================================================
# Utility Endpoints
# =============================================================================

@router.post("/decompress-point", response_model=DecompressPointResponse)
async def decompress_point(
    request: DecompressPointRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Decompress a compressed ECC point to uncompressed format.

    Bridges Python's cryptography library (compressed points) and the browser Web Crypto API
    (which needs uncompressed points for raw import). The client already calls this with a bearer
    token as part of an authenticated key operation, so it is authenticated + rate-limited (the
    point itself carries no secret, but an unauthenticated, unbounded modular-sqrt endpoint is a
    cheap CPU/alloc DoS surface).

    Compressed P-384: 49 bytes (0x02/0x03 + 48-byte x)
    Uncompressed P-384: 97 bytes (0x04 + 48-byte x + 48-byte y)
    """
    _ecc_rate_limit(current_user, "decompress")
    try:
        # Decode the compressed point
        compressed_bytes = base64.b64decode(request.compressed_point)
        
        # Verify it's a compressed point (49 bytes for P-384)
        if len(compressed_bytes) != 49:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid compressed point length: {len(compressed_bytes)} (expected 49 for P-384)"
            )
        
        if compressed_bytes[0] not in (0x02, 0x03):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid compressed point format: must start with 0x02 or 0x03"
            )
        
        # Use cryptography library to decompress
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        # Load the compressed point
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(),
            compressed_bytes
        )
        
        # Export as uncompressed
        uncompressed_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Verify uncompressed format (97 bytes for P-384)
        if len(uncompressed_bytes) != 97:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unexpected uncompressed point length: {len(uncompressed_bytes)}"
            )
        
        # Encode to base64
        uncompressed_base64 = base64.b64encode(uncompressed_bytes).decode('utf-8')
        
        return DecompressPointResponse(uncompressed_point=uncompressed_base64)

    except HTTPException:
        # A deliberate 4xx (bad length / prefix) must surface as-is, not be swallowed into a 500.
        raise
    except ValueError:
        # Caller-supplied point failed to parse. Don't echo the crypto-library text back at 400
        # (a non-500 status bypasses the global 500-sanitizer).
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid compressed point"
        )
    except Exception as e:
        # 500 detail is scrubbed + server-logged by the global handler, so keeping str(e) here is safe.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Point decompression failed: {str(e)}"
        )


# =============================================================================
# ECC Endpoints (Stub Implementation)
# =============================================================================

_POP_CHALLENGE_TTL_SECONDS = 300  # a registration challenge is single-use + short-lived

# The private-key envelope is stored verbatim and never parsed, so the only bound the server
# applies to it is a size cap. Defined here because BOTH of the field's writers -- first
# registration below and replacement further down -- must use the same one: a cap on one writer
# only is not a cap. Measured in UTF-8 BYTES, matching the serialized cap in the envelope design
# and the way the client measures, so the two cannot disagree about the same blob.
_MAX_ENVELOPE_BYTES = 16384


@router.post("/keys/register/challenge")
async def register_challenge(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Issue a one-time proof-of-possession challenge for key registration: a server
    EPHEMERAL public key + nonce the client MACs with its private key (ECDH key-confirmation).
    Bound to the current user, single-use, short-lived. See app/services/ecc_pop.py."""
    _ecc_rate_limit(current_user, "register")
    priv_pem, pub_pem, nonce_b64 = ecc_pop.generate_challenge()
    # One live challenge per user: drop any prior ones so the table can't accrete.
    db.query(ECCRegistrationChallenge).filter(
        ECCRegistrationChallenge.user_id == current_user.id
    ).delete(synchronize_session=False)
    ch = ECCRegistrationChallenge(user_id=current_user.id, server_private_key=priv_pem, nonce=nonce_b64)
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return {"challenge_id": str(ch.id), "server_ephemeral_public_key": pub_pem, "nonce": nonce_b64}


def _verify_registration_pop(db: Session, user: User, request: "KeypairRegisterRequest") -> None:
    """Enforce ECDH key-confirmation proof-of-possession for register_public_key. The challenge
    is consumed (deleted) whether or not it verifies, so a failed MAC can't be replayed against
    it. Raises 400 on a missing / malformed / unknown / expired challenge or a bad MAC."""
    pop = request.pop
    if pop is None or not pop.challenge_id or not pop.mac:
        raise HTTPException(status_code=400, detail="Proof of possession is required to register a key.")
    try:
        cid = uuid.UUID(str(pop.challenge_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid proof-of-possession challenge.")
    ch = db.query(ECCRegistrationChallenge).filter(
        ECCRegistrationChallenge.id == cid,
        ECCRegistrationChallenge.user_id == user.id,
    ).first()
    if ch is None:
        raise HTTPException(status_code=400, detail="Invalid or expired proof-of-possession challenge.")
    # Consume it FIRST (single-use): capture the values, then delete + commit so a wrong MAC
    # can't be brute-forced by retrying against the same challenge.
    created_at, server_priv, nonce = ch.created_at, ch.server_private_key, ch.nonce
    db.delete(ch)
    db.commit()
    if created_at is None or (datetime.utcnow() - created_at) > timedelta(seconds=_POP_CHALLENGE_TTL_SECONDS):
        raise HTTPException(status_code=400, detail="Proof-of-possession challenge has expired; request a new one.")
    if not ecc_pop.verify_pop(server_priv, request.public_key, nonce, pop.mac):
        raise HTTPException(status_code=400, detail="Proof of possession failed for this public key.")


@router.post("/keys/register", status_code=status.HTTP_201_CREATED, response_model=KeypairRegisterResponse)
async def register_public_key(
    request: KeypairRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Register user's ECC P-384 public key for Zero-Trust encryption.
    
    - Validates public key format
    - Calculates SHA-256 fingerprint
    - Stores in database for ECDH key wrapping
    - Optionally stores password-encrypted private key for recovery
    """
    _ecc_rate_limit(current_user, "register")
    # A delegated/temp session must NOT set the account's PERMANENT zero-knowledge identity.
    # Registration is first-write-wins and irreversible (no key rotation; re-register 409s;
    # recovery binds to the registered key), so a scoped temp cred could otherwise plant its own
    # key, permanently lock the real owner out, and backdoor every future share. Mirrors the same
    # refusal on PUT /keys/private.
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A temporary session cannot register an account encryption key.",
        )
    try:
        # Validate public key format by trying to import it
        public_key_obj = ECCCryptoService.import_public_key(request.public_key)
        
        # Calculate fingerprint (SHA-256 of public key bytes)
        public_key_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
        
        # Refuse re-registration. Vault DEKs are ECDH-wrapped to the user's CURRENT
        # public key; replacing the keypair would orphan every wrapped DEK and
        # permanently lock the user out of their zero-knowledge vaults (there is no
        # re-wrap/rotation flow). Clients also guard on has_keypair, but the server
        # is the authoritative gate — this is what closes the cross-tab/device race
        # where two first-time registrations could otherwise clobber each other.
        existing_keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
        if existing_keypair:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An encryption key is already set up for this account.",
            )

        # Size cap, checked FIRST so an oversized body is refused before any proof work or write.
        # This is the field's other writer, so it applies the same bound as replacement, from the
        # same constant; without it an account with no keypair could register an arbitrarily large
        # blob that every later read returns verbatim.
        if request.encrypted_private_key is not None:
            try:
                _reg_bytes = len(request.encrypted_private_key.encode("utf-8"))
            except UnicodeEncodeError:
                raise HTTPException(status_code=400, detail="encrypted_private_key is malformed")
            if _reg_bytes > _MAX_ENVELOPE_BYTES:
                raise HTTPException(status_code=400, detail="encrypted_private_key is too large")

        # Proof-of-possession: the caller must prove they hold the PRIVATE key matching this
        # public key (ECDH key-confirmation, via POST /keys/register/challenge), so a
        # substituted / not-held key can't be registered. Raises 400 on missing/invalid/expired.
        _verify_registration_pop(db, current_user, request)

        keypair = UserKeyPair(
            user_id=current_user.id,
            public_key=request.public_key,
            encrypted_private_key=request.encrypted_private_key,
            curve='SECP384R1',
            fingerprint=fingerprint,
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(keypair)
        db.commit()
        db.refresh(keypair)

        # Team-onboarding: the recipient now HAS a key, so any pending
        # "set up your key so a vault can be shared with you" invites are resolved —
        # clear them (the manager re-shares, which now succeeds). Best-effort: a failed
        # cleanup must never fail the registration.
        try:
            db.query(ZKShareInvite).filter(
                ZKShareInvite.target_user_id == current_user.id
            ).delete(synchronize_session=False)
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()

        _audit_zk(db, current_user, "zk_keypair_registered",
                  resource_id=current_user.id, resource_type="user",
                  details={"fingerprint": fingerprint})

        return KeypairRegisterResponse(
            message="Public key registered successfully",
            user_id=str(current_user.id),
            fingerprint=fingerprint,
            key_id=f"key_{current_user.id}"
        )

    except HTTPException:
        # Don't let the 409 conflict get rewrapped below.
        db.rollback()
        raise
    except IntegrityError:
        # Two concurrent registrations for the same user race past the precheck and both commit;
        # the loser violates the user_keypairs unique constraint. Surface a generic conflict, never
        # the raw INSERT SQL / bound params / constraint names.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A public key is already registered for this account"
        )
    except ValueError:
        # Genuine client validation failure (malformed PEM or wrong curve). State the fixed
        # requirement -- the curve is a public standard, useful feedback -- but don't echo the
        # crypto-library parse text (str(e)) at a 400 (which bypasses the 500-sanitizer).
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid public key: must be a PEM-encoded secp384r1 public key"
        )
    except Exception as e:
        # Anything else is unexpected: route it through the 500-sanitizer (generic client message
        # + server-side log + correlation id) instead of leaking str(e) at a mislabeled 400.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Public key registration failed: {str(e)}"
        )



@router.get("/keys/public", response_model=PublicKeyResponse)
async def get_public_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve user's public key information.
    
    Returns:
    - Public key (PEM format)
    - Fingerprint (SHA-256 hash)
    - Whether user has registered a keypair
    """
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    
    if keypair:
        # Update last_used timestamp
        keypair.last_used = datetime.now(timezone.utc)
        db.commit()
        
        return PublicKeyResponse(
            user_id=str(current_user.id),
            public_key=keypair.public_key,
            fingerprint=keypair.fingerprint,
            has_keypair=True
        )
    else:
        return PublicKeyResponse(
            user_id=str(current_user.id),
            public_key=None,
            fingerprint=None,
            has_keypair=False
        )


@router.get("/keys/private")
async def get_private_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return the CURRENT user's password-encrypted private-key blob so a new
    browser session can unlock it locally.

    Zero-knowledge is preserved: the blob is encrypted under the user's passphrase
    on the client (PBKDF2 + AES-GCM), so the server only ever stores and returns
    ciphertext it cannot read. Returns has_keypair=False when none exists (no 404,
    so the client can branch cleanly)."""
    if not may_release_private_envelope(db, current_user):
        raise HTTPException(
            status_code=403, detail=TEMP_ZK_KEY_ACCESS_DENIED
        )
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    if not keypair or not keypair.encrypted_private_key:
        return {"has_keypair": False, "encrypted_private_key": None}
    return {"has_keypair": True, "encrypted_private_key": keypair.encrypted_private_key}


class KeyUpdatePoP(BaseModel):
    """Proof that the caller holds the CURRENTLY REGISTERED private key, bound to this exact
    replacement. See docs/design/vault-private-key-update-pop-v1.md."""
    challenge_id: str = Field(..., description="from POST /ecc/keys/private/challenge")
    mac: str = Field(..., description="base64 HMAC over the update transcript")


class PrivateKeyUpdateRequest(BaseModel):
    """The user's private key RE-WRAPPED in the browser under a NEW passphrase (opaque blob;
    the server cannot read it). The PUBLIC key is unchanged, so this is a passphrase change,
    not a key rotation."""
    encrypted_private_key: str = Field(..., description="password-encrypted private-key blob")
    pop: Optional[KeyUpdatePoP] = Field(None, description="required proof of possession")


# One indistinguishable failure for every reason a proof can fail. Telling a caller WHICH part of
# the attempt was wrong helps only an attacker; a legitimate client's correct response to any of
# them is identical -- request a fresh challenge and retry.
_UPDATE_POP_FAILED = (
    "Proof of possession failed. Request a new challenge and try again."
)



@router.post("/keys/private/challenge")
async def key_update_challenge(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Issue a one-time challenge for REPLACING the stored private-key envelope.

    Interactive sessions only, and only for an account that already has a keypair -- with no
    keypair there is nothing to replace and nothing to prove against.

    Issuance takes a row lock on the owning user so exactly one challenge is live per user even
    under concurrent requests. Without the lock two issuances can interleave their delete and
    insert and leave two live challenges, multiplying an attacker's attempts per round-trip.
    """
    # Refuse BEFORE charging the budget. A temporary session is the OWNER's User row tagged as
    # temporary, and the limiter keys on the user id -- so charging a refused request would let a
    # leaked temp credential hold the owner out of this route indefinitely. That is an
    # availability attack on precisely what proof-bound replacement exists to protect, and a
    # refused caller can never consume a challenge or attempt a proof, so excluding it costs the
    # budget nothing.
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(
            status_code=403,
            detail="A temporary credential cannot change the account encryption passphrase.",
        )
    _ecc_rate_limit(current_user, "key_update_challenge")
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    if not keypair or not keypair.public_key:
        raise HTTPException(status_code=404, detail="No encryption key is set up for this account.")

    # Serialize issuance on the owning user row.
    db.query(User).filter(User.id == current_user.id).with_for_update().first()
    priv_pem, pub_pem, nonce_b64 = ecc_update_pop.generate_challenge()
    db.query(ECCKeyUpdateChallenge).filter(
        ECCKeyUpdateChallenge.user_id == current_user.id
    ).delete(synchronize_session=False)
    ch = ECCKeyUpdateChallenge(
        user_id=current_user.id, server_private_key=priv_pem, nonce=nonce_b64
    )
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return {
        "challenge_id": str(ch.id),
        "server_ephemeral_public_key": pub_pem,
        "nonce": nonce_b64,
    }


@router.put("/keys/private")
async def update_private_key(
    request: PrivateKeyUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change the encryption passphrase: store a private-key blob the browser RE-ENCRYPTED under
    a new passphrase, WITHOUT touching the public key.

    Because the public key is unchanged, every vault DEK stays valid (they are ECDH-wrapped to
    that public key), so NO per-vault re-wrap is needed — the user simply unlocks with the new
    passphrase from now on. Zero-knowledge is preserved: the server only ever stores the opaque
    ciphertext it cannot read. This is distinct from a key ROTATION (a new public key would
    orphan every wrapped DEK); we deliberately keep the public key fixed. Rate-limited on its own
    per-user bucket, separate from registration so exhausting one cannot lock out the other.

    Requires an INTERACTIVE session: a temporary credential authenticates AS the account owner,
    and this overwrites the owner's private-key blob verbatim (no current-passphrase proof server
    side), so a delegated/temp cred must not be able to corrupt it and irreversibly lock the owner
    out of every zero-knowledge vault. Changing the account passphrase is an owner operation."""
    # Refuse before charging the budget -- see the note on the challenge route: a temp session
    # shares the owner's rate-limit bucket, so a charged refusal is an owner lockout.
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary credential cannot change the account encryption passphrase.")
    _ecc_rate_limit(current_user, "key_update")

    # STEP 1 - validate the request WITHOUT parsing the envelope. A malformed request is refused
    # here and does NOT consume a challenge, so an honest client cannot destroy its own in-flight
    # challenge with a bad request. The server never learns the envelope's format: the transcript
    # already binds the stored bytes to the proof, and a format-aware server would reject every
    # replacement today's client makes, since the versioned writer ships disabled.
    if not request.encrypted_private_key:
        raise HTTPException(status_code=400, detail="encrypted_private_key is required")
    try:
        envelope_bytes = len(request.encrypted_private_key.encode("utf-8"))
    except UnicodeEncodeError:
        # JSON admits a lone surrogate, which is not encodable. That is a malformed request, not
        # a server fault. NB the bound stays on UTF-8 BYTES: narrowing it to ASCII would refuse
        # legitimate callers and would drift from the client-side check.
        raise HTTPException(status_code=400, detail="encrypted_private_key is malformed")
    if envelope_bytes > _MAX_ENVELOPE_BYTES:
        raise HTTPException(status_code=400, detail="encrypted_private_key is too large")
    # An account with no keypair has nothing to replace and nothing to prove against, and it
    # learns that from GET /ecc/keys/public anyway, so answering honestly reveals nothing. This
    # check precedes the proof check so the "no keypair" case keeps its own distinct status.
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    if not keypair:
        raise HTTPException(status_code=404, detail="No encryption key is set up for this account.")

    # A malformed request is reported distinctly from a failed proof. That is not in tension with
    # the indistinguishability rule below: a caller who sent the wrong SHAPE can act on it, learns
    # nothing about the challenge or the key, and is refused before anything is consumed. Telling
    # them "proof failed, get a new challenge" instead sends them round a loop that cannot help,
    # burning one issuance and one verification from two rate-limited budgets per attempt.
    pop = request.pop
    if pop is None or not pop.challenge_id or not pop.mac:
        raise HTTPException(status_code=400, detail="pop.challenge_id and pop.mac are required")
    try:
        cid = uuid.UUID(str(pop.challenge_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="pop.challenge_id is not a valid challenge id")

    # STEP 2 - claim and CONSUME the challenge before verifying. Consumption must not depend on
    # the result: if a failed proof left the challenge alive an attacker could brute-force MACs
    # against one issuance. One-time means a wrong answer costs a fresh, rate-limited issuance.
    ch = db.query(ECCKeyUpdateChallenge).filter(
        ECCKeyUpdateChallenge.id == cid,
        ECCKeyUpdateChallenge.user_id == current_user.id,
    ).with_for_update().first()
    if ch is None:
        _audit_zk(db, current_user, "zk_key_update_pop_failed",
                  resource_id=current_user.id, resource_type="user",
                  details={"reason": "no_live_challenge"}, status="failure")
        raise HTTPException(status_code=400, detail=_UPDATE_POP_FAILED)
    created_at, server_priv, nonce = ch.created_at, ch.server_private_key, ch.nonce
    db.delete(ch)
    db.commit()

    # STEP 3 - expiry, then the proof. Failures are audited with a short reason code and never the
    # attempted MAC, nonce or envelope bytes: both routes are authenticated and rate-limited, and
    # the limiter fails OPEN on a backing-store outage, so this record is what keeps an attempt
    # burst visible in exactly the window where the limit is not.
    expired = created_at is None or (
        datetime.utcnow() - created_at
    ) > timedelta(seconds=ecc_update_pop.CHALLENGE_TTL_SECONDS)
    ok = (not expired) and ecc_update_pop.verify_pop(
        server_priv, keypair.public_key, str(cid), nonce,
        str(current_user.id), request.encrypted_private_key, pop.mac,
    )
    if not ok:
        _audit_zk(db, current_user, "zk_key_update_pop_failed",
                  resource_id=current_user.id, resource_type="user",
                  details={"reason": "expired" if expired else "bad_proof"}, status="failure")
        raise HTTPException(status_code=400, detail=_UPDATE_POP_FAILED)

    keypair.encrypted_private_key = request.encrypted_private_key
    keypair.updated_at = datetime.now(timezone.utc)
    db.commit()
    _audit_zk(db, current_user, "zk_passphrase_changed",
              resource_id=current_user.id, resource_type="user")
    return {"ok": True, "message": "Encryption passphrase updated."}


# NOTE: POST /ecc/vaults (create_vault_with_ecc) was REMOVED. It was a dead,
# orphaned creation path (the live zero-knowledge create flow is POST /vaults with a
# browser-wrapped DEK — see api_server.create_vault / static/js/app.js). It was unsafe
# on three counts: it generated the vault DEK SERVER-SIDE (os.urandom — breaking the
# zero-knowledge guarantee), it skipped the VAULT_CREATE endpoint permission, and it
# bypassed _resolve_vault_type_for_create / _zk_enabled (the plan capability ceiling).
# Vault creation must go through POST /vaults so all three gates apply.


def _is_hierarchical(vault: Vault) -> bool:
    return getattr(vault, 'key_wrapping_mode', 'direct') == 'hierarchical'


def _team_key_map(vault: Vault) -> dict:
    """Parse Vault.team_key (JSON text) into {dek_version(str): {wrapped_dek, ephemeral_public_key,
    team_key_version}}. Tolerant of NULL/garbage (returns {})."""
    raw = getattr(vault, 'team_key', None)
    if not raw:
        return {}
    try:
        m = json.loads(raw)
        return m if isinstance(m, dict) else {}
    except (ValueError, TypeError):
        return {}


def _team_rotation_owed(db: Session, vault: Vault) -> bool:
    """True iff a TEAMPRIV holder was deactivated at the CURRENT team epoch WITHOUT the team
    keypair being rotated — the signature of a bare revoke (DELETE /permissions, DELETE /members)
    or a reconciler sweep on a hierarchical vault. A PROPER team rotation bumps team_key_version
    and leaves deactivated rows only at OLD epochs, so a deactivated TEAMPRIV at the current epoch
    means the removed member still holds the CURRENT team private key. While this is owed, /rekey
    MUST rotate the team keypair — a cheap DEK-only rotation would wrap the new DEK to the
    unchanged team pubkey, silently re-granting that member access to all NEW content."""
    if not _is_hierarchical(vault):
        return False
    cur = getattr(vault, 'team_key_version', 1) or 1
    return db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault.id,
        VaultMemberKey.key_version == cur,
        VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
        VaultMemberKey.is_active == False,  # noqa: E712
    ).first() is not None


def _rekey_owed(db: Session, vault: Vault) -> bool:
    """True when a member's key was deactivated at the CURRENT epoch WITHOUT a DEK rotation —
    the signature of a legacy revoke, an orphan-reconciler sweep, or an offboarding blacklist
    (a deactivated user's wrapped-DEK rows). A manager should rotate the vault key (browser
    /rekey) for forward secrecy on new content. Derived (not stored): a rekey mints a new epoch
    the removed member never receives, so no deactivated row remains at the NEW current epoch and
    the flag clears itself. Hierarchical vaults reuse the team-rotation-owed signal."""
    if _is_hierarchical(vault):
        return _team_rotation_owed(db, vault)
    cur = getattr(vault, 'dek_version', 1) or 1
    return db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault.id,
        VaultMemberKey.key_version == cur,
        VaultMemberKey.is_active == False,  # noqa: E712
    ).first() is not None


class IndexKeyWrap(BaseModel):
    """One member's wrapped copy of the vault name-index key."""
    user_id: str
    encrypted_index_key: str = Field(..., max_length=8192)
    ephemeral_public_key: str = Field(..., max_length=8192)


class IndexKeyPut(BaseModel):
    wraps: List[IndexKeyWrap] = Field(..., min_length=1, max_length=512)


@router.get("/vaults/{vault_id}/index-key")
async def get_vault_index_key(
    vault_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's wrapped copy of this vault's name-index key, or `null` if the vault has none.

    A `null` is an ordinary answer, not an error: vaults created before this key existed do not
    have one, and a client that gets `null` falls back to the legacy per-epoch derivation. Making
    it a 404 would force every caller to treat the normal migration state as a failure.

    Gated by the same check that releases the DEK. That is deliberate rather than convenient: this
    key does not decrypt anything, but it does let its holder CONFIRM a guessed filename against
    stored indices, so releasing it more freely than the DEK would hand out a capability to
    principals who cannot read the vault at all.
    """
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not may_release_vault_key(db, current_user, vault):
        raise HTTPException(status_code=403, detail="No access to this vault's keys")

    row = db.query(VaultMemberIndexKey).filter(
        VaultMemberIndexKey.vault_id == vault.id,
        VaultMemberIndexKey.user_id == current_user.id,
        VaultMemberIndexKey.is_active == True,  # noqa: E712
    ).order_by(VaultMemberIndexKey.index_key_version.desc()).first()

    if row is None:
        return {"index_key": None, "index_key_version": None}
    return {
        "index_key": row.encrypted_index_key,
        "ephemeral_public_key": row.ephemeral_public_key,
        "index_key_version": row.index_key_version,
        # The account the server selected this row for. The unwrap transcript binds the recipient,
        # and the client takes it from here rather than local state -- the same choice the DEK
        # unwrap makes, because localStorage-hydrated identity tolerates corrupt data.
        "recipient_user_id": str(row.user_id),
    }


@router.put("/vaults/{vault_id}/index-key")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def put_vault_index_key(
    vault_id: str,
    body: IndexKeyPut,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Store the wrapped name-index key: mint it, or add a wrap for a NEW member.

    Minting is lazy: a vault gains this key the first time a client that can read it posts one,
    which is what lets existing vaults adopt it without a migration that needs plaintext names.

    **Two shapes, one endpoint.** If the vault has no active wrap at this version, this mints the
    key (adds every wrap in the body). If it already has wraps, this ADDS a wrap for each member in
    the body who does not yet have one -- the share case, where a new member must receive the SAME
    key the others hold, or they compute indices under a key nobody else uses.

    **The key itself is immutable at a version.** A wrap that targets a member who already has one
    is refused with 409: overwriting it would swap the key under that member (a mint race, or a
    manager handing out a different key), and last-writer-wins would leave members disagreeing about
    what a name hashes to. Replacing the key is the explicit, opt-in "rotate name index" operation
    (a new version), never a side effect of this call.

    Authorization is the vault-management gate, not mere read access: handing a member a wrap binds
    who can compute this vault's name indices, which is the same class of decision as granting a
    DEK. Adding a wrap of the RIGHT key is trusted to the manager, exactly as a DEK re-wrap on share
    is -- the server holds only opaque wraps and cannot check the plaintext key.
    """
    _ecc_rate_limit(current_user, "mutate")
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403,
                            detail="Only the vault owner or a manager can set the name-index key")

    # Validate every user_id up front so a malformed one is a clean 400, not a partial write.
    incoming = []
    for wrap in body.wraps:
        try:
            uid = uuid.UUID(str(wrap.user_id))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="user_id must be a UUID")
        incoming.append((uid, wrap))

    # Members who already hold a wrap at this version. Their wrap is immutable here: overwriting it
    # would swap the key under them. A body that targets any of them is refused whole -- partial
    # success would leave the caller unsure which wraps landed.
    existing_uids = {
        r.user_id for r in db.query(VaultMemberIndexKey.user_id).filter(
            VaultMemberIndexKey.vault_id == vault.id,
            VaultMemberIndexKey.index_key_version == 1,
            VaultMemberIndexKey.is_active == True,  # noqa: E712
        ).all()
    }
    overwrites = [str(uid) for uid, _ in incoming if uid in existing_uids]
    if overwrites:
        raise HTTPException(
            status_code=409,
            detail=("A name-index-key wrap already exists for a member in this request; the key "
                    "cannot be replaced for an existing member. Add only new members."))

    for uid, wrap in incoming:
        db.add(VaultMemberIndexKey(
            vault_id=vault.id,
            user_id=uid,
            encrypted_index_key=wrap.encrypted_index_key,
            ephemeral_public_key=wrap.ephemeral_public_key,
            granted_by=current_user.id,
        ))
    try:
        db.commit()
    except IntegrityError:
        # A concurrent call added a wrap for one of these members between the check and the commit
        # (the unique (vault, user, version) index). Same situation as finding it already there.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A name-index-key wrap for a member in this request was just created; re-read.")
    return {"status": "ok", "wraps": len(incoming), "index_key_version": 1}


@router.get("/vaults/{vault_id}/keys", response_model=VaultKeysResponse)
async def get_vault_keys(
    vault_id: str,
    key_version: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the caller's encrypted vault DEK for a zero-knowledge vault.

    DIRECT mode: returns the DEK wrapped to the caller's identity key for the requested/current
    DEK epoch. HIERARCHICAL mode (two-axis): returns the DEK wrapped to the TEAM public key for
    the requested DEK epoch D, PLUS the caller's wrap of the team PRIVATE key at the team epoch
    T = team_key[D].team_key_version, so the browser unwraps team_priv (with their identity key)
    then the DEK (with team_priv). Always reports current_dek_version.

    The server never sees a plaintext DEK or team private key. Runs the orphan reconciler first
    so a key left active by a failed legacy revoke is dropped before it can be served.
    """
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not may_release_vault_key(db, current_user, vault):
        raise HTTPException(
            status_code=403, detail=TEMP_ZK_KEY_ACCESS_DENIED
        )

    # Confine a scoped temp credential to its granted vaults — the SAME gate the standard
    # read path applies (app/services/vault_service.py get_vault -> enforce_vault). Without it a cred scoped
    # to vault A could still read vault B's wrapped DEK here. No-op for normal principals.
    enforce_vault(current_user, vault_id)
    # A scoped temp credential must also hold a capability, not just vault membership: reading the
    # wrapped-DEK routing blob is a "see the vault's contents" action. Accept see_files OR
    # change_permissions — the ZK SHARE (add-member) flow reads this to re-wrap the DEK for a new
    # recipient, so a manage-permissions cred must be able to read it. No-op for normal principals.
    if is_scoped(current_user) and not (
        {"vault.see_files", "vault.change_permissions"} & set(effective_vault_caps(current_user, vault_id))
    ):
        raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this action")

    # Close any authz/crypto divergence before handing out a key.
    _reconcile_orphan_member_keys(db, vault)

    owed = _rekey_owed(db, vault)  # surface "a member was removed without a rotation" to holders
    current = getattr(vault, 'dek_version', 1) or 1
    want = key_version if key_version is not None else current
    mode = getattr(vault, 'key_wrapping_mode', 'direct')

    def _no_access():
        return VaultKeysResponse(vault_id=vault_id, mode=mode, has_access=False,
                                 current_dek_version=current)

    if _is_hierarchical(vault):
        # Two-axis: resolve the DEK wrap for epoch `want` from the team_key map, then the team
        # epoch T it was wrapped under, then the caller's TEAMPRIV row at T.
        entry = _team_key_map(vault).get(str(want))
        if not entry:
            return _no_access()
        team_epoch = entry.get('team_key_version')
        teampriv = db.query(VaultMemberKey).filter(
            VaultMemberKey.vault_id == vault_id,
            VaultMemberKey.user_id == current_user.id,
            VaultMemberKey.key_version == team_epoch,
            VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
            VaultMemberKey.is_active == True,  # noqa: E712
        ).first()
        if not teampriv:
            return _no_access()
        return VaultKeysResponse(
            vault_id=vault_id, mode='hierarchical', has_access=True,
            recipient_user_id=str(current_user.id),
            wrapped_dek=entry.get('wrapped_dek'),
            ephemeral_public_key=entry.get('ephemeral_public_key'),
            key_version=want, current_dek_version=current,
            team_public_key=getattr(vault, 'team_public_key', None),
            wrapped_team_privkey=teampriv.wrapped_dek,
            team_ephemeral_public_key=teampriv.ephemeral_public_key,
            team_key_version=team_epoch,
            rekey_owed=owed,
        )

    # DIRECT mode: the DEK is wrapped straight to the caller at the requested DEK epoch. (No
    # wrapping_algorithm filter here: a direct vault never holds TEAMPRIV rows, and filtering
    # could exclude a legacy row written under the model-default algorithm.)
    member_key = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.user_id == current_user.id,
        VaultMemberKey.key_version == want,
        VaultMemberKey.is_active == True  # noqa: E712
    ).first()
    if not member_key:
        return _no_access()
    return VaultKeysResponse(
        vault_id=vault_id,
        mode=mode,
        has_access=True,
        recipient_user_id=str(current_user.id),
        wrapped_dek=member_key.wrapped_dek,  # Use the property alias
        ephemeral_public_key=member_key.ephemeral_public_key,
        key_version=member_key.key_version,
        current_dek_version=current,
        rekey_owed=owed,
    )


@router.get("/users/{user_id}/public-key")
async def get_user_public_key(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return ANOTHER user's ECC public key so an existing vault member can wrap
    the vault DEK for them (zero-knowledge re-share). Public keys are not secret;
    only the public half is exposed.

    Scoped to callers who could legitimately share a vault (own/manage one, or admin) so this
    isn't a has-a-keypair enumeration oracle any authenticated account can sweep, and
    rate-limited on top. Non-sharers get 403 without revealing whether the target has a key."""
    _ecc_rate_limit(current_user, "public_key")
    if not _manages_any_vault(db, current_user):
        raise HTTPException(status_code=403, detail="Only a vault owner or manager may look up a member's key")
    kp = db.query(UserKeyPair).filter(UserKeyPair.user_id == user_id).first()
    if not kp:
        return {"user_id": user_id, "public_key": None, "fingerprint": None, "has_keypair": False}
    return {
        "user_id": user_id,
        "public_key": kp.public_key,
        "fingerprint": kp.fingerprint,
        "has_keypair": True,
    }


class GrantMemberKeyRequest(BaseModel):
    user_id: str
    # DIRECT vaults only -- rejected on the hierarchical path, whose rows are keyed by the
    # separate team epoch. The DEK epoch the supplied `wrapped_dek` was built against. A wrap is only meaningful
    # paired with its epoch, and the client is the only party that knows which one it used --
    # the server can read the vault's CURRENT epoch, which is a different question whenever a
    # rotation lands in between. Optional so a client that predates this field keeps working
    # (it gets the old, racy behaviour); supplied, it is verified under the row lock and a
    # mismatch is a 409, mirroring `from_version` on the rekey path.
    dek_version: Optional[int] = None
    # DIRECT mode: the DEK wrapped to the recipient's public key.
    wrapped_dek: Optional[str] = None          # base64
    ephemeral_public_key: Optional[str] = None  # base64, ephemeral ECDH public key for the unwrap
    # HIERARCHICAL mode: the TEAM PRIVATE key wrapped to the recipient's public key (O(1) —
    # the DEK is not re-wrapped per member; it stays wrapped to the team public key).
    wrapped_team_privkey: Optional[str] = None
    team_ephemeral_public_key: Optional[str] = None


@router.post("/vaults/{vault_id}/members")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def grant_member_key(
    vault_id: str,
    request: GrantMemberKeyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Store a vault DEK that a MANAGER WRAPPED IN THE BROWSER for another user
    (zero-knowledge sharing). The server only persists opaque ciphertext + the
    ephemeral public key; it never sees the DEK.

    Authorization: the caller must be the owner / a global admin / a Manager
    (_can_manage_vault) — the SAME gate as the authz grant POST /vaults/{id}/permissions,
    so this DEK-minting path is not a weaker surface that any plain member could use to
    re-grant a revoked user a working key. The caller must ALSO hold an active key (so they
    could actually unwrap+re-wrap the DEK). The recipient must have a registered keypair."""
    _ecc_rate_limit(current_user, "mutate")
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")

    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can share this vault")

    granter_key = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.user_id == current_user.id,
        VaultMemberKey.is_active == True,
    ).first()
    if not granter_key:
        raise HTTPException(status_code=403, detail="You don't hold a key for this vault")

    target = db.query(User).filter(User.id == request.user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    if not db.query(UserKeyPair).filter(UserKeyPair.user_id == request.user_id).first():
        raise HTTPException(
            status_code=400,
            detail="Target user has not set up an encryption key",
        )

    # A Manager must not overwrite (or mint) the wrap of the OWNER or a PEER MANAGER. The server
    # holds only opaque wraps and cannot tell a correct DEK from an attacker's, so swapping the
    # wrap under a guaranteed key-holder or a peer would feed them a key of the caller's choosing:
    # they lose access to existing content and their new uploads become readable only to the
    # caller's pick. grant had NEITHER guard, unlike revoke (the owner-guard + peer-manager guard
    # below mirror it) and the index-key PUT (which 409s an overwrite for the same reason). Uses
    # the resolved target.id (canonical) so a non-canonical user_id string can't slip past. Keep
    # this ABOVE the direct/hierarchical split below so it protects both wrapping modes -- a
    # hierarchical vault's owner/peer TEAMPRIV wrap is overwritten by the same upsert.
    if str(target.id) == str(vault.owner_id) and str(current_user.id) != str(vault.owner_id):
        raise HTTPException(
            status_code=403,
            detail="Only the vault owner can set the owner's own key wrap",
        )
    if not _is_owner_or_admin(vault, current_user) and str(target.id) != str(current_user.id):
        peer = _member_row(db, vault.id, target.id)
        if peer and peer.manage_permission:
            raise HTTPException(
                status_code=403,
                detail="Only the vault owner or an admin can re-wrap a manager's key",
            )

    # HIERARCHICAL: store the recipient's wrap of the TEAM PRIVATE key at the current TEAM
    # epoch — O(1), the DEK is not touched. DIRECT: store the DEK wrapped to the recipient at
    # the current DEK epoch. Either way, upsert keyed by (vault, user, key_version) (the
    # table's uniqueness) so re-sharing refreshes the current-epoch row in place.
    if _is_hierarchical(vault):
        if not (request.wrapped_team_privkey and request.team_ephemeral_public_key):
            raise HTTPException(
                status_code=400,
                detail="This vault uses hierarchical wrapping; supply wrapped_team_privkey + team_ephemeral_public_key.",
            )
        if request.dek_version is not None:
            raise HTTPException(
                status_code=400,
                detail=("dek_version does not apply to a hierarchical vault; its member rows "
                        "are keyed by the team epoch. Omit it."),
            )
        epoch = getattr(vault, 'team_key_version', 1) or 1
        blob, eph, algo = request.wrapped_team_privkey, request.team_ephemeral_public_key, TEAMPRIV_ALGO
    else:
        if not (request.wrapped_dek and request.ephemeral_public_key):
            raise HTTPException(
                status_code=400,
                detail="This vault uses direct wrapping; supply wrapped_dek + ephemeral_public_key.",
            )
        # Re-read the vault under a row lock before deciding the epoch, so a rotation cannot
        # commit between the read and the upsert. populate_existing() is load-bearing: this
        # session already holds the row from the entry read, and without it the identity map
        # hands back the stale instance -- the lock would be taken and the value compared
        # would still predate it.
        #
        # The lock alone is not sufficient anyway: it stops the value moving during the write,
        # not the client's blob being older than the value we read. The declared epoch below
        # is the actual fix; the lock is what makes checking it meaningful.
        locked = (db.query(Vault).populate_existing()
                  .filter(Vault.id == vault_id).with_for_update().first())
        if locked is None:
            # Hard-deleted between the entry read and here. Saying 404 is honest; defaulting
            # the epoch to 1 would answer a 409 naming an epoch that no longer exists.
            raise HTTPException(status_code=404, detail="Vault not found")
        epoch = getattr(locked, 'dek_version', 1) or 1
        if request.dek_version is not None and request.dek_version != epoch:
            raise HTTPException(
                status_code=409,
                detail=(f"Vault was re-keyed concurrently (current epoch {epoch}); "
                        "refetch the vault key and re-share."),
            )
        blob, eph, algo = request.wrapped_dek, request.ephemeral_public_key, DIRECT_DEK_ALGO

    existing = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.user_id == request.user_id,
        VaultMemberKey.key_version == epoch,
    ).first()
    if existing:
        existing.wrapped_dek = blob
        existing.ephemeral_public_key = eph
        existing.wrapping_algorithm = algo
        existing.is_active = True
        existing.granted_by = current_user.id
        existing.granted_at = datetime.now(timezone.utc)
        existing.revoked_at = None
        existing.revoked_by = None
    else:
        db.add(VaultMemberKey(
            vault_id=vault_id,
            user_id=request.user_id,
            wrapped_dek=blob,
            ephemeral_public_key=eph,
            wrapping_algorithm=algo,
            key_version=epoch,
            granted_by=current_user.id,
            granted_at=datetime.now(timezone.utc),
        ))
    db.commit()  # persist the grant on its own — authoritative, BEFORE any best-effort cleanup
    # The share landed, so drop any pending onboarding invite for this (vault, recipient)
    # — belt-and-suspenders (it is normally already cleared when the recipient registered a
    # keypair). A SEPARATE commit so a cleanup failure can only drop the stale invite, never
    # roll back the grant we already committed and are about to report as ok.
    try:
        db.query(ZKShareInvite).filter(
            ZKShareInvite.vault_id == vault_id,
            ZKShareInvite.target_user_id == request.user_id,
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    _audit_zk(db, current_user, "zk_member_key_granted", resource_id=vault_id,
              details={"target_user_id": str(request.user_id), "key_version": epoch,
                       "mode": getattr(vault, 'key_wrapping_mode', 'direct')})
    return {"status": "ok", "vault_id": vault_id, "user_id": request.user_id,
            "key_version": epoch, "mode": getattr(vault, 'key_wrapping_mode', 'direct')}


class ZKInviteRequest(BaseModel):
    # Coerce at the boundary (mirrors the grant/revoke path params) so a non-canonical UUID
    # can't slip past a string comparison.
    user_id: uuid.UUID


@router.post("/vaults/{vault_id}/invites")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def invite_to_vault(
    vault_id: str,
    request: ZKInviteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Invite a KEYLESS user to a zero-knowledge vault (team-onboarding for keyless recipients).

    A zero-knowledge DEK can only be wrapped for a user who has an encryption key, so a
    manager cannot share directly with a keyless recipient. Instead of a dead-end, this
    records the intent and lets us prompt the recipient to set up a key; the manager then
    re-shares (POST .../members) once they have one. NO key material is created here.
    Manager-gated exactly like the grant path (owner / global admin / Manager)."""
    _ecc_rate_limit(current_user, "mutate")
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can invite members")
    target = db.query(User).filter(User.id == request.user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    # Only keyless users need an invite; a user WITH a key can be shared to directly.
    if db.query(UserKeyPair).filter(UserKeyPair.user_id == request.user_id).first():
        raise HTTPException(
            status_code=400,
            detail="This user already has an encryption key — share the vault with them directly.",
        )
    existing = db.query(ZKShareInvite).filter(
        ZKShareInvite.vault_id == vault_id,
        ZKShareInvite.target_user_id == request.user_id,
    ).first()
    if existing:
        existing.invited_by = current_user.id
        existing.created_at = datetime.utcnow()
    else:
        db.add(ZKShareInvite(vault_id=vault_id, target_user_id=request.user_id,
                             invited_by=current_user.id))
    try:
        db.commit()
    except IntegrityError:
        # A concurrent invite for the same (vault, target) already created the row — the
        # UNIQUE constraint held, so this is an idempotent no-op, not a 500. (Mirrors the
        # lost-unique-race handling on the rename path.)
        db.rollback()
        return {"status": "invited", "vault_id": vault_id, "user_id": str(request.user_id)}
    _audit_zk(db, current_user, "zk_share_invited", resource_id=vault_id,
              details={"target_user_id": str(request.user_id)})
    return {"status": "invited", "vault_id": vault_id, "user_id": str(request.user_id)}


@router.get("/keys/invites")
async def list_share_invites(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """The CURRENT user's pending zero-knowledge share invites, so the UI can prompt a
    keyless recipient to set up an encryption key. `needs_keypair` is True when they have
    no key yet (the case worth prompting on). No key material is involved; the vault name
    stays client-sealed, so only the vault id + inviter are returned."""
    has_keypair = db.query(UserKeyPair).filter(
        UserKeyPair.user_id == current_user.id
    ).first() is not None
    rows = db.query(ZKShareInvite).filter(
        ZKShareInvite.target_user_id == current_user.id
    ).order_by(ZKShareInvite.created_at.desc()).all()
    invites = []
    for r in rows:
        inviter = db.query(User).filter(User.id == r.invited_by).first() if r.invited_by else None
        invites.append({
            "vault_id": str(r.vault_id),
            "invited_by": str(r.invited_by) if r.invited_by else None,
            "invited_by_username": getattr(inviter, "username", None),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return {"needs_keypair": not has_keypair, "count": len(invites), "invites": invites}


@router.delete("/vaults/{vault_id}/members/{user_id}")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def revoke_member_key(
    vault_id: str,
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deactivate a member's wrapped DEK(s) WITHOUT rotating the vault DEK (legacy /
    back-compat path).

    Authorization: owner / global admin / Manager (_can_manage_vault) — the SAME gate as
    rekey_vault and POST /vaults/{id}/permissions, so deactivating another user's key is not
    a weaker surface than a plain permission change. Previously this required only that the
    caller HOLD an active key for the vault, which let any shared member (or, before the auth
    delegation fix, a revoked/locked token) deactivate any OTHER member's — including the
    OWNER's — wrapped DEK rows.

    The vault owner can never be revoked: the orphan reconciler skips owner rows and a rekey
    needs the owner's DEK, so removing the owner's key would permanently lock the vault's
    guaranteed key-holder out with no self-rescue. Mirrors the rekey owner-guard.

    This only stops the member from unwrapping via the server; it does NOT give forward
    secrecy, because the member (and anyone who already unwrapped) has seen the current
    DEK and can still read existing and future same-epoch content. For a real revoke use
    POST /ecc/vaults/{vault_id}/rekey, which mints a NEW DEK epoch the removed member never
    receives (the browser revoke flow calls /rekey). Deactivates the member's rows across
    ALL epochs so no stale-epoch key is left readable."""
    _ecc_rate_limit(current_user, "mutate")
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can revoke a member's key")
    # user_id is a uuid.UUID (FastAPI-coerced from the path), so this compares canonical
    # UUIDs — a non-canonical form (uppercase / hyphen-less) can't slip past the owner-guard
    # while the DB (which normalizes UUID text) still matches the owner's rows below.
    if user_id == vault.owner_id:
        raise HTTPException(status_code=400, detail="Cannot revoke the vault owner")
    # A Manager cannot unseat a PEER Manager — that stays owner/admin-only, matching
    # DELETE /vaults/{id}/permissions (which the browser revoke flow pairs this with).
    if not _is_owner_or_admin(vault, current_user):
        peer = _member_row(db, vault.id, user_id)
        if peer and peer.manage_permission:
            raise HTTPException(status_code=403, detail="Only the vault owner or an admin can revoke a manager")
    rows = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.user_id == user_id,
        VaultMemberKey.is_active == True,
    ).all()
    for mk in rows:
        mk.is_active = False
        mk.revoked_at = datetime.now(timezone.utc)
        mk.revoked_by = current_user.id
    if rows:
        db.commit()
    _audit_zk(db, current_user, "zk_member_key_revoked", resource_id=vault_id,
              details={"target_user_id": str(user_id), "keys_deactivated": len(rows)})
    return {"status": "ok"}


# =============================================================================
# Zero-knowledge DEK rotation on revoke (forward-only versioning)
# =============================================================================

class MemberKeyWrap(BaseModel):
    """One member's copy of the wrapped key material, wrapped to their public key in the browser.
    DIRECT rekey: wrapped_dek is the new DEK. HIERARCHICAL team rotation: wrapped_dek is the new
    TEAM PRIVATE key (the field is generic)."""
    user_id: str
    wrapped_dek: str = Field(..., max_length=8192)
    ephemeral_public_key: str = Field(..., max_length=8192)


class RekeyRequest(BaseModel):
    """Atomic revoke + rotation. The browser does all crypto and submits opaque wraps; the
    server bumps the epoch(s) in one transaction and never sees a DEK or team private key.

    DIRECT vaults: member_keys = the new DEK wrapped for every REMAINING member.
    HIERARCHICAL vaults: a new DEK is ALWAYS minted (team_dek_wrapped, wrapped to a team pubkey).
      - Routine rotation (team keypair unchanged): member_keys MUST be empty.
      - Team-member revoke (forward secrecy): supply a NEW team_public_key (!= stored) and
        member_keys = the new TEAM PRIVATE key wrapped for every remaining member.
    """
    from_version: int = Field(..., description="DEK epoch the client rotated FROM (optimistic lock)")
    to_version: int = Field(..., description="DEK epoch the client rotated TO (must be from_version+1)")
    # A UUID (not a bare str) so the owner-guard below compares canonical UUIDs: a
    # non-canonical form can't slip past `str(revoke_user_id) == str(owner_id)` while the
    # DB still normalizes it and deactivates the owner's rows.
    revoke_user_id: Optional[uuid.UUID] = Field(None, description="member being removed, if any")
    member_keys: List[MemberKeyWrap] = Field(..., max_length=512, description="per-remaining-member wraps (empty for a routine hierarchical rotation)")
    # Hierarchical only:
    team_dek_wrapped: Optional[str] = Field(None, description="the new DEK wrapped to a team public key")
    team_dek_ephemeral_public_key: Optional[str] = None
    team_public_key: Optional[str] = Field(None, description="a NEW team public key (presence => team-keypair rotation)")


@router.get("/vaults/{vault_id}/member-keys")
async def list_member_keys(
    vault_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the authoritative re-wrap target list for a rotation: the distinct users
    who currently hold an ACTIVE key at the vault's current epoch, plus current_dek_version.
    Public routing info only (user ids + the current epoch) — NEVER other members' wrapped
    blobs. The caller must hold an active key for the vault. Runs the orphan reconciler
    first so the target set excludes users whose access was already removed."""
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")

    # Confine a scoped temp credential to its granted vaults (parity with the standard read
    # path). Without it a cred scoped to vault A could enumerate vault B's member roster here.
    enforce_vault(current_user, vault_id)
    # A scoped temp credential must also hold a permission-view (or -change) capability to enumerate
    # the member roster (user ids) — a see_files-only cred should not read the permission surface, but
    # a legitimate rekey cred (change_permissions) must. No-op for normal principals.
    if is_scoped(current_user) and not (
        {"vault.see_permissions", "vault.change_permissions"} & set(effective_vault_caps(current_user, vault_id))
    ):
        raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this action")

    caller_key = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.user_id == current_user.id,
        VaultMemberKey.is_active == True,  # noqa: E712
    ).first()
    if not caller_key:
        raise HTTPException(status_code=403, detail="You don't hold a key for this vault")

    _reconcile_orphan_member_keys(db, vault)

    current = getattr(vault, 'dek_version', 1) or 1
    if _is_hierarchical(vault):
        # Hierarchical members hold TEAMPRIV rows keyed by the TEAM epoch (not dek_version);
        # the re-wrap target on a team-keypair rotation is the active TEAMPRIV holders at it.
        team_epoch = getattr(vault, 'team_key_version', 1) or 1
        rows = db.query(VaultMemberKey.user_id).filter(
            VaultMemberKey.vault_id == vault_id,
            VaultMemberKey.key_version == team_epoch,
            VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
            VaultMemberKey.is_active == True,  # noqa: E712
        ).distinct().all()
        # Intersect with current authz — the SAME filter rekey_vault applies — so the client's
        # supplied set matches the server's `remaining` exactly (a sub-grace orphan holder would
        # otherwise be listed here but dropped in rekey, 400-ing a legitimate rotation).
        return {"vault_id": vault_id, "current_dek_version": current,
                "team_key_version": team_epoch, "mode": "hierarchical",
                "members": [str(r[0]) for r in rows if _is_member(db, vault, r[0])]}
    rows = db.query(VaultMemberKey.user_id).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.key_version == current,
        VaultMemberKey.is_active == True,  # noqa: E712
    ).distinct().all()
    members = [str(r[0]) for r in rows if _is_member(db, vault, r[0])]
    return {"vault_id": vault_id, "current_dek_version": current, "members": members}


@router.post("/vaults/{vault_id}/rekey")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def rekey_vault(
    vault_id: str,
    request: RekeyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Atomically revoke a member (optional) and rotate the zero-knowledge vault DEK to a
    new epoch, re-wrapped for the remaining members. The browser mints DEK v_{n+1}, wraps
    it for each remaining member, and posts the set here; the server bumps Vault.dek_version
    and stores the opaque wraps in ONE transaction — never seeing the DEK.

    Forward-only: existing files keep their old epoch (and remaining members keep their
    old-epoch wrapped rows to read them); only NEW uploads use the new epoch, which the
    revoked member never receives. This gives forward secrecy for new content; content the
    removed member could already read is, by design, assumed already compromised (the DEK
    is extractable in the browser). This is forward secrecy for content created after
    removal, not retroactive secrecy for content the removed member already accessed.

    Authorization: owner / global admin / Manager (parity with /vaults permission changes —
    a security-critical op must not be a weaker authz surface than a plain permission edit).
    """
    _ecc_rate_limit(current_user, "mutate")
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can rotate the vault key")

    # Clean up any pre-existing orphan keys FIRST (it commits) so the 'remaining members'
    # computation is exact — must happen BEFORE we take the row lock below, since its commit
    # would otherwise release that lock and break the rotation's atomicity.
    _reconcile_orphan_member_keys(db, vault)

    # Lock the vault row so concurrent rekeys / version-checked uploads serialize. From here
    # to the final commit there are NO intermediate commits, so the lock holds throughout.
    #
    # populate_existing() is load-bearing, not decoration. This session already holds the vault
    # from the entry read above, and without it the identity map hands back that instance
    # unrefreshed -- the row would be genuinely locked while `current` still carried the value
    # read before the lock, so two concurrent rotations could both satisfy the check below.
    locked = (db.query(Vault).populate_existing()
              .filter(Vault.id == vault_id).with_for_update().first())
    current = getattr(locked, 'dek_version', 1) or 1

    # Optimistic-lock: the client must have rotated from the live epoch.
    if request.from_version != current:
        raise HTTPException(
            status_code=409,
            detail=f"Vault was re-keyed concurrently (current epoch {current}); refetch and retry.",
        )
    if request.to_version != current + 1:
        raise HTTPException(status_code=400, detail="to_version must be from_version + 1")

    # The owner can never be revoked or dropped from the re-wrap set — that would lock the
    # vault's guaranteed key-holder out and break the recovery story (applies to both modes).
    if request.revoke_user_id and str(request.revoke_user_id) == str(locked.owner_id):
        raise HTTPException(status_code=400, detail="Cannot revoke the vault owner")
    # A Manager cannot unseat a PEER Manager via rekey either — that stays owner/admin-only,
    # parity with revoke_member_key and DELETE /vaults/{id}/permissions. Without this a low-tier
    # manager could strip a co-manager's ZK key access by omitting them from member_keys.
    if request.revoke_user_id and not _is_owner_or_admin(locked, current_user):
        peer = _member_row(db, vault_id, request.revoke_user_id)
        if peer and peer.manage_permission:
            raise HTTPException(status_code=403,
                                detail="Only the vault owner or an admin can revoke a manager")

    now = datetime.now(timezone.utc)

    def _validate_cover(remaining: set, *, recipient_label: str):
        """Shared rekey invariant: member_keys must cover EXACTLY the remaining authorized
        members, the revoked user must not be among them, no dups, every recipient has a
        keypair, and the OWNER must be present (recovery guarantee)."""
        supplied = {mk.user_id for mk in request.member_keys}
        if len(supplied) != len(request.member_keys):
            raise HTTPException(status_code=400, detail="Duplicate user_id in member_keys")
        if request.revoke_user_id and str(request.revoke_user_id) in supplied:
            raise HTTPException(status_code=400, detail="The revoked user must not be in member_keys")
        if supplied != remaining:
            raise HTTPException(status_code=400, detail=(
                f"member_keys must cover EXACTLY the remaining {recipient_label}. "
                f"missing={sorted(remaining - supplied)} unexpected={sorted(supplied - remaining)}"))
        # Recovery guarantee: whenever the owner is an expected recipient (in `remaining`), they
        # MUST be re-wrapped — never silently dropped, which would lock the vault's guaranteed
        # key-holder out. Conditioned on `remaining` so an edge vault whose owner holds no active
        # key row isn't bricked (and `supplied == remaining` already covers them when they are).
        if str(locked.owner_id) in remaining and str(locked.owner_id) not in supplied:
            raise HTTPException(status_code=400, detail="The vault owner must be re-wrapped (recovery guarantee)")
        for uid in supplied:
            if not db.query(UserKeyPair).filter(UserKeyPair.user_id == uid).first():
                raise HTTPException(status_code=400, detail=f"Member {uid} has no encryption key; cannot rotate")

    def _deactivate_revoked():
        if request.revoke_user_id:
            for mk in db.query(VaultMemberKey).filter(
                VaultMemberKey.vault_id == vault_id,
                VaultMemberKey.user_id == request.revoke_user_id,
                VaultMemberKey.is_active == True,  # noqa: E712
            ).all():
                mk.is_active = False
                mk.revoked_at = now
                mk.revoked_by = current_user.id

    if _is_hierarchical(locked):
        # A new DEK is ALWAYS minted and wrapped to a team pubkey (routine: the current team
        # pubkey; revoke: the new one). The DEK wrap is mandatory.
        if not (request.team_dek_wrapped and request.team_dek_ephemeral_public_key):
            raise HTTPException(status_code=400,
                                detail="Hierarchical rekey requires the new DEK wrapped to the team public key")
        cur_team_epoch = getattr(locked, 'team_key_version', 1) or 1
        # Is the revoked user a TEAM member (holds a TEAMPRIV row)? If so, the team keypair MUST
        # be rotated — a DEK-only rotation would NOT revoke them (their old team-priv unwraps the
        # new DEK, which is wrapped to the unchanged team pubkey). This is the central enforcement.
        revoking_team_member = bool(request.revoke_user_id) and db.query(VaultMemberKey).filter(
            VaultMemberKey.vault_id == vault_id,
            VaultMemberKey.user_id == request.revoke_user_id,
            VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
            VaultMemberKey.is_active == True,  # noqa: E712
        ).first() is not None
        rotating_team_key = bool(request.team_public_key) and request.team_public_key != getattr(locked, 'team_public_key', None)

        # A team-keypair rotation is REQUIRED both when this request revokes a team member AND
        # when a prior bare revoke / reconciler sweep already deactivated a current-epoch TEAMPRIV
        # holder (rotation owed). Otherwise a cheap DEK-only rotation would re-grant a removed
        # member (their retained team private key unwraps any DEK wrapped to the unchanged pubkey).
        if (revoking_team_member or _team_rotation_owed(db, locked)) and not rotating_team_key:
            raise HTTPException(status_code=400, detail=(
                "A team member was removed, so the team keypair must be rotated: supply a new "
                "team_public_key and the new team private key re-wrapped for the remaining members."))

        if rotating_team_key:
            new_team_epoch = cur_team_epoch + 1
            # Remaining = active TEAMPRIV holders at the CURRENT team epoch, still authorized,
            # minus the revoked user (team-epoch axis, NOT dek_version).
            rows = db.query(VaultMemberKey.user_id).filter(
                VaultMemberKey.vault_id == vault_id,
                VaultMemberKey.key_version == cur_team_epoch,
                VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS),
                VaultMemberKey.is_active == True,  # noqa: E712
            ).distinct().all()
            remaining = {str(r[0]) for r in rows if _is_member(db, locked, r[0])}
            if request.revoke_user_id:
                remaining.discard(str(request.revoke_user_id))
            _validate_cover(remaining, recipient_label="team members")
            # 1) New TEAMPRIV rows at the new team epoch.
            for mk in request.member_keys:
                db.add(VaultMemberKey(
                    vault_id=vault_id, user_id=mk.user_id,
                    wrapped_dek=mk.wrapped_dek, ephemeral_public_key=mk.ephemeral_public_key,
                    wrapping_algorithm=TEAMPRIV_ALGO, key_version=new_team_epoch,
                    granted_by=current_user.id, granted_at=now,
                ))
            # 2) Swap the team public key + advance the team epoch.
            locked.team_public_key = request.team_public_key
            locked.team_key_version = new_team_epoch
            team_epoch_for_dek = new_team_epoch
        else:
            # Routine DEK rotation — team keypair unchanged, NO per-member work.
            if request.member_keys:
                raise HTTPException(status_code=400,
                                    detail="A routine hierarchical rotation takes no member_keys (the team keypair is unchanged)")
            _deactivate_revoked()  # defensive: a non-team (e.g. stale direct) row, if any
            team_epoch_for_dek = cur_team_epoch

        # Append the new DEK epoch -> team-wrap entry (recording which team epoch wrapped it).
        team_map = _team_key_map(locked)
        team_map[str(request.to_version)] = {
            "wrapped_dek": request.team_dek_wrapped,
            "ephemeral_public_key": request.team_dek_ephemeral_public_key,
            "team_key_version": team_epoch_for_dek,
        }
        locked.team_key = json.dumps(team_map)
        if rotating_team_key:
            _deactivate_revoked()
        locked.dek_version = request.to_version
        db.commit()
        _audit_zk(db, current_user, "zk_vault_rekeyed", resource_id=vault_id, details={
            "revoked_user_id": str(request.revoke_user_id) if request.revoke_user_id else None,
            "from_version": request.from_version, "to_version": request.to_version,
            "mode": "hierarchical", "team_key_version": getattr(locked, 'team_key_version', 1)})
        return {"status": "ok", "vault_id": vault_id, "dek_version": request.to_version,
                "team_key_version": getattr(locked, 'team_key_version', 1)}

    # ---- DIRECT mode (existing behavior + owner guards) ----
    # Authoritative remaining-member set = distinct active holders at the current epoch who
    # ARE STILL AUTHORIZED (owner or a vault_members row), minus the user being revoked. The
    # authz intersection is essential: a holder whose access was removed by a non-rekey path
    # must NOT be re-wrapped into the new epoch. Drop non-members silently so a stale orphan
    # can never block a legitimate rotation.
    rows = db.query(VaultMemberKey.user_id).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.key_version == current,
        VaultMemberKey.is_active == True,  # noqa: E712
    ).distinct().all()
    remaining = {str(r[0]) for r in rows if _is_member(db, locked, r[0])}
    if request.revoke_user_id:
        remaining.discard(str(request.revoke_user_id))
    _validate_cover(remaining, recipient_label="members")

    # 1) Insert the new-epoch wrapped DEK for each remaining member.
    for mk in request.member_keys:
        db.add(VaultMemberKey(
            vault_id=vault_id,
            user_id=mk.user_id,
            wrapped_dek=mk.wrapped_dek,
            ephemeral_public_key=mk.ephemeral_public_key,
            wrapping_algorithm=DIRECT_DEK_ALGO,
            key_version=request.to_version,
            granted_by=current_user.id,
            granted_at=now,
        ))
    # 2) Deactivate ALL of the revoked user's rows, across every epoch.
    _deactivate_revoked()
    # 3) Bump the vault epoch (still under the row lock).
    locked.dek_version = request.to_version
    db.commit()
    _audit_zk(db, current_user, "zk_vault_rekeyed", resource_id=vault_id, details={
        "revoked_user_id": str(request.revoke_user_id) if request.revoke_user_id else None,
        "from_version": request.from_version, "to_version": request.to_version, "mode": "direct"})
    return {"status": "ok", "vault_id": vault_id, "dek_version": request.to_version}


def _lowest_epoch_in_use(db, vault_id, vault):
    """The lowest DEK epoch still referenced by any file's CONTENT (File.encryption_metadata
    key_version), any ZK folder's NAME (Folder.name_key_version), or the vault's OWN sealed
    name/description (Vault.name_key_version). Returns None when nothing references an epoch.

    Files, folder names and the vault name have no shared "content epoch": each is sealed under
    whatever the DEK epoch was at seal time, so retiring a member key below any of these would make
    that item permanently undecryptable for everyone. The vault name has no content of its own, so
    -- exactly like a folder name -- its epoch MUST be counted or a retire could strand it. Absent
    metadata everywhere => epoch 1 (the first sealed build's constant). Read-only; the caller runs
    it under the vault-row lock so the floor cannot move before the delete."""
    from app.core.models import File, Folder

    def _as_epoch(value):
        # None/absent metadata => epoch 1; a present value is used as-is (int-coerced). Preserves the
        # prior inline behaviour exactly, including a stored 0 (which never occurs; epochs are >= 1).
        if value is None:
            return 1
        try:
            return int(value)
        except (TypeError, ValueError):
            return 1

    min_in_use = None
    for f in db.query(File).filter(File.vault_id == vault_id).all():
        meta = f.encryption_metadata or {}
        v = _as_epoch(meta.get('key_version', 1) if isinstance(meta, dict) else 1)
        if min_in_use is None or v < min_in_use:
            min_in_use = v
    for fol in db.query(Folder.name_key_version).filter(Folder.vault_id == vault_id).all():
        v = _as_epoch(fol[0])
        if min_in_use is None or v < min_in_use:
            min_in_use = v
    if getattr(vault, 'enc_name', None):
        v = _as_epoch(getattr(vault, 'name_key_version', None))
        if min_in_use is None or v < min_in_use:
            min_in_use = v
    return min_in_use


@router.post("/vaults/{vault_id}/retire-version")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def retire_dek_versions(
    vault_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Hard-delete wrapped-DEK rows for epochs no live file OR folder-name still uses, bounding
    row growth after repeated rotations. The DEK epoch a file used (File.encryption_metadata.
    key_version) AND the epoch a zero-knowledge folder NAME was sealed under (Folder.
    name_key_version) are both non-secret routing metadata the server may scan to find the
    lowest epoch still referenced and drop every member row below it. Owner/admin/Manager only.
    Safe no-op when nothing is retirable. (Increment 1.5.)

    Folders MUST be counted: a ZK folder name is encrypted under its own epoch's DEK (folders
    have no content epoch), so retiring a member key for that epoch would make the folder name
    permanently undecryptable for everyone — data loss."""
    _ecc_rate_limit(current_user, "mutate")
    from app.core.models import File, Folder  # local import: avoid a heavier import at module load

    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can retire key versions")

    # Lock the vault row so a concurrent rekey/upload can't move the epoch or add a file
    # under an epoch we're about to retire between our scan and the delete.
    # populate_existing() for the same reason as the rotation path: the entry read already put
    # this vault in the session, and a locked query alone would return it unrefreshed.
    locked = (db.query(Vault).populate_existing()
              .filter(Vault.id == vault_id).with_for_update().first())

    # Lowest DEK epoch still referenced by any file CONTENT, any ZK folder NAME, or the vault's own
    # sealed name (all under the row lock, so the floor can't move before the delete below).
    min_in_use = _lowest_epoch_in_use(db, vault_id, locked)
    # No files => nothing references any epoch; keep only the current epoch's rows.
    dek_floor = min_in_use if min_in_use is not None else (getattr(locked, 'dek_version', 1) or 1)

    # Census, taken before anything is deleted: rows whose label belongs to neither vocabulary.
    # The two modes then treat them in OPPOSITE directions -- hierarchical filters on the label
    # so they survive, direct filters only on the epoch so they do not -- which is why the
    # response reports how many were FOUND and how many of those were DELETED, rather than one
    # number that would mean something different depending on the mode.
    #
    # The expected value is zero: every label this build writes, and the legacy default that
    # predates them, is registered. A non-zero count means rows are present that this build
    # cannot place on an epoch axis, so nothing it says about retiring stale wraps covers them.
    def _unclassified_ids():
        return {
            row_id for row_id, algo in db.query(
                VaultMemberKey.id, VaultMemberKey.wrapping_algorithm
            ).filter(VaultMemberKey.vault_id == vault_id).all()
            if _classify_algo(algo) is None
        }

    unclassified_before = _unclassified_ids()
    unclassified = len(unclassified_before)
    if _is_hierarchical(locked):
        # TWO AXES. (1) Prune the team_key map of DEK epochs below the DEK floor. (2) Delete
        # TEAMPRIV rows below the TEAM floor = the lowest team epoch any SURVIVING team_key entry
        # still needs (NOT the DEK floor — a DEK floor applied to TEAMPRIV rows would delete the
        # team-priv needed to unwrap a live DEK epoch and lock the whole vault out). The
        # wrapping_algorithm filter on BOTH deletes guarantees we never cross the axes.
        team_map = _team_key_map(locked)
        survivors = {e: meta for e, meta in team_map.items() if int(e) >= dek_floor}
        if survivors != team_map:
            locked.team_key = json.dumps(survivors)
        team_versions = [int(m.get('team_key_version', 1)) for m in survivors.values()]
        team_floor = min(team_versions) if team_versions else (getattr(locked, 'team_key_version', 1) or 1)
        stale = db.query(VaultMemberKey).filter(
            VaultMemberKey.vault_id == vault_id,
            (VaultMemberKey.wrapping_algorithm.in_(TEAMPRIV_ALGOS) & (VaultMemberKey.key_version < team_floor))
            | (VaultMemberKey.wrapping_algorithm.in_(DIRECT_DEK_ALGOS) & (VaultMemberKey.key_version < dek_floor)),
        ).all()
        deleted = len(stale)
        for mk in stale:
            db.delete(mk)
        db.commit()  # always persist the (possibly pruned) team_key map
        unclassified_deleted = len(unclassified_before - _unclassified_ids())
        _audit_zk(db, current_user, "zk_versions_retired", resource_id=vault_id,
                  details={"retired_dek_below": dek_floor, "retired_team_below": team_floor,
                           "rows_deleted": deleted, "mode": "hierarchical",
                           "unclassified_rows": unclassified,
                           "unclassified_rows_deleted": unclassified_deleted})
        return {"status": "ok", "vault_id": vault_id, "retired_dek_below": dek_floor,
                "retired_team_below": team_floor, "rows_deleted": deleted,
                "unclassified_rows": unclassified,
                "unclassified_rows_deleted": unclassified_deleted}

    # DIRECT mode: a single DEK axis (unchanged behavior). No algorithm filter here, so an
    # unrecognised label is removed along with everything else below the floor -- defensible,
    # since nothing references an epoch below it, and now reported rather than assumed.
    stale = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.key_version < dek_floor,
    ).all()
    deleted = len(stale)
    for mk in stale:
        db.delete(mk)
    if deleted:
        db.commit()
    unclassified_deleted = len(unclassified_before - _unclassified_ids())
    _audit_zk(db, current_user, "zk_versions_retired", resource_id=vault_id,
              details={"retired_below_version": dek_floor, "rows_deleted": deleted, "mode": "direct",
                       "unclassified_rows": unclassified,
                       "unclassified_rows_deleted": unclassified_deleted})
    return {"status": "ok", "vault_id": vault_id, "retired_below_version": dek_floor,
            "rows_deleted": deleted, "unclassified_rows": unclassified,
            "unclassified_rows_deleted": unclassified_deleted}
