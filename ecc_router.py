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
from database import get_db
from models import User, Vault, UserKeyPair, VaultMemberKey, ZKShareInvite, ECCRegistrationChallenge, vault_members, RoleEnum
import ecc_pop
from ecc_crypto_service import ECCCryptoService
from audit_logger import AuditLogger
from rate_limiter import rate_limiter as _rate_limiter
from endpoint_permissions import require_endpoint_permission
from temp_scope import require_vault_cap, enforce_vault
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta

router = APIRouter(tags=["ECC - Elliptic Curve Cryptography"])
security_scheme = HTTPBearer()


# =============================================================================
# Pydantic Models
# =============================================================================

class RegistrationPoP(BaseModel):
    """Proof-of-possession for key registration: the challenge id + the client's ECDH
    key-confirmation MAC over (nonce || public_key). See ecc_pop.py."""
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


class CreateVaultRequest(BaseModel):
    """Request to create a vault with ECC."""
    name: str
    description: Optional[str] = None
    password: Optional[str] = None


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
    from api_server import get_current_user as _hardened_get_current_user
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
              resource_type: str = "vault", details: Optional[dict] = None) -> None:
    """Best-effort audit row for a /ecc ZK-crypto mutation.

    Called AFTER the mutation has committed (AuditLogger.log_action commits its own row), so a
    failure to record the audit never rolls back or 500s the crypto change it documents — it
    only drops the audit entry. The /ecc plane previously wrote ZERO audit rows, a forensic
    blind spot for the security-critical key grant / revoke / rekey / retire / register
    operations (standard vault create/delete are audited)."""
    try:
        AuditLogger(db).log_action(
            action=action,
            status="success",
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
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid compressed point: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Point decompression failed: {str(e)}"
        )


# =============================================================================
# ECC Endpoints (Stub Implementation)
# =============================================================================

_POP_CHALLENGE_TTL_SECONDS = 300  # a registration challenge is single-use + short-lived


@router.post("/keys/register/challenge")
async def register_challenge(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Issue a one-time proof-of-possession challenge for key registration: a server
    EPHEMERAL public key + nonce the client MACs with its private key (ECDH key-confirmation).
    Bound to the current user, single-use, short-lived. See ecc_pop.py."""
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
        # Don't let the 409 conflict get rewrapped as a generic 400 below.
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid public key format: {str(e)}"
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
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    if not keypair or not keypair.encrypted_private_key:
        return {"has_keypair": False, "encrypted_private_key": None}
    return {"has_keypair": True, "encrypted_private_key": keypair.encrypted_private_key}


class PrivateKeyUpdateRequest(BaseModel):
    """The user's private key RE-WRAPPED in the browser under a NEW passphrase (opaque blob;
    the server cannot read it). The PUBLIC key is unchanged, so this is a passphrase change,
    not a key rotation."""
    encrypted_private_key: str = Field(..., description="password-encrypted private-key blob")


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
    orphan every wrapped DEK); we deliberately keep the public key fixed. Rate-limited on the
    same per-user bucket as registration.

    Requires an INTERACTIVE session: a temporary credential authenticates AS the account owner,
    and this overwrites the owner's private-key blob verbatim (no current-passphrase proof server
    side), so a delegated/temp cred must not be able to corrupt it and irreversibly lock the owner
    out of every zero-knowledge vault. Changing the account passphrase is an owner operation."""
    _ecc_rate_limit(current_user, "register")
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary credential cannot change the account encryption passphrase.")
    if not request.encrypted_private_key:
        raise HTTPException(status_code=400, detail="encrypted_private_key is required")
    keypair = db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first()
    if not keypair:
        raise HTTPException(status_code=404, detail="No encryption key is set up for this account.")
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


# Tag distinguishing a wrapped TEAM PRIVATE key (hierarchical) from a wrapped DEK (direct) in
# the shared vault_member_keys table. EVERY hierarchical query MUST filter on it.
TEAMPRIV_ALGO = 'ECDH-P384-AES-GCM-TEAMPRIV'
DIRECT_DEK_ALGO = 'ECDH-P384-AES-KW'


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
        VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO,
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

    # Confine a scoped temp credential to its granted vaults — the SAME gate the standard
    # read path applies (vault_service.get_vault -> enforce_vault). Without it a cred scoped
    # to vault A could still read vault B's wrapped DEK here. No-op for normal principals.
    enforce_vault(current_user, vault_id)

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
            VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO,
            VaultMemberKey.is_active == True,  # noqa: E712
        ).first()
        if not teampriv:
            return _no_access()
        return VaultKeysResponse(
            vault_id=vault_id, mode='hierarchical', has_access=True,
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
        epoch = getattr(vault, 'team_key_version', 1) or 1
        blob, eph, algo = request.wrapped_team_privkey, request.team_ephemeral_public_key, TEAMPRIV_ALGO
    else:
        if not (request.wrapped_dek and request.ephemeral_public_key):
            raise HTTPException(
                status_code=400,
                detail="This vault uses direct wrapping; supply wrapped_dek + ephemeral_public_key.",
            )
        epoch = getattr(vault, 'dek_version', 1) or 1
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
    wrapped_dek: str
    ephemeral_public_key: str


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
    member_keys: List[MemberKeyWrap] = Field(..., description="per-remaining-member wraps (empty for a routine hierarchical rotation)")
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
            VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO,
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
    is extractable in the browser). Full user-facing semantics + the honest claims boundary:
    docs/vault-zk-dek-rotation.md.

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
    locked = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()
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
            VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO,
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
                VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO,
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
    from models import File, Folder  # local import: avoid a heavier import at module load

    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can retire key versions")

    # Lock the vault row so a concurrent rekey/upload can't move the epoch or add a file
    # under an epoch we're about to retire between our scan and the delete.
    locked = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()

    # Lowest DEK epoch still in use by any file's CONTENT or any ZK folder's NAME
    # (absent metadata => epoch 1).
    min_in_use = None
    for f in db.query(File).filter(File.vault_id == vault_id).all():
        meta = f.encryption_metadata or {}
        v = meta.get('key_version', 1) if isinstance(meta, dict) else 1
        try:
            v = int(v)
        except (TypeError, ValueError):
            v = 1
        if min_in_use is None or v < min_in_use:
            min_in_use = v
    for fol in db.query(Folder.name_key_version).filter(Folder.vault_id == vault_id).all():
        v = fol[0] if fol[0] is not None else 1
        try:
            v = int(v)
        except (TypeError, ValueError):
            v = 1
        if min_in_use is None or v < min_in_use:
            min_in_use = v
    # No files => nothing references any epoch; keep only the current epoch's rows.
    dek_floor = min_in_use if min_in_use is not None else (getattr(locked, 'dek_version', 1) or 1)

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
            ((VaultMemberKey.wrapping_algorithm == TEAMPRIV_ALGO) & (VaultMemberKey.key_version < team_floor))
            | ((VaultMemberKey.wrapping_algorithm == DIRECT_DEK_ALGO) & (VaultMemberKey.key_version < dek_floor)),
        ).all()
        deleted = len(stale)
        for mk in stale:
            db.delete(mk)
        db.commit()  # always persist the (possibly pruned) team_key map
        _audit_zk(db, current_user, "zk_versions_retired", resource_id=vault_id,
                  details={"retired_dek_below": dek_floor, "retired_team_below": team_floor,
                           "rows_deleted": deleted, "mode": "hierarchical"})
        return {"status": "ok", "vault_id": vault_id, "retired_dek_below": dek_floor,
                "retired_team_below": team_floor, "rows_deleted": deleted}

    # DIRECT mode: a single DEK axis (unchanged behavior).
    stale = db.query(VaultMemberKey).filter(
        VaultMemberKey.vault_id == vault_id,
        VaultMemberKey.key_version < dek_floor,
    ).all()
    deleted = len(stale)
    for mk in stale:
        db.delete(mk)
    if deleted:
        db.commit()
    _audit_zk(db, current_user, "zk_versions_retired", resource_id=vault_id,
              details={"retired_below_version": dek_floor, "rows_deleted": deleted, "mode": "direct"})
    return {"status": "ok", "vault_id": vault_id, "retired_below_version": dek_floor, "rows_deleted": deleted}
