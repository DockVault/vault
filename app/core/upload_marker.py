"""In-flight SFTP upload markers, in Redis.

At SFTP write-open the server places an EPHEMERAL marker keyed by (vault, folder, final-name); it
lets the web listing show a disabled "uploading by <member>" row and doubles as a same-name LOCK
(SET NX) that refuses a second concurrent upload of the same final name in the same folder. The
final name is stored ENCRYPTED (never cleartext) and the Redis sub-key is a deterministic KEYED hash
of (vault, folder, name), so nothing at rest reveals the name. The member is stored by ID, not name.

Every Redis touch here is BEST-EFFORT behind the read-through guard (redis_guard.best_effort): with
the breaker open the marker is SKIPPED, the same-name lock FAILS OPEN (the upload proceeds), and the
listing returns NO rows -- an outage must never block uploads or leak names. The marker is removed
EXPLICITLY on close/abort; its TTL is only the backstop for a client killed before it can clean up.
"""
import json

from app.core.database import redis_client
from app.core import redis_guard
from app.core.config import settings
from app.core.security import (
    encrypt_upload_marker_name,
    upload_marker_lock_index,
)

_KEY_PREFIX = "upload_marker"
_DEFAULT_TTL_SECONDS = 900

# Sentinel: the read-through guard was open (Redis unavailable) so the op was SKIPPED. Distinct from
# a real result, so a caller can fail OPEN instead of mistaking "unknown" for "not held" / "no rows".
SKIPPED = object()


def marker_ttl_seconds() -> int:
    """The marker's backstop TTL in seconds. Readable so a kill test can refuse to judge when the TTL
    is shorter than its observation window."""
    ttl = getattr(settings, "upload_marker_ttl_seconds", 0) or 0
    return int(ttl) if ttl > 0 else _DEFAULT_TTL_SECONDS


def _folder_token(folder_id) -> str:
    # NULL folder (vault root) folds to a fixed token, matching the (vault, folder) binding the
    # ciphertext AAD and the lock index use for the root.
    return str(folder_id) if folder_id is not None else "root"


def marker_key(vault_id, folder_id, name: str) -> str:
    """The Redis key: vault and folder in the clear (UUIDs, not secret) for folder-scoped
    enumeration, plus the keyed hash of the name (never the name itself)."""
    return "%s:v=%s:f=%s:n=%s" % (
        _KEY_PREFIX, vault_id, _folder_token(folder_id),
        upload_marker_lock_index(vault_id, folder_id, name))


def _folder_scan_pattern(vault_id, folder_id) -> str:
    return "%s:v=%s:f=%s:n=*" % (_KEY_PREFIX, vault_id, _folder_token(folder_id))


def place(vault_id, folder_id, name: str, member_id) -> object:
    """Claim the same-name lock and publish the marker for an in-flight upload.

    Returns None when the lock was ACQUIRED (marker now published); the holder's member id (str)
    when a DIFFERENT upload already holds it (the caller REFUSES, naming the member); or SKIPPED when
    Redis is unavailable (fail OPEN -- proceed with no marker). Best-effort (class D).
    """
    key = marker_key(vault_id, folder_id, name)
    payload = json.dumps({
        "n": encrypt_upload_marker_name(vault_id, folder_id, name),
        "m": str(member_id),
    })
    acquired = redis_guard.best_effort(
        "upload_marker.place",
        lambda: redis_client.set(key, payload, nx=True, ex=marker_ttl_seconds()),
        default=SKIPPED)
    if acquired is SKIPPED:
        return SKIPPED            # Redis down: fail OPEN, no marker
    if acquired:
        return None               # lock acquired, marker published
    # Not acquired: a marker for this exact (vault, folder, name) already exists. Read it to name the
    # holder; a miss (it just expired or was removed) means there is no holder to refuse against, so
    # fail OPEN and let the caller retry the claim rather than refuse blindly.
    existing = redis_guard.best_effort(
        "upload_marker.holder",
        lambda: redis_client.get(key),
        default=SKIPPED)
    if existing is SKIPPED or existing is None:
        return SKIPPED
    try:
        return json.loads(existing).get("m")
    except (ValueError, TypeError):
        return SKIPPED


def holder(vault_id, folder_id, name: str) -> object:
    """Read who, if anyone, holds an in-flight upload of (vault, folder, name) WITHOUT taking the
    lock: the holder's member id (str) when a live upload holds the name, None when it is free, or
    SKIPPED when Redis is down (callers fail OPEN -- an outage never blocks a rename/upload). Lets a
    committed-rows-only check (rename clash) also refuse to land on a name a live upload will take."""
    key = marker_key(vault_id, folder_id, name)
    raw = redis_guard.best_effort(
        "upload_marker.holder_read", lambda: redis_client.get(key), default=SKIPPED)
    if raw is SKIPPED:
        return SKIPPED
    if raw is None:
        return None
    try:
        return json.loads(raw).get("m")
    except (ValueError, TypeError):
        return None


def remove(vault_id, folder_id, name: str) -> None:
    """Remove the marker for a (vault, folder, name) on close/abort."""
    remove_key(marker_key(vault_id, folder_id, name))


def remove_key(key: str) -> None:
    """Best-effort delete of a marker by its key. A skip (Redis down) just leaves the TTL to reap it
    -- the backstop. Never raises, so it is safe in a teardown finally."""
    redis_guard.best_effort("upload_marker.remove", lambda: redis_client.delete(key), default=None)


def refresh_key(key: str) -> None:
    """Best-effort TTL refresh, so a slow-but-live transfer's marker does not expire mid-upload."""
    redis_guard.best_effort(
        "upload_marker.refresh", lambda: redis_client.expire(key, marker_ttl_seconds()), default=None)


def list_folder(vault_id, folder_id):
    """The in-flight markers for a (vault, folder) as a list of {"enc_name", "member_id"}.

    Empty on an outage (guard open) -- the listing simply shows no in-flight rows while Redis is
    down. The FINAL name stays ENCRYPTED here; the listing decrypts it only for an authorized viewer.
    """
    pattern = _folder_scan_pattern(vault_id, folder_id)
    keys = redis_guard.best_effort(
        "upload_marker.scan",
        lambda: list(redis_client.scan_iter(match=pattern, count=100)),
        default=None)
    if not keys:
        return []
    values = redis_guard.best_effort(
        "upload_marker.read",
        lambda: redis_client.mget(keys),
        default=None)
    if not values:
        return []
    out = []
    for raw in values:
        if not raw:
            continue
        try:
            blob = json.loads(raw)
            out.append({"enc_name": blob["n"], "member_id": blob.get("m")})
        except (ValueError, KeyError, TypeError):
            continue
    return out
