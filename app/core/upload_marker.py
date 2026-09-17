"""In-flight SFTP upload markers, in Redis.

At SFTP write-open the server places an EPHEMERAL marker keyed by (vault, folder, final-name); it
lets the web listing show a disabled "uploading by <member>" row and doubles as a same-name LOCK
(SET NX) that refuses a second concurrent upload of the same final name in the same folder. The
final name is stored ENCRYPTED (never cleartext) and the Redis sub-key is a deterministic KEYED hash
of (vault, folder, name), so nothing at rest reveals the name. The member is stored by ID, not name.

Enumeration for the listing is by a per-(vault, folder) INDEX SET, not a keyspace SCAN: place adds
the marker key to `upload_marker:idx:v=<vault>:f=<folder>` and list_folder reads that set + MGETs
the members, so a folder view costs O(markers in this folder), never O(all Redis keys). The index
carries the same TTL as its markers (refreshed together); a stale member (its marker already gone)
is harmless -- MGET returns None for it and list_folder prunes it lazily.

Every Redis touch here is BEST-EFFORT behind the read-through guard (redis_guard.best_effort): with
the breaker open the marker is SKIPPED, the same-name lock FAILS OPEN (the upload proceeds), and the
listing returns NO rows -- an outage never blocks uploads or leaks names. The marker is removed
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


def index_key(vault_id, folder_id) -> str:
    """The per-(vault, folder) index SET holding this folder's live marker keys, for O(folder)
    enumeration instead of a keyspace SCAN."""
    return "%s:idx:v=%s:f=%s" % (_KEY_PREFIX, vault_id, _folder_token(folder_id))


def place(vault_id, folder_id, name: str, member_id) -> object:
    """Claim the same-name lock and publish the marker for an in-flight upload.

    Returns None when the lock was ACQUIRED (marker now published, indexed); the holder's member id
    (str) when a DIFFERENT upload already holds it (the caller REFUSES, naming the member); or SKIPPED
    when Redis is unavailable (fail OPEN -- proceed with no marker). Best-effort (class D).
    """
    mkey = marker_key(vault_id, folder_id, name)
    ikey = index_key(vault_id, folder_id)
    ttl = marker_ttl_seconds()
    payload = json.dumps({
        "n": encrypt_upload_marker_name(vault_id, folder_id, name),
        "m": str(member_id),
    })
    acquired = redis_guard.best_effort(
        "upload_marker.place",
        lambda: redis_client.set(mkey, payload, nx=True, ex=ttl),
        default=SKIPPED)
    if acquired is SKIPPED:
        return SKIPPED            # Redis down: fail OPEN, no marker
    if acquired:
        # Index the marker for folder-scoped enumeration; the index carries the marker's TTL.
        redis_guard.best_effort("upload_marker.index_add", lambda: redis_client.sadd(ikey, mkey), default=None)
        redis_guard.best_effort("upload_marker.index_ttl", lambda: redis_client.expire(ikey, ttl), default=None)
        return None
    # Not acquired: a marker for this exact (vault, folder, name) already exists. Read it to name the
    # holder; a miss (it just expired or was removed) means there is no holder to refuse against, so
    # fail OPEN and let the caller retry the claim rather than refuse blindly.
    existing = redis_guard.best_effort(
        "upload_marker.holder", lambda: redis_client.get(mkey), default=SKIPPED)
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
    raw = redis_guard.best_effort(
        "upload_marker.holder_read",
        lambda: redis_client.get(marker_key(vault_id, folder_id, name)),
        default=SKIPPED)
    if raw is SKIPPED:
        return SKIPPED
    if raw is None:
        return None
    try:
        return json.loads(raw).get("m")
    except (ValueError, TypeError):
        return None


def remove(vault_id, folder_id, name: str) -> None:
    """Remove the marker for a (vault, folder, name) on close/abort: delete the marker key and drop
    it from the folder index. Best-effort (never raises), so it is safe in a teardown finally; a skip
    (Redis down) just leaves the TTL to reap both."""
    mkey = marker_key(vault_id, folder_id, name)
    ikey = index_key(vault_id, folder_id)
    redis_guard.best_effort("upload_marker.remove", lambda: redis_client.delete(mkey), default=None)
    redis_guard.best_effort("upload_marker.index_srem", lambda: redis_client.srem(ikey, mkey), default=None)


def refresh(vault_id, folder_id, name: str) -> None:
    """Best-effort TTL refresh of a marker AND its index entry, so a slow-but-live transfer's marker
    (and its same-name lock and listing row) does not expire mid-upload."""
    ttl = marker_ttl_seconds()
    redis_guard.best_effort(
        "upload_marker.refresh", lambda: redis_client.expire(marker_key(vault_id, folder_id, name), ttl), default=None)
    redis_guard.best_effort(
        "upload_marker.index_refresh", lambda: redis_client.expire(index_key(vault_id, folder_id), ttl), default=None)


def list_folder(vault_id, folder_id):
    """The in-flight markers for a (vault, folder) as a list of {"enc_name", "member_id"}, read from
    the folder index (O(folder), not a keyspace SCAN).

    Empty on an outage (guard open) -- the listing simply shows no in-flight rows while Redis is
    down. A stale index member (marker already expired/removed) reads back as None from MGET and is
    pruned lazily. The FINAL name stays ENCRYPTED here; the listing decrypts it only for an
    authorized viewer.
    """
    ikey = index_key(vault_id, folder_id)
    keys = redis_guard.best_effort(
        "upload_marker.index_members", lambda: list(redis_client.smembers(ikey)), default=None)
    if not keys:
        return []
    values = redis_guard.best_effort(
        "upload_marker.read", lambda: redis_client.mget(keys), default=None)
    if not values:
        return []
    out, stale = [], []
    for k, raw in zip(keys, values):
        if not raw:
            stale.append(k)          # the marker expired/was removed but its index entry lingers
            continue
        try:
            blob = json.loads(raw)
            out.append({"enc_name": blob["n"], "member_id": blob.get("m")})
        except (ValueError, KeyError, TypeError):
            stale.append(k)
    if stale:
        redis_guard.best_effort(
            "upload_marker.index_prune", lambda: redis_client.srem(ikey, *stale), default=None)
    return out
