"""What the audit log records of the personal data attached to each event: the recording levels.

Every event is recorded: who acted, what happened, when, its outcome and the ids it concerns. What a level
governs is the personal data attached to it, by kind, never by event:

    names           vault, file and folder names            none / fingerprint / full
    signin_names    a name typed at a failed sign-in that   none / fingerprint / full
                    is no account's or temporary
                    credential's, or a name or text typed
                    into an Activity filter
    emails          email addresses                         none / full
    ip              the client's address                    none / shortened / full
    user_agent      the browser's description               none / full

Secrets (session tokens, passwords, link tokens) are never recorded, and of an error only its type is.
Values an administrator already sees elsewhere (real usernames, roles, labels, ids) are always recorded.

The deployment's .env sets the most each kind may record (AUDIT_MAX_NAMES, AUDIT_MAX_SIGNIN_NAMES,
AUDIT_MAX_EMAILS, AUDIT_MAX_IP, AUDIT_MAX_USER_AGENT; each ``full`` by default). The levels in force are
kept in their own table, ``audit_privacy_policies``, which only grows: each change adds a version. Every
write applies, for each kind, the lower of the .env limit and the stored level, so neither the panel nor a
direct edit of the table records more than .env allows. With ``audit_levels`` in SETTINGS_LOCKED_KEYS the
limit is also the level. Policy 1 is what earlier releases recorded: no names, everything else in full.

This module is the one place that decides. AuditLogger.build_row calls ``apply`` for every audit row, for the
web app and the SFTP server alike (app/services/audit_row_hooks.py), and the row then holds:

- in its own columns (username, ip_address, user_agent) and in ``details``, only values recorded in full,
  so a release that knows nothing of levels never shows a shortened address or a fingerprint as the value;
- in ``recorded``, what was kept in another form (a shortened address, for example), and the names of
  detail keys that were dropped because nothing says what they hold;
- in ``privacy_version``, the version of the policy it was recorded under. A row with none was written by an
  earlier release.

Every key a row's details can carry is classified in DETAIL_KEYS (tests/test_audit_privacy.py reads every
call site and fails on a key that is not). A key that is not classified is dropped as the row is written,
and an alert is raised, so an unclassified value is never recorded by mistake.

``apply`` never raises: the row records a change, in that change's transaction, and an exception would
fail the change. If deciding fails, the row is written without any personal value, with
``privacy_version`` -1, and an alert is raised: a deployment that must record everything learns that a row
was recorded with less, rather than losing the row.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

# --------------------------------------------------------------------------- levels

NONE = "none"
FINGERPRINT = "fingerprint"
SHORTENED = "shortened"
FULL = "full"
LEVELS = (NONE, FINGERPRINT, SHORTENED, FULL)          # least to most
_RANK = {level: rank for rank, level in enumerate(LEVELS)}

NAMES = "names"
SIGNIN_NAMES = "signin_names"
EMAILS = "emails"
IP = "ip"
USER_AGENT = "user_agent"
POLICY_KEYS = (NAMES, SIGNIN_NAMES, EMAILS, IP, USER_AGENT)

# The levels each kind may be recorded at.
CHOICES: Dict[str, Tuple[str, ...]] = {
    NAMES: (NONE, FINGERPRINT, FULL),
    SIGNIN_NAMES: (NONE, FINGERPRINT, FULL),
    EMAILS: (NONE, FULL),
    IP: (NONE, SHORTENED, FULL),
    USER_AGENT: (NONE, FULL),
}
# The .env line that sets each kind's limit, and the Settings field it is read into.
ENV_NAMES: Dict[str, str] = {
    NAMES: "AUDIT_MAX_NAMES",
    SIGNIN_NAMES: "AUDIT_MAX_SIGNIN_NAMES",
    EMAILS: "AUDIT_MAX_EMAILS",
    IP: "AUDIT_MAX_IP",
    USER_AGENT: "AUDIT_MAX_USER_AGENT",
}
LABELS: Dict[str, str] = {
    NAMES: "Vault, file and folder names",
    SIGNIN_NAMES: "Names typed at a failed sign-in (no such account)",
    EMAILS: "Email addresses",
    IP: "IP addresses",
    USER_AGENT: "Browser descriptions",
}
# What earlier releases recorded, and so the first policy: names never, everything else in full.
POLICY_ONE: Dict[str, str] = {NAMES: NONE, SIGNIN_NAMES: FULL, EMAILS: FULL, IP: FULL, USER_AGENT: FULL}
# The stamp of a row whose recording could not be decided, written without any personal value.
FALLBACK_VERSION = -1
# SETTINGS_LOCKED_KEYS names this group to make each .env limit also the level.
LOCK_GROUP = "audit_levels"
# Who a version written by the server itself (a level brought down to a new limit) is signed by.
SERVER_CONFIGURATION = "server configuration"
# The action of the audit row each new version writes.
CHANGED_ACTION = "audit_privacy_changed"
# Keys PUT /settings refuses: the levels are never kept in the general settings.
SETTINGS_KEYS_REFUSED = frozenset({"recording_levels", "audit_levels", "audit_privacy", "audit_privacy_policy",
                                   *(name.lower() for name in ENV_NAMES.values())})

# A shortened address keeps this many leading bits: the /24 an IPv4 address is in, the /48 of an IPv6 one.
SHORT_PREFIX = {4: 24, 6: 48}
# The address column holds at most this many characters.
IP_COLUMN_LENGTH = 45


def env_field(key: str) -> str:
    return ENV_NAMES[key].lower()


def rank(level: str) -> int:
    return _RANK[level]


def lower(a: str, b: str) -> str:
    """The lower of two levels."""
    return a if _RANK[a] <= _RANK[b] else b


# --------------------------------------------------------------------------- what each detail key holds

NAME = "name"
SIGNIN_NAME = "signin_name"
EMAIL = "email"
ADDRESS = "ip"
AGENT = "user_agent"
IDENTIFIER = "identifier"     # always recorded: ids, counts, roles, usernames, labels, settings, reasons
SECRET = "secret"             # never recorded
ERROR = "error"               # only an exception's type
COUNT = "count"               # only a number: a key whose name could also hold a list keeps nothing else
NESTED = "nested"             # a dict whose own keys are classified, under "<key>."
KINDS = (NAME, SIGNIN_NAME, EMAIL, ADDRESS, AGENT, IDENTIFIER, SECRET, ERROR, COUNT, NESTED)
# The policy key that sets each personal kind's level.
KIND_POLICY = {NAME: NAMES, SIGNIN_NAME: SIGNIN_NAMES, EMAIL: EMAILS, ADDRESS: IP, AGENT: USER_AGENT}

_IDENTIFIER_KEYS = (
    # ids
    "change_id", "cred_id", "dest_folder_id", "dest_parent_folder_id", "dest_vault_id", "device_id",
    "group_id", "link_id", "made_by_id", "new_file_id", "new_folder_id", "note_id", "owner_id",
    "public_link_id", "receiver_id", "recipient_user_id", "revoked_user_id", "session_id", "share_id",
    "share_ids", "source_vault_id", "tag_id", "target_id", "target_user_id", "temp_credential_id", "user_id",
    "user_ids", "vault_id", "vault_ids", "members", "opened_by_temp_credential_id", "record_id", "alert_id",
    # accounts, and who acted (real usernames, which administrators see on the Users page)
    "username", "target_username", "target_user", "created_username", "deleted_username", "updated_username",
    "temp_username", "requested_by", "approved_by", "invited_by", "by", "made_by", "cleared_by", "auditor",
    "created_role", "new_role", "old_role", "role", "target_role", "already_member",
    # who set an account's password, and who added an SSH key (a username, or the host operator's name)
    "password_set_by", "added_by",
    # labels an administrator gives or sees elsewhere: tokens, SSH keys, devices, groups, tags
    "name", "label", "tag", "fingerprint", "token_prefix", "scope", "key", "keys", "setting",
    # what happened, and how
    "action", "kind", "type", "mode", "method", "via", "reason", "reasons", "revoked_because",
    "withdrawn_because", "outcome", "status", "surface", "level", "posture", "message", "step_up",
    "approver_refusals", "secret_kind", "capability", "claim_audience", "endpoint_group", "required_group",
    "granted_groups", "revoked_groups", "permission", "target_type", "view_only", "format", "fields",
    "updated_fields", "completed", "chunked", "forced", "minted", "rotated", "sealed", "same_for_all",
    "password_protected", "require_otp", "require_password", "has_expiry", "email_sent", "is_temporary",
    "job", "table", "superseded", "cleared", "is_active",
    "at_promotion", "added_by_left_because", "link_made_by_other", "locked", "was_locked",
    # a zero-knowledge key change: the operation, and how it was proved ("key" or "absent"), never the proof
    "op", "proof",
    # the auditor right: the grant, and who proposed it (a username)
    "grant_id", "proposed_by",
    # legal holds: the case's number, a hold's dates, and what it kept and why (never a name)
    "case_number", "confirm_by", "hold_only", "purge_after", "by_release", "kept_reason", "kept_at", "held_by_case",
    # an owner's notice of compliance access: whether its email waits or there is no address, whether a copy goes
    # to the address before an administrator's change, and why a send failed (a category, never a server's answer)
    "email_status", "copy_to_previous", "send_error",
    # a case's steps: what it is for (a code), its days of access and their end, whether it holds, whether the
    # server's operator approved it, how an objection came (from an owner or an administrator), whether its access
    # ended, and a hold placed and confirmed by an approval
    "purpose", "days", "ends_at", "hold", "by_operator", "by_owner", "access_ended", "by_approval",
    # reading under a case: whether a password vault was opened without its password, and a view in the preview
    "password_override", "preview",
    # a listing or a search under a case: the folder listed, and of a search the query's length (never its text),
    # how many names it read, whether it stopped early, and how many matched
    "folder_id", "query_length", "scanned", "truncated", "matches",
    # an export from a case: its id, how many files were exported, missing, unreadable or did not match their
    # stored checksum, and the SHA-256 of its manifest (a digest of the export's own list, never of a file)
    "export_id", "file_count", "manifest_sha256", "missing", "unreadable", "mismatched",
    # names shown on the Activity page because of a case: how many events, and a digest of their ids (never a name)
    "events", "events_digest",
    # a recorded name revealed outside a case: the event, and the reason's category from a fixed list (its text is
    # sealed in compliance_reveals, never here)
    "event_id", "reason_category",
    # numbers and times
    "added", "removed", "kept", "count", "rows", "total", "bytes", "bytes_sent", "bytes_uploaded", "chunk_size",
    "file_size", "file_type", "size", "size_limit", "granted_bytes", "previous_bytes", "max_total_bytes",
    "served_bytes", "total_bytes", "range_start", "range_end", "limit", "max_uses", "slot", "token_len",
    "ttl_minutes", "interval_minutes", "window_minutes", "window_seconds", "retention_days",
    "previous_retention_days", "attempts", "failed_attempts", "files_deleted", "files_left", "deleted",
    "deletions", "rows_deleted", "revoked_count", "terminated_count", "sessions_closed", "keys_deactivated",
    "deactivated_creds", "revoked_credentials", "deadlines_removed", "children_moved_up", "unclassified_rows",
    "unclassified_rows_deleted", "wraps", "vaults", "epoch", "key_version", "team_key_version",
    "from_version", "to_version", "retired_below_version", "retired_dek_below", "retired_team_below",
    "expires_at", "locked_until", "effective_at", "requested_at", "oldest", "newest", "timestamp",
    "repeat_count", "last_repeat", "change",
    "password_set_at", "sign_in_locks_cleared", "from_revision", "to_revision", "dek_epoch", "team_epoch",
    "proof_rows_deleted",
    # an administrator's clean-up of unfinished uploads
    "scanned_dirs", "dirs_removed", "bytes_reclaimed", "rows_pruned", "active_sessions_kept", "idle_minutes",
    # a vault's settings after a change
    "expire_files_after_days", "expire_files_unit", "unlock_remember_minutes",
    # a settings value before and after a change, and a recording policy
    "old", "new", "version", "previous_version", "levels", "limits",
    # Email Studio: its sending profiles, templates, automatic emails and the images templates use; a file name
    # here is the name of an image an administrator uploaded, which every administrator sees in Email Studio
    "profile_id", "promoted_default", "template_id", "action_key", "enabled", "resource_id", "filename",
    "content_type", "byte_size",
)

DETAIL_KEYS: Dict[str, str] = {key: IDENTIFIER for key in _IDENTIFIER_KEYS}
DETAIL_KEYS.update({
    # names, encrypted where they are stored
    "file_name": NAME, "folder_name": NAME, "old_name": NAME, "new_name": NAME, "vault_name": NAME,
    # email addresses
    "email": EMAIL, "to": EMAIL, "old_email": EMAIL, "new_email": EMAIL,
    # addresses
    "ip_address": ADDRESS, "address": ADDRESS, "client_ip": ADDRESS,
    "user_agent": AGENT,
    # never recorded
    "session_token": SECRET, "token": SECRET, "password": SECRET, "passcode": SECRET, "secret": SECRET,
    "code": SECRET, "otp": SECRET, "link_token": SECRET,
    "error": ERROR,
    # how many messages an email from a template went to, was sent, failed or could not be built for
    "recipients": COUNT, "attempted": COUNT, "sent": COUNT, "failed": COUNT, "errors": COUNT,
    # what changed on a settings save or an account: the setting's or field's name, then its old and new
    # value; an account's email address is an email address
    "changes": NESTED,
    "changes.*": IDENTIFIER,
    "changes.email": EMAIL,
    "changes.password": IDENTIFIER,
    # the filters of an export: what was typed into the person, search and credential boxes is typed text,
    # and the address is an address
    "filters": NESTED,
    "filters.category": IDENTIFIER, "filters.channel": IDENTIFIER, "filters.status": IDENTIFIER,
    "filters.action": IDENTIFIER, "filters.user_match": IDENTIFIER, "filters.no_account": IDENTIFIER,
    "filters.temp_credential_id": IDENTIFIER, "filters.vault_id": IDENTIFIER, "filters.from_date": IDENTIFIER,
    "filters.to_date": IDENTIFIER, "filters.case": IDENTIFIER,
    "filters.user": SIGNIN_NAME, "filters.q": SIGNIN_NAME, "filters.temp_credential": SIGNIN_NAME,
    "filters.ip": ADDRESS,
})


def kind_of(path: str) -> Optional[str]:
    """The kind of the detail at ``path`` (``key`` or ``parent.key``), or None when nothing says.

    An exact entry wins; then the parent's wildcard (``parent.*``)."""
    kind = DETAIL_KEYS.get(path)
    if kind is not None:
        return kind
    parent, dot, _ = path.rpartition(".")
    if dot:
        return DETAIL_KEYS.get(parent + ".*")
    return None


# --------------------------------------------------------------------------- the .env limits

def _env_value(settings, key: str) -> str:
    return str(getattr(settings, env_field(key), FULL) or "").strip().lower()


def env_problems(settings) -> list:
    """What makes the .env limits unreadable, each as the line to fix (empty when they are all readable)."""
    problems = []
    for key in POLICY_KEYS:
        if _env_value(settings, key) not in CHOICES[key]:
            problems.append(f"{ENV_NAMES[key]} must be one of {', '.join(CHOICES[key])} "
                            f"(for example {ENV_NAMES[key]}=full)")
    return problems


def env_limits(settings=None) -> Dict[str, str]:
    """Each kind's .env limit. An unreadable one counts as none (the start refuses it before any row)."""
    settings = settings if settings is not None else _settings()
    out = {}
    for key in POLICY_KEYS:
        value = _env_value(settings, key)
        out[key] = value if value in CHOICES[key] else NONE
    return out


def locked(settings=None) -> bool:
    """Whether SETTINGS_LOCKED_KEYS makes each .env limit also the level."""
    from app.core import settings_registry
    return settings_registry.group_locked(LOCK_GROUP, settings if settings is not None else _settings())


def effective(stored: Mapping[str, str], settings=None) -> Dict[str, str]:
    """The level each kind is recorded at: the lower of the .env limit and the stored level, or the limit
    itself while the levels are locked. A stored value that is not a level for its kind counts as none."""
    settings = settings if settings is not None else _settings()
    limits = env_limits(settings)
    if locked(settings):
        return dict(limits)
    out = {}
    for key in POLICY_KEYS:
        value = stored.get(key)
        value = value if value in CHOICES[key] else NONE
        out[key] = lower(limits[key], value)
    return out


def _settings():
    from app.core.config import settings
    return settings


# --------------------------------------------------------------------------- the policy in force

@dataclass(frozen=True)
class Policy:
    version: int
    levels: Mapping[str, str]


DEFAULT_POLICY = Policy(1, dict(POLICY_ONE))

# How often each process reads the table again for a newer version.
REFRESH_SECONDS = 5.0
_STATEMENT_TIMEOUT_MS = 5000


class PolicyUnavailable(RuntimeError):
    """The recording policy could not be read."""


class _Cache:
    def __init__(self):
        self.policy: Optional[Policy] = None
        # When version 1 was written: the first row an earlier release wrote after it is one recorded behind the
        # notice (a rollback), and the Activity page says so.
        self.began = None
        self._lock = threading.Lock()

    def load(self, session_factory) -> Policy:
        from app.core.models import AuditPrivacyPolicy
        with self._lock:
            db = session_factory()
            try:
                _statement_timeout(db)
                policy = read_latest(db) or DEFAULT_POLICY
                began = db.query(AuditPrivacyPolicy.created_at).filter(AuditPrivacyPolicy.version == 1).scalar()
                db.rollback()
            finally:
                db.close()
            self.policy = policy
            self.began = began
            return policy


_cache = _Cache()
_refresher: Optional[threading.Thread] = None
_refresher_stop = threading.Event()


def _statement_timeout(db) -> None:
    from sqlalchemy import text
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {_STATEMENT_TIMEOUT_MS}"))


def _default_session_factory():
    from app.core.database import started_session
    return started_session()


def read_latest(db) -> Optional[Policy]:
    """The highest version in the table, or None when it is empty."""
    from app.core.models import AuditPrivacyPolicy
    row = db.query(AuditPrivacyPolicy).order_by(AuditPrivacyPolicy.version.desc()).first()
    return policy_of(row) if row is not None else None


def policy_of(row) -> Policy:
    return Policy(int(row.version), {key: getattr(row, key) for key in POLICY_KEYS})


def load(session_factory=None) -> Policy:
    """Read the policy in force into this process's copy now, and return it."""
    return _cache.load(session_factory or _default_session_factory)


def use(policy: Optional[Policy]) -> None:
    """Hold ``policy`` as the one in force (a process that has just written it, and tests)."""
    _cache.policy = policy


def levels_began():
    """When version 1 was written (naive UTC), as this process last read it; None before."""
    return _cache.began


# Whether this process writes audit rows of a running deployment (the web app, the SFTP server, the host
# operator's account tool): set by start() and require(). Such a process reads the policy in force before its
# first row. Any other process that builds rows (a test, a script) holds policy 1 until it is given another.
_required = False


def require() -> None:
    """Say this process writes a running deployment's audit rows: until it holds the policy in force, the
    first row reads it from the database, and a row written when that fails is recorded without personal
    values (never under policy 1 by default)."""
    global _required
    _required = True


def current() -> Policy:
    """The policy in force, from this process's copy. In a process that writes a deployment's rows
    (require()), the first call with no copy reads it, and raises PolicyUnavailable when it cannot; any other
    process holds policy 1, which is also what a database with no version yet records under."""
    policy = _cache.policy
    if policy is not None:
        return policy
    if not _required:
        return DEFAULT_POLICY
    try:
        return load()
    except Exception as exc:  # noqa: BLE001
        raise PolicyUnavailable(type(exc).__name__) from None


def refresh(session_factory=None) -> bool:
    """Bring this process's copy up to date. Never raises: a failure keeps the copy it had."""
    try:
        before = _cache.policy
        after = load(session_factory)
        return before != after
    except Exception:  # noqa: BLE001
        return False


def start(session_factory=None, *, interval: float = REFRESH_SECONDS, load_now: bool = True) -> threading.Thread:
    """Keep this process's copy fresh on a daemon thread. With ``load_now`` the policy is brought within
    the .env limits and read before this returns; otherwise the thread's first turn does both, for a
    process whose start must not wait on the database (the SFTP server's)."""
    global _refresher
    require()
    factory = session_factory or _default_session_factory
    if load_now:
        prepare(factory)
    global _refresher_stop
    if _refresher is not None and _refresher.is_alive():
        return _refresher
    stopping = _refresher_stop = threading.Event()

    def run():
        if not load_now:
            try:
                prepare(factory)
            except Exception as exc:  # noqa: BLE001 -- the next turn reads the table again
                _say(f"Warning: the recording levels were not checked against .env at start "
                     f"({type(exc).__name__}); the stored levels stay, each still capped by .env as rows "
                     "are written")
        while True:
            refresh(factory)
            _flush_alerts(factory)
            from app.core import recording_marker
            recording_marker.check_daily(factory)
            if stopping.wait(interval):
                return

    _refresher = threading.Thread(target=run, name="recording-levels-refresh", daemon=True)
    _refresher.start()
    return _refresher


def stop() -> None:
    _refresher_stop.set()


def _say(message: str) -> None:
    try:
        print(message, flush=True)
    except Exception:  # noqa: BLE001
        pass


# One process at a time writes a version: the advisory lock below, in the transaction that writes it.
_LOCK_CLASS = 0x6170
_LOCK_KEY = 1


def lock_policies(db) -> None:
    """Take the policies' transaction-scoped lock (Postgres), so two processes starting together, or a
    save and a start, never write the same version or each a clamp of the other's."""
    from sqlalchemy import text
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:cls, :key)"), {"cls": _LOCK_CLASS, "key": _LOCK_KEY})


def write_version(db, levels: Mapping[str, str], *, previous: Optional[Policy], reason: str,
                  by_id=None, by_name: Optional[str] = None, user=None, now=None) -> Policy:
    """Add the next version with ``levels`` and its audit row, in the caller's transaction (the caller holds
    lock_policies and commits). Returns the new policy."""
    from datetime import datetime, timezone
    from app.core.models import AuditPrivacyPolicy
    from app.services.audit_logger import AuditLogger
    version = (previous.version if previous is not None else 0) + 1
    when = now or datetime.now(timezone.utc).replace(tzinfo=None)
    row = AuditPrivacyPolicy(version=version, created_at=when, created_by=by_id, created_by_name=by_name,
                             reason=reason, **{key: levels[key] for key in POLICY_KEYS})
    db.add(row)
    details = {"version": version, "previous_version": previous.version if previous else None,
               "reason": reason, "levels": {key: levels[key] for key in POLICY_KEYS},
               "limits": env_limits()}
    if previous is not None:
        details["old"] = {key: previous.levels.get(key) for key in POLICY_KEYS}
    db.add(AuditLogger(db).build_row(action=CHANGED_ACTION, status="success", user=user,
                                     username=None if user is not None else by_name,
                                     resource_type="audit_privacy_policy", resource_id=str(version),
                                     details=details))
    # While the levels record less than earlier releases, an earlier release must not start on this data
    # (app/core/recording_marker.py): the marker goes with the version, in its transaction.
    from app.core import recording_marker
    recording_marker.sync(db, levels)
    return Policy(version, {key: levels[key] for key in POLICY_KEYS})


def target_levels(stored: Mapping[str, str], settings=None) -> Dict[str, str]:
    """What the stored levels must become to sit within .env: each brought down to its limit, or set to it
    while the levels are locked. A stored value that is not a level for its kind becomes none."""
    return effective(stored, settings)


def prepare(session_factory=None) -> Policy:
    """At a process's start: write policy 1 when the table is empty, bring the stored levels within the
    .env limits (writing a new version signed by the server's configuration when they were above), and
    hold the result as the policy in force. Under the policies' lock, so the web app and the SFTP server
    starting together write each version once."""
    factory = session_factory or _default_session_factory
    db = factory()
    changed = False
    try:
        lock_policies(db)
        latest = read_latest(db)
        if latest is None:
            latest = write_version(db, POLICY_ONE, previous=None, reason="initial", by_name=SERVER_CONFIGURATION)
        wanted = target_levels(latest.levels)
        if wanted != dict(latest.levels):
            reason = "locked" if locked() else "limit"
            latest = write_version(db, wanted, previous=latest, reason=reason, by_name=SERVER_CONFIGURATION)
            changed = True
        else:
            # Checked at every start too: a database restored from a backup, or a marker an operator removed.
            from app.core import recording_marker
            try:
                with db.begin_nested():
                    recording_marker.sync(db)
            except Exception as exc:  # noqa: BLE001 -- the start goes on; the daily check tries again
                _say(f"Warning: the marker that keeps an earlier release from starting on these recording levels "
                     f"could not be checked ({type(exc).__name__})")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    use(latest)
    try:
        load(factory)          # and when the levels began
    except Exception:  # noqa: BLE001 -- the refresher reads it at its next turn
        pass
    if changed:
        # Every user is told, as after a save in the panel (app/core/recording_notice.py).
        from app.core import recording_notice
        recording_notice.announce(latest.version, session_factory=factory)
    return latest


# --------------------------------------------------------------------------- applying the levels

_TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,99}")
_SAFE_KEY = re.compile(r"[a-z][a-z0-9_.*]{0,63}")


def shorten(value) -> Optional[str]:
    """The network a shortened address keeps: the /24 of an IPv4 address, the /48 of an IPv6 one (an
    IPv4-mapped IPv6 address is shortened as the IPv4 address). None when the value is not an address."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(ipaddress.ip_network(f"{address}/{SHORT_PREFIX[address.version]}", strict=False))


def _host_operator() -> str:
    from app.core.credential_changes import HOST_OPERATOR
    return HOST_OPERATOR


def username_is_typed(row) -> bool:
    """Whether the row's username is a name someone typed rather than an account's: a row with no account
    names one only for a failed sign-in, and then only when the name is no account's or temporary credential's
    (a failed sign-in for one says so: AuditLogger.build_row's names_account). The server's operator acting from the host and the
    server's own configuration (a version of the levels the start signs) are neither."""
    return (getattr(row, "user_id", None) is None and bool(getattr(row, "username", None))
            and not getattr(row, "_names_account", False)
            and row.username not in (_host_operator(), SERVER_CONFIGURATION))


class _Recorder:
    """What one row keeps, as it is decided."""

    def __init__(self, row, levels: Mapping[str, str], vault_id=None):
        self.row = row
        self.levels = levels
        # The vault the row's names are in, which keys their fingerprints (None: names are not recorded).
        self.vault_id = vault_id
        self.recorded: Dict[str, Any] = {}
        self.dropped: list = []

    def level(self, kind: str) -> str:
        return self.levels[KIND_POLICY[kind]]

    # A value of a personal kind at its level: (value kept in place, value recorded in another form). Either
    # may be None; names are decided by name(), never kept in place.
    def personal(self, kind: str, value) -> Tuple[Any, Any]:
        level = self.level(kind)
        if level == FULL:
            return value, None
        if level == SHORTENED and kind == ADDRESS:
            return None, shorten(value)
        if level == FINGERPRINT and kind == SIGNIN_NAME:
            from app.core.audit_fingerprints import SIGNIN, fingerprint
            return None, fingerprint(SIGNIN, value)
        return None, None

    def detail(self, path: str, value):
        """(keep, value): whether the detail stays in ``details``, and as what."""
        kind = kind_of(path)
        if kind is None:
            self.dropped.append(path if _SAFE_KEY.fullmatch(path) else "(a key that is not a plain name)")
            return False, None
        if kind == IDENTIFIER:
            return True, value
        if kind == SECRET:
            return False, None
        if kind == ERROR:
            return (True, value) if isinstance(value, str) and _TYPE_NAME.fullmatch(value) else (False, None)
        if kind == COUNT:
            return (True, value) if isinstance(value, int) else (False, None)
        if kind == NESTED:
            if not isinstance(value, dict):
                return True, value
            return True, self.details(value, prefix=path + ".")
        if kind == NAME:
            self.name(path, value)
            return False, None
        kept, other = self.personal(kind, value)
        if other is not None:
            self.recorded.setdefault("details", {})[path] = other
        return (kept is not None, kept)

    def details(self, raw: dict, prefix: str = "") -> dict:
        out = {}
        for key, value in raw.items():
            keep, kept = self.detail(prefix + str(key), value)
            if keep:
                out[key] = kept
        return out

    def name(self, path: str, value) -> None:
        """A vault, file or folder name: never in the details. At the fingerprint level, its fingerprint under
        its vault's key goes into recorded.names; in full, the name too, sealed (seal_name). A name whose vault
        the row does not say is not recorded."""
        if self.level(NAME) == NONE or self.vault_id is None or not isinstance(value, str):
            return
        from app.core.audit_fingerprints import NAME as NAME_KEY, fingerprint
        kept = {"fp": fingerprint(NAME_KEY, value, self.vault_id)}
        if self.level(NAME) == FULL:
            kept["sealed"] = seal_name(self.vault_id, self.row.id, path, value)
        names = self.recorded.setdefault("names", {"vault": str(self.vault_id), "values": {}})
        names["values"][path] = kept

    def columns(self) -> None:
        row = self.row
        if username_is_typed(row):
            kept, other = self.personal(SIGNIN_NAME, row.username)
            row.username = kept
            if other is not None:
                self.recorded["signin_name"] = other
        if getattr(row, "ip_address", None):
            kept, other = self.personal(ADDRESS, row.ip_address)
            row.ip_address = kept[:IP_COLUMN_LENGTH] if isinstance(kept, str) else kept
            if other is not None:
                self.recorded["ip"] = other
        if getattr(row, "user_agent", None):
            row.user_agent, _ = self.personal(AGENT, row.user_agent)


def _name_field(key: str) -> str:
    return "audit-name:" + key


def seal_name(vault_id, row_id, key: str, name: str) -> str:
    """A name recorded in full, sealed under a key derived for its vault and its audit row, with the detail
    key it was recorded under bound in: it opens only for that row and that key, and the database holds no
    plaintext copy. The row's id is the one build_row gives it before any hook runs."""
    if row_id is None:
        raise ValueError("a row's name is sealed under its id, and this row has none yet")
    from app.core.security import encrypt_object_field
    return encrypt_object_field(vault_id, row_id, name, _name_field(key))


def open_name(vault_id, row_id, key: str, sealed: str) -> str:
    """The name seal_name sealed. Raises when the vault, the row or the key is not the one it was sealed
    under, or the value was changed."""
    from app.core.security import decrypt_object_field
    return decrypt_object_field(vault_id, row_id, sealed, _name_field(key))


def names_vault(row, raw_details):
    """The vault a row's names are in: the vault itself for a vault event, else the vault its details name.
    The same rule the Activity page uses to decide whose names a viewer may see."""
    import uuid as _uuid
    raw = getattr(row, "resource_id", None) if getattr(row, "resource_type", None) == "vault" else (
        raw_details.get("vault_id") if isinstance(raw_details, dict) else None)
    try:
        return _uuid.UUID(str(raw)) if raw else None
    except (TypeError, ValueError):
        return None


def apply(row, raw_details) -> None:
    """Decide what ``row`` records of its personal values, in place: its username, address and user agent,
    its details (from ``raw_details``, the caller's details as given), ``recorded`` and ``privacy_version``.
    Never raises."""
    try:
        policy = current()
        recorder = _Recorder(row, effective(policy.levels), names_vault(row, raw_details))
        recorder.columns()
        if isinstance(raw_details, dict):
            row.details = recorder.details(raw_details)
        elif raw_details is not None:
            row.details = None
            recorder.dropped.append("(details that are not a set of keys)")
        else:
            row.details = None
        if recorder.dropped:
            recorder.recorded["dropped"] = sorted(set(recorder.dropped))
            for path in recorder.dropped:
                raise_alert(UNCLASSIFIED, path, getattr(row, "action", None))
        if recorder.recorded:
            # Only when there is something: an unset column is stored as NULL, where None would be stored
            # as a JSON null.
            row.recorded = recorder.recorded
        row.privacy_version = policy.version
    except Exception as exc:  # noqa: BLE001 -- the row is written all the same, see the module docstring
        fallback(row, raw_details, exc)


def fallback(row, raw_details, exc) -> None:
    """Write ``row`` with no personal value: no typed name, address or user agent, only the details
    classified as always recorded, nothing in ``recorded``, and version -1; and raise an alert. Never
    raises."""
    try:
        raise_alert(FAILED, type(exc).__name__, getattr(row, "action", None))
    except Exception:  # noqa: BLE001
        pass
    for attr in ("ip_address", "user_agent"):
        try:
            setattr(row, attr, None)
        except Exception:  # noqa: BLE001
            pass
    try:
        from sqlalchemy import null
        row.recorded = null()          # SQL NULL: None would be stored as a JSON null
    except Exception:  # noqa: BLE001
        pass
    try:
        if username_is_typed(row):
            row.username = None
    except Exception:  # noqa: BLE001
        try:
            row.username = None
        except Exception:  # noqa: BLE001
            pass
    try:
        row.details = ({k: v for k, v in raw_details.items() if DETAIL_KEYS.get(str(k)) == IDENTIFIER}
                       if isinstance(raw_details, dict) else None)
    except Exception:  # noqa: BLE001
        try:
            row.details = None
        except Exception:  # noqa: BLE001
            pass
    try:
        row.privacy_version = FALLBACK_VERSION
    except Exception:  # noqa: BLE001
        pass


def for_output(kind: str, value) -> str:
    """``value`` as a line of the container's output may show it, at its kind's level. Never raises."""
    try:
        if value is None:
            return "-"
        level = effective(current().levels)[KIND_POLICY[kind]]
        if level == FULL:
            return str(value)
        if level == SHORTENED and kind == ADDRESS:
            return shorten(value) or "(not recorded)"
        if level == FINGERPRINT and kind == SIGNIN_NAME:
            from app.core.audit_fingerprints import SIGNIN, fingerprint
            return fingerprint(SIGNIN, value) or "(not recorded)"
        return "(not recorded)"
    except Exception:  # noqa: BLE001
        return "(not recorded)"


# --------------------------------------------------------------------------- alerts

UNCLASSIFIED = "unclassified"
FAILED = "failed"
# A failed sign-in's or second-factor code's security record (app/core/security_records.py) that could not be
# written, while its audit row was (``subject`` is the error's type).
RECORD_NOT_WRITTEN = "security_record"
ALERT_EVENT = "audit_recording_degraded"
# A process raises the same alert at most once in this many seconds.
ALERT_COOLDOWN_SECONDS = 600.0
_ALERTS_MAX = 100

_alerts_lock = threading.Lock()
_alerts_pending: "OrderedDict[Tuple[str, str], dict]" = OrderedDict()
_alerts_sent: Dict[Tuple[str, str], float] = {}


def raise_alert(reason: str, subject: Optional[str], action: Optional[str]) -> bool:
    """Queue an alert for the administrators: a detail key with no classification (``subject`` is its key)
    or a row recorded without its personal values because deciding failed, or a failure's security record
    that could not be written (for both, ``subject`` is the error's type). Written by this process's background thread, never on the row's own transaction. Returns whether
    it was queued (not within the cooldown of the same alert). No value of the row goes into it."""
    key = (reason, str(subject or ""))
    now = time.monotonic()
    with _alerts_lock:
        last = _alerts_sent.get(key)
        if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
            return False
        if len(_alerts_pending) >= _ALERTS_MAX and key not in _alerts_pending:
            return False
        _alerts_sent[key] = now
        _alerts_pending[key] = {"reason": reason, "subject": str(subject or ""),
                                "action": str(action or "")[:100]}
    return True


def pending_alerts() -> list:
    with _alerts_lock:
        return list(_alerts_pending.values())


def alert_message(alert: Mapping[str, str]) -> str:
    if alert["reason"] == UNCLASSIFIED:
        return (f"An audit row of '{alert['action'] or 'an event'}' carried a detail ({alert['subject']}) "
                "that nothing classifies, so it was not recorded. The event itself was recorded.")
    if alert["reason"] == RECORD_NOT_WRITTEN:
        return (f"Security records of failed sign-ins could not be written ({alert['subject']}), first on a "
                f"'{alert['action'] or 'failed sign-in'}'. Their audit rows were recorded, but the failed sign-in "
                "counts in the security metrics, which read these records, leave them out.")
    return (f"An audit row of '{alert['action'] or 'an event'}' was recorded without its personal values "
            f"(names, addresses, user agent), because deciding what to record failed "
            f"({alert['subject']}). The event itself was recorded, with recording version -1.")


def _flush_alerts(session_factory) -> int:
    """Write the queued alerts. Never raises: what cannot be written now stays queued for the next turn."""
    with _alerts_lock:
        batch = list(_alerts_pending.items())
    written = 0
    for key, alert in batch:
        try:
            db = session_factory()
        except Exception:  # noqa: BLE001
            return written
        try:
            # One alert for each: the process's cooldown already keeps a repeat from flooding, and the
            # security monitor's own folding would hide a second key behind the first alert's text.
            from datetime import datetime, timezone
            from app.core.models import SecurityAlert
            db.add(SecurityAlert(
                event_type=ALERT_EVENT, severity="warning", message=alert_message(alert),
                details={"reason": alert["reason"], "subject": alert["subject"], "action": alert["action"]},
                timestamp=datetime.now(timezone.utc).replace(tzinfo=None), resolved=False))
            db.commit()
            with _alerts_lock:
                _alerts_pending.pop(key, None)
            written += 1
        except Exception:  # noqa: BLE001
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
        finally:
            db.close()
    return written


def flush_alerts(session_factory=None) -> int:
    return _flush_alerts(session_factory or _default_session_factory)


def _reset_for_tests() -> None:
    global _required, _refresher
    stop()
    _refresher = None
    with _alerts_lock:
        _alerts_pending.clear()
        _alerts_sent.clear()
    _cache.policy = None
    _cache.began = None
    _required = False


# The lock names this group, so that SETTINGS_LOCKED_KEYS=audit_levels makes each .env limit the level.
def _register() -> None:
    from app.core import settings_registry
    settings_registry.register_lock_group(LOCK_GROUP, "Recording levels")


_register()
