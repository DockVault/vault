"""What users are told about what this vault records: the public notice, its stores list, the banner shown after
a change, and the notification sent to every user.

The notice (GET /privacy/recording, and the page /recording that shows it) says, in plain words and with no
sign-in: what the audit log records of each kind of personal data (the levels in force, app/core/audit_privacy.py),
how long records are kept, who can see them, the legal basis and the contact the operator states, and every other
place this vault keeps personal data with how long each keeps it (STORES). It shows the levels in force only;
the versions before need sign-in.

Each new version of the levels notifies every user (once per user and version) and shows a banner after sign-in
until the user says they have read it. That records reading it, not consent: the levels are the operator's
decision.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from app.core import audit_privacy as ap

# --------------------------------------------------------------------------- the stores

@dataclass(frozen=True)
class Store:
    key: str                  # the table, or a name for a store that is not one
    what: str                 # what personal data it holds
    kept: Callable[[], str]   # how long it keeps it, in plain words, as configured now
    table: Optional[str] = None
    follows_levels: bool = False


def _days(n: int) -> str:
    return "for ever" if not n else (f"{n} day" if n == 1 else f"{n} days")


def _audit_kept() -> str:
    from app.core import audit_retention
    numbers = audit_retention.current()
    text = (f"Kept {_days(numbers.max_days)}" if numbers.max_days else "Kept for ever, unless an administrator sets a "
            "maximum")
    if numbers.max_days:
        text += f"; administration and security events at least {_days(numbers.admin_min_days)}"
    if numbers.max_mb:
        text += f"; the oldest events go first once the log passes {numbers.max_mb} MB"
    return text + "."


def _security_record_kept() -> str:
    from app.core import security_records, settings_registry
    return f"Kept {_days(settings_registry.resolve(security_records.WINDOW_KEY))}, whatever the recording levels say."


def _alerts_kept() -> str:
    from app.core import security_records, settings_registry
    return (f"Names and addresses are removed after {_days(settings_registry.resolve(security_records.WINDOW_KEY))}; "
            f"resolved alerts are deleted after "
            f"{_days(settings_registry.resolve(security_records.ALERT_RETENTION_KEY))}.")


def _sessions_kept() -> str:
    from app.core.session_retention import SESSION_DATA_RETENTION_DAYS
    return f"For the session's life, then {_days(SESSION_DATA_RETENTION_DAYS)}."


STORES = (
    Store("audit_logs", "Every event: who acted (the username), what happened, when and its outcome, with the "
          "personal data the recording levels keep: names, a name typed at a failed sign-in, email addresses, the "
          "address and the browser description.", _audit_kept, table="audit_logs", follows_levels=True),
    Store("security_records", "Each failed sign-in in full: the name exactly as typed (which can be a password typed "
          "into the wrong box), the address and how it came in, for blocking and investigating attacks.",
          _security_record_kept, table="security_records"),
    Store("security_alerts", "Security alerts, with the name and the address that raised them.", _alerts_kept,
          table="security_alerts"),
    Store("active_sessions", "Each sign-in session: its address and browser, so you can see where you are signed in.",
          _sessions_kept, table="active_sessions"),
    Store("pending_logins", "A sign-in waiting for its second factor: its address.",
          lambda: "Minutes: until the sign-in finishes or expires, then with the sessions.", table="pending_logins"),
    Store("sign_in_lockouts", "The address of failed sign-ins counted towards a lock.",
          lambda: "Until the lock ends: a day at most.", table="sign_in_lockouts"),
    Store("rate_limit_records", "The address or account counted by the request limits when the cache is down.",
          lambda: "An hour.", table="rate_limit_records"),
    Store("receiver_upload_sessions", "The address of someone uploading through an upload link.",
          lambda: "For the upload's life, then with the upload's own records.", table="receiver_upload_sessions"),
    Store("notifications", "Your notifications, including one telling you of a sign-in or a change to your account "
          "from an address.", lambda: "Until you dismiss them.", table="notifications"),
    Store("cache", "Counts of requests and failed sign-ins by address and by account, in the cache.",
          lambda: "Minutes, or a day at most."),
    Store("container_output", "The server's output, which shows each request's address and route.",
          lambda: "As long as the operator's log rotation keeps it."),
    Store("log_access_file", "A copy of the server's output kept for log access.",
          lambda: "Up to 15 MB; the oldest lines go first."),
    Store("backups", "Backups of the database and its settings, made by the operator.",
          lambda: "As long as the operator keeps them."),
)

# Tables with an address or a name column that are not a store of personal data, and why.
NOT_STORES = {
    "audit_privacy_policies": "its ip and user_agent columns hold recording levels, not addresses",
}

_PERSONAL_COLUMN = r"(^|_)(ip|ip_address|client_ip|address|source|identifier|user_agent)$"


def unlisted_stores(metadata) -> list:
    """Tables with a column that holds an address, an identifier counted by address, or a browser description,
    that neither STORES lists nor NOT_STORES explains. A store the notice does not list is a store users are
    not told about."""
    import re
    listed = {s.table for s in STORES if s.table} | set(NOT_STORES)
    out = []
    for name, table in sorted(metadata.tables.items()):
        if name not in listed and any(re.search(_PERSONAL_COLUMN, c.name) for c in table.columns):
            out.append(name)
    return out


WHO_CAN_SEE = (
    "Administrators see every event on the Activity page, with the personal data recorded at these levels. Vault, "
    "file and folder names only for vaults they can read themselves.",
    "You see your own sessions, notifications and the events of your account where the app shows them.",
    "The operator who runs this vault can read the database and its backups.",
)
FINGERPRINT_CAVEAT = ("A fingerprint hides a name from someone who reads the database without the server's "
                      "configuration file; anyone who holds that file (it is in the operator's backups) can test "
                      "guesses, and finds a short or common name quickly.")
LEVEL_WORDS = {
    ap.NONE: "Not recorded",
    ap.FINGERPRINT: "Recorded as a fingerprint (a keyed code, not the value)",
    ap.SHORTENED: ("Shortened: only the network it is in is kept (the first three parts of an IPv4 address, the "
                   "first three groups of an IPv6 address)"),
    ap.FULL: "Recorded in full",
}
NOTICE_KEYS = ("recording_notice_legal_basis", "recording_notice_contact")
NOTICE_MAX_LENGTH = 1000


# --------------------------------------------------------------------------- the public notice

_CACHE_SECONDS = 60.0
_cache_lock = threading.Lock()
_cache: dict = {"at": None, "value": None}


def _stated(db) -> dict:
    from app.core.models import SystemSetting
    row = db.query(SystemSetting.value).filter(SystemSetting.key == "global").first()
    value = row[0] if row and isinstance(row[0], dict) else {}
    out = {}
    for key in NOTICE_KEYS:
        text = value.get(key)
        out[key] = text.strip()[:NOTICE_MAX_LENGTH] if isinstance(text, str) and text.strip() else None
    return out


def _contact_fallback(db) -> Optional[str]:
    try:
        from app.config.effective import get_effective_branding
        cfg = get_effective_branding(db)
        return cfg.contact_email or cfg.support_email
    except Exception:  # noqa: BLE001 -- the notice says none was stated
        return None


def build_notice(db) -> dict:
    """The public notice, as configured now. Never names a person, an address or a past version."""
    policy = ap.current()
    levels = ap.effective(policy.levels)
    stated = _stated(db)
    stores = []
    for store in STORES:
        try:
            kept = store.kept()
        except Exception:  # noqa: BLE001 -- a store whose lifetime cannot be read is still listed
            kept = "See the operator."
        stores.append({"key": store.key, "what": store.what, "kept": kept, "follows_levels": store.follows_levels})
    return {
        "version": policy.version,
        "levels": [{"key": key, "label": ap.LABELS[key], "level": levels[key], "words": LEVEL_WORDS[levels[key]]}
                   for key in ap.POLICY_KEYS],
        "always": "Every event is recorded: who acted (an account's username), what happened, when and its outcome. "
                  "Passwords, codes and link tokens are never recorded.",
        "fingerprints": FINGERPRINT_CAVEAT if any(levels[k] == ap.FINGERPRINT for k in ap.POLICY_KEYS) else None,
        "who_can_see": list(WHO_CAN_SEE),
        "legal_basis": stated["recording_notice_legal_basis"],
        "contact": stated["recording_notice_contact"] or _contact_fallback(db),
        "stores": stores,
        "changes": "Each change of the levels applies to events recorded from then on, and every user is told.",
    }


def notice(db, *, now: Optional[float] = None) -> dict:
    """build_notice, computed at most once a minute per process: the page is public, so a flood of requests
    reads the database once a minute, not once a request."""
    now = time.monotonic() if now is None else now
    with _cache_lock:
        if _cache["value"] is not None and now - _cache["at"] < _CACHE_SECONDS:
            return _cache["value"]
    value = build_notice(db)
    with _cache_lock:
        _cache.update(at=now, value=value)
    return value


def forget_notice() -> None:
    with _cache_lock:
        _cache.update(at=None, value=None)


# --------------------------------------------------------------------------- the banner and the notification

SEEN_ACTION = "privacy_notice_seen"
NOTIFICATION_TYPE = "recording_levels_changed"
NOTIFICATION_TARGET = "#recording"


def banner(user, version: int) -> dict:
    """What the page shows a signed-in user: whether the levels changed since they last read the notice. Version
    1 is what the vault recorded before the levels existed, so it is never a change."""
    seen = getattr(user, "privacy_seen_version", None) or 1
    return {"version": version, "seen": seen, "show": version > seen,
            "text": "What this vault records has changed. See what is recorded and how long it is kept."}


def announce(version: int, *, session_factory=None, nudge: Optional[Callable[[str], None]] = None) -> int:
    """Notify every active account of version ``version``, once each (dedup ``privacy:v<n>``). Never raises.
    ``nudge(user_id)`` tells a signed-in user's page at once. Returns how many were notified."""
    from sqlalchemy.exc import IntegrityError
    from app.core.models import Notification, User
    factory = session_factory or ap._default_session_factory
    notified = []
    try:
        db = factory()
    except Exception:  # noqa: BLE001
        return 0
    try:
        ids = [uid for (uid,) in db.query(User.id).filter(User.is_active.is_(True)).all()]
        for uid in ids:
            try:
                with db.begin_nested():
                    db.add(Notification(user_id=uid, type=NOTIFICATION_TYPE,
                                        title="What this vault records has changed",
                                        body=f"The recording levels are now version {version}. See what is "
                                             "recorded and how long it is kept.",
                                        target=NOTIFICATION_TARGET, dedup_key=f"privacy:v{version}:{uid}"))
                notified.append(uid)
            except IntegrityError:
                pass      # already told of this version
        db.commit()
    except Exception:  # noqa: BLE001 -- the banner still shows at the next sign-in
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0
    finally:
        db.close()
    if nudge is not None:
        for uid in notified:
            try:
                nudge(str(uid))
            except Exception:  # noqa: BLE001
                pass
    return len(notified)
