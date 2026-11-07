"""Per-person erase: a person's name removed from the audit log and the other records, on request.

Whose name. Only a name no account has: a deleted account's username, or a name typed at a failed sign-in. An
account's own name is refused (its trail is still being written: delete the account first), and so is the name of a
temporary credential that exists, a name an invitation still waiting is for, any name that starts with "erased-",
in any case (the placeholders an erase writes: erasing one would erase rows already erased), and the names the
server writes for itself (the host's operator, the server). The name is matched exactly, byte for byte, as the
audit log stores it: no case folding, no Unicode normalisation; a name typed at a failed sign-in that the audit log
recorded as a fingerprint is matched by its fingerprint under the key in use. The preview lists the near misses (the
same name in another case, or the same letters in another form) for the administrator to ask for separately.

Inside free text (a notification, an alert's notes, a change record's summary) the name is replaced as a whole word
only, and only when it is at least TEXT_MIN characters long; a JSON value equal to the name, or to its fingerprint,
is replaced whatever its length.

Asking. An administrator previews what an erase would change in each store (preview()), then asks for it with the
step-up (the password every time, ``admin.retention.write``). In one transaction, under the audit chain's lock
(request()):

- the ``erase_requests`` row, holding the name only sealed: AES-256-GCM over a random 32-byte ``r`` and the name,
  under a key derived from ENCRYPTION_KEY with a label of its own, bound to the request's id (seal_name);
- the chain's ``request`` seal (``what: erase``): ``subject``, a commitment to the name (SHA-256 over the request's
  id, ``r`` and the name, so it binds the name without revealing it, against every holder of ENCRYPTION_KEY too), and
  ``placeholder``, the username the erase writes in its place (``erased-`` and 8 random hex characters, never derived
  from the name), with ``not_before``, its own time plus the delay;
- the ``person_erase_requested`` audit row, naming the placeholder, never the name.

Every administrator is told, in the app and by email; the notice names the placeholder only. The erase waits the
reduction delay (RETENTION_REDUCTION_DELAY_DAYS); any administrator can cancel it until it begins (cancel(): a
``cancel`` seal, the sealed name deleted). Once it has begun it is not stopped: it completes.

Running is the pruner's (app/core/audit_chain_erase.py): it takes the name from this row only after the token opens
and its subject is the one the request seal carries, and the placeholder from the seal, never from this row. It
waits while the hold switch is on, while a rule another part of the app registers says so (register_wait: legal
holds and open cases), while an account, a temporary credential or a waiting invitation has the name, and, with
ERASE_BLOCKED_BY_PROTECTED_MINIMUM=true, while any audit row it would change is younger than the protected minimum
for its kind.

What it covers: every table of the database is in COVERAGE, with the store that erases the name there or the reason
nothing need be (tests/test_person_erase.py ties it to the models and to docs/data-inventory.md).
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import unicodedata
import uuid
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from app.core import audit_chain_format as fmt
from app.core import settings_registry as registry

PREFIX = "erased-"
PLACEHOLDER = re.compile(r"^erased-[0-9a-f]{8}$")
NAME_MAX = 255

PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
CANCELLED = "cancelled"
# A row the view holds no request of while this process has not read the chain through: not known yet, rather than
# "not recorded".
UNREAD = "unread"

REQUESTED_ACTION = "person_erase_requested"
CANCELLED_ACTION = "person_erase_cancelled"
ERASED_ACTION = "person_erased"
RESOURCE_TYPE = "erase_request"

LABEL_SUBJECT = b"dvaudit-erase-subject-v1\x00"
LABEL_NAME_AD = b"dvaudit-erase-name-v1\x00"
TOKEN_PREFIX = "en1:"
_GCM_NONCE = 12

PROTECTED_MINIMUM_KEY = "erase_blocked_by_protected_minimum"

registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=PROTECTED_MINIMUM_KEY, kind="bool", default=False, env="erase_blocked_by_protected_minimum",
    editable=registry.ENV_ONLY, reduction=registry.LOWER, group="audit_retention",
    label="A per-person erase waits for the protected minimum",
    help="With it on, an erase waits while any audit row it would change is younger than the protected minimum for "
         "its kind, for deployments whose records must be kept intact that long."))


class Refused(Exception):
    """An erase that cannot be asked for, cancelled or previewed as asked, said in plain words."""


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def is_reserved_name(name) -> bool:
    """Whether ``name`` starts with "erased-", in any case and in any compatible form (fullwidth letters
    included): the placeholders an erase writes."""
    if not isinstance(name, str):
        return False
    return unicodedata.normalize("NFKC", name).casefold().startswith(PREFIX)


# --------------------------------------------------------------------------- the name: commitment and token

def subject_of(request_id, r: bytes, name: str) -> bytes:
    """The commitment the request seal carries: SHA-256 over the request's id, ``r`` and the name exactly as
    the erase compares it."""
    return hashlib.sha256(LABEL_SUBJECT + fmt.e_uuid(request_id) + fmt.e_bytes(r) + fmt.e_text(name)).digest()


def _name_key(cfg) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    secret = (getattr(cfg, "encryption_key", "") or "").encode()
    if not secret:
        raise Refused("ENCRYPTION_KEY is not set")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"dockvault-erase-name-v1",
                info=b"erase-name").derive(secret)


def _ad(request_id) -> bytes:
    return LABEL_NAME_AD + fmt.as_uuid(request_id).bytes


def seal_name(cfg, request_id, r: bytes, name: str) -> str:
    """The token erase_requests keeps: AES-256-GCM over E(r) || E(name), bound to the request's id."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(_GCM_NONCE)
    ct = AESGCM(_name_key(cfg)).encrypt(nonce, fmt.e_bytes(r) + fmt.e_text(name), _ad(request_id))
    return TOKEN_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def _take(data: bytes, at: int, tag: int):
    if len(data) < at + 5 or data[at] != tag:
        raise ValueError("not a sealed name")
    n = int.from_bytes(data[at + 1:at + 5], "big")
    end = at + 5 + n
    if len(data) < end:
        raise ValueError("not a sealed name")
    return data[at + 5:end], end


def open_name(cfg, request_id, token: Optional[str]) -> tuple:
    """(r, name) from a token seal_name made for ``request_id``. Raises ValueError for any other token."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
        raise ValueError("not a sealed name")
    try:
        raw = base64.b64decode(token[len(TOKEN_PREFIX):], validate=True)
        plain = AESGCM(_name_key(cfg)).decrypt(raw[:_GCM_NONCE], raw[_GCM_NONCE:], _ad(request_id))
    except (InvalidTag, ValueError, TypeError) as exc:
        raise ValueError("the sealed name does not open") from exc
    r, at = _take(plain, 0, 0x02)
    name, end = _take(plain, at, 0x01)
    if end != len(plain):
        raise ValueError("not a sealed name")
    return r, name.decode("utf-8", "surrogatepass")


# --------------------------------------------------------------------------- what may be erased

def _now(st=None) -> datetime:
    return (st or _ai().state()).clock()


def name_problem(name) -> Optional[str]:
    """Why ``name`` cannot be erased whatever the database holds, or None."""
    if not isinstance(name, str) or name == "":
        return "Type the name to erase."
    if len(name) > NAME_MAX:
        return f"The audit log keeps at most {NAME_MAX} characters of a name; this one is longer."
    if "\x00" in name:
        return "A name with a NUL character is in no record."
    if is_reserved_name(name):
        return ("Names that start with 'erased-' are the placeholders erases write: rows with such a name are "
                "already erased.")
    if name in system_names():
        return ("This name is one the server writes for itself (the host's operator, the server, the steps compliance "
                "access takes on its own), not a person's: its rows cannot be erased by name, those of an account an "
                "older release let take it included.")
    return None


def system_names() -> frozenset:
    """The names the app writes into the records for itself, which are no person's: the host's operator, the
    server's own configuration, the server acting from .env, and the steps compliance access takes on its own."""
    from app.core.audit_chain_policy_seals import SERVER_NAME
    from app.core.audit_privacy import SERVER_CONFIGURATION
    from app.core.credential_changes import HOST_OPERATOR
    from app.core.legal_holds import SYSTEM
    return frozenset({HOST_OPERATOR, SERVER_CONFIGURATION, SERVER_NAME, SYSTEM})


def server_name_form(name: str) -> str:
    """``name`` as it is compared with the names the server writes for itself: its compatible form (NFKC), in any
    case, with every space, underscore, hyphen and dot left out, so "System", " system " and "server_configuration"
    read as the server's own names do."""
    return re.sub(r"[\s_.\-]+", "", unicodedata.normalize("NFKC", name).casefold())


def is_server_name(name) -> bool:
    """Whether ``name`` reads as one of the names the server writes for itself (system_names, compared in
    server_name_form). An account may not take such a name: the server's own rows would read as its, and once the
    account is gone its records could not be erased (name_problem refuses the server's names)."""
    if not isinstance(name, str):
        return False
    form = server_name_form(name)
    return any(form == server_name_form(n) for n in system_names())


# --------------------------------------------------------------------------- accounts named like the server

SERVER_NAMED_NOTICE = "account_named_like_the_server"


def _server_steps(name: str) -> str:
    """What the server writes under the server name ``name`` reads as, in words."""
    from app.core.audit_chain_policy_seals import SERVER_NAME
    from app.core.audit_privacy import SERVER_CONFIGURATION
    from app.core.legal_holds import SYSTEM
    form = server_name_form(name)
    for own, words in ((SYSTEM, "the steps compliance access takes on its own"),
                       (SERVER_CONFIGURATION, "the recording levels it sets at its start"),
                       (SERVER_NAME, "a limit on the audit log's retention set in .env")):
        if form == server_name_form(own):
            return words
    return "its own steps"


def server_named(db, now: Optional[datetime] = None) -> dict:
    """{"accounts": [...], "invitations": [...]}: the usernames of the accounts that are exactly a name the server
    writes for itself (their rows and the server's read alike, and an erase of the name is refused), and of the
    invitations still waiting whose names read as one (is_server_name: they can no longer be accepted). An older
    release let them be made; the accounts keep working. An account named so in another case or spacing is not
    listed: its rows are told apart from the server's by the name itself, and its erase works."""
    from app.core.models import AccountInvitation, User
    now = now or datetime.utcnow()
    own = system_names()
    accounts = sorted(u for (u,) in db.query(User.username).filter(User.username.in_(sorted(own))).all())
    waiting = db.query(AccountInvitation.username).filter(
        AccountInvitation.accepted_at.is_(None), AccountInvitation.revoked_at.is_(None),
        AccountInvitation.expires_at > now).all()
    return {"accounts": accounts, "invitations": sorted(u for (u,) in waiting if is_server_name(u))}


def server_named_words(username: str, *, invitation: bool) -> tuple:
    """(title, body) of what every administrator is told about one such account or invitation."""
    steps = _server_steps(username)
    if invitation:
        return ("An invitation is for a name the server uses in its records",
                f'The invitation for "{username}" can no longer be accepted: the server writes this name into '
                f"the records for itself ({steps}). Revoke it and invite again under another name.")
    return ("An account has a name the server uses in its records",
            f'The account "{username}" was made before such names were kept from accounts. It keeps working, but '
            f"the server writes this name into the records for itself ({steps}): on the Activity page those rows "
            "read as the account's, and once the account is deleted, an erase of its records by name is refused. "
            "New accounts cannot take such a name.")


def report_server_named(session_factory=None, now: Optional[datetime] = None) -> dict:
    """At the web server's start: tell every active administrator, once in the app, of each account and waiting
    invitation whose name reads as one the server writes for itself, and say how many in the log (no names).
    Returns server_named's answer. Never raises."""
    import hashlib as _hashlib
    from sqlalchemy.exc import IntegrityError
    found = {"accounts": [], "invitations": []}
    try:
        if session_factory is None:
            from app.core.database import SessionLocal as session_factory
        db = session_factory()
    except Exception:  # noqa: BLE001
        return found
    try:
        from app.core.models import Notification, RoleEnum, User
        found = server_named(db, now)
        items = [(u, False) for u in found["accounts"]] + [(u, True) for u in found["invitations"]]
        if not items:
            return found
        admins = [uid for (uid,) in db.query(User.id).filter(User.role == RoleEnum.ADMIN,
                                                               User.is_active.is_(True)).all()]
        for username, invitation in items:
            title, body = server_named_words(username, invitation=invitation)
            tag = _hashlib.sha256((("i:" if invitation else "a:") + username).encode("utf-8")).hexdigest()[:24]
            for uid in admins:
                try:
                    with db.begin_nested():
                        db.add(Notification(user_id=uid, type=SERVER_NAMED_NOTICE, title=title, body=body,
                                            target="#users", dedup_key=f"server-name:{tag}:{uid}"))
                except IntegrityError:
                    pass                    # told at an earlier start
        db.commit()
        registry._say(f"Warning: {len(found['accounts'])} accounts and {len(found['invitations'])} waiting "
                      "invitations have a name the server writes into the records for itself; every administrator "
                      "is told in the app.")
    except Exception as exc:  # noqa: BLE001
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        registry._say(f"Warning: the accounts named like the server could not be checked ({type(exc).__name__})")
    finally:
        db.close()
    return found


def holder(db, name: str, now: datetime) -> Optional[str]:
    """Who still has ``name``, so that it must not be erased: an account, a temporary credential, or an invitation
    still waiting (as words), or None."""
    from sqlalchemy import or_
    from app.core.models import AccountInvitation, TemporaryCredential, User
    if db.query(User.id).filter(User.username == name).first() is not None:
        return "an account has this name: delete the account first"
    if db.query(TemporaryCredential.id).filter(TemporaryCredential.temp_username == name).first() is not None:
        return "a temporary credential has this name: delete it first"
    waiting = (db.query(AccountInvitation.id)
               .filter(AccountInvitation.username == name, AccountInvitation.accepted_at.is_(None),
                       AccountInvitation.revoked_at.is_(None), AccountInvitation.expires_at > now)
               .first())
    if waiting is not None:
        return "an invitation for this name is waiting: revoke it first"
    return None


# Rules other parts of the app register (legal holds, open cases): rule(db, now) -> why every erase waits, or None.
# The modules that register them are imported with this one (WAIT_MODULES, at its end), so no path that asks
# rule_waits can run without them.
WAIT_RULES: List[Callable] = []
WAIT_MODULES: tuple = ("app.core.compliance_retention",)


def register_wait(rule: Callable) -> Callable:
    """Make every erase wait while ``rule(db, now)`` returns a reason (words), not None: legal holds and open cases
    (app/core/compliance_retention.py holds_back) register here. Every path of the audit log and the records that
    changes or deletes what they may need asks rule_waits in the transaction that would change or delete: an
    erase's units and its last step, the removal of earlier values, the shortening of addresses, the deletion of
    ended invitations, ended one-time proofs and old notifications, and of an ended erase's sealed name."""
    if rule not in WAIT_RULES:
        WAIT_RULES.append(rule)
    return rule


def rule_waits(db, now: datetime) -> Optional[str]:
    """The first reason a registered rule gives for every erase to wait, or None."""
    for rule in list(WAIT_RULES):
        try:
            why = rule(db, now)
        except Exception as exc:  # noqa: BLE001 -- a rule that cannot tell keeps the records
            return f"a rule that holds erases back could not be read ({type(exc).__name__})"
        if why:
            return str(why)
    return None


def protected_minimum() -> bool:
    return bool(registry.resolve(PROTECTED_MINIMUM_KEY))


# --------------------------------------------------------------------------- the placeholder

def draw_placeholder(db, view) -> str:
    """``erased-`` and 8 random lowercase hex characters, drawn again while it is an account's username, or the
    placeholder of an erase in the chain or in erase_requests. Never derived from the name."""
    from app.core.models import EraseRequest, User
    taken = {d.get("placeholder") for d in view.requests.values() if d.get("placeholder")}
    for _ in range(64):
        candidate = PREFIX + secrets.token_hex(4)
        if candidate in taken:
            continue
        if db.query(User.id).filter(User.username == candidate).first() is not None:
            continue
        if db.query(EraseRequest.id).filter(EraseRequest.placeholder == candidate).first() is not None:
            continue
        return candidate
    raise Refused("No placeholder could be drawn; try again.")


# --------------------------------------------------------------------------- the stores

# A name inside free text is replaced only as a whole word, and only when it is at least this long: a shorter one
# would change other words, as would a name inside another word (an erase of "admin" leaves "administrator").
TEXT_MIN = 3


def _word(name: str):
    return re.compile(r"(?<![\w@.-])" + re.escape(name) + r"(?![\w@-]|\.\w)")


def replace_text(text, name: str, placeholder: str):
    """``text`` with every whole-word occurrence of ``name`` given the placeholder (a name shorter than TEXT_MIN is
    never replaced inside text)."""
    if not isinstance(text, str) or len(name) < TEXT_MIN or name not in text:
        return text
    return _word(name).sub(placeholder, text)


def replace_json(value, name: str, placeholder: str, also: tuple = ()):
    """``value`` (decoded JSON) with every string equal to ``name`` (or to one of ``also``: its fingerprint) given the
    placeholder, and every whole-word occurrence of ``name`` inside a longer string (keys too)."""
    if isinstance(value, str):
        return placeholder if value == name or value in also else replace_text(value, name, placeholder)
    if isinstance(value, list):
        return [replace_json(v, name, placeholder, also) for v in value]
    if isinstance(value, dict):
        return {replace_json(k, name, placeholder, also): replace_json(v, name, placeholder, also)
                for k, v in value.items()}
    return value


def json_mentions(column, name: str, also: tuple = ()):
    """A condition for a JSON column whose text holds ``name`` (as it is, or as JSON escapes it) or one of ``also``:
    a prefilter, which replace_json decides."""
    from sqlalchemy import Text, cast, or_
    import json as _json
    text = cast(column, Text)
    forms = {name, _json.dumps(name)[1:-1]} | {a for a in also if a}
    return or_(*[text.contains(f, autoescape=True) for f in forms])


def signin_fingerprint(name: str, cfg=None) -> Optional[str]:
    """The fingerprint the audit log records a name typed at a failed sign-in as, at the fingerprint level, under
    the fingerprint key in use (None when there is no key)."""
    from app.core import audit_fingerprints as afp
    try:
        return afp.fingerprint(afp.SIGNIN, name, settings=cfg)
    except Exception:  # noqa: BLE001 -- no key: nothing is recorded as a fingerprint either
        return None


class Store:
    """A place outside the audit log where a person's name can stay after the account is gone: how many rows the
    erase would change there (count), and the change that gives them the placeholder (erase, returning how many it
    changed). Each takes (db, name, placeholder, also, now): ``also`` holds the name's fingerprint."""

    def __init__(self, key: str, label: str, count: Callable, erase: Callable):
        self.key, self.label, self.count, self.erase = key, label, count, erase


def _models():
    from app.core import models
    return models


def _simple_store(key: str, label: str, table: str, columns: tuple) -> Store:
    """A store whose name columns hold a username exactly (who made, decided or sent something)."""
    from sqlalchemy import or_

    def model():
        return getattr(_models(), table)

    def found(db, name):
        m = model()
        return db.query(m).filter(or_(*[getattr(m, c) == name for c in columns]))

    def count(db, name, placeholder, also, now):
        return found(db, name).count()

    def erase(db, name, placeholder, also, now):
        n = 0
        for row in found(db, name).all():
            for c in columns:
                if getattr(row, c) == name:
                    setattr(row, c, placeholder)
            n += 1
        return n
    return Store(key, label, count, erase)


class _Probe:
    """A copy of a row's values, which a store's change() may change without touching the row."""

    def __init__(self, row):
        import copy
        for c in row.__table__.columns:
            setattr(self, c.key, copy.deepcopy(getattr(row, c.key)))


def _changing_store(key: str, label: str, rows: Callable, change: Callable) -> Store:
    """A store whose rows a prefilter finds (``rows``) and ``change`` decides: it changes a row in place and says
    whether anything changed. The count is of the rows it would change, worked out on a copy of each."""

    def count(db, name, placeholder, also, now):
        return sum(1 for row in rows(db, name, also, now) if change(_Probe(row), name, placeholder, also))

    def erase(db, name, placeholder, also, now):
        return sum(1 for row in rows(db, name, also, now) if change(row, name, placeholder, also))
    return Store(key, label, count, erase)


def _set(obj, field: str, value) -> bool:
    if getattr(obj, field) != value:
        setattr(obj, field, value)
        return True
    return False


def _security_records() -> Store:
    def rows(db, name, also, now):
        m = _models().SecurityRecord
        return db.query(m).filter(m.name == name).all()

    def change(r, name, placeholder, also):
        done = _set(r, "name", placeholder)
        for f in ("address", "ip_via", "account_id"):
            done = _set(r, f, None) or done
        return done
    return _changing_store("security_records", "Failed sign-ins kept in full", rows, change)


def _security_alerts() -> Store:
    from sqlalchemy import or_

    def rows(db, name, also, now):
        m = _models().SecurityAlert
        return db.query(m).filter(or_(m.username == name, m.resolved_by == name,
                                      m.resolution_notes.contains(name, autoescape=True))).all()

    def change(a, name, placeholder, also):
        from app.core import security_records as sr
        done = False
        if a.username == name:
            done = _set(a, "message", sr._scrubbed(a.message or "", name, a.ip_address)) or done
            details = replace_json(a.details, name, placeholder, also)
            if a.ip_address:
                details = replace_json(details, a.ip_address, sr.CLEARED_ADDRESS)
            done = _set(a, "details", details) or done
            done = _set(a, "username", placeholder) or done
            for f in ("ip_address", "ip_via", "user_id"):
                done = _set(a, f, None) or done
        if a.resolved_by == name:
            done = _set(a, "resolved_by", placeholder) or done
        return _set(a, "resolution_notes", replace_text(a.resolution_notes, name, placeholder)) or done
    return _changing_store("security_alerts", "Security alerts", rows, change)


def _credential_changes() -> Store:
    from sqlalchemy import or_

    def rows(db, name, also, now):
        m = _models().CredentialChange
        return db.query(m).filter(or_(m.requested_by_name == name, m.decided_by_name == name,
                                      m.summary.contains(name, autoescape=True),
                                      json_mentions(m.payload, name, also),
                                      json_mentions(m.approval_snapshot, name, also))).all()

    def change(c, name, placeholder, also):
        done = False
        for f in ("requested_by_name", "decided_by_name"):
            if getattr(c, f) == name:
                done = _set(c, f, placeholder) or done
        done = _set(c, "summary", replace_text(c.summary, name, placeholder)) or done
        for f in ("payload", "approval_snapshot"):
            if getattr(c, f) is not None:
                done = _set(c, f, replace_json(getattr(c, f), name, placeholder, also)) or done
        return done
    return _changing_store("credential_changes", "Records of changes to sign-in details", rows, change)


def _invitations() -> Store:
    from sqlalchemy import or_

    def rows(db, name, also, now):
        m = _models().AccountInvitation
        return db.query(m).filter(m.username == name, or_(m.accepted_at.isnot(None), m.revoked_at.isnot(None),
                                                          m.expires_at <= now)).all()

    def change(i, name, placeholder, also):
        changed = _set(i, "username", placeholder)
        return _set(i, "email", None) or changed
    return _changing_store("account_invitations", "Invitations that named them", rows, change)


def _saved_searches() -> Store:
    def rows(db, name, also, now):
        m = _models().ActivitySavedSearch
        return db.query(m).filter(json_mentions(m.filters, name, also)).all()

    def change(s, name, placeholder, also):
        return _set(s, "filters", replace_json(s.filters, name, placeholder, also))
    return _changing_store("activity_saved_searches", "Saved Activity searches that name them", rows, change)


def _notifications() -> Store:
    from sqlalchemy import or_

    def rows(db, name, also, now):
        m = _models().Notification
        if len(name) < TEXT_MIN:
            return []
        return db.query(m).filter(or_(m.title.contains(name, autoescape=True),
                                      m.body.contains(name, autoescape=True))).all()

    def change(n, name, placeholder, also):
        changed = _set(n, "title", replace_text(n.title, name, placeholder))
        return _set(n, "body", replace_text(n.body, name, placeholder)) or changed
    return _changing_store("notifications", "Other people's notifications that name them", rows, change)


STORES: List[Store] = [
    _security_records(),
    _security_alerts(),
    _credential_changes(),
    _simple_store("admin_grants", "Who made an administrator", "AdminGrant", ("granted_by_name",)),
    _invitations(),
    _saved_searches(),
    _notifications(),
    _simple_store("notes", "Notes they sent", "Note", ("sent_from_name",)),
    _simple_store("managed_setting_changes", "Retention changes they asked for or cancelled", "ManagedSettingChange",
                  ("requested_by_name", "decided_by_name")),
    _simple_store("managed_settings", "Retention values they set", "ManagedSetting", ("updated_by_name",)),
    _simple_store("audit_privacy_policies", "Recording levels they set", "AuditPrivacyPolicy", ("created_by_name",)),
    _simple_store("user_ssh_keys", "SSH keys they added to other accounts", "UserSSHKey", ("created_by_name",)),
    _simple_store("erase_requests", "Other erases they asked for or cancelled", "EraseRequest",
                  ("requested_by_name", "decided_by_name")),
    _simple_store("audit_value_removals", "Removals of recorded values they asked for or cancelled",
                  "AuditValueRemoval", ("requested_by_name", "decided_by_name")),
]
STORE_KEYS = {s.key: s for s in STORES}

# Every table, and every store outside the database the data inventory lists: what an erase does there. A store
# key names the handler above (or the audit log's, in app/core/audit_chain_erase.py); anything else is the reason
# nothing need be done.
AUDIT_ROWS = "the audit log: the person's rows are erased under the integrity chain"
DELETED = "deleted with the account"
IDS_ONLY = "holds account ids only, cleared or deleted with the account; no name"
NO_PERSON = "holds no person's name"
# Compliance access keeps who asked for, approved, confirmed, rejected, released or closed a case, a legal hold or an
# auditor's right, and who revealed a name or was told: the record of an investigation, kept for the case's record
# floor (COMPLIANCE_RECORD_MIN_DAYS), which an erase does not change. An auditor's account cannot be deleted while a
# case names it, so its name is never erased.
COMPLIANCE_RECORD = ("the record of compliance access (who asked, approved, confirmed, rejected, released or closed), "
                     "kept for the case's record floor: an erase does not change it")
HELD = "what a legal hold keeps of a vault (ids, names sealed at rest), until the purge after its release"
COVERAGE: Dict[str, str] = {
    "audit_logs": AUDIT_ROWS,
    "audit_archive_blocks": AUDIT_ROWS,
    "audit_seals": "holds no name: a row's values enter only as a hash under its nonce, which the erase destroys",
    "erase_requests": "erase_requests",
    "audit_value_removals": "audit_value_removals",
    "security_records": "security_records",
    "security_alerts": "security_alerts",
    "credential_changes": "credential_changes",
    "admin_grants": "admin_grants",
    "account_invitations": "account_invitations",
    "activity_saved_searches": "activity_saved_searches",
    "notifications": "notifications",
    "notes": "notes",
    "managed_setting_changes": "managed_setting_changes",
    "managed_settings": "managed_settings",
    "audit_privacy_policies": "audit_privacy_policies",
    "user_ssh_keys": "user_ssh_keys",
    "users": "an erase is refused while an account has the name",
    "temporary_credentials": "an erase is refused while a temporary credential has the name; deleted with the account",
    "rate_limit_records": "kept an hour: gone long before an erase runs (it waits the reduction delay)",
    "active_sessions": DELETED, "pending_logins": DELETED, "devices": DELETED, "device_grants": DELETED,
    "second_factor_enrollments": DELETED, "second_factor_recovery_codes": DELETED, "otp_codes": DELETED,
    "password_reset_tokens": DELETED, "email_change_codes": DELETED, "sign_in_lockouts": DELETED,
    "user_groups": DELETED, "user_permissions": DELETED, "user_endpoint_permissions": DELETED,
    "temp_credential_vault_access": DELETED, "vault_favorites": DELETED, "vault_views": DELETED,
    "vault_members": DELETED, "vault_group_access": "access of groups; no person's name",
    "shares": DELETED, "share_claims": DELETED, "user_keypairs": DELETED, "vault_member_keys": DELETED,
    "vault_member_index_keys": DELETED, "zk_share_invites": DELETED, "zk_key_proof_challenges": DELETED,
    "public_links": DELETED, "note_public_links": DELETED, "receivers": DELETED, "user_preferences": DELETED,
    "groups": "group names and descriptions an administrator writes; no deleted person's name is kept there",
    "vault_key_proofs": IDS_ONLY, "vault_storage_grants": IDS_ONLY, "vault_key_history": IDS_ONLY,
    "vaults": "names and descriptions sealed at rest; the owner's id (an account that owns a vault cannot be "
              "deleted)",
    "folders": "names sealed at rest and ids", "files": "names sealed at rest and the uploader's id, cleared with "
                                                          "the account",
    "chunked_upload_sessions": "an uploader's id and a file name, cleared within a day",
    "receiver_upload_sessions": "a sender's address, kept about a day",
    "log_pull_tokens": IDS_ONLY,
    "sftp_processes": NO_PERSON, "system_settings": NO_PERSON, "schema_steps": NO_PERSON,
    "retired_object_ids": NO_PERSON, "share_tags": NO_PERSON, "note_link_tags": NO_PERSON, "receiver_tags": NO_PERSON,
    "second_factor_actions": NO_PERSON, "email_actions": NO_PERSON, "email_profiles": NO_PERSON,
    "email_templates": NO_PERSON, "email_resources": NO_PERSON, "ecc_registration_challenges": IDS_ONLY,
    "ecc_key_update_challenges": IDS_ONLY, "data_requirements": NO_PERSON,
    "compliance_cases": COMPLIANCE_RECORD, "legal_hold_vaults": COMPLIANCE_RECORD, "auditor_grants": COMPLIANCE_RECORD,
    "compliance_reveals": COMPLIANCE_RECORD, "compliance_notice_outbox": COMPLIANCE_RECORD,
    "compliance_exports": IDS_ONLY, "compliance_case_people": IDS_ONLY, "compliance_case_scopes": IDS_ONLY,
    "compliance_case_vaults": IDS_ONLY, "compliance_case_counters": NO_PERSON,
    "held_files": HELD, "held_folders": HELD, "held_name_history": HELD,
    # Outside the database (the data inventory's other sections).
    "cache": "entries expire on their own within a day (a lock on a name that is no account: 30 days), and those "
             "about names typed at sign-in hold only a keyed stand-in",
    "logs": "container output and the log-access file are outside the database: what was logged stays until "
            "rotated away",
    "email": "email already sent cannot be called back",
    "exports and backups": "exports, backups and copies made before the erase keep what they held",
    "the browser": "nothing of another person is kept in a browser",
}


# --------------------------------------------------------------------------- the preview

def _near_misses(db, name: str) -> List[str]:
    """Names in the audit log equal to ``name`` in another case, or to its compatible form, but not the same
    text: they are erased only by an erase of their own."""
    from sqlalchemy import func, or_
    from app.core.models import AuditLog as A
    forms = {name.lower(), unicodedata.normalize("NFKC", name).casefold()}
    found = (db.query(A.username).filter(or_(*[func.lower(A.username) == f for f in forms]), A.username != name)
             .distinct().limit(20).all())
    return sorted(r[0] for r in found if r[0])


def audit_matches(model, name: str, fp: Optional[str]):
    """A condition for the audit rows of ``name``: its username exactly, or (a name typed at a failed sign-in recorded
    at the fingerprint level) no username and its fingerprint in ``recorded``. A prefilter: row_matches decides."""
    from sqlalchemy import Text, and_, cast, or_
    if not fp:
        return model.username == name
    return or_(model.username == name, and_(model.username.is_(None), cast(model.recorded, Text).contains(fp)))


def row_matches(row: dict, name: str, fp: Optional[str]) -> bool:
    """Whether an audit row (``recorded`` as its stored text, or decoded) is one of ``name``'s."""
    if row.get("username") == name:
        return True
    if not fp or row.get("username") is not None or not row.get("recorded"):
        return False
    recorded = row["recorded"]
    if isinstance(recorded, str):
        try:
            import json as _json
            recorded = _json.loads(recorded)
        except ValueError:
            return False
    return isinstance(recorded, dict) and recorded.get("signin_name") == fp


def preview(db, name: str, now: datetime, st=None) -> dict:
    """What erasing ``name`` would change now, store by store, and what it leaves. Raises Refused."""
    from sqlalchemy import func
    from app.core.models import AuditLog as A
    why = name_problem(name)
    if why:
        raise Refused(why)
    st = st or _ai().state()
    view = st.view
    has = holder(db, name, now)
    fp = signin_fingerprint(name, st.cfg())
    mine = audit_matches(A, name, fp)
    times, undated, kept = None, 0, 0
    try:
        from app.core import retention
        with db.begin_nested():
            # A compliance case's rows that must be kept stay as they are: counted apart (retention.kept_as_is).
            dated = db.query(A.username, A.recorded, A.timestamp).filter(
                *retention.changeable(A, now, mine, A.timestamp.isnot(None))).all()
            times = [t for u, r, t in dated if row_matches({"username": u, "recorded": r}, name, fp)]
            undated = db.query(func.count()).select_from(A).filter(A.username == name,
                                                                   A.timestamp.is_(None)).scalar() or 0
            clause = retention.kept_as_is(A, now)
            if clause is not None:
                kept = sum(1 for u, r in db.query(A.username, A.recorded).filter(mine, A.timestamp.isnot(None),
                                                                                  clause).all()
                           if row_matches({"username": u, "recorded": r}, name, fp))
    except Exception:  # noqa: BLE001 -- too slow to count in a request: the erase counts them as it runs
        times = None
    placeholder = PREFIX + "00000000"
    stores = [{"key": s.key, "label": s.label, "count": int(s.count(db, name, placeholder, (fp,) if fp else (), now)
                                                             or 0)} for s in STORES]
    mentions = None
    try:
        with db.begin_nested():
            mentions = int(db.query(func.count()).select_from(A).filter(
                A.username != name, json_mentions(A.details, name)).scalar() or 0)
    except Exception:  # noqa: BLE001 -- a slow count is not needed to ask
        mentions = None
    not_reached = [COVERAGE["exports and backups"], COVERAGE["logs"], COVERAGE["email"],
                   "other people's audit rows that name them in their details are not changed",
                   "a name typed at a failed sign-in recorded as a fingerprint under an earlier fingerprint key"]
    if undated:
        not_reached.append(f"{undated} audit rows with no time")
    if kept:
        not_reached.append(f"{kept} audit rows of a compliance case whose records must be kept, which stay as they are "
                           "until the case lets them go: the erase waits for them, and completes once it has erased "
                           "them")
    return {
        "refused": has,
        "audit_rows": len(times) if times is not None else None,
        "oldest": min(times).isoformat() + "Z" if times else None,
        "newest": max(times).isoformat() + "Z" if times else None,
        "undated_rows": int(undated),
        "archived_days": sum(1 for e in view.archives.values() if e.parts),
        "stores": stores,
        "near_misses": _near_misses(db, name),
        "mentioned_by_others": mentions,
        "delay_days": delay_days(view, st),
        "not_reached": not_reached,
    }


def delay_days(view, st) -> int:
    """The delay of a new erase request: the longer of the honoured state's and the chain's newest state's. The
    honoured state gives no shorter one today (audit_chain_honour.honoured_state keeps the longer delay of the
    two), so the max holds the request to the newest delay whatever that function comes to do."""
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_policy as pol
    try:
        honoured = honour.honoured_state(view, st.known_record(), st.clock())
    except Exception:  # noqa: BLE001
        honoured = view.newest_state()
    return max(pol.delay_days(honoured), pol.delay_days(view.newest_state()))


# --------------------------------------------------------------------------- asking, cancelling, listing

def _pending_names(db, cfg) -> Dict[str, str]:
    """{name: request id} of the erases not ended in the database whose token opens."""
    from app.core.models import EraseRequest
    out = {}
    for row in db.query(EraseRequest).filter(EraseRequest.status.in_((PENDING, RUNNING))).all():
        try:
            _r, name = open_name(cfg, row.id, row.name_token)
        except ValueError:
            continue
        out[name] = str(row.id)
    return out


def request(w, name: str, actor, *, now: Optional[datetime] = None) -> dict:
    """Ask for an erase of ``name`` in the chain writer ``w``'s transaction: the erase_requests row, the request
    seal and the audit row. Raises Refused."""
    from app.core.models import EraseRequest
    from app.services.audit_logger import AuditLogger
    why = name_problem(name)
    if why:
        raise Refused(why)
    st = w.st
    view = st.view
    now = now or st.clock()
    db = w.db
    has = holder(db, name, now)
    if has:
        raise Refused(f"This name cannot be erased now: {has}.")
    if name in _pending_names(db, st.cfg()):
        raise Refused("An erase of this name is already waiting.")
    placeholder = draw_placeholder(db, view)
    request_id = uuid.uuid4()
    r = secrets.token_bytes(32)
    subject = subject_of(request_id, r, name)
    token = seal_name(st.cfg(), request_id, r, name)
    delay = timedelta(days=delay_days(view, st))
    effective = now + delay
    row = AuditLogger(db).build_row(
        action="person_erase_requested", status="success", user=actor, resource_type=RESOURCE_TYPE,
        resource_id=str(request_id),
        details={"request_id": str(request_id), "placeholder": placeholder,
                 "effective_at": effective.isoformat() + "Z"})
    db.add(row)
    erase_row = EraseRequest(id=request_id, status=PENDING, name_token=token, placeholder=placeholder,
                             requested_by=getattr(actor, "id", None), requested_by_name=getattr(actor, "username", None),
                             requested_at=now, effective_at=effective)
    db.add(erase_row)
    db.flush()
    user_id = str(actor.id) if getattr(actor, "id", None) is not None else None
    seal = w.append("request", detail=lambda seq, sealed_at: {
        "what": "erase", "request": str(request_id), "setting": None, "old": None, "new": None,
        "subject": subject.hex(), "placeholder": placeholder, "not_before": fmt.time_text(sealed_at + delay),
        "audit_row": str(row.id), "by": "admin", "user_id": user_id})
    erase_row.request_seq = seal.seq
    erase_row.effective_at = fmt.parse_time_text(seal.detail["not_before"])
    return entry_of(erase_row, view, extra_seal=seal)


def held_request(view, request_id) -> int:
    """The seq of the erase request the chain holds for ``request_id``. Raises LookupError when it holds none."""
    wanted = str(request_id)
    for seq, d in view.requests.items():
        if d.get("what") == "erase" and d.get("request") == wanted:
            return seq
    raise LookupError(request_id)


def ended_as(view, seq: int) -> str:
    if seq in view.cancels:
        return "cancelled"
    if seq in view.finals:
        return "completed"
    return "ended"


def cancel(w, request_id, actor) -> dict:
    """An administrator's cancel of an erase that has not begun, in ``w``'s transaction: the cancel seal, the row
    ended with its sealed name deleted, and the audit row. Raises LookupError (no such erase in the chain) and
    Refused (no longer waiting, or already running)."""
    from app.core.models import EraseRequest
    view = w.st.view
    seq = held_request(view, request_id)
    if seq not in view.pending_requests():
        raise Refused(f"This erase is no longer waiting: it was {ended_as(view, seq)}.")
    if seq in view.erase_through:
        raise Refused("This erase has begun: it completes, and cannot be cancelled now.")
    row = w.db.get(EraseRequest, fmt.as_uuid(request_id))
    audit = _end_row(w.db, row, request_id, view.requests[seq].get("placeholder"), actor, w.st.clock())
    user_id = str(actor.id) if getattr(actor, "id", None) is not None else None
    w.append("cancel", detail={"cancels": seq, "request": str(request_id), "audit_row": str(audit.id), "by": "admin",
                               "user_id": user_id})
    return entry_of(row, w.st.view) if row is not None else {"id": str(request_id), "status": CANCELLED}


def _end_row(db, row, request_id, placeholder, actor, now):
    from app.services.audit_logger import AuditLogger
    if row is not None:
        row.status = CANCELLED
        # The sealed name goes with the cancel; while a registered rule holds deletions back (a legal hold, an open
        # case) it stays, sealed, until the erase job deletes it once nothing does (sweep_names).
        if rule_waits(db, now) is None:
            row.name_token = None
        row.decided_by = getattr(actor, "id", None)
        row.decided_by_name = getattr(actor, "username", None)
        row.decided_at = now
        row.waiting = None
    audit = AuditLogger(db).build_row(
        action="person_erase_cancelled", status="success", user=actor, resource_type=RESOURCE_TYPE,
        resource_id=str(request_id), details={"request_id": str(request_id), "placeholder": placeholder})
    db.add(audit)
    return audit


def cancel_while_stopped(db, request_id, actor, st=None) -> dict:
    """A cancel while sealing is stopped, in ``db``'s transaction: the erase must be one this process's view holds
    waiting and not begun; its row is ended and its sealed name deleted (so it can never run), and the next pass
    seals the cancel from the database. Raises LookupError and Refused as cancel() does."""
    from app.core.models import EraseRequest
    st = st or _ai().state()
    view = st.view
    seq = held_request(view, request_id)
    if seq not in view.pending_requests():
        raise Refused(f"This erase is no longer waiting: it was {ended_as(view, seq)}.")
    if seq in view.erase_through:
        raise Refused("This erase has begun: it completes, and cannot be cancelled now.")
    row = db.get(EraseRequest, fmt.as_uuid(request_id))
    _end_row(db, row, request_id, view.requests[seq].get("placeholder"), actor, st.clock())
    return entry_of(row, view) if row is not None else {"id": str(request_id), "status": CANCELLED}


def sweep_names(db, view, now: datetime) -> int:
    """Delete the sealed name of every erase the chain holds as ended (cancelled or completed) whose row still keeps
    it, once no registered rule holds deletions back; in ``db``'s transaction (the caller commits). Returns how many.
    A row the chain holds no request of, or one it still holds waiting, keeps its name."""
    from app.core.models import EraseRequest
    rows = db.query(EraseRequest).filter(EraseRequest.name_token.isnot(None),
                                         EraseRequest.status.in_((CANCELLED, COMPLETED))).all()
    if not rows or rule_waits(db, now) is not None:
        return 0
    pending = view.pending_requests()
    gone = 0
    for row in rows:
        try:
            seq = held_request(view, row.id)
        except LookupError:
            continue
        if seq not in pending:
            row.name_token = None
            gone += 1
    return gone


def _iso(v) -> Optional[str]:
    return v.isoformat() + "Z" if v else None


def entry_of(row, view, extra_seal=None) -> dict:
    """An erase as the page lists it: its state from the chain (pending, running, completed, cancelled), the row's
    copies beside it. Never the name."""
    seq = None
    if extra_seal is not None:
        seq = extra_seal.seq
    elif row is not None:
        try:
            seq = held_request(view, row.id)
        except LookupError:
            seq = None
    if seq is None:
        status = "not recorded"
    elif seq in view.cancels:
        status = CANCELLED
    elif seq in view.finals:
        status = COMPLETED
    elif seq in view.erase_through:
        status = RUNNING
    else:
        status = PENDING
    if status == PENDING and row is not None and row.status == CANCELLED:
        # Cancelled in the database (its name is gone, so it can never run): the chain records the cancel with
        # this transaction's seal, or from the database once sealing runs again.
        status = CANCELLED
    chain = (view.requests.get(seq) or {}) if seq is not None else {}
    if extra_seal is not None:
        chain = extra_seal.detail
    return {
        "id": str(row.id) if row is not None else None,
        "status": status,
        "request_seq": seq,
        "placeholder": chain.get("placeholder") or (row.placeholder if row is not None else None),
        "requested_by": row.requested_by_name if row is not None else None,
        "requested_at": _iso(row.requested_at) if row is not None else None,
        "effective_at": chain.get("not_before") or (_iso(row.effective_at) if row is not None else None),
        "started_at": _iso(row.started_at) if row is not None else None,
        "through": view.erase_through.get(seq) if seq is not None else None,
        "completed_at": _iso(row.completed_at) if row is not None else None,
        "decided_by": row.decided_by_name if row is not None else None,
        "decided_at": _iso(row.decided_at) if row is not None else None,
        "waiting": row.waiting if row is not None and status in (PENDING, RUNNING) else None,
        "counts": row.counts if row is not None else None,
        "cancellable": status == PENDING,
    }


def listing(db, st=None) -> list:
    """Every erase, newest first, as the chain holds it; a row the chain holds no request of says so, or, while
    this process has not read the chain through (ChainState.view_read), that it is not known yet (UNREAD)."""
    from app.core.models import EraseRequest
    st = st or _ai().state()
    rows = db.query(EraseRequest).order_by(EraseRequest.requested_at.desc()).limit(200).all()
    out = [entry_of(r, st.view) for r in rows]
    if not st.view_read:
        for entry in out:
            if entry["status"] == "not recorded":
                entry["status"] = UNREAD
    return out


# --------------------------------------------------------------------------- telling the administrators

NOTICE_TYPE = "retention_change"
EMAIL_ACTION = "retention_change"


def _date(text) -> str:
    try:
        when = fmt.parse_time_text(text) if isinstance(text, str) else text
        return when.strftime("%d %B %Y, %H:%M UTC").lstrip("0")
    except Exception:  # noqa: BLE001
        return str(text or "")


def notice_words(event: str, facts: dict, by: Optional[str] = None) -> tuple:
    """(title, body) of the notice every administrator gets. Names the placeholder, never the name."""
    by = by or "An administrator"
    ph = facts.get("placeholder") or "a placeholder"
    if event == "asked":
        return ("An erase of a person's records is waiting",
                f"{by} asked to erase a person's name from the audit log and the other records; it will read "
                f"{ph} there. It runs on {_date(facts.get('effective_at'))} unless an administrator cancels it "
                "on the Settings page.")
    if event == "cancelled":
        return ("A waiting erase was cancelled", f"{by} cancelled the erase that would have written {ph}. Nothing "
                                                 "changes.")
    return ("An erase of a person's records is complete",
            f"The erase {ph} is complete: {facts.get('audit_rows', 0)} audit rows and "
            f"{facts.get('other_rows', 0)} other records now read {ph}.")


def tell_administrators(event: str, facts: dict, by: Optional[str] = None) -> None:
    """Tell every active administrator, in the app and by email, after the commit. Never raises."""
    try:
        from app.api import api_server as api
        from app.core.database import get_db_context
        from app.core.models import RoleEnum, User
        title, body = notice_words(event, facts, by)
        with get_db_context() as db:
            admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
            recipients = [(a.email, a.username) for a in admins]
            api._notify_users([str(a.id) for a in admins], NOTICE_TYPE, title=title, body=body, target="#settings")
            api._fire_action_email_bulk(db, EMAIL_ACTION, recipients,
                                        {"change": body, "by": by or "", "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001
        registry._say(f"Warning: the administrators were not told of an erase ({type(exc).__name__})")


def _load_wait_modules() -> None:
    import importlib
    for name in WAIT_MODULES:
        importlib.import_module(name)


_load_wait_modules()
