"""The passkey settings: what an administrator tunes on Settings → Sign-in, and the rules that read them.

Registered in the settings registry (group ``webauthn``, page ``signin``, lockable by the deployment) so the
panel lists them with the value in force and ``SETTINGS_LOCKED_KEYS`` can name them; every write goes through
the sign-in settings routes under the fixed step-up ``admin.auth_policy.write``. The service's policy
(app/services/webauthn_service.PasskeyPolicy) is built from them here, so the routes never read a setting by
name.

    webauthn_mode                   off · optional · required_for_roles
    webauthn_required_roles         roles whose accounts must hold a passkey (after a grace window)
    webauthn_enrollment_grace_days  how long such an account may still sign in without one
    webauthn_sign_in                roles a user-verified passkey signs in alone (never admin)
    webauthn_require_uv             the authenticator must verify the person (a PIN, a fingerprint, a face)
    webauthn_allowed_algs           signature algorithms; a removed one keeps existing keys usable for 30 days
    webauthn_attestation            none · direct (direct only with trust anchors, WEBAUTHN_ATTESTATION_ROOTS)
    webauthn_allowed_aaguids        authenticator makes, by their identifier; only with direct attestation
    webauthn_device_bound_roles     roles whose passkeys must be bound to one device (no synced passkey)

The requirement's grace window starts the first time it applies to an account (``users.passkey_required_since``);
the server's operator can clear the requirement for one account from the host (``passkey_requirement_cleared_at``),
the break-glass for a person whose browser cannot make a passkey. Turning the mode ``off`` keeps every row.

A requirement waits while no passkey can be made at the vault's address (none configured, plain http, an address
reached by IP): nobody is held at the sign-in for a passkey there is no way to make, and the grace starts over
once one can be made again. The page and the host tool say that it waits.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple

from app.core import settings_registry as registry

GROUP = "webauthn"
PAGE = "signin"                 # the Settings section's slot for how people sign in
SINCE = "0.36.0"
STEP_UP_ACTION = "admin.auth_policy.write"

MODE = "webauthn_mode"
REQUIRED_ROLES = "webauthn_required_roles"
GRACE_DAYS = "webauthn_enrollment_grace_days"
SIGN_IN_ROLES = "webauthn_sign_in"
REQUIRE_UV = "webauthn_require_uv"
ALLOWED_ALGS = "webauthn_allowed_algs"
ATTESTATION = "webauthn_attestation"
ALLOWED_AAGUIDS = "webauthn_allowed_aaguids"
DEVICE_BOUND_ROLES = "webauthn_device_bound_roles"
KEYS = (MODE, REQUIRED_ROLES, GRACE_DAYS, SIGN_IN_ROLES, REQUIRE_UV, ALLOWED_ALGS, ATTESTATION, ALLOWED_AAGUIDS,
        DEVICE_BOUND_ROLES)

OFF, OPTIONAL, REQUIRED_FOR_ROLES = "off", "optional", "required_for_roles"
NONE, DIRECT = "none", "direct"
ROLES = ("user", "external", "admin")
SIGN_IN_CHOICES = ("user", "external")           # an administrator always adds the password
ALG_CODES = {"ES256": -7, "RS256": -257, "EdDSA": -8}
ALG_GRACE_DAYS = 30
# The settings-store row that remembers when an algorithm left the allowed list ({"RS256": "<iso>"}).
ALG_REMOVED_KEY = "webauthn_alg_removed"


def _uuids(value) -> Optional[str]:
    for item in value or []:
        try:
            uuid.UUID(str(item))
        except (ValueError, TypeError, AttributeError):
            return f"{ALLOWED_AAGUIDS}: {item!r} is not an authenticator identifier (a UUID)"
    return None


def _spec(key: str, kind: str, default, label: str, help: str = "", level: str = registry.ESSENTIAL, **kw):
    return registry.register(registry.SettingSpec(
        key=key, kind=kind, default=default, editable=registry.ADMIN, lockable=True, group=GROUP, label=label,
        help=help, since=SINCE, level=level, page=PAGE, **kw))


_spec(MODE, "enum", OPTIONAL, "Passkeys", choices=(OFF, OPTIONAL, REQUIRED_FOR_ROLES),
      help="Off keeps every registered passkey but accepts none. Optional lets people add one. Required for "
           "roles makes the roles below set one up, after a grace period.")
_spec(REQUIRED_ROLES, "list", [], "Roles that must have a passkey", choices=ROLES, level=registry.ADVANCED,
      help="Applies with the mode 'required for roles'. No save-time check can know whether every person's "
           "browser can make a passkey: the grace period and the host tool are the safety net.")
_spec(GRACE_DAYS, "int", 14, "Days to set a required passkey up", minimum=1, maximum=90, unit="days",
      level=registry.ADVANCED,
      help="From the first sign-in under the requirement; the person is warned with the date until then.")
_spec(SIGN_IN_ROLES, "list", ["user", "external"], "Roles a passkey signs in alone", choices=SIGN_IN_CHOICES,
      help="A user-verified passkey is the whole sign-in for these roles. Administrators always type their "
           "password after a passkey; other roles not listed do too. Only a discoverable passkey (one the device or "
           "key keeps with the account) signs in alone; one that is not still serves as the second factor after the "
           "password.")
_spec(REQUIRE_UV, "bool", True, "The authenticator must verify the person",
      help="Off, a passkey that did not check a PIN, fingerprint or face is one possession factor: the "
           "password always follows it, and it never counts for a compliance step-up.")
_spec(ALLOWED_ALGS, "list", ["ES256", "RS256", "EdDSA"], "Signature algorithms", choices=tuple(ALG_CODES),
      level=registry.ADVANCED,
      validate=lambda v: f"{ALLOWED_ALGS} needs at least one algorithm" if not v else None,
      help="Removing one leaves existing keys of it usable for 30 days, with a notice to their owners.")
_spec(ATTESTATION, "enum", NONE, "Attestation", choices=(NONE, DIRECT), level=registry.ADVANCED,
      help="Direct asks the authenticator to prove its make, checked against the trust anchors in "
           "WEBAUTHN_ATTESTATION_ROOTS; without anchors it cannot be turned on. It applies to passkeys added from "
           "then on: one added earlier keeps signing in, and no longer proves a compliance step-up.")
_spec(ALLOWED_AAGUIDS, "list", [], "Allowed authenticator makes", level=registry.ADVANCED, validate=_uuids,
      help="Authenticator identifiers (AAGUIDs); only with direct attestation, which alone proves them. A "
           "passkey of a make not on the list is not added; one added earlier keeps signing in, and no longer "
           "proves a compliance step-up.")
_spec(DEVICE_BOUND_ROLES, "list", [], "Roles whose passkeys must be device-bound", choices=ROLES,
      level=registry.ADVANCED,
      help="A synced passkey (one copied between devices) is refused for these roles at registration and in "
           "a compliance step-up. Without direct attestation the authenticator's own word is taken for whether "
           "it is synced.")


# --------------------------------------------------------------------------- the values in force

def mode() -> str:
    return registry.resolve(MODE)


def enabled() -> bool:
    return mode() != OFF


def required_roles() -> Tuple[str, ...]:
    return tuple(registry.resolve(REQUIRED_ROLES) or ())


def grace_days() -> int:
    return int(registry.resolve(GRACE_DAYS))


def sign_in_roles() -> Tuple[str, ...]:
    return tuple(r for r in (registry.resolve(SIGN_IN_ROLES) or ()) if r in SIGN_IN_CHOICES)


def require_uv() -> bool:
    return bool(registry.resolve(REQUIRE_UV))


def allowed_alg_names() -> Tuple[str, ...]:
    return tuple(a for a in (registry.resolve(ALLOWED_ALGS) or ()) if a in ALG_CODES) or ("ES256",)


def allowed_alg_codes() -> Tuple[int, ...]:
    return tuple(ALG_CODES[a] for a in allowed_alg_names())


def attestation() -> str:
    return registry.resolve(ATTESTATION)


def allowed_aaguids() -> Tuple[str, ...]:
    return tuple(str(a) for a in (registry.resolve(ALLOWED_AAGUIDS) or ()))


def device_bound_roles() -> Tuple[str, ...]:
    return tuple(registry.resolve(DEVICE_BOUND_ROLES) or ())


def role_name(user) -> str:
    role = getattr(user, "role", None)
    return getattr(role, "value", role) or ""


def device_bound_for(user) -> bool:
    return role_name(user) in device_bound_roles()


# --------------------------------------------------------------------------- trust anchors (direct attestation)

_anchors_cache: dict = {"path": None, "mtime": None, "anchors": ()}


def trust_anchors() -> Tuple[bytes, ...]:
    """The operator's root certificates for direct attestation, DER, from the PEM bundle named by
    WEBAUTHN_ATTESTATION_ROOTS; empty without one (direct attestation is then refused at save)."""
    from app.core.config import settings
    path = (getattr(settings, "webauthn_attestation_roots", "") or "").strip()
    if not path:
        return ()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return ()
    if _anchors_cache["path"] == path and _anchors_cache["mtime"] == mtime:
        return _anchors_cache["anchors"]
    anchors = []
    try:
        from cryptography import x509
        with open(path, "rb") as handle:
            for cert in x509.load_pem_x509_certificates(handle.read()):
                from cryptography.hazmat.primitives import serialization
                anchors.append(cert.public_bytes(serialization.Encoding.DER))
    except Exception:  # noqa: BLE001 -- an unreadable bundle is no anchors, never a crash at sign-in
        anchors = []
    _anchors_cache.update(path=path, mtime=mtime, anchors=tuple(anchors))
    return _anchors_cache["anchors"]


def policy():
    """The service's policy from the settings in force."""
    from app.services.webauthn_service import PasskeyPolicy
    direct = attestation() == DIRECT
    anchors = trust_anchors() if direct else ()
    # Direct attestation stays direct when the anchors cannot be read (the file gone or garbage after the save): the
    # service then refuses every registration (attestation_unverifiable) rather than taking keys unverified.
    return PasskeyPolicy(require_uv=require_uv(), allowed_algs=allowed_alg_codes(),
                         attestation=DIRECT if direct else NONE,
                         allowed_aaguids=allowed_aaguids() if direct else (), trust_anchors=anchors)


def unattested_count(db) -> Optional[int]:
    """How many passkeys in use were added without direct attestation, while the vault asks for it; None while it
    does not (the number would say nothing). The Sign-in page shows it: those keys keep signing in and prove no
    compliance step-up until their owners add them again."""
    if attestation() != DIRECT:
        return None
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return 0
    return db.query(WebAuthnCredential.id).filter(WebAuthnCredential.retired_at.is_(None),
                                                  WebAuthnCredential.attested.is_(False)).count()


# --------------------------------------------------------------------------- the requirement and its grace

@dataclass(frozen=True)
class Requirement:
    required: bool                      # the role must hold a passkey and the account holds none
    since: Optional[datetime] = None    # when the requirement first applied to this account
    due: Optional[datetime] = None      # when the grace ends
    overdue: bool = False               # the grace ended: the sign-in stops at the enrollment
    cleared: bool = False               # the host operator cleared it for this account
    paused: bool = False                # the role must hold one, and none can be made at the vault's address now


def requirement(db, user, *, now: Optional[datetime] = None) -> Requirement:
    """Whether ``user`` must set a passkey up, and where its grace stands. A cleared account is never required;
    an account holding a passkey is not; ``since`` is read from the account (``mark_required`` sets it)."""
    from app.core.active_factors import active_factors
    now = now or datetime.utcnow()
    cleared = getattr(user, "passkey_requirement_cleared_at", None) is not None
    if cleared:
        return Requirement(False, cleared=True)
    if mode() != REQUIRED_FOR_ROLES or role_name(user) not in required_roles():
        return Requirement(False)
    if usable_passkeys(db, user.id, now=now) > 0:
        return Requirement(False)
    if not passkeys_can_be_made():
        # The address changed under the requirement (emptied, plain http, an IP put first): it waits. An account is
        # never shut out by a rule it has no way to meet; the guard at save could not know.
        return Requirement(False, paused=True)
    since = getattr(user, "passkey_required_since", None)
    due = since + timedelta(days=grace_days()) if since is not None else None
    return Requirement(True, since=since, due=due, overdue=bool(due is not None and now > due))


def usable_passkeys(db, user_id, *, without=None, now: Optional[datetime] = None) -> int:
    """How many passkeys of the account can still be used: not retired, and of an algorithm that is allowed now or
    was removed less than 30 days ago (:func:`algorithm_usable`). A key of an algorithm an administrator removed
    is refused at every use once its 30 days are over; it is on the account in name only, and a role's requirement
    is not met by it. ``without`` leaves one key out (the one about to be removed)."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not enabled() or not has_table(db, WebAuthnCredential.__tablename__):
        return 0
    now = now or datetime.utcnow()
    keys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_id,
                                               WebAuthnCredential.retired_at.is_(None)).all()
    return sum(1 for key in keys
               if getattr(key, "id", None) != without and algorithm_usable(db, getattr(key, "cose_alg", None), now=now)[0])


def only_lapsed_passkeys(db, user_id, *, now: Optional[datetime] = None) -> bool:
    """Whether the account holds passkeys and none of them can be used any more: each is of an algorithm an
    administrator removed more than 30 days ago. Its factor went away under it, by nobody's act on the account.
    False with passkeys turned off (none is a factor then, by the deployment's choice), and for an account that
    holds none."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not enabled() or not has_table(db, WebAuthnCredential.__tablename__):
        return False
    now = now or datetime.utcnow()
    keys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_id,
                                               WebAuthnCredential.retired_at.is_(None)).all()
    return bool(keys) and not any(algorithm_usable(db, getattr(key, "cose_alg", None), now=now)[0] for key in keys)


# Run at every start. A reset of an account's second factor retires its passkeys; one made by a release that knew
# no passkeys (run for a while after going back to it) left them as they were, though the account's second factor
# was taken from it for a reason (a lost device, an account taken over). A passkey made before the reset the
# account has not answered yet is retired as of that reset; one made after it (its answer) is left. An account
# with no reset has no such moment: nothing is earlier than it, and nothing of that account is touched.
RETIRE_PASSKEYS_FROM_BEFORE_A_RESET = (
    "UPDATE webauthn_credentials SET retired_at = "
    "(SELECT u.second_factor_reset_at FROM users u WHERE u.id = webauthn_credentials.user_id) "
    "WHERE retired_at IS NULL AND created_at < "
    "(SELECT u.second_factor_reset_at FROM users u WHERE u.id = webauthn_credentials.user_id)"
)
# The same from the record of the reset. The mark above is gone once the account set a factor up again (the earlier
# release asks for that at the next sign-in), and was never set for an account whose only factor was a passkey
# (that release saw no factor on it). Every reset another administrator or the server's operator makes is also
# kept, with its time, among the changes to the account's sign-in details, on every release since 0.33.0, for
# the 14 days such a record is kept. A passkey made before the account's latest recorded reset is retired as of
# it. A reset made by this release retires the account's passkeys itself, so on its own data this finds nothing,
# but for a key registered in the very moment of a reset (made a moment before the reset's record, written a
# moment after the reset looked): that one is from before the reset, and is retired here at the next start. Only a
# change that was applied counts (made at once, or approved): a request that was never applied has no time today,
# and is left out by what it is as well, whatever a later release may write on such a row.
RETIRE_PASSKEYS_FROM_BEFORE_A_RECORDED_RESET = (
    "UPDATE webauthn_credentials SET retired_at = "
    "(SELECT max(c.applied_at) FROM credential_changes c "
    "WHERE c.target_user_id = webauthn_credentials.user_id AND c.kind = 'second_factor' "
    "AND c.status IN ('made', 'approved')) "
    "WHERE retired_at IS NULL AND created_at < "
    "(SELECT max(c.applied_at) FROM credential_changes c "
    "WHERE c.target_user_id = webauthn_credentials.user_id AND c.kind = 'second_factor' "
    "AND c.status IN ('made', 'approved'))"
)


def must_hold(user) -> bool:
    """Whether ``user``'s role must hold a passkey now, whatever the account holds: the requirement names its role,
    was not cleared for this account, and does not wait (a passkey can be made at the vault's address)."""
    if getattr(user, "passkey_requirement_cleared_at", None) is not None:
        return False
    if mode() != REQUIRED_FOR_ROLES or role_name(user) not in required_roles():
        return False
    return passkeys_can_be_made()


def passkeys_can_be_made() -> bool:
    """Whether a browser can make a passkey at the vault's address as it is configured now."""
    from app.core.public_url import readiness
    return bool(readiness().get("usable"))


def requirement_paused() -> bool:
    """Whether a requirement is set and waits: some role must hold a passkey, and none can be made here now."""
    return mode() == REQUIRED_FOR_ROLES and bool(required_roles()) and not passkeys_can_be_made()


def pause_grace(user) -> bool:
    """The grace does not run while the requirement waits: it starts over at the first sign-in after a passkey can
    be made again. Returns whether anything changed; the caller commits."""
    if getattr(user, "passkey_required_since", None) is None:
        return False
    user.passkey_required_since = None
    return True


def mark_required(user, *, now: Optional[datetime] = None) -> bool:
    """Start the grace for ``user`` when it has not started: the first sign-in under the requirement. Returns
    whether anything changed; the caller commits."""
    if getattr(user, "passkey_required_since", None) is not None:
        return False
    user.passkey_required_since = now or datetime.utcnow()
    return True


def requirement_public(req: Requirement) -> dict:
    def _t(value):
        return value.isoformat() + "Z" if value else None
    return {"required": req.required, "since": _t(req.since), "due": _t(req.due), "overdue": req.overdue,
            "cleared": req.cleared, "paused": req.paused}


# --------------------------------------------------------------------------- the 30-day algorithm grace

def _removed(db) -> dict:
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == ALG_REMOVED_KEY).first()
    try:
        data = json.loads(row.value) if row is not None and row.value else {}
    except (TypeError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def record_algorithm_change(db, old_names, new_names, *, now: Optional[datetime] = None) -> None:
    """Remember when an algorithm left the allowed list (and forget it when it returns), in the caller's
    transaction, so a key of that algorithm stays usable for ALG_GRACE_DAYS."""
    from app.core.models import SystemSetting
    now = now or datetime.utcnow()
    removed = _removed(db)
    for name in set(old_names or ()) - set(new_names or ()):
        removed[name] = now.isoformat()
    for name in set(new_names or ()):
        removed.pop(name, None)
    row = db.query(SystemSetting).filter(SystemSetting.key == ALG_REMOVED_KEY).first()
    if row is None:
        db.add(SystemSetting(key=ALG_REMOVED_KEY, value=json.dumps(removed)))
    else:
        row.value = json.dumps(removed)


def algorithm_usable(db, cose_alg: int, *, now: Optional[datetime] = None) -> Tuple[bool, bool]:
    """(usable, in_grace) for a stored key's algorithm: allowed now, or removed less than 30 days ago."""
    now = now or datetime.utcnow()
    if cose_alg in allowed_alg_codes():
        return True, False
    name = next((n for n, c in ALG_CODES.items() if c == cose_alg), None)
    if name is None:
        return False, False
    removed_at = _removed(db).get(name)
    try:
        removed = datetime.fromisoformat(removed_at) if removed_at else None
    except ValueError:
        removed = None
    if removed is None:
        return False, False
    in_grace = now - removed < timedelta(days=ALG_GRACE_DAYS)
    return in_grace, in_grace


# --------------------------------------------------------------------------- the guards at save

def save_refusal(db, key: str, value, *, settings_now: Optional[dict] = None) -> Optional[str]:
    """Why ``key`` may not be set to ``value`` now, beyond the spec's own bounds, in plain words, or None.
    ``settings_now`` may carry the other values as they would be after this save."""
    from app.core.public_url import readiness
    current = {k: registry.resolve(k) for k in KEYS}
    current.update(settings_now or {})
    proposed = dict(current)
    proposed[key] = value if value is not None else registry.spec_for(key).default
    if key == SIGN_IN_ROLES and value is not None and any(r not in SIGN_IN_CHOICES for r in value):
        return "Administrators always type their password after a passkey: 'admin' cannot be in this list."
    if (proposed[MODE] == REQUIRED_FOR_ROLES and proposed[REQUIRED_ROLES]) and not readiness().get("usable"):
        from app.core.public_url import why_no_passkeys
        return "Requiring passkeys needs the vault's public address. " + why_no_passkeys()
    if proposed[ATTESTATION] == DIRECT and not trust_anchors():
        return ("Direct attestation needs trust anchors: put a PEM bundle of root certificates in the deployment's "
                "certs folder, set WEBAUTHN_ATTESTATION_ROOTS in .env to its path as the server sees it "
                "(/app/certs/<file name>), restart, and try again.")
    if proposed[ALLOWED_AAGUIDS] and proposed[ATTESTATION] != DIRECT:
        return "A list of allowed authenticator makes proves nothing without direct attestation: turn that on first."
    if key in (MODE, REQUIRED_ROLES, GRACE_DAYS) and proposed[MODE] == REQUIRED_FOR_ROLES \
            and "admin" in (proposed[REQUIRED_ROLES] or ()):
        why = _last_administrator_refusal(db, int(proposed[GRACE_DAYS]))
        if why:
            return why
    return None


def _last_administrator_refusal(db, grace: int) -> Optional[str]:
    """Refuse a requirement on administrators that would leave none able to sign in: every administrator who can
    act (active, not locked) holds no passkey whose algorithm still signs in, has no clearance, and has a grace
    that has already run out (or would, with the new grace). An administrator whose grace has not started yet is
    protected by the window; one who cannot sign in anyway protects nobody."""
    from app.core import last_admin
    from app.core.models import RoleEnum, User, WebAuthnCredential
    now = datetime.utcnow()
    admins = [a for a in db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
              if last_admin.can_administer(a)]
    if not admins:
        return None
    for admin in admins:
        if getattr(admin, "passkey_requirement_cleared_at", None) is not None:
            return None
        keys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == admin.id,
                                                   WebAuthnCredential.retired_at.is_(None)).all()
        if any(algorithm_usable(db, getattr(k, "cose_alg", None), now=now)[0] for k in keys):
            return None
        since = getattr(admin, "passkey_required_since", None)
        if since is None or now <= since + timedelta(days=grace):
            return None
    return ("This would leave no administrator able to sign in: none holds a passkey and every grace period has "
            "run out. Have an administrator register a passkey first, or lengthen the grace period.")
