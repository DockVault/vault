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
      help="Off keeps every registered passkey but accepts none: an account whose only second factor is a "
           "passkey sets an authenticator app up at its next sign-in, and its passkeys count again when passkeys "
           "are turned back on. Optional lets people add one. Required for roles makes the roles below set one "
           "up, after a grace period.")
_spec(REQUIRED_ROLES, "list", [], "Roles that must have a passkey", choices=ROLES, level=registry.ADVANCED,
      help="Applies with the mode 'required for roles'. No save-time check can know whether every person's "
           "browser can make a passkey: the grace period and the host tool are the safety net.")
_spec(GRACE_DAYS, "int", 14, "Days to set a required passkey up", minimum=1, maximum=90, unit="days",
      level=registry.ADVANCED,
      help="From the first sign-in under the requirement; the person is warned with the date until then.")
_spec(SIGN_IN_ROLES, "list", ["user", "external"], "Roles a passkey signs in alone", choices=SIGN_IN_CHOICES,
      help="A user-verified passkey is the whole sign-in for these roles. Administrators always type their "
           "password after a passkey; other roles not listed do too. Only a discoverable passkey (one the device or "
           "key keeps with the account) signs in alone; one the browser reported as not discoverable when it was "
           "added is asked for the password too, and still serves as the second factor after it.")
_spec(REQUIRE_UV, "bool", True, "The authenticator must verify the person",
      help="Off, a passkey that did not check a PIN, fingerprint or face is one possession factor: the "
           "password always follows it, and it never counts for a compliance step-up. Turned on again, a passkey "
           "that was added while it was off and has never checked one is refused at every use and no longer "
           "counts: an account left with only such passkeys sets a second factor up again at its next sign-in.")
_spec(ALLOWED_ALGS, "list", ["ES256", "RS256", "EdDSA"], "Signature algorithms", choices=tuple(ALG_CODES),
      level=registry.ADVANCED,
      validate=lambda v: f"{ALLOWED_ALGS} needs at least one algorithm" if not v else None,
      help="Removing one leaves existing keys of it usable for 30 days. Their owners are told when it is removed, "
           "and again when they use such a key; their list of passkeys shows the date.")
_spec(ATTESTATION, "enum", NONE, "Attestation", choices=(NONE, DIRECT), level=registry.ADVANCED,
      help="Direct asks the authenticator to prove its make, checked against the trust anchors in "
           "WEBAUTHN_ATTESTATION_ROOTS; without anchors it cannot be turned on. It applies to passkeys added from "
           "then on: one added earlier keeps signing in, and no longer proves a compliance step-up.")
_spec(ALLOWED_AAGUIDS, "list", [], "Allowed authenticator makes", level=registry.ADVANCED, validate=_uuids,
      help="Authenticator identifiers (AAGUIDs); only with direct attestation, which alone proves them. A "
           "passkey of a make not on the list is not added; one added earlier keeps signing in, and no longer "
           "proves a compliance step-up. While attestation is not direct the list is kept and applies to "
           "nothing.")
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


def canonical_aaguid(value) -> Optional[str]:
    """An authenticator make as its UUID in the one spelling the vault compares (lower case, with dashes), or
    None for what is no UUID. The save takes every spelling a UUID is read in (32 hex digits as some tools print
    it, braces, urn:uuid:), and the makes of the keys are compared as text: a make saved in another spelling
    matched no authenticator, so every registration of it was refused and its keys stopped proving compliance
    step-ups, while the save had reported success."""
    try:
        return str(uuid.UUID(str(value).strip()))
    except (ValueError, TypeError, AttributeError):
        return None


def allowed_aaguids() -> Tuple[str, ...]:
    """The makes of authenticator the setting allows, each in the one spelling they are compared in and once."""
    makes = (canonical_aaguid(a) for a in (registry.resolve(ALLOWED_AAGUIDS) or ()))
    return tuple(dict.fromkeys(make for make in makes if make))


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


def address_now() -> str:
    """The relying-party id a passkey is made for at the vault's address as it is now: the address's host name.
    "" when no passkey can be made or used there (no address, one sign-in cannot be built on, an IP address)."""
    from app.services import webauthn_service as ws
    rp = ws.relying_party("")
    return rp.rp_id if rp is not None else ""


def at_this_address(key, here: Optional[str] = None) -> bool:
    """Whether ``key`` can be offered at the vault's address as it is now. A passkey is bound to the host name it
    was made at: after the vault moves to another name, the browser has no key to give for the new one, and the
    old ones answer again only if the name goes back. A key with no address recorded (a row from before it was)
    is taken as made here."""
    here = address_now() if here is None else here
    made_at = getattr(key, "rp_id", None)
    return bool(here) and (made_at is None or made_at == here)


def fill_the_addresses_not_recorded(db) -> int:
    """Write the address the vault has now on every passkey that has none on record, in the caller's transaction;
    returns how many. Run at start. No released database holds such a key (the column came with the table), so
    this is for a table an earlier build of this release made: the keys in it were made at the address the vault
    had then, which is taken to be the one it has at this start. Nothing while the vault has no address a passkey
    can be made at."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    here = address_now()
    if not here or not has_table(db, WebAuthnCredential.__tablename__):
        return 0
    return int(db.query(WebAuthnCredential).filter(WebAuthnCredential.rp_id.is_(None)).update(
        {WebAuthnCredential.rp_id: here}, synchronize_session=False) or 0)


def verified_the_person(key, required: Optional[bool] = None) -> bool:
    """Whether ``key`` can meet the rule that the authenticator verify the person (a PIN, a fingerprint, a face):
    the rule is off, or the key has verified the person, when it was added or at a use since. While the rule is
    on, every use of a key asks for the verification, and a key that never gave it (one that cannot, or one whose
    owner never set its PIN) is refused each time: it is no factor the account can give, as a key of a removed
    algorithm is none. It counts again by itself when it verifies the person at a use (its owner set a PIN and
    signed in with it), or when the rule is turned off. ``required`` reads the rule as it would be after a
    save."""
    required = require_uv() if required is None else bool(required)
    return not required or bool(getattr(key, "uv_initialized", False))


def never_verified(db) -> dict:
    """The passkeys in use that never verified the person, for the Sign-in page and for telling their owners:
    ``{"passkeys": how many, "owners": [account ids], "accounts_with_no_other": how many of those accounts hold
    no passkey that did}``. With the rule on these are the keys that no longer count; with it off, the ones that
    would stop counting if it were turned on."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return {"passkeys": 0, "owners": [], "accounts_with_no_other": 0}
    in_use = db.query(WebAuthnCredential).filter(WebAuthnCredential.retired_at.is_(None)).all()
    never = [key.user_id for key in in_use if not getattr(key, "uv_initialized", False)]
    did = {key.user_id for key in in_use if getattr(key, "uv_initialized", False)}
    owners = list(dict.fromkeys(never))
    return {"passkeys": len(never), "owners": owners,
            "accounts_with_no_other": sum(1 for owner in owners if owner not in did)}


def made_at_another_address(db) -> dict:
    """The passkeys in use that were made at another address than the vault has now: ``{"passkeys": how many,
    "accounts": of how many accounts}``. Read at start, for the line that tells the operator who changed the
    vault's host name what it did to the passkeys there are. A key with no address on record is taken as made
    here; while the vault has no address a passkey can be made at, every key is one made elsewhere."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return {"passkeys": 0, "accounts": 0}
    here = address_now()
    elsewhere = [key.user_id for key in db.query(WebAuthnCredential).filter(
        WebAuthnCredential.retired_at.is_(None)).all() if not at_this_address(key, here)]
    return {"passkeys": len(elsewhere), "accounts": len(set(elsewhere))}


def made_at_another_address_line(elsewhere: dict) -> Optional[str]:
    """What the start says of :func:`made_at_another_address`, or None when there is nothing to say: no such key,
    or passkeys turned off (none is used at any address then)."""
    keys, accounts = int(elsewhere.get("passkeys") or 0), int(elsewhere.get("accounts") or 0)
    if keys <= 0 or not enabled():
        return None
    return ("Passkeys: %d passkey%s of %d account%s %s made at another address than the vault has now and cannot "
            "be used here. An account left with no other second factor sets one up again at its next sign-in. "
            "They work again if the address goes back; 'python dockvault.py status' on the host says where they "
            "were made." % (keys, "" if keys == 1 else "s", accounts, "" if accounts == 1 else "s",
                            "was" if keys == 1 else "were"))


def usable_passkeys(db, user_id, *, without=None, now: Optional[datetime] = None,
                    whatever_the_switch: bool = False, verification: Optional[bool] = None) -> int:
    """How many passkeys of the account can still be used: not retired, made at the address the vault has now
    (:func:`at_this_address`), of an algorithm that is allowed now or was removed less than 30 days ago
    (:func:`algorithm_usable`), and able to meet the rule that the authenticator verify the person
    (:func:`verified_the_person`). A key of an algorithm an administrator removed is refused at every use once its
    30 days are over, a key made at another address is never offered by the browser, and a key that never
    verified the person is refused at every use while the vault asks for that: each is on the account in name
    only, is no second factor, and does not meet a role's requirement. ``without`` leaves one key out (the one
    about to be removed). With passkeys turned off none is a factor; ``whatever_the_switch`` counts them all the
    same, for the one who asks what a removal leaves (the switch is the deployment's and may be turned back on).
    ``verification`` reads the rule as it would be after a save."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if (not whatever_the_switch and not enabled()) or not has_table(db, WebAuthnCredential.__tablename__):
        return 0
    now = now or datetime.utcnow()
    keys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_id,
                                               WebAuthnCredential.retired_at.is_(None)).all()
    here = address_now()
    return sum(1 for key in keys
               if getattr(key, "id", None) != without
               and why_a_key_is_no_factor(db, key, now=now, here=here, verification=verification) is None)


PASSKEYS_AT_ANOTHER_ADDRESS = "passkeys_at_another_address"
PASSKEYS_NO_LONGER_ACCEPTED = "passkeys_no_longer_accepted"
PASSKEYS_WITHOUT_VERIFICATION = "passkeys_without_verification"
PASSKEYS_TURNED_OFF = "passkeys_turned_off"


def why_a_key_is_no_factor(db, key, *, now: Optional[datetime] = None, here: Optional[str] = None,
                           verification: Optional[bool] = None, accepted: Optional[dict] = None) -> Optional[str]:
    """Why ``key`` (one that was not retired) is no factor the account can give at the address ``here`` (the
    vault's as it is now, when not given), or None when it is one. The one rule for a single key, read by
    everything that counts keys or shows one: ``passkeys_at_another_address`` (:func:`at_this_address`),
    ``passkeys_no_longer_accepted`` (its algorithm was removed and its 30 days are over: :func:`algorithm_usable`),
    ``passkeys_without_verification`` (:func:`verified_the_person`), in that order, which is the order
    :func:`why_none_can_be_used` gives an account's reason in. The switch is not read here: turned off, no
    passkey is a factor whatever the key is, and the one who asks says so. ``accepted`` is a dict the caller keeps
    over many keys, so that each algorithm is looked up once."""
    if not at_this_address(key, address_now() if here is None else here):
        return PASSKEYS_AT_ANOTHER_ADDRESS
    algorithm = getattr(key, "cose_alg", None)
    if accepted is None:
        usable = algorithm_usable(db, algorithm, now=now)[0]
    else:
        if algorithm not in accepted:
            accepted[algorithm] = algorithm_usable(db, algorithm, now=now)[0]
        usable = accepted[algorithm]
    if not usable:
        return PASSKEYS_NO_LONGER_ACCEPTED
    if not verified_the_person(key, verification):
        return PASSKEYS_WITHOUT_VERIFICATION
    return None


def why_none_can_be_used(db, user_id, *, now: Optional[datetime] = None) -> Optional[str]:
    """For an account that holds passkeys of which none can be used: why. ``passkeys_at_another_address`` when
    none was made at the address the vault has now (the vault moved, or its address can carry no passkey);
    ``passkeys_no_longer_accepted`` when the ones made here are of an algorithm that was removed and has run out;
    ``passkeys_without_verification`` when the ones left never verified the person and the vault asks for that;
    ``passkeys_turned_off`` when passkeys are turned off here, whatever the keys are. None for an account that
    holds none, or one it can use."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return None
    now = now or datetime.utcnow()
    keys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_id,
                                               WebAuthnCredential.retired_at.is_(None)).all()
    if keys and not enabled():
        return PASSKEYS_TURNED_OFF
    here = address_now()
    made_here = [key for key in keys if at_this_address(key, here)]
    accepted = [key for key in made_here if algorithm_usable(db, getattr(key, "cose_alg", None), now=now)[0]]
    if not keys or any(verified_the_person(key) for key in accepted):
        return None
    if accepted:
        return PASSKEYS_WITHOUT_VERIFICATION
    return PASSKEYS_NO_LONGER_ACCEPTED if made_here else PASSKEYS_AT_ANOTHER_ADDRESS


def only_lapsed_passkeys(db, user_id, *, now: Optional[datetime] = None) -> bool:
    """Whether the account holds passkeys and none of them can be used now: each is of an algorithm an
    administrator removed more than 30 days ago, was made at another address than the vault has now, or never
    verified the person while the vault asks for that; or passkeys are turned off here. Its factor went away
    under it, by nobody's act on the account: it sets one up again at its next sign-in, as after a reset, and
    the keys count again by themselves if the algorithm, the address, the rule or the switch comes back. Turned
    off, passkeys are no factor by the deployment's choice; the account that had made one its second factor is
    not left with its password alone because of that choice. False for an account that holds none."""
    now = now or datetime.utcnow()
    return why_none_can_be_used(db, user_id, now=now) is not None


def only_a_passkey(db) -> dict:
    """The accounts whose only second factor is a passkey, for the Sign-in page and for telling them:
    ``{"accounts": how many, "administrators": how many of them are administrators, "owners": [account ids]}``.
    They hold a passkey that was not retired and no authenticator app in use. While passkeys are on these are the
    accounts that would set a factor up again if passkeys were turned off; while they are off, the ones that do."""
    from app.core.models import RoleEnum, SecondFactorEnrollment, User, WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return {"accounts": 0, "administrators": 0, "owners": []}
    holders = list(dict.fromkeys(
        key.user_id for key in db.query(WebAuthnCredential).filter(WebAuthnCredential.retired_at.is_(None)).all()))
    with_an_app = {row.user_id for row in db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.status == "active").all()}
    owners = [owner for owner in holders if owner not in with_an_app]
    administrators = {user.id for user in db.query(User).filter(User.role == RoleEnum.ADMIN).all()}
    return {"accounts": len(owners), "administrators": sum(1 for owner in owners if owner in administrators),
            "owners": owners}


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


# --------------------------------------------------------------------------- the requirement lifted for one account

# The server's operator may lift a role's requirement for one account (a person whose browser cannot make a
# passkey): ``passkey_requirement_cleared_at``. It is for that account as it stands: it ends when the account adds
# a passkey (it then meets the requirement like anyone) and when its role changes (what was lifted was that
# role's requirement; a user later made an administrator is not exempt from what administrators owe). The
# operator can put it back. The person and the administrators are told of each, and administrators see who is
# exempt on the Sign-in page and on the Users page.

def lifting_refusal(user) -> Optional[str]:
    """Why the requirement cannot be lifted for ``user`` now, in words, or None. Only a requirement that names
    the account's role is lifted: lifted for an account no requirement names, it would exempt the account from
    whatever is required later, unseen."""
    if getattr(user, "passkey_requirement_cleared_at", None) is not None:
        return "The passkey requirement is already lifted for this account."
    if mode() != REQUIRED_FOR_ROLES or role_name(user) not in required_roles():
        return ("This account's role is not required to hold a passkey: there is nothing to lift. (Settings, "
                "Sign-in names the roles that are.)")
    return None


def lift_requirement(user, *, now: Optional[datetime] = None) -> None:
    """Lift the role's requirement for ``user``, in the caller's transaction."""
    user.passkey_requirement_cleared_at = now or datetime.utcnow()


def end_lifting(user) -> bool:
    """The requirement applies to ``user`` again, in the caller's transaction; whether anything changed."""
    if getattr(user, "passkey_requirement_cleared_at", None) is None:
        return False
    user.passkey_requirement_cleared_at = None
    return True


def lifted_for(db, limit: int = 500) -> list:
    """The accounts a requirement was lifted for, for the Sign-in page: ``[{username, role, lifted_at}]`` by
    username, the first ``limit`` of them."""
    from app.core.models import User
    rows = db.query(User).filter(User.passkey_requirement_cleared_at.isnot(None)).all()
    rows = sorted(rows, key=lambda u: (u.username or "").lower())[:limit]
    return [{"username": u.username, "role": role_name(u),
             "lifted_at": u.passkey_requirement_cleared_at.isoformat() + "Z"} for u in rows]


LIFTED, PUT_BACK = "lifted", "put_back"


def tell_of_a_lifting(db, user, what: str, *, by: str) -> None:
    """Tell the person and every other active administrator that the requirement was lifted for the account, or
    put back. After the commit; best effort (it never undoes the change)."""
    try:
        from app.api import api_server as api
        from app.core.models import RoleEnum, User
        day = datetime.utcnow().date().isoformat()
        if what == LIFTED:
            mine = ("The passkey requirement was lifted for your account",
                    f"{by} lifted the requirement that your role hold a passkey, for your account. You sign in "
                    "without one. It applies again when you add a passkey or your role changes, or when it is "
                    "put back.")
            theirs = (f"The passkey requirement was lifted for {user.username}",
                      f"{by} lifted the requirement that the role {role_name(user)} hold a passkey, for "
                      f"{user.username}. It applies again when the account adds a passkey or its role changes, "
                      "or when the server's operator puts it back (dockvault.py accounts, "
                      "restore-passkey-requirement). Settings, Sign-in lists the accounts it is lifted for.")
        else:
            mine = ("The passkey requirement applies to your account again",
                    f"{by} put back the requirement that your role hold a passkey. You are given the usual time "
                    "to add one, from your next sign-in.")
            theirs = (f"The passkey requirement applies to {user.username} again",
                      f"{by} put back the requirement that the role {role_name(user)} hold a passkey, for "
                      f"{user.username}.")
        api._notify_users([str(user.id)], "security", title=mine[0], body=mine[1], target="#profile",
                          dedup_prefix=f"passkey_requirement_{what}:{day}")
        admins = [str(a.id) for a in db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
                  if a.id != user.id]
        if admins:
            api._notify_users(admins, "security", title=theirs[0], body=theirs[1], target="#settings",
                              dedup_prefix=f"passkey_requirement_{what}:{user.id}:{day}")
    except Exception as exc:  # noqa: BLE001 -- the change is made; nothing here may undo it
        import logging
        logging.getLogger(__name__).warning("a change of a passkey requirement was not told: %s", type(exc).__name__)


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


def algorithm_accepted_until(db, cose_alg: int, *, now: Optional[datetime] = None) -> Optional[datetime]:
    """Until when a stored key of this algorithm is still accepted: 30 days from the algorithm's removal, while
    those days run. None for an algorithm that is allowed (no end is set), and for one whose days are over or
    that was never allowed (the key is refused already)."""
    now = now or datetime.utcnow()
    if cose_alg in allowed_alg_codes():
        return None
    name = next((n for n, c in ALG_CODES.items() if c == cose_alg), None)
    removed_at = _removed(db).get(name) if name is not None else None
    try:
        removed = datetime.fromisoformat(removed_at) if removed_at else None
    except ValueError:
        removed = None
    if removed is None:
        return None
    until = removed + timedelta(days=ALG_GRACE_DAYS)
    return until if now < until else None


def owners_of_keys_of(db, alg_names) -> list:
    """The accounts that hold a passkey in use of one of ``alg_names``, each once: whom a removal of those
    algorithms concerns."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    codes = {ALG_CODES[name] for name in alg_names or () if name in ALG_CODES}
    if not codes or not has_table(db, WebAuthnCredential.__tablename__):
        return []
    held = db.query(WebAuthnCredential).filter(WebAuthnCredential.retired_at.is_(None)).all()
    return list(dict.fromkeys(key.user_id for key in held if getattr(key, "cose_alg", None) in codes))


# --------------------------------------------------------------------------- the guards at save

def asks_for_more(key: str, was, now) -> bool:
    """Whether a save that takes ``key`` from ``was`` to ``now`` asks for more than what is in force: a requirement
    turned on, a role added to it, a shorter time to meet it, the rule on verifying the person turned on, direct
    attestation turned on, an authenticator make added to the list. A save that asks for less, or for the same,
    is never held back by what the other settings need: it is the way out of a state they no longer fit (the
    file of root certificates gone, the vault's address changed)."""
    if key == MODE:
        return now == REQUIRED_FOR_ROLES and was != REQUIRED_FOR_ROLES
    if key in (REQUIRED_ROLES, ALLOWED_AAGUIDS):
        return bool(set(now or ()) - set(was or ()))
    if key == GRACE_DAYS:
        return int(now) < int(was)
    if key == REQUIRE_UV:
        return bool(now) and not bool(was)
    if key == ATTESTATION:
        return now == DIRECT and was != DIRECT
    return False


def save_refusal(db, key: str, value, *, settings_now: Optional[dict] = None) -> Optional[str]:
    """Why ``key`` may not be set to ``value`` now, beyond the spec's own bounds, in plain words, or None.
    ``settings_now`` may carry the other values as they would be after this save.

    What the settings need of each other (a requirement needs the vault's address, direct attestation needs its
    root certificates, a list of makes needs direct attestation, a requirement on administrators needs one who
    can meet it) is asked only of a save that asks for more than what is in force (:func:`asks_for_more`). Asked
    of every save, a state the settings no longer fit could not be left: with the root certificates gone, no
    passkey setting could be changed at all, turning passkeys off among them."""
    from app.core.public_url import readiness
    current = {k: registry.resolve(k) for k in KEYS}
    current.update(settings_now or {})
    proposed = dict(current)
    proposed[key] = value if value is not None else registry.spec_for(key).default
    if key == SIGN_IN_ROLES and value is not None and any(r not in SIGN_IN_CHOICES for r in value):
        return "Administrators always type their password after a passkey: 'admin' cannot be in this list."
    if not asks_for_more(key, current[key], proposed[key]):
        return None
    required = proposed[MODE] == REQUIRED_FOR_ROLES and bool(proposed[REQUIRED_ROLES])
    if key in (MODE, REQUIRED_ROLES) and required and not readiness().get("usable"):
        from app.core.public_url import why_no_passkeys
        return "Requiring passkeys needs the vault's public address. " + why_no_passkeys()
    if key in (ATTESTATION, ALLOWED_AAGUIDS) and proposed[ATTESTATION] == DIRECT and not trust_anchors():
        return ("Direct attestation needs trust anchors: put a PEM bundle of root certificates in the deployment's "
                "certs folder, set WEBAUTHN_ATTESTATION_ROOTS in .env to its path as the server sees it "
                "(/app/certs/<file name>), restart, and try again.")
    if key == ALLOWED_AAGUIDS and proposed[ATTESTATION] != DIRECT:
        return "A list of allowed authenticator makes proves nothing without direct attestation: turn that on first."
    on_administrators = required and "admin" in (proposed[REQUIRED_ROLES] or ())
    if key == REQUIRED_ROLES and "admin" in (current[REQUIRED_ROLES] or ()):
        on_administrators = False              # another role was added: nothing new is asked of administrators
    if key in (MODE, REQUIRED_ROLES, GRACE_DAYS, REQUIRE_UV) and on_administrators:
        why = _last_administrator_refusal(db, int(proposed[GRACE_DAYS]), verification=bool(proposed[REQUIRE_UV]))
        if why:
            return why
    return None


def _last_administrator_refusal(db, grace: int, *, verification: Optional[bool] = None) -> Optional[str]:
    """Refuse a requirement on administrators that would leave none able to sign in: every administrator who can
    act (active, not locked) holds no passkey that can be used (:func:`usable_passkeys`: made at the address the
    vault has now, of an algorithm that still signs in, able to verify the person where the vault asks for it),
    has no clearance, and has a grace that has already run out (or would, with the new grace). An administrator
    whose grace has not started yet is protected by the window; one who cannot sign in anyway protects nobody. A
    key made at another address is one the browser never offers here: it protects nobody either, as the
    requirement itself reads it. ``verification`` is the rule on verifying the person as it would be after the
    save: turning it on takes the keys that never did out of the count, so it is asked the same question."""
    from app.core import last_admin
    from app.core.models import RoleEnum, User
    now = datetime.utcnow()
    admins = [a for a in db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
              if last_admin.can_administer(a)]
    if not admins:
        return None
    for admin in admins:
        if getattr(admin, "passkey_requirement_cleared_at", None) is not None:
            return None
        if usable_passkeys(db, admin.id, now=now, whatever_the_switch=True, verification=verification) > 0:
            return None
        since = getattr(admin, "passkey_required_since", None)
        if since is None or now <= since + timedelta(days=grace):
            return None
    return ("This would leave no administrator able to sign in: none holds a passkey and every grace period has "
            "run out. Have an administrator register a passkey first, or lengthen the grace period.")
