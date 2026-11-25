"""Where the stored mail relay password may go: one rule for every route that saves or tests a mail relay.

The SMTP password an administrator saves, with a sending profile (app/api/email_studio_router.py) or with the
older SMTP settings of the general settings (PUT /settings), is write-only: no page and no route returns it. A
request that keeps the stored password may therefore not change where it is sent:

    a request that changes the relay's server, port or username, or turns its certificate check off, and keeps
    a stored password, must carry the password itself. Without it the request is refused (REENTER_PASSWORD) and
    nothing is saved or sent.

A request that changes none of these keeps the stored password, as before. A relay with no stored password has
none to send, and one whose server is emptied sends nothing, so neither is asked. A request that replaces the
password, or removes it, keeps nothing that could be sent elsewhere.

Saving or testing a relay is also under the fixed step-up STEP_UP_ACTION (app/core/fixed_step_up.py): the
administrator's own password every time, and their second factor when they have one, whatever the step-up
matrix says. The routes record each refusal under REFUSED_ACTION, and each change they accept with the changes
this module names, so the audit log shows where a relay was pointed and by whom.

A save checks the rule twice: before its step-up, so a refused request spends none, and again after it, on the
stored relay it writes, locked until the save commits. Another save may have stored a password meanwhile; the
second check keeps it from being paired with this save's server. A save of the general settings confirmed as
leaving their SMTP settings alone, which another save changed meanwhile, is refused (CHANGED_MEANWHILE, 409).
A test send sends what it read, as it read it, and needs no second check.
"""
from typing import Mapping, NamedTuple, Union

STEP_UP_ACTION = "admin.mail_relay.write"

# The refusal a route answers (400), as the page shows it beside the password field.
REASON = "smtp_password_required"
REENTER_PASSWORD = ("Re-enter the SMTP password to use a different server, port or username, "
                    "or to stop checking the server's certificate.")

# A save of the general settings confirmed as leaving their SMTP settings alone that would change them, as another
# save left them meanwhile (409).
CHANGED_REASON = "smtp_settings_changed"
CHANGED_MEANWHILE = ("The mail server settings were changed while this save was being confirmed. "
                     "Load the settings again and save.")

# The audit row of a refused request.
REFUSED_ACTION = "mail_relay_change_refused"

DEFAULT_PORT = 587

# What the rule compares, under the names the stored settings and the audit rows use.
SERVER = "smtp_server"
PORT = "smtp_port"
USERNAME = "smtp_username"
INSECURE_TLS = "smtp_allow_insecure_tls"
PASSWORD = "smtp_password"
FIELDS = (SERVER, PORT, USERNAME, INSECURE_TLS)

_OFF = ("", "false", "0", "no", "off")


class Relay(NamedTuple):
    """Where a relay sends its password: compared field by field, never displayed."""
    server: str
    port: Union[int, str]
    username: str
    insecure_tls: bool


def _port(value) -> Union[int, str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_PORT
    if isinstance(value, bool):
        return str(value)
    try:
        return int(str(value).strip())
    except ValueError:
        # Not a port: kept as written, so it differs from every port and counts as a change.
        return str(value).strip()


def _flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in _OFF
    return bool(value)


def relay(server=None, port=None, username=None, insecure_tls=False) -> Relay:
    """The relay these values describe. A server's case and surrounding spaces, a username's surrounding spaces
    and a missing port (the default, 587) make no difference."""
    return Relay(server=str(server or "").strip().lower(), port=_port(port),
                 username=str(username or "").strip(), insecure_tls=_flag(insecure_tls))


def of(values: Mapping) -> Relay:
    """The relay a mapping under the settings' names (smtp_server, smtp_port, ...) describes."""
    values = values or {}
    return relay(values.get(SERVER), values.get(PORT), values.get(USERNAME), values.get(INSECURE_TLS))


def of_profile(profile) -> Relay:
    """The relay a stored sending profile describes."""
    return relay(profile.smtp_server, profile.smtp_port, profile.smtp_username,
                 bool(getattr(profile, "smtp_allow_insecure_tls", False)))


def changes(before: Relay, after: Relay) -> dict:
    """{field: {"old": ..., "new": ...}} for what moves where the password goes: the server, the port or the
    username, and the certificate check when it is turned off. Turning the check back on moves nothing."""
    out = {}
    for field, old, new in ((SERVER, before.server, after.server), (PORT, before.port, after.port),
                            (USERNAME, before.username, after.username)):
        if old != new:
            out[field] = {"old": old, "new": new}
    if after.insecure_tls and not before.insecure_tls:
        out[INSECURE_TLS] = {"old": False, "new": True}
    return out


def keeps_profile_password(password) -> bool:
    """Whether a sending profile's save or test send keeps the profile's stored password: it carries none, or an
    empty one, as the form sends a password field left blank. The rule, the save and the test send each ask this,
    so they never disagree on whether a request carries a password. (A save of the general settings that sends an
    empty password removes the stored one instead.)"""
    return not password


def refused(before: Relay, after: Relay, *, password_stored: bool, password_kept: bool) -> dict:
    """The changes that refuse the request: changes(before, after) when the relay holds a stored password and the
    request keeps it (it neither carries a password nor removes the stored one) and the relay still has a server
    to send it to; otherwise none."""
    if not (password_stored and password_kept) or not after.server:
        return {}
    return changes(before, after)


def settings_change(stored: Mapping, payload) -> bool:
    """Whether a save of the general settings changes the mail relay they hold: a relay field whose value differs
    from the stored one, or any password at all. A whole-page save sends every field back as it is stored, which
    changes nothing; a password sent counts whatever it is, so the answer never says whether it matched."""
    if not isinstance(payload, Mapping):
        return False
    stored = stored or {}
    if PASSWORD in payload and (payload.get(PASSWORD) or stored.get(PASSWORD)):
        return True
    if not any(field in payload for field in FIELDS):
        return False
    after = of({**stored, **payload})
    before = of(stored)
    return before != after
