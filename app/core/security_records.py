"""The security record: failed sign-ins, kept in full for a short window, apart from the audit log.

Every failed sign-in the app audits (a web password, a second-factor code, an SFTP password) also writes a
row to ``security_records``, in the same transaction as its audit row: when, what failed, the account it
named (when the name is an account), the name exactly as typed, the address, the way in, and the reason. It
keeps those values in full whatever the audit log's recording levels keep, because blocking an address,
counting failures and investigating an attack need them; and it keeps them only for the window,
``security_record_days`` (30 days by default, within SECURITY_RECORD_MIN_DAYS and SECURITY_RECORD_MAX_DAYS
from .env). Shortening the window deletes sooner, so it waits (app/core/setting_changes.py). An SFTP key the
server turns down writes no record, as it writes no audit row: a client offers its keys one after another
until one is taken, so a key turned down is routine rather than a failed sign-in, and the SFTP key throttle
bounds a flood of them.

The pruner (app/core/retention.py) deletes records older than the window, and at the same window clears the
name and the address from security alerts, resolved or not: an unresolved alert no longer holds personal
data for ever. An alert's message never carries them: it holds ``{username}`` and ``{ip_address}`` where they
belong, and the text is completed from the alert's own fields when it is shown (render_message), so once
they are cleared the message says so. The window both jobs act on is the longer of the database's value and
the audit chain's honoured one, and they wait while the chain cannot give it (window()). The security
monitor's statistics of failed sign-ins read these records.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, or_

from app.core import settings_registry as registry

WINDOW_KEY = "security_record_days"
ALERT_RETENTION_KEY = "security_alert_retention_days"

# What failed.
LOGIN = "login_failure"
SECOND_FACTOR = "second_factor_failure"

# The placeholders an alert's message holds instead of the name and the address.
NAME_TOKEN = "{username}"
ADDRESS_TOKEN = "{ip_address}"
CLEARED_NAME = "(name removed)"
CLEARED_ADDRESS = "(address removed)"

registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=WINDOW_KEY, kind="int", default=30, env="security_record_days", minimum=1, maximum=3650,
    floor="security_record_min_days", ceiling="security_record_max_days", reduction=registry.LOWER,
    group="retention", unit="days", label="Keep failed sign-ins in full for",
    help="Each failed sign-in, with the name typed and the address, for blocking and investigating attacks. "
         "Security alerts lose their names and addresses after the same time."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=ALERT_RETENTION_KEY, kind="int", default=90, env="security_alert_retention_days", minimum=1,
    maximum=3650, editable=registry.ENV_ONLY, reduction=registry.LOWER, group="retention", unit="days",
    label="Keep resolved security alerts for"))


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _chain_days() -> Optional[int]:
    """security_record_days as the audit chain's honoured state gives it, or None while the chain cannot give it
    (no chain yet, or sealing stopped)."""
    from app.core import audit_chain_policy_seals as ps
    values = ps.numbers()
    if values is None:
        return None
    try:
        return int(values[WINDOW_KEY])
    except (KeyError, TypeError, ValueError):
        return None


def window() -> Optional[timedelta]:
    """How long a failed sign-in is kept in full, and an alert keeps its name and address; None waits. A
    setting an administrator may lower, so the two jobs act on the audit chain's honoured value
    (audit_chain_policy_seals.numbers), never on the database's alone, and on whichever of the two keeps
    longer: a value written into the database without the server's key cannot make them delete sooner. While
    the chain cannot give the value, nothing is deleted or cleared."""
    days = int(registry.resolve(WINDOW_KEY))
    chain = _chain_days()
    if chain is None:
        return None
    return timedelta(days=max(days, chain))


def record(db, *, kind: str, name: Optional[str], address: Optional[str], channel: Optional[str] = None,
           reason: Optional[str] = None, account_id=None, at: Optional[datetime] = None):
    """Add a security record to ``db``'s transaction, and return it. The caller commits it with the audit
    row of the same failure. When ``account_id`` is not given, the name is looked up among the accounts."""
    from app.core.models import SecurityRecord
    if account_id is None and name:
        # Under a savepoint of its own (audit_logger._looked_up): the record is written under the savepoint
        # the failure's audit row opens for it (AuditLogger._add_security_record), and on PostgreSQL a lookup
        # that fails there (waiting past the lock timeout behind a change to the users table, or a transient
        # error) would abort that savepoint and lose the record. Rolled back to its own, the lookup leaves the
        # record without its account, which is still a record.
        from app.services.audit_logger import _looked_up
        account_id = _looked_up(db, lambda: _account_named(db, name))
    import uuid
    row = SecurityRecord(id=uuid.uuid4(), at=at or utcnow(), kind=kind, account_id=account_id,
                         name=(name or None) and name[:255],
                         address=(address or None) and str(address)[:45], channel=channel,
                         reason=(reason or None) and str(reason)[:255])
    db.add(row)
    return row


def _account_named(db, name: str):
    """The id of the account ``name`` names: its username, or for a sign-in by email address its email address;
    None when there is none."""
    from app.core.models import User
    account_id = db.query(User.id).filter(User.username == name).scalar()
    if account_id is None and "@" in name:    # a sign-in by email address
        account_id = db.query(User.id).filter(func.lower(User.email) == name.strip().lower()).scalar()
    return account_id


def render_message(alert) -> str:
    """An alert's message as shown: its placeholders completed from the alert's own name and address, or
    saying they were removed."""
    text = alert.message or ""
    if NAME_TOKEN in text:
        text = text.replace(NAME_TOKEN, alert.username if alert.username else CLEARED_NAME)
    if ADDRESS_TOKEN in text:
        text = text.replace(ADDRESS_TOKEN, alert.ip_address if alert.ip_address else CLEARED_ADDRESS)
    return text


def _scrubbed(message: Optional[str], name: Optional[str], address: Optional[str]) -> Optional[str]:
    """``message`` with the name and the address it spells out replaced by the placeholders (an alert
    written before the message held them)."""
    if not message:
        return message
    for value, token in ((name, NAME_TOKEN), (address, ADDRESS_TOKEN)):
        if value and len(value) >= 2:
            message = message.replace(value, token)
    return message


def prune_records(p):
    """The pruner's job: records older than the window; nothing while the audit chain cannot give it."""
    from app.core import retention
    from app.core.models import SecurityRecord
    keep = window()
    if keep is None:
        registry._say("The pruner's security_records job waits for the audit chain")
        return retention.JobResult()
    return p.delete_in_batches(
        SecurityRecord, retention.deletable(SecurityRecord, p.now, SecurityRecord.at < p.now - keep),
        SecurityRecord.at)


def clear_alert_values(p):
    """The pruner's job: the name and the address of every alert older than the window, resolved or not,
    cleared (and taken out of its message), in batches. Deletes nothing. Nothing while the audit chain cannot
    give the window."""
    from app.core import retention
    from app.core.models import SecurityAlert
    result = retention.JobResult()
    keep = window()
    if keep is None:
        registry._say("The pruner's security_alert_values job waits for the audit chain")
        return result
    while p.time_left():
        with p.transaction() as db:
            alerts = (db.query(SecurityAlert)
                      .filter(*retention.deletable(SecurityAlert, p.now, SecurityAlert.timestamp < p.now - keep,
                                                   or_(SecurityAlert.username.isnot(None),
                                                       SecurityAlert.ip_address.isnot(None))))
                      .order_by(SecurityAlert.timestamp).limit(p.batch_rows).with_for_update(skip_locked=True).all())
            for alert in alerts:
                alert.message = _scrubbed(alert.message, alert.username, alert.ip_address)
                alert.username = None
                alert.ip_address = None
            p.record(db, retention.JobResult(cleared=len(alerts)), SecurityAlert.__tablename__)
            result.cleared += len(alerts)
        if len(alerts) < p.batch_rows:
            break
    return result
