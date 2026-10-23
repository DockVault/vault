"""Working records the pruner deletes (app/core/retention.py): what ended a while ago, and old notifications.

- Invitations (``account_invitations``) go 30 days after they end: after they are accepted, revoked or expire,
  whichever comes first. A pending invitation is never deleted. Once one has ended, only the administrators' list
  of invitations reads it: an administrator's invitation hands the lineage it kept to ``admin_grants`` when it is
  accepted (app/core/admin_grants.py), so deleting the row later shortens nobody's lineage.
- One-time proofs go 30 days after they end, when they are used or expire: password reset links
  (``password_reset_tokens``), one-time codes (``otp_codes``) and email-change codes (``email_change_codes``, no
  longer written). Nothing reads one once it has ended. An unused one is still replaced when a new one is issued.
- Notifications go ``notification_retention_days`` after they were made, read or not. 0, the default, keeps each
  until the person dismisses it, as before.

The log-access file's size (LOG_PULL_SINK_MAX_MB, app/services/log_sink.py) is listed here too, so the Settings
page can say how much of the server's output it keeps. These jobs are not stopped by the hold switch: they are
working records, not logs. They wait while a legal hold stands or a compliance case is open (the rules registered
with person_erase.register_wait), asked in each batch's transaction.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import or_

from app.core import settings_registry as registry

INVITATION_DAYS_KEY = "ended_invitation_days"
ONE_TIME_DAYS_KEY = "ended_one_time_proof_days"
NOTIFICATION_DAYS_KEY = "notification_retention_days"
SINK_KEY = "log_pull_sink_max_mb"

registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=INVITATION_DAYS_KEY, kind="int", default=30, editable=registry.FIXED, group="working_records",
    unit="days", label="Invitations that were accepted, revoked or expired",
    help="Kept 30 days after they end, then deleted. A pending invitation is kept."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=ONE_TIME_DAYS_KEY, kind="int", default=30, editable=registry.FIXED, group="working_records",
    unit="days", label="Used or expired password reset links and one-time codes",
    help="Kept 30 days after they are used or expire, then deleted."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=NOTIFICATION_DAYS_KEY, kind="int", default=0, env="notification_retention_days", minimum=30, maximum=3650,
    unlimited=0, reduction=registry.LOWER, group="retention", unit="days",
    label="Delete notifications after",
    help="Each person's notifications, read or not, are deleted this long after they arrive. No limit keeps "
         "them until the person dismisses them."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=SINK_KEY, kind="int", default=15, env="log_pull_sink_max_mb", minimum=3, maximum=1000,
    editable=registry.ENV_ONLY, reduction=registry.LOWER, group="retention", unit="MB",
    label="Size of the log-access file",
    help="The copy of the server's output that Log access reads, in three files that rotate; the oldest lines "
         "go first. A log pull reads at most the newest 5 MB of it."))


def ended_invitation_conditions(model, now: datetime) -> list:
    """The invitations that ended (accepted, revoked or expired) more than 30 days before ``now``."""
    cut = now - timedelta(days=registry.resolve(INVITATION_DAYS_KEY))
    return [or_(model.accepted_at < cut, model.revoked_at < cut, model.expires_at < cut)]


def ended_one_time_conditions(model, now: datetime) -> list:
    """The reset links or codes of ``model`` used or expired more than 30 days before ``now``."""
    cut = now - timedelta(days=registry.resolve(ONE_TIME_DAYS_KEY))
    return [or_(model.consumed_at < cut, model.expires_at < cut)]


def _chain_days() -> Optional[int]:
    """notification_retention_days as the audit chain's honoured state gives it, or None while the chain cannot
    give it (no chain yet, or sealing stopped)."""
    from app.core import audit_chain_policy_seals as ps
    values = ps.numbers()
    if values is None:
        return None
    try:
        return int(values[NOTIFICATION_DAYS_KEY])
    except (KeyError, TypeError, ValueError):
        return None


def notification_days() -> Optional[int]:
    """The days after which the notifications job deletes a notification: 0 keeps them, None waits. A setting
    an administrator may lower, so the job acts on the audit chain's honoured value (audit_chain_policy_seals
    .numbers), never on the database's alone, and on whichever of the two keeps longer: a value written
    into the database without the server's key cannot make it delete sooner. While the chain cannot give the
    value, nothing is deleted."""
    days = registry.resolve(NOTIFICATION_DAYS_KEY)
    if not days:
        return 0
    chain = _chain_days()
    if chain is None:
        return None
    if not chain:
        return 0
    return max(days, chain)


def old_notification_conditions(model, now: datetime, days: int) -> list:
    """The notifications made more than ``days`` days before ``now``."""
    return [model.created_at < now - timedelta(days=days)]


def _waits():
    """What holds these deletions back, asked in each batch's transaction: the rules registered with
    person_erase.register_wait (a legal hold stands, or a compliance case is open)."""
    from app.core import person_erase
    return person_erase.rule_waits


def prune_invitations(p, *, model=None):
    """Invitations that ended 30 days ago. The model is a parameter so the real condition can run against a
    throwaway schema."""
    from app.core import retention
    from app.core.models import AccountInvitation
    model = model or AccountInvitation
    return p.delete_in_batches(model, retention.deletable(model, p.now, *ended_invitation_conditions(model, p.now)),
                               model.expires_at, waits=_waits())


def prune_one_time_proofs(p, *, models=None):
    """Reset links, one-time codes and email-change codes used or expired 30 days ago, table by table."""
    from app.core import retention
    from app.core.models import EmailChangeCode, OtpCode, PasswordResetToken
    result = retention.JobResult()
    for model in models or (PasswordResetToken, OtpCode, EmailChangeCode):
        if not p.time_left():
            break
        done = p.delete_in_batches(
            model, retention.deletable(model, p.now, *ended_one_time_conditions(model, p.now)), model.expires_at,
            waits=_waits())
        result.add(done.deleted, done.oldest, done.newest)
    return result


def prune_notifications(p, *, model=None):
    """Notifications older than notification_retention_days (notification_days); nothing while it is 0 (keep
    them), nor while the audit chain cannot give it."""
    from app.core import retention
    from app.core.models import Notification
    model = model or Notification
    days = notification_days()
    if days is None:
        registry._say("The pruner's notifications job waits for the audit chain")
        return retention.JobResult()
    if not days:
        return retention.JobResult()
    return p.delete_in_batches(
        model, retention.deletable(model, p.now, *old_notification_conditions(model, p.now, days)), model.created_at,
        waits=_waits())


def notifications_kept() -> str:
    """How long notifications are kept, for the recording notice."""
    days = registry.resolve(NOTIFICATION_DAYS_KEY)
    if not days:
        return "Until you dismiss them."
    return f"Until you dismiss them, or {days} days after they arrive."
