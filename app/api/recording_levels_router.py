"""What the audit log records: the recording levels, in Settings -> Activity and records.

    GET /settings/recording   each kind of personal data: the level in force, the stored level, the .env
                              limit and where it comes from, which levels may be chosen and, for one .env
                              forbids, the line to add; the presets; a sample of what a row records at each
                              level; and every version saved, newest first.
    PUT /settings/recording   save new levels (``{"levels": {...}}``, a kind left out keeps its level).

A save is refused when a level is not one its kind has, when it is above the .env limit (the answer names the
line to add), when the deployment locks the levels (SETTINGS_LOCKED_KEYS names audit_levels), and when it would
record less than earlier releases do while an SFTP server of another version may be running: that server
records as earlier releases did, whatever the levels say. Saving asks for the password every time, plus any
second factor the account has enrolled (the fixed step-up ``admin.audit_privacy.write``), which no setting of
the step-up matrix weakens. The new version and its audit row are written in one transaction: when the row
cannot be written, nothing is saved.

Every route is a plain ``def`` (the thread pool runs it), every statement it sends is bounded by a statement
timeout, and only an interactive administrator reaches it (a temporary credential is refused).
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import audit_privacy as ap
from app.core import fixed_step_up
from app.core.database import get_db
from app.core.models import AuditPrivacyPolicy, User

router = APIRouter(tags=["Recording levels"])

STATEMENT_TIMEOUT_MS = 5000
HISTORY_LIMIT = 50

STEP_UP_ACTION = "admin.audit_privacy.write"
_step_up = fixed_step_up.guard(STEP_UP_ACTION)

# The presets, each brought within the deployment's limits when it is offered.
PRESETS: Dict[str, Dict[str, str]] = {
    "minimal": {ap.NAMES: ap.NONE, ap.SIGNIN_NAMES: ap.NONE, ap.EMAILS: ap.NONE, ap.IP: ap.NONE,
                ap.USER_AGENT: ap.NONE},
    "standard": {ap.NAMES: ap.FINGERPRINT, ap.SIGNIN_NAMES: ap.FINGERPRINT, ap.EMAILS: ap.FULL,
                 ap.IP: ap.SHORTENED, ap.USER_AGENT: ap.FULL},
    "full": {key: ap.FULL for key in ap.POLICY_KEYS},
}
PRESET_LABELS = {"minimal": "Minimal", "standard": "Standard", "full": "Full"}

# A row as the sample shows it: one value of each kind, and how each level records it.
SAMPLE = {
    ap.NAMES: "Q3 plan.xlsx",
    ap.SIGNIN_NAMES: "j.smith",
    ap.EMAILS: "j.smith@example.com",
    ap.IP: "203.0.113.45",
    ap.USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0",
}
LEVEL_WORDS = {ap.NONE: "Not recorded", ap.FINGERPRINT: "Fingerprint", ap.SHORTENED: "Shortened",
               ap.FULL: "Full"}


def limit_statements(db: Session, timeout_ms: int = STATEMENT_TIMEOUT_MS) -> None:
    """Bound every statement of the transaction ``db`` is in (Postgres). Call it again after a commit."""
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {int(timeout_ms)}"))


def env_line(key: str, level: str) -> str:
    return f"{ap.ENV_NAMES[key]}={level}"


def within(levels: Dict[str, str], limits: Dict[str, str]) -> Dict[str, str]:
    """``levels`` with each brought down to its limit."""
    return {key: ap.lower(levels[key], limits[key]) for key in ap.POLICY_KEYS}


def sample_value(key: str, level: str) -> Optional[str]:
    """How the sample row records its value of ``key`` at ``level``: the value, a shortened address, a
    fingerprint's form, or None (not recorded)."""
    value = SAMPLE[key]
    if level == ap.FULL:
        return value
    if level == ap.SHORTENED:
        return ap.shorten(value)
    if level == ap.FINGERPRINT:
        return "fp1:…"
    return None


def stricter_than_earlier_releases(levels: Dict[str, str]) -> bool:
    """Whether ``levels`` record less, of any kind, than releases before the levels did (policy 1)."""
    return any(ap.rank(levels[key]) < ap.rank(ap.POLICY_ONE[key]) for key in ap.POLICY_KEYS)


def _history(db: Session):
    rows = (db.query(AuditPrivacyPolicy).order_by(AuditPrivacyPolicy.version.desc()).limit(HISTORY_LIMIT).all())
    return [{"version": r.version, "levels": {key: getattr(r, key) for key in ap.POLICY_KEYS},
             "reason": r.reason, "by": r.created_by_name,
             "at": r.created_at.isoformat() + "Z" if r.created_at else None} for r in rows]


def describe(db: Session) -> dict:
    """The table the panel shows, read from the database (the newest version) and this process's .env."""
    from app.core import settings_registry
    latest = ap.read_latest(db) or ap.DEFAULT_POLICY
    limits = ap.env_limits()
    locked = ap.locked()
    in_force = ap.effective(latest.levels)
    kinds = []
    for key in ap.POLICY_KEYS:
        choices = []
        for level in ap.CHOICES[key]:
            allowed = ap.rank(level) <= ap.rank(limits[key]) and (not locked or level == limits[key])
            choices.append({"level": level, "label": LEVEL_WORDS[level], "allowed": allowed,
                            "env_line": None if ap.rank(level) <= ap.rank(limits[key]) else env_line(key, level),
                            "sample": sample_value(key, level)})
        kinds.append({"key": key, "label": ap.LABELS[key], "level": in_force[key], "stored": latest.levels.get(key),
                      "limit": limits[key], "env": ap.ENV_NAMES[key],
                      "limit_source": "env" if settings_registry._env_is_set(ap.ENV_NAMES[key]) else "default",
                      "choices": choices})
    from app.core.sftp_versions import sftp_same_version
    check = sftp_same_version(db)
    return {
        "version": latest.version, "kinds": kinds, "locked": locked,
        "lock_line": f"SETTINGS_LOCKED_KEYS={ap.LOCK_GROUP}",
        "presets": [{"key": name, "label": PRESET_LABELS[name], "levels": within(levels, limits)}
                    for name, levels in PRESETS.items()],
        "sftp": {"same_version": check.ok, "explain": check.explain()},
        "history": _history(db),
    }


@router.get("/settings/recording")
def get_recording_levels(current_user: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    """The recording levels, their limits, the presets, a sample and the versions saved."""
    limit_statements(db)
    return describe(db)


class RecordingLevels(BaseModel):
    levels: Dict[str, str] = {}


def refusal(db: Session, latest: ap.Policy, asked: Dict[str, str]):
    """(status, why) for a save the panel may not make, or None. ``asked`` is the whole new set of levels."""
    if ap.locked():
        return 409, (f"The recording levels are set by the deployment ({ap.LOCK_GROUP} is in "
                     "SETTINGS_LOCKED_KEYS): each is its .env limit.")
    limits = ap.env_limits()
    for key in ap.POLICY_KEYS:
        if ap.rank(asked[key]) > ap.rank(limits[key]):
            return 400, (f"{ap.LABELS[key]}: .env allows at most {limits[key]}. To record {asked[key]}, add "
                         f"{env_line(key, asked[key])} to .env, then run docker compose up -d.")
    if stricter_than_earlier_releases(asked):
        from app.core.sftp_versions import sftp_same_version
        check = sftp_same_version(db)
        if not check.ok:
            return 409, ("These levels record less than an SFTP server of an earlier version does, and one may be "
                         "running: it would go on recording as before. " + check.explain())
    return None


@router.put("/settings/recording")
def put_recording_levels(body: RecordingLevels, request: Request,
                         current_user: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    """Save new levels: a new version and its audit row in one transaction."""
    limit_statements(db)
    for key, level in body.levels.items():
        if key not in ap.POLICY_KEYS:
            raise HTTPException(status_code=400, detail=f"{key} is not a kind of recorded data")
        if level not in ap.CHOICES[key]:
            raise HTTPException(status_code=400, detail=(f"{ap.LABELS[key]} can be recorded as "
                                                         f"{', '.join(ap.CHOICES[key])}, not {level}"))
    latest = ap.read_latest(db) or ap.DEFAULT_POLICY
    asked = {key: body.levels.get(key, latest.levels.get(key)) for key in ap.POLICY_KEYS}
    why = refusal(db, latest, asked)
    if why:
        raise HTTPException(status_code=why[0], detail=why[1])
    _step_up(db, current_user, request)       # may commit (a receipt is used once): bound the rest again
    limit_statements(db)
    try:
        ap.lock_policies(db)
        latest = ap.read_latest(db) or ap.DEFAULT_POLICY
        if dict(latest.levels) == asked:
            db.rollback()
            limit_statements(db)
            return {"status": "unchanged", **describe(db)}
        saved = ap.write_version(db, asked, previous=latest, reason="admin", by_id=current_user.id,
                                 by_name=current_user.username, user=current_user)
        db.commit()
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 -- no change without its audit row
        db.rollback()
        raise HTTPException(status_code=503, detail="The recording levels were not saved: their audit record "
                                                    "could not be written. Nothing was changed.")
    ap.use(saved)
    # Every user is told, and a signed-in user's page at once (app/core/recording_notice.py).
    from app.core import recording_notice
    recording_notice.forget_notice()
    recording_notice.announce(saved.version, nudge=_nudge)
    limit_statements(db)
    return {"status": "saved", **describe(db)}


def _nudge(user_id: str) -> None:
    """Tell a signed-in user's page that a notification arrived (it carries no content)."""
    from app.api.api_server import _fire_offloop, broadcast_event
    from app.core.recording_notice import NOTIFICATION_TARGET, NOTIFICATION_TYPE
    _fire_offloop(broadcast_event, {"event": {"type": "notification", "notification_type": NOTIFICATION_TYPE,
                                              "target": NOTIFICATION_TARGET, "owner_user_id": user_id}},
                  include_metrics=False)
