"""What the person who runs the server can do to an account from the host, outside the web app.

Run inside the web container by ``dockvault.py accounts`` (docker compose exec), never over the
network::

    python -m app.core.host_operator lookup --username alice
    python -m app.core.host_operator reset-password --username alice --confirm-username alice
    python -m app.core.host_operator reset-second-factor --username alice --confirm-username alice
    python -m app.core.host_operator unlock --username alice --confirm-username alice
    python -m app.core.host_operator list
    python -m app.core.host_operator approve --request-id <id> --confirm-username alice
    python -m app.core.host_operator user-managers
    python -m app.core.host_operator regranted-defaults

It is the way round the rule that a second change to someone's sign-in details within 14 days needs a
second administrator (app/core/credential_changes.py): on a deployment with one administrator, or
none who can sign in, the server's operator acts here. ``unlock`` clears an account's locks (those
failed sign-ins armed, and an administrator's), for when no administrator can sign in to do it. Each change is recorded, audited and notified
exactly as an administrator's would be, under the name ``operator@host``.

Safety:
  * every change names the account twice (``--username`` or the request's account, and
    ``--confirm-username``), and nothing happens unless the two match;
  * the one secret it can produce (a password reset link, or a temporary password when reset links are
    not configured) is written only into the JSON answer on this process's standard output, which
    dockvault.py reads through the exec pipe and shows on the operator's terminal alone. It is never
    logged, stored in plain text, or put in the audit log.

Answers are one JSON object on standard output; the exit status is 0 when it succeeded, 2 when it was
refused (the answer's ``error`` says why).
"""
import argparse
import json
import secrets
import string
import sys

ACTIONS = ("lookup", "list", "reset-password", "reset-second-factor", "approve", "user-managers",
           "regranted-defaults", "unlock")

# The permissions an administrator has by default and a user does not: to view and to manage users.
USER_MANAGEMENT_GROUPS = ("USER_MANAGE", "USER_VIEW")


class _Answer(Exception):
    """The answer, carried out of the work so it is printed last, after everything the web app
    printed on its way (which goes to standard error, see run)."""

    def __init__(self, obj, code):
        super().__init__("answer")
        self.obj, self.code = obj, code


def _answer(obj, code=0):
    raise _Answer(obj, code)


def _refuse(message):
    return _answer({"ok": False, "error": message}, 2)


def temporary_password(length=20) -> str:
    """A random password with every character class, for when reset links are not configured."""
    alphabet = string.ascii_letters + string.digits + "-_.!@#%+="
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def build_parser():
    p = argparse.ArgumentParser(prog="python -m app.core.host_operator")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("--username", help="the account to act on")
    p.add_argument("--confirm-username", dest="confirm_username",
                   help="the same username again; nothing changes unless it matches")
    p.add_argument("--request-id", dest="request_id", help="approve: the held request")
    p.add_argument("--temporary-password", dest="temporary_password", action="store_true",
                   help="reset-password: set a temporary password instead of creating a reset link")
    return p


def confirmation_problem(username, confirm_username):
    """Why a change must not go ahead, or None. Both names must be given and equal, exactly."""
    if not (username or "").strip():
        return "Name the account with --username."
    if confirm_username is None or confirm_username != username:
        return "The username typed again does not match. Nothing was changed."
    return None


def _describe(db, user):
    from app.core.models import SecondFactorEnrollment
    has_factor = db.query(SecondFactorEnrollment.id).filter(
        SecondFactorEnrollment.user_id == user.id, SecondFactorEnrollment.status == "active").first() is not None
    return {
        "username": user.username,
        "email": user.email,
        "role": user.role.value if user.role is not None else None,
        "active": bool(user.is_active),
        "locked_by_administrator": bool(user.is_locked) and user.locked_until is None,
        "last_login": user.last_login.isoformat() + "Z" if user.last_login else None,
        "second_factor": has_factor,
    }


def user_managers(db):
    """Every account that is not an administrator and holds the permission to view or to manage users,
    with who granted each and when: ``granted_by`` None means no granter is recorded, which is how an
    administrator's defaults are stored (an account created as an administrator and demoted before 0.33.0
    kept them), or a grant whose granter's account was deleted since. Read-only."""
    from app.core.models import RoleEnum, User, UserEndpointPermission
    from sqlalchemy.orm import aliased
    granter = aliased(User)
    rows = (db.query(User.username, User.role, User.is_active, UserEndpointPermission.endpoint_group,
                     UserEndpointPermission.granted_at, granter.username)
            .join(UserEndpointPermission, UserEndpointPermission.user_id == User.id)
            .outerjoin(granter, granter.id == UserEndpointPermission.granted_by)
            .filter(User.role != RoleEnum.ADMIN,
                    UserEndpointPermission.endpoint_group.in_(USER_MANAGEMENT_GROUPS))
            .order_by(User.username, UserEndpointPermission.endpoint_group).all())
    accounts = {}
    for username, role, active, group, granted_at, granted_by in rows:
        account = accounts.setdefault(username, {
            "username": username, "role": role.value if role is not None else None,
            "active": bool(active), "permissions": []})
        account["permissions"].append({
            "group": group, "granted_by": granted_by,
            "granted_at": granted_at.replace(tzinfo=None).isoformat() + "Z" if granted_at else None})
    return list(accounts.values())


def _groups_of(details, *keys):
    """The permission groups an audit row's details name under the first of ``keys`` present (a list),
    else under ``endpoint_group``. Rows from the earliest releases carry only ``endpoint_group``."""
    details = details if isinstance(details, dict) else {}
    for key in keys:
        if isinstance(details.get(key), list):
            return [g for g in details[key] if isinstance(g, str)]
    group = details.get("endpoint_group")
    return [group] if isinstance(group, str) else []


def _naive(when):
    return when.replace(tzinfo=None) if when is not None and when.tzinfo is not None else when


def regranted_defaults(db):
    """Each permission an administrator revoked that a restart granted again, as releases before 0.33.1
    did with every role default at every start: the account holds the group again, with no granter
    recorded, granted after its latest revocation (``REVOKE_PERMISSION`` in the audit log), and nothing
    else explains the grant since then (an administrator granting it, ``GRANT_PERMISSION``; a change of
    role, ``permissions_reset_for_role``; or a start giving a new default, ``permission_default_granted``).
    Read-only: an administrator revokes the permission again if it is still not wanted. A revocation the
    audit log no longer holds (a retention limit pruned it) cannot be found."""
    from app.core.models import AuditLog, User, UserEndpointPermission

    revoked, explained = {}, {}
    for action, resource_id, when, details in db.query(
            AuditLog.action, AuditLog.resource_id, AuditLog.timestamp, AuditLog.details).filter(
            AuditLog.status == "success",
            AuditLog.action.in_(("REVOKE_PERMISSION", "GRANT_PERMISSION", "permission_granted",
                                 "permissions_reset_for_role", "permission_default_granted"))).all():
        if not resource_id or when is None:
            continue
        if action == "REVOKE_PERMISSION":
            into, groups = revoked, _groups_of(details, "revoked_groups")
        elif action == "permissions_reset_for_role":
            into, groups = explained, _groups_of(details, "added")
        else:
            into, groups = explained, _groups_of(details, "granted_groups")
        for group in groups:
            key = (resource_id, group)
            into[key] = max(into.get(key, _naive(when)), _naive(when))
    if not revoked:
        return []
    rows = (db.query(User.id, User.username, User.role, User.is_active, UserEndpointPermission.endpoint_group,
                     UserEndpointPermission.granted_at)
            .join(UserEndpointPermission, UserEndpointPermission.user_id == User.id)
            .filter(UserEndpointPermission.granted_by.is_(None))
            .order_by(User.username, UserEndpointPermission.endpoint_group).all())
    found = []
    for user_id, username, role, active, group, granted_at in rows:
        key = (str(user_id), group)
        revoked_at, granted_at = revoked.get(key), _naive(granted_at)
        if revoked_at is None or granted_at is None or granted_at <= revoked_at:
            continue
        if explained.get(key) is not None and explained[key] > revoked_at:
            continue
        found.append({"username": username, "role": role.value if role is not None else None,
                      "active": bool(active), "group": group,
                      "revoked_at": revoked_at.isoformat() + "Z",
                      "granted_again_at": granted_at.isoformat() + "Z"})
    return found


def _find(db, username):
    from app.core.models import User
    return db.query(User).filter(User.username == username).first()


def _wait_for_background_work(started_before, timeout=30.0):
    """The web app sends its emails on background threads, which a short-lived process would kill as
    it exits. Give the ones this run started time to finish."""
    import threading
    import time
    from app.core import audit_signal
    deadline = time.monotonic() + timeout
    # The Activity page's signals for this run's audit rows go out first. Their publisher lives as long
    # as the process, so it is flushed, never joined: a join would always wait out the whole timeout.
    audit_signal.flush(min(timeout, 5.0))
    for t in threading.enumerate():
        if t not in started_before and t is not threading.current_thread() and t.name != "audit-signal":
            t.join(max(0.0, deadline - time.monotonic()))


def run(argv=None) -> int:
    """Do what was asked and print the answer as the last line on standard output. Everything the web
    app prints while it works (start-up notes, a mail failure) is sent to standard error instead, so
    standard output carries the answer alone."""
    import contextlib
    import threading
    args = build_parser().parse_args(argv)
    answer = {"ok": False, "error": "The account tool stopped before it could answer."}
    code = 1
    with contextlib.redirect_stdout(sys.stderr):
        # Importing the web app sets up the configuration, the database and the cache exactly as the
        # server does, from this container's own environment. Threads it starts on import are its
        # own; only those this run starts afterwards (the emails) are waited for.
        import app.api.api_server as api
        started_before = set(threading.enumerate())
        try:
            _run(args, api)
        except _Answer as done:
            answer, code = done.obj, done.code
        finally:
            _wait_for_background_work(started_before)
    sys.stdout.write(json.dumps(answer) + "\n")
    sys.stdout.flush()
    return code


def _run(args, api) -> int:
    from app.core import credential_changes as cc
    from app.core.database import get_db_context
    from app.services.audit_logger import AuditLogger

    with get_db_context() as db:
        if args.action == "list":
            rows = cc.open_requests(db)
            from app.core.models import User
            names = dict(db.query(User.id, User.username).filter(
                User.id.in_([r.target_user_id for r in rows])).all()) if rows else {}
            return _answer({"ok": True, "requests": [
                api._credential_request_dict(r, names.get(r.target_user_id)) for r in rows]})

        if args.action == "user-managers":
            return _answer({"ok": True, "accounts": user_managers(db)})

        if args.action == "regranted-defaults":
            return _answer({"ok": True, "permissions": regranted_defaults(db)})

        if args.action == "approve":
            if not args.request_id:
                return _refuse("Name the request with --request-id (see: list).")
            import uuid
            from fastapi import HTTPException
            try:
                change_id = uuid.UUID(args.request_id)
            except ValueError:
                return _refuse("That is not a request id.")
            try:
                change, target = api._open_credential_request(db, change_id)
            except HTTPException as exc:
                return _refuse(str(exc.detail))
            problem = confirmation_problem(target.username, args.confirm_username)
            if problem:
                return _refuse(problem)
            request_row = api._credential_request_dict(change, target.username)
            try:
                result = api._approve_credential_change(db, change, target, approver=None)
            except HTTPException as exc:
                return _refuse(str(exc.detail))
            return _answer({"ok": True, "approved": request_row,
                            "secret": result.get("reset_link"),
                            "secret_kind": "reset_link" if result.get("reset_link") else None,
                            "email_sent": result.get("email_sent")})

        user = _find(db, args.username) if args.username else None
        if user is None:
            return _refuse(f"There is no account named {args.username!r}." if args.username
                           else "Name the account with --username.")
        if args.action == "lookup":
            return _answer({"ok": True, "account": _describe(db, user)})

        problem = confirmation_problem(args.username, args.confirm_username)
        if problem:
            return _refuse(problem)

        if args.action == "reset-password":
            from app.core.password_reset import pepper_ok
            if args.temporary_password or not pepper_ok(api._reset_pepper()):
                from app.core.security import hash_password
                secret = temporary_password()
                outcome = api._credential_change(db, None, user, cc.PASSWORD,
                                                 summary="Temporary password set by the host operator",
                                                 payload={"password_hash": hash_password(secret)})
                db.commit()
                api._notify_credential_change(db, cc.PASSWORD, user, outcome.result, by_name=cc.HOST_OPERATOR)
                AuditLogger(db).log_action(
                    action="user_updated", status="success", username=cc.HOST_OPERATOR,
                    resource_type="user", resource_id=str(user.id),
                    details={"updated_username": user.username, "changes": {"password": "changed"},
                             "by": "host operator"})
                return _answer({"ok": True, "account": user.username, "secret": secret,
                                "secret_kind": "temporary_password"})
            outcome = api._credential_change(db, None, user, cc.RESET_LINK,
                                             summary="Password reset link created by the host operator",
                                             payload={"delivery": "copy"})
            db.commit()
            api._notify_credential_change(db, cc.RESET_LINK, user, outcome.result, by_name=cc.HOST_OPERATOR)
            AuditLogger(db).log_action(
                action="password_reset_link_minted", status="success", username=cc.HOST_OPERATOR,
                resource_type="user", resource_id=str(user.id),
                details={"target_user_id": str(user.id), "ttl_minutes": outcome.result["expires_in_minutes"],
                         "by": "host operator"})
            return _answer({"ok": True, "account": user.username, "secret": outcome.result["reset_link"],
                            "secret_kind": "reset_link",
                            "expires_in_minutes": outcome.result["expires_in_minutes"]})

        if args.action == "unlock":
            from datetime import datetime, timezone
            from app.core import sign_in_lockout
            was_locked = bool(user.is_locked)
            user.is_locked = False
            user.locked_until = None
            user.failed_login_attempts = 0
            user.updated_at = datetime.now(timezone.utc)
            cleared = sign_in_lockout.clear_for_user(db, user.id)
            db.commit()
            AuditLogger(db).log_action(
                action="USER_LOCK_CHANGED", status="success", username=cc.HOST_OPERATOR,
                resource_type="user", resource_id=str(user.id),
                details={"target_username": user.username, "locked": False, "was_locked": was_locked,
                         "sign_in_locks_cleared": cleared, "by": "host operator"})
            api._notify_account_status_changes(db, user, by_name=cc.HOST_OPERATOR,
                                               locked=(was_locked, False), sign_in_locks_cleared=cleared)
            return _answer({"ok": True, "account": user.username, "was_locked": was_locked,
                            "sign_in_locks_cleared": cleared})

        if args.action == "reset-second-factor":
            outcome = api._credential_change(db, None, user, cc.SECOND_FACTOR,
                                             summary="Second factor reset by the host operator", payload={})
            db.commit()
            api._notify_credential_change(db, cc.SECOND_FACTOR, user, outcome.result, by_name=cc.HOST_OPERATOR)
            AuditLogger(db).log_action(
                action="second_factor_admin_reset", status="success", username=cc.HOST_OPERATOR,
                resource_type="user", resource_id=str(user.id),
                details={"target_username": user.username, "by": "host operator"})
            return _answer({"ok": True, "account": user.username,
                            "had_second_factor": outcome.result.get("had_second_factor")})
    return _refuse("Nothing to do.")


if __name__ == "__main__":
    sys.exit(run())
