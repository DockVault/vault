"""What the person who runs the server can do to an account from the host, outside the web app.

Run inside the web container by ``dockvault.py accounts`` (docker compose exec), never over the
network::

    python -m app.core.host_operator lookup --username alice
    python -m app.core.host_operator reset-password --username alice --confirm-username alice
    python -m app.core.host_operator reset-second-factor --username alice --confirm-username alice
    python -m app.core.host_operator list
    python -m app.core.host_operator approve --request-id <id> --confirm-username alice

It is the way round the rule that a second change to someone's sign-in details within 14 days needs a
second administrator (app/core/credential_changes.py): on a deployment with one administrator, or
none who can sign in, the server's operator acts here. Each change is recorded, audited and notified
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

ACTIONS = ("lookup", "list", "reset-password", "reset-second-factor", "approve")


def _answer(obj, code=0):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
    return code


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


def _find(db, username):
    from app.core.models import User
    return db.query(User).filter(User.username == username).first()


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # Importing the web app sets up the configuration, the database and the cache exactly as the
    # server does, from this container's own environment.
    import app.api.api_server as api
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
                api._credential_change(db, None, user, cc.PASSWORD,
                                       summary="Temporary password set by the host operator",
                                       payload={"password_hash": hash_password(secret)})
                db.commit()
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
            AuditLogger(db).log_action(
                action="password_reset_link_minted", status="success", username=cc.HOST_OPERATOR,
                resource_type="user", resource_id=str(user.id),
                details={"target_user_id": str(user.id), "ttl_minutes": outcome.result["expires_in_minutes"],
                         "by": "host operator"})
            return _answer({"ok": True, "account": user.username, "secret": outcome.result["reset_link"],
                            "secret_kind": "reset_link",
                            "expires_in_minutes": outcome.result["expires_in_minutes"]})

        if args.action == "reset-second-factor":
            outcome = api._credential_change(db, None, user, cc.SECOND_FACTOR,
                                             summary="Second factor reset by the host operator", payload={})
            db.commit()
            AuditLogger(db).log_action(
                action="second_factor_admin_reset", status="success", username=cc.HOST_OPERATOR,
                resource_type="user", resource_id=str(user.id),
                details={"target_username": user.username, "by": "host operator"})
            return _answer({"ok": True, "account": user.username,
                            "had_second_factor": outcome.result.get("had_second_factor")})
    return _refuse("Nothing to do.")


if __name__ == "__main__":
    sys.exit(run())
