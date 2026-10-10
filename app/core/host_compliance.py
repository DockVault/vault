"""What the person who runs the server can do about compliance access from the host, outside the web app.

Run inside the web container by ``dockvault.py cases`` (docker compose exec), never over the network::

    python -m app.core.host_compliance list
    python -m app.core.host_compliance show --grant <id>      (or --case <id>)
    python -m app.core.host_compliance grant-approve --grant <id> --confirm-username alice
    python -m app.core.host_compliance revoke-auditor --username alice --confirm-username alice [--reason ...]
    python -m app.core.host_compliance approve --case <id> --confirm-case <reference>
    python -m app.core.host_compliance reject --case <id> --confirm-case <reference> --reason ...
    python -m app.core.host_compliance confirm-hold --case <id> --confirm-case <reference>
    python -m app.core.host_compliance downgrade-blockers --target X.Y.Z

Every compliance step that gives power takes two people. On a deployment with one administrator, or with none
independent of the step, the server's operator is the second one: ``grant-approve`` approves a proposed auditor
right, ``approve`` a case and ``confirm-hold`` a case's legal hold, recorded as ``operator@host`` exactly as an
administrator's step would be. Each is refused while an independent administrator with an authenticator exists:
the host operator has no account, so none of the exclusions of the independence rule (app/core/independence.py)
can apply to it, and an administrator they do apply to must decide instead. ``list`` and ``show`` say whether the
host may (``host_may_approve``, ``host_may_confirm``) and who else can. Revoking only removes power and is always
allowed.

Safety: a change names its subject twice (the account's username, or the case's reference, the first eight
characters of its id as ``list`` and ``show`` print it: a case has no number until it is approved), and nothing
happens unless the two match. Answers are one JSON object on standard output; the exit status is 0 when it
succeeded, 2 when it was refused (the answer's ``error`` says why), and 1 when something unexpected stopped it
(the answer says it stopped; what happened is on standard error).

The case steps (approving and turning down a case, confirming a hold) are run by the code that runs them for an
administrator: the module that owns each registers it in CASE_STEPS with register_case_step, and an action whose
step no module has registered is refused.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid

from app.core.host_operator import _Answer, _answer, _refuse, _wait_for_background_work, confirmation_problem

ACTIONS = ("list", "show", "approve", "reject", "confirm-hold", "grant-approve", "revoke-auditor",
           "downgrade-blockers")
# The case steps the host can take, run by the module that owns each: action -> fn(db, case, *, reason=None),
# which approves (or turns down, or confirms the hold of) ``case`` as the server's operator, in ``db``'s
# transaction, and returns what the answer says.
CASE_STEPS: dict = {}
STEP_ACTIONS = ("approve", "reject", "confirm-hold")
REFERENCE_LENGTH = 8

ACCESS_OFF = ("Compliance access is turned off on this deployment (COMPLIANCE_ACCESS=disabled): nothing can be "
              "approved.")


def register_case_step(action: str, fn) -> None:
    if action not in STEP_ACTIONS:
        raise LookupError(f"{action} is not a case step the host takes")
    CASE_STEPS[action] = fn


def reference(case_id) -> str:
    """How the host names a case before it has a number: the first characters of its id."""
    return str(case_id).replace("-", "")[:REFERENCE_LENGTH]


def build_parser():
    p = argparse.ArgumentParser(prog="python -m app.core.host_compliance")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("--grant", help="show, grant-approve: the auditor grant's id")
    p.add_argument("--case", help="show, approve, reject, confirm-hold: the case's id")
    p.add_argument("--confirm-case", dest="confirm_case",
                   help="the case's reference typed again (list shows it); nothing changes unless it matches")
    p.add_argument("--username", help="revoke-auditor: the account whose auditor right is revoked")
    p.add_argument("--confirm-username", dest="confirm_username",
                   help="the account's username typed again; nothing changes unless it matches")
    p.add_argument("--reason", help="reject: why (shown to the auditor); revoke-auditor: why, optional")
    p.add_argument("--target", help="downgrade-blockers: the version to go back to (X.Y.Z)")
    return p


def case_confirmation_problem(case_id, typed):
    """Why a case step must not go ahead, or None: the case's reference must be typed again, exactly."""
    if not (typed or "").strip():
        return "Type the case's reference again with --confirm-case (list shows it). Nothing was changed."
    if typed.strip().lower() != reference(case_id):
        return "The case's reference typed again does not match. Nothing was changed."
    return None


def _id(value, what):
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        _refuse(f"That is not {what} id.")


def _grant_summary(db, grant):
    from app.core import auditor_rights as rights
    out = rights.grant_dict(db, grant)
    if grant.status == "proposed":
        from app.core.models import User
        holder = db.get(User, grant.user_id) if grant.user_id is not None else None
        independent = rights.independent_approvers(db, grant)
        problems = rights.preconditions(db, holder)
        out["independent_approvers"] = [a.username for a in independent]
        out["host_may_approve"] = (rights.access_enabled() and not independent and not problems
                                   and not rights.is_lapsed(grant))
    return out


def _case_summary(db, case):
    from app.core import case_eligibility
    from app.core.models import ComplianceCaseVault
    independent = case_eligibility.independent_approvers(db, case) if case.status == "pending" else []
    from app.core import legal_holds
    to_confirm = legal_holds.confirmable(db, case)
    confirmers = legal_holds.independent_confirmers(db, case) if to_confirm else []
    return {"id": str(case.id), "reference": reference(case.id), "number": case.number, "status": case.status,
            "auditor": case.auditor_username, "requested_at": case.requested_at.isoformat() + "Z",
            "purpose": case.purpose, "legal_basis": case.legal_basis,
            "vaults": db.query(ComplianceCaseVault).filter(ComplianceCaseVault.case_id == case.id).count(),
            "independent_approvers": [a.username for a in independent],
            "host_may_approve": case.status == "pending" and not independent,
            # The legal hold: how many of its vaults wait for a confirmation, who could confirm it, and whether
            # the server's operator may (only when nobody can).
            "holds_to_confirm": len(to_confirm),
            "independent_confirmers": [a.username for a in confirmers],
            "host_may_confirm": bool(to_confirm) and not confirmers}


def downgrade_blockers(db, target) -> list:
    """What stops this deployment going back to ``target``: each record of data a release older than it cannot
    read (app/core/data_requirements.py), as {key, requires_at_least, reason, undo}. Empty: nothing does."""
    from app.core import data_requirements as dr
    return [{"key": r.key, "requires_at_least": r.requires_at_least, "reason": r.reason, "undo": r.undo}
            for r in dr.unmet(dr.read_requirements(db.connection()), target)]


def _version(target):
    from app.core import data_requirements as dr
    value = (target or "").strip().lstrip("vV")
    if dr._parse(value) is None:
        _refuse("Name the version to go back to with --target X.Y.Z.")
    return value


def run(argv=None) -> int:
    """Do what was asked and print the answer as the last line on standard output; everything the web app
    prints on its way goes to standard error."""
    import contextlib
    import threading
    args = build_parser().parse_args(argv)
    answer = {"ok": False, "error": "The compliance tool stopped before it could answer."}
    code = 1
    with contextlib.redirect_stdout(sys.stderr):
        try:
            import app.api.api_server as api  # noqa: F401 -- sets up the configuration, the database and the cache
            started_before = set(threading.enumerate())
            try:
                _run(args)
            except _Answer as done:
                answer, code = done.obj, done.code
            finally:
                _wait_for_background_work(started_before)
        except (Exception, SystemExit):  # noqa: BLE001 - whatever stopped it, the caller still gets one answer
            # Something nothing here expected (the database out of reach, say, or a start-up that refused this
            # container's configuration and exited): the answer above says the tool stopped, with exit status 1,
            # and what happened goes to standard error, never into it. As the account tool does (host_operator).
            import traceback
            traceback.print_exc()
    sys.stdout.write(json.dumps(answer) + "\n")
    sys.stdout.flush()
    return code


def _run(args) -> None:
    from app.core import audit_privacy
    audit_privacy.require()
    from app.core.database import get_db_context
    with get_db_context() as db:
        _act(db, args)
    _refuse("Nothing to do.")


def _act(db, args) -> None:
    from app.core import auditor_rights as rights
    from app.core.models import AUDITOR_GRANT_OPEN, AuditorGrant, ComplianceCase, User

    if args.action == "downgrade-blockers":
        target = _version(args.target)
        return _answer({"ok": True, "target": target, "blockers": downgrade_blockers(db, target)})

    if args.action == "list":
        grants = (db.query(AuditorGrant).filter(AuditorGrant.status.in_(AUDITOR_GRANT_OPEN))
                  .order_by(AuditorGrant.proposed_at).all())
        cases = (db.query(ComplianceCase).filter(ComplianceCase.closed_at.is_(None))
                 .order_by(ComplianceCase.requested_at).all())
        return _answer({"ok": True, "grants": [_grant_summary(db, g) for g in grants],
                        "cases": [_case_summary(db, c) for c in cases]})

    if args.action == "show":
        if args.grant:
            grant = db.get(AuditorGrant, _id(args.grant, "an auditor grant"))
            if grant is None:
                return _refuse("There is no such auditor grant.")
            out = _grant_summary(db, grant)
            if "provenance" not in out:
                holder = db.get(User, grant.user_id) if grant.user_id is not None else None
                out["provenance"] = rights.provenance(db, holder)
            return _answer({"ok": True, "grant": out})
        if args.case:
            case = db.get(ComplianceCase, _id(args.case, "a case"))
            if case is None:
                return _refuse("There is no such case.")
            out = _case_summary(db, case)
            out["auditor_provenance"] = rights.provenance(db, db.get(User, case.auditor_id))
            if out["host_may_approve"]:
                # The justification is shown to whoever may approve: here, only when the operator may.
                from app.core.security import open_case_field
                try:
                    out["justification"] = open_case_field(case.id, case.justification_enc, "justification")
                except Exception:  # noqa: BLE001 -- a sealed value that does not open is shown as such, never as text
                    out["justification"] = None
                    out["justification_unreadable"] = True
            return _answer({"ok": True, "case": out})
        return _refuse("Name what to show with --grant or --case (see: list).")

    if args.action == "grant-approve":
        return _grant_approve(db, args)

    if args.action == "revoke-auditor":
        user = db.query(User).filter(User.username == args.username).first() if args.username else None
        if user is None:
            return _refuse(f"There is no account named {args.username!r}." if args.username
                           else "Name the account with --username.")
        problem = confirmation_problem(args.username, args.confirm_username)
        if problem:
            return _refuse(problem)
        grant = rights.open_grant(db, user.id, lock=True)
        if grant is None:
            return _refuse(f"{user.username} holds no auditor right and none is proposed.")
        rights.revoke(db, grant, actor=None, reason=(args.reason or "").strip() or None)
        db.commit()
        return _answer({"ok": True, "revoked": rights.grant_dict(db, grant)})

    # The case steps.
    case = db.get(ComplianceCase, _id(args.case, "a case")) if args.case else None
    if case is None:
        return _refuse("There is no such case." if args.case else "Name the case with --case (see: list).")
    problem = case_confirmation_problem(case.id, args.confirm_case)
    if problem:
        return _refuse(problem)
    if args.action == "reject" and not (args.reason or "").strip():
        return _refuse("Say why with --reason: the auditor sees it.")
    if args.action == "approve":
        if not rights.access_enabled():
            return _refuse(ACCESS_OFF)
        from app.core import case_eligibility
        independent = case_eligibility.independent_approvers(db, case)
        if independent:
            from app.core import legal_holds
            legal_holds.record_refusal(db, "case_approved", case, actor=None, reason="independent_admin")
            return _refuse("An independent administrator can approve this case "
                           f"({', '.join(sorted(a.username for a in independent))}), so the server's operator may "
                           "not: the host operator has no account the approval rule could check.")
    step = CASE_STEPS.get(args.action)
    if step is None:
        return _refuse(f"{args.action} is not available from the host in this release.")
    result = step(db, case, reason=(args.reason or "").strip() or None)
    db.commit()
    return _answer({"ok": True, "case": result})


def _grant_approve(db, args) -> None:
    from app.core import auditor_rights as rights
    from app.core.models import User
    if not args.grant:
        return _refuse("Name the auditor grant with --grant (see: list).")
    grant = rights.grant_by_id(db, _id(args.grant, "an auditor grant"), lock=True)
    if grant is None:
        return _refuse("There is no such auditor grant.")
    holder = db.get(User, grant.user_id) if grant.user_id is not None else None
    problem = confirmation_problem(holder.username if holder is not None else None, args.confirm_username)
    if problem:
        return _refuse(problem)

    def refused(reason, message, reasons=None):
        rights.record_refusal(db, actor=None, step="grant-approve", reason=reason, grant=grant, reasons=reasons)
        return _refuse(message)

    if not rights.access_enabled():
        return _refuse(ACCESS_OFF)
    if grant.status != "proposed":
        return refused(rights.NOT_PROPOSED, "That auditor right is not waiting for approval.")
    if rights.is_lapsed(grant):
        return refused(rights.LAPSED, rights.text(rights.LAPSED).capitalize() + ".")
    independent = rights.independent_approvers(db, grant)
    if independent:
        return refused("independent_admin",
                       "An independent administrator can approve this auditor right "
                       f"({', '.join(sorted(a.username for a in independent))}), so the server's operator may not: "
                       "the host operator has no account the approval rule could check.")
    problems = rights.preconditions(db, holder)
    if problems:
        return refused(problems[0], "The account cannot hold the auditor right: "
                       + "; ".join(rights.text(p) for p in problems) + ".", reasons=problems)
    rights.approve(db, grant, approver=None)
    db.commit()
    return _answer({"ok": True, "granted": rights.grant_dict(db, grant)})


if __name__ == "__main__":
    # ``python -m`` runs this file as __main__, a second copy of the module: the modules that own the case steps
    # register them into app.core.host_compliance, which the web app imports. Run that one, so its CASE_STEPS
    # are the ones looked up.
    from app.core import host_compliance as _imported
    sys.exit(_imported.run())
