"""One independence rule for every two-person approval, offline (app/core/independence.py).

The rule on who may approve an administrator's second change to someone's sign-in details moved here with
identical results: credential_changes uses this one implementation, and its own tests run unchanged. Compliance
access applies the same rule with the auditor as the account it is about, and refuses besides an
administrator in the auditor's lineage, whoever created the auditor's account, whoever changed its sign-in
details while the grant stood, a person the case concerns and the grant's proposer. The cases below are the
two ways one person could otherwise read a vault (a stand-in administrator, a stand-in account), a fresh
administrator, and a changer.
"""
import ast
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import credential_changes as cc  # noqa: E402
from app.core import independence as ind  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
AT = datetime(2026, 10, 1, 12, 0, 0)
OLD = AT - timedelta(days=400)


def _grant(lineage=(), granted_at=OLD):
    return SimpleNamespace(lineage=[str(x) for x in lineage], granted_at=granted_at)


# --------------------------------------------------------------------------- one implementation

def test_credential_changes_uses_the_one_rule_and_its_reasons():
    assert cc.refusal_reason is ind.refusal_reason
    for name in ("ASKED", "OWN_ACCOUNT", "REQUESTER_GONE", "MADE_BY_REQUESTER", "MADE_REQUESTER", "CHANGED_ACCOUNT",
                 "BECAME_ADMIN_AFTER", "NEW_ADMIN", "PASSWORD_NOT_OWN", "TENURE"):
        assert getattr(cc, name) is getattr(ind, name), name
    assert ind.TENURE == timedelta(days=14)
    tree = ast.parse((ROOT / "app" / "core" / "credential_changes.py").read_text(encoding="utf-8"))
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assigned = {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    assert "refusal_reason" not in defined
    assert not assigned & {"ASKED", "OWN_ACCOUNT", "MADE_BY_REQUESTER", "MADE_REQUESTER", "CHANGED_ACCOUNT",
                           "BECAME_ADMIN_AFTER", "NEW_ADMIN", "PASSWORD_NOT_OWN", "TENURE", "REQUESTER_GONE"}


def test_the_reasons_are_distinct():
    reasons = [ind.ASKED, ind.OWN_ACCOUNT, ind.REQUESTER_GONE, ind.MADE_BY_REQUESTER, ind.MADE_REQUESTER,
               ind.CHANGED_ACCOUNT, ind.BECAME_ADMIN_AFTER, ind.NEW_ADMIN, ind.PASSWORD_NOT_OWN, ind.MADE_BY_SUBJECT,
               ind.MADE_SUBJECT, ind.CREATED_SUBJECT, ind.CHANGED_SUBJECT, ind.CONCERNED, ind.PROPOSED]
    assert len(set(reasons)) == len(reasons)


# --------------------------------------------------------------------------- compliance

AUDITOR, PROPOSER, APPROVER, MAKER, OTHER = (uuid.uuid4() for _ in range(5))


def _decide(approver=APPROVER, *, requester=AUDITOR, subject=AUDITOR, approver_grant=None, requester_grant=None,
            subject_grant=None, changed=(), password_by_other=False, created_by=None, changers=(), concerned=(),
            proposer=PROPOSER):
    return ind.compliance_refusal_reason(
        approver, requester_id=requester, subject_id=subject, approver_grant=approver_grant,
        requester_grant=requester_grant, subject_grant=subject_grant, changed=set(changed), requested_at=AT,
        approver_password_set_by_other=password_by_other, subject_created_by=created_by,
        credential_changers=changers, concerned=concerned, proposer_id=proposer)


# (name, the decision's arguments, the reason or None)
CASES = [
    ("an independent administrator approves a case", {}, None),
    ("an independent administrator approves a grant someone else proposed", {"requester": PROPOSER}, None),
    # A stand-in administrator: the auditor made the approver an administrator.
    ("stand-in admin: the auditor's case", {"approver_grant": _grant([AUDITOR])}, ind.MADE_BY_REQUESTER),
    ("stand-in admin: the auditor's grant, proposed by another", {"requester": PROPOSER,
                                                                  "approver_grant": _grant([AUDITOR])},
     ind.MADE_BY_SUBJECT),
    ("stand-in admin, two steps down the lineage", {"requester": PROPOSER,
                                                    "approver_grant": _grant([MAKER, AUDITOR])}, ind.MADE_BY_SUBJECT),
    ("the approver made the auditor an administrator: the case", {"requester_grant": _grant([APPROVER]),
                                                                   "subject_grant": _grant([APPROVER])},
     ind.MADE_REQUESTER),
    ("the approver made the auditor an administrator: the grant", {"requester": PROPOSER,
                                                                    "subject_grant": _grant([APPROVER])},
     ind.MADE_SUBJECT),
    # A stand-in account: the approver created the auditor's account.
    ("stand-in account: the case", {"created_by": APPROVER}, ind.CREATED_SUBJECT),
    ("stand-in account: the grant", {"requester": PROPOSER, "created_by": str(APPROVER)}, ind.CREATED_SUBJECT),
    ("someone else created the account", {"created_by": OTHER}, None),
    # A fresh administrator.
    ("an administrator for 13 days", {"approver_grant": _grant(granted_at=AT - timedelta(days=13))}, ind.NEW_ADMIN),
    ("an administrator since after the request", {"approver_grant": _grant(granted_at=AT + timedelta(hours=1))},
     ind.BECAME_ADMIN_AFTER),
    ("an administrator for exactly 14 days", {"approver_grant": _grant(granted_at=AT - timedelta(days=14))}, None),
    # A changer.
    ("changed the auditor's sign-in while the grant stood", {"changers": [{"id": str(APPROVER), "name": "x",
                                                                           "at": "2026-01-01T00:00:00"}]},
     ind.CHANGED_SUBJECT),
    ("a changer listed by a bare id", {"changers": [APPROVER]}, ind.CHANGED_SUBJECT),
    ("the host operator changed it", {"changers": [{"id": None, "name": "operator@host"}]}, None),
    ("someone else changed it", {"changers": [{"id": str(OTHER), "name": "o"}]}, None),
    ("changed the account in the 14 days before", {"changed": [APPROVER]}, ind.CHANGED_ACCOUNT),
    # The others the compliance rule adds.
    ("a person the case concerns", {"concerned": [OTHER, APPROVER]}, ind.CONCERNED),
    ("a person the case concerns, by text", {"concerned": [str(APPROVER)]}, ind.CONCERNED),
    ("the grant's proposer approves the case", {"proposer": APPROVER}, ind.PROPOSED),
    ("the grant's proposer, by text", {"proposer": str(APPROVER)}, ind.PROPOSED),
    ("no proposer known", {"proposer": None}, None),
    # The rule's own refusals come first.
    ("the auditor approves their own case", {"approver": AUDITOR}, ind.ASKED),
    ("the auditor approves their own grant", {"approver": AUDITOR, "requester": PROPOSER}, ind.OWN_ACCOUNT),
    ("the proposer approves the grant they proposed", {"approver": PROPOSER, "requester": PROPOSER}, ind.ASKED),
    ("a password someone else set", {"password_by_other": True}, ind.PASSWORD_NOT_OWN),
    ("lineage before creator", {"approver_grant": _grant([AUDITOR]), "created_by": APPROVER}, ind.MADE_BY_REQUESTER),
    ("fresh before concerned", {"approver_grant": _grant(granted_at=AT - timedelta(days=1)),
                                "concerned": [APPROVER]}, ind.NEW_ADMIN),
]


@pytest.mark.parametrize("name,kwargs,expected", CASES, ids=[c[0] for c in CASES])
def test_who_may_approve_a_compliance_step(name, kwargs, expected):
    kwargs = dict(kwargs)
    approver = kwargs.pop("approver", APPROVER)
    assert _decide(approver, **kwargs) == expected


def test_the_auditor_lineage_is_read_only_when_someone_else_asked():
    # The auditor asked (a case): their lineage is the requester's, read by the rule itself.
    assert _decide(approver_grant=_grant([AUDITOR])) == ind.MADE_BY_REQUESTER
    # No auditor named: nothing to read.
    assert _decide(subject=None, requester=PROPOSER, approver_grant=_grant([AUDITOR])) is None


@pytest.mark.parametrize("entries,expected", [
    ([], set()), (None, set()), ([{"id": "a"}, {"id": None}, {"name": "x"}, "b", None], {"a", "b"}),
    ([uuid.UUID(int=1)], {str(uuid.UUID(int=1))}),
])
def test_the_changers_of_a_grant_are_read_as_ids(entries, expected):
    assert ind.changer_ids(entries) == expected
