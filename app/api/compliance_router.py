"""Compliance access: the auditor right, cases, legal holds.

Every step that grants or uses the power to read someone else's vault (proposing and approving an auditor
grant, reconfirming one, requesting, approving or extending a case, exporting from it, placing a legal hold and
confirming or releasing it) asks for the compliance step-up: the password and a TOTP or recovery code, every
time, whatever the admin's step-up matrix says (app/core/fixed_step_up.py, compliance_step_up). The check is
called inside the route's body, which lets a plain ``def`` route use it, and is made here, at import, so the
boot contract sees each of these actions guarded.

Routes here never use endpoint groups (whose administrator bypass would let any administrator through) and
never name a permission: authorization does not know about compliance access.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.core import fixed_step_up

router = APIRouter(tags=["Compliance"])

STEP_UP_GRANT_PROPOSE = fixed_step_up.compliance_step_up("compliance.grant.propose")
STEP_UP_GRANT_APPROVE = fixed_step_up.compliance_step_up("compliance.grant.approve")
STEP_UP_GRANT_RECONFIRM = fixed_step_up.compliance_step_up("compliance.grant.reconfirm")
STEP_UP_CASE_REQUEST = fixed_step_up.compliance_step_up("compliance.case.request")
STEP_UP_CASE_APPROVE = fixed_step_up.compliance_step_up("compliance.case.approve")
STEP_UP_CASE_EXPORT = fixed_step_up.compliance_step_up("compliance.case.export")
STEP_UP_HOLD_PLACE = fixed_step_up.compliance_step_up("compliance.hold.place")
STEP_UP_HOLD_DECIDE = fixed_step_up.compliance_step_up("compliance.hold.decide")
