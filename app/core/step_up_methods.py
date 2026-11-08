"""The ways a person can meet a step-up, as a table.

A step-up requirement has two parts (app/core/second_factor_policy.py): the **factor part** (``otp``: a code,
a recovery code, later a passkey) and the **password part** (``password``: the account password, later a
fresh sign-in at the identity provider). A method meets one part. The step-up route checks each part
separately and mints one receipt when both are met; this table says which methods to offer for a
requirement, in a fixed order, given what the account holds (app/core/active_factors.py) and what the
policy allows (``Context``). The receipt code never changes: a method that is not in this table cannot be
offered, and a method meets only the part the table says.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional

from app.core.active_factors import ActiveFactors

PASSWORD = "password"
TOTP = "totp"
EMAIL = "email"
RECOVERY = "recovery"
PASSKEY = "passkey"
IDP_REAUTH = "idp_reauth"

FACTOR_PART = "factor"
PASSWORD_PART = "password"


@dataclass(frozen=True)
class Context:
    """What the policy allows beyond the account's own factors."""
    passkey_step_up: bool = False     # a user-verified passkey may meet the factor part (the passkey policy)
    idp_reauth: bool = False          # a fresh sign-in at a linked provider may meet the password part


@dataclass(frozen=True)
class Method:
    name: str
    meets: FrozenSet[str]
    available: Callable[[ActiveFactors, Context], bool]


TABLE = (
    Method(TOTP, frozenset({FACTOR_PART}), lambda f, c: f.code_method == TOTP),
    Method(EMAIL, frozenset({FACTOR_PART}), lambda f, c: f.code_method == EMAIL),
    Method(RECOVERY, frozenset({FACTOR_PART}), lambda f, c: f.code),
    Method(PASSKEY, frozenset({FACTOR_PART}), lambda f, c: f.passkeys > 0 and c.passkey_step_up),
    Method(IDP_REAUTH, frozenset({PASSWORD_PART}), lambda f, c: c.idp_reauth),
    Method(PASSWORD, frozenset({PASSWORD_PART}), lambda f, c: True),
)
_BY_NAME = {m.name: m for m in TABLE}


def offered(req: dict, factors: ActiveFactors, context: Optional[Context] = None) -> List[str]:
    """The methods to offer for ``req`` (``{otp, password, must_enroll}``): in table order, every method that
    meets a part the requirement asks for and that the account can present. A requirement the account must
    enroll for first offers nothing."""
    if req.get("must_enroll"):
        return []
    context = context or Context()
    out = []
    for method in TABLE:
        wanted = ((FACTOR_PART in method.meets and bool(req.get("otp")))
                  or (PASSWORD_PART in method.meets and bool(req.get("password"))))
        if wanted and method.available(factors, context):
            out.append(method.name)
    return out


def meets_factor(name: str) -> bool:
    method = _BY_NAME.get((name or "").lower())
    return method is not None and FACTOR_PART in method.meets


def meets_password(name: str) -> bool:
    method = _BY_NAME.get((name or "").lower())
    return method is not None and PASSWORD_PART in method.meets
