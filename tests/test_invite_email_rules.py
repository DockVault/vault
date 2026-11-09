"""An invitation's email address meets the account policy's email rules when it is made and when it is sent
again, offline: the policy may have changed in between, and a link the policy now refuses would be refused
when it is used.
"""
import ast
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

SOURCE = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
OFF = {"email_requirement": "optional", "signup_email_domain_mode": "off", "signup_email_domains": []}


@pytest.mark.parametrize("policy,email,refused", [
    ({}, None, None),
    ({}, "ada@example.com", None),
    ({"email_requirement": "required"}, None, "An email address is required for new accounts."),
    ({"email_requirement": "required"}, "ada@example.com", None),
    ({}, "ada@exämple.com", "That email domain is not permitted."),
    ({"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.org"]}, "ada@example.com",
     "That email domain is not permitted."),
    ({"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.com"]}, "ada@example.com", None),
    ({"signup_email_domain_mode": "denylist", "signup_email_domains": ["example.com"]}, "ada@sub.example.com",
     "That email domain is not permitted."),
])
def test_the_email_rules(policy, email, refused):
    assert api._invite_email_refusal({**OFF, **policy}, email) == refused


def _function(name):
    return next(n for n in ast.walk(ast.parse(SOURCE))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


@pytest.mark.parametrize("route,email", [("create_invite", "email"), ("resend_invite", "normalize_email(inv.email)")])
def test_making_and_resending_an_invitation_both_ask_the_rules(route, email):
    calls = [c for c in ast.walk(_function(route)) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Name) and c.func.id == "_invite_email_refusal"]
    assert len(calls) == 1 and ast.unparse(calls[0].args[1]) == email, route


def test_resend_asks_the_rules_before_it_revokes_anything():
    body = ast.unparse(_function("resend_invite"))
    assert body.index("_invite_email_refusal(") < body.index("AccountInvitation.revoked_at: now")
