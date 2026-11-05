"""Shared helpers for the tests of POST /auth/sign-out (the API's and the web app's): a token's claims, the session
row a token names, a token the server signs with the claims a test chooses (an expired copy of a session's token
among them), and the sign-outs recorded for an account. Imported by the test modules that need them; holds no
tests."""
import hashlib
import json

import jwt

from _account_change_helpers import in_api_container, psql


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def session_row(token):
    """(is_active, revoked) of the session a token names, as psql prints it: "t|f" is signed in."""
    digest = hashlib.sha256(claims(token)["session_token"].encode()).hexdigest()
    return psql(f"SELECT is_active, revoked FROM active_sessions WHERE session_token = '{digest}'")


def signed_by_the_server(chosen, minutes):
    """A token the server signs with the claims `chosen`, valid for `minutes` from now (negative: expired)."""
    out = in_api_container(
        "import json\n"
        "from datetime import timedelta\n"
        "from app.core.security import create_access_token\n"
        f"print(create_access_token(json.loads({json.dumps(json.dumps(chosen))}), timedelta(minutes={int(minutes)})))\n")
    return out.stdout.strip().splitlines()[-1]


def expired_copy(token):
    """The same session's token, signed by the server, expired five minutes ago."""
    return signed_by_the_server({k: v for k, v in claims(token).items() if k not in ("exp", "iat")}, -5)


def sign_outs_recorded(user_id):
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE user_id = '{user_id}' AND action = 'logout'"))
