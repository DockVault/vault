"""Server-side input-handling hardening.

Covers four defence layers on the non-injection server surface:

1. A `str`-typed id path param that is compared against a UUID column must be coerced up front
   (400 on a malformed id) so a database cast error can't surface schema/SQL in a 500 body; and
   no 500 response may ever echo the raw exception text (`str(e)`).
2. The audit-log CSV export neutralises spreadsheet formula cells (an attacker-influenced value
   such as a failed-login username can't execute when an admin opens the export).
3. The dashboard recent-events endpoint clamps its client-supplied `limit` (over-fetch / negative
   value can't DoS or error).
4. The user-create handler no longer dumps the request model (which includes the plaintext
   password) to stdout.

The behavioural checks run against the live instance; two source-level locks read the shipped
api_server.py so a future edit can't silently reintroduce the leak.
"""
import uuid
from pathlib import Path

import pytest

from conftest import unique

API_SERVER = (Path(__file__).resolve().parent.parent / "api_server.py").read_text(
    encoding="utf-8", errors="ignore"
)


# --------------------------------------------------------------------------------------------------
# Error-based schema disclosure (str-typed id + verbose 500)
# --------------------------------------------------------------------------------------------------
def test_user_activity_rejects_non_uuid_id(admin):
    r = admin.get("/api/security/user-activity/not-a-uuid-abc")
    assert r.status_code == 400, r.text
    body = r.text.lower()
    # None of the underlying SQL / driver / schema must leak into the response.
    for leak in ("select", "psycopg2", "audit_logs", "invalidtextrepresentation", "::uuid"):
        assert leak not in body, f"schema/SQL leaked in 400 body: {r.text!r}"


def test_user_activity_accepts_valid_uuid(admin):
    # A well-formed (but unused) UUID resolves cleanly to an empty analysis, never a 500.
    r = admin.get(f"/api/security/user-activity/{uuid.uuid4()}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("total_actions") == 0


def test_verbose_500_detail_is_sanitised_in_source():
    # The user-activity handler must not interpolate str(e) into its 500 detail...
    assert "Error analyzing user activity: {str(e)}" not in API_SERVER
    # ...and a global handler must sanitise ANY HTTPException(500) detail (defence-in-depth for the
    # broader `HTTPException(500, detail=f"…{str(e)}")` pattern).
    assert "@app.exception_handler(StarletteHTTPException)" in API_SERVER
    assert "Sanitized HTTP 500" in API_SERVER


# --------------------------------------------------------------------------------------------------
# CSV / formula injection in the audit export
# --------------------------------------------------------------------------------------------------
def test_audit_export_neutralises_formula_username(admin, anon):
    marker = unique("pwn")
    formula = f"=cmd|'/c {marker}'!A1"  # no comma/quote/newline -> written to CSV unquoted
    # An UNAUTHENTICATED failed login records the attacker-chosen username verbatim in the audit log.
    r = anon.post("/auth/login", json={"username": formula, "password": "wrong-Passw0rd!"})
    assert r.status_code == 401, r.text

    export = admin.get("/audit/export")
    assert export.status_code == 200, export.text
    text = export.text
    # Non-vacuity: the row we just created is present.
    assert formula in text, "failed-login username was not recorded in the export"
    # The formula cell is neutralised with a leading apostrophe...
    assert ("'" + formula) in text, "formula cell was not apostrophe-prefixed"
    # ...so it never appears as a bare comma-adjacent field that a spreadsheet would evaluate.
    assert ("," + formula) not in text, "un-neutralised formula cell present in export"


def test_login_rejects_markup_username(anon):
    # The attempted login username is echoed into the failed-login SecurityAlert the admin API
    # returns; reject angle brackets at the boundary (mirrors UserCreate.username) so a hostile
    # value can never carry markup into an admin surface. A malformed username is a 422, not a 401.
    r = anon.post("/auth/login", json={"username": "a<script>b", "password": "wrong-Passw0rd!"})
    assert r.status_code == 422, r.text


# --------------------------------------------------------------------------------------------------
# Unbounded dashboard limit
# --------------------------------------------------------------------------------------------------
def test_dashboard_recent_events_clamps_large_limit(admin):
    r = admin.get("/api/dashboard/recent-events", params={"limit": 100000})
    assert r.status_code == 200, r.text
    rows = r.json()
    assert isinstance(rows, list)
    assert len(rows) <= 100, f"limit not clamped: got {len(rows)} rows"


def test_dashboard_recent_events_survives_negative_limit(admin):
    # A negative limit must be clamped, not passed to the DB (LIMIT -5 -> error -> 500).
    r = admin.get("/api/dashboard/recent-events", params={"limit": -5})
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)


# --------------------------------------------------------------------------------------------------
# Credential leak in a debug print
# --------------------------------------------------------------------------------------------------
def test_user_create_does_not_dump_request_model_to_stdout():
    # The old [DEBUG] prints dumped user_create.model_dump() — which includes the plaintext
    # password — to container stdout on every user creation.
    assert "[DEBUG] UserCreate" not in API_SERVER
    assert "user_create.model_dump()" not in API_SERVER
