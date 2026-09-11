"""Changing who can reach a vault must leave a trace.

Access control was the largest hole in the audit log. Granting a person access to a vault, granting a
whole group, or adding someone to a group that already has access — none of it wrote an audit row. The log recorded the uploads and the logins while the permission changes that
allowed them passed unrecorded, which is the one thing a security log cannot be missing.

Measured across every state-changing endpoint in the API, before and after:

    130 state-changing endpoints · 91 audited · 39 silent      (before)
    130 state-changing endpoints · 97 audited · 33 silent      (after)

The six added here are the access-control set that was genuinely missing. Device lifecycle looked
missing too and was not: those endpoints already log through `_audit_device`, a second audit helper
the first scan did not know about, so they were counted as silent when they were covered. Adding
writes there produced a DUPLICATE row per event, which is why they are absent now — a log with two
entries for one action is a worse log, not a more complete one.

The remaining 33 are policy and routine actions — notification reads, favourite toggles, per-chunk
upload progress — deliberately left alone: auditing those would bury the entries added here, and a
log nobody reads is not an improvement on one that is incomplete.

All six go through one helper so they share a shape and cannot drift apart entry by entry. It is
best-effort on purpose: the permission change has already been committed when it runs, so an
exception there would report failure for work that succeeded and invite a retry that double-applies
it.

Lanes:
  * unit        — every access-control endpoint records something, the helper cannot break the
                  request, and the revoke path only logs when a revoke actually happened.
  * integration — grant access over HTTP and read the row back out of the audit log.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"

# The endpoints whose whole purpose is to change who can reach what.
ACCESS_ENDPOINTS = [
    ('post', "/vaults/{vault_id}/permissions"),
    ('delete', "/vaults/{vault_id}/permissions/{user_id}"),
    ('post', "/vaults/{vault_id}/group-access"),
    ('delete', "/vaults/{vault_id}/group-access/{group_id}"),
    ('post', "/groups/{group_id}/members"),
    ('delete', "/groups/{group_id}/members/{user_id}"),
]

# Device lifecycle is NOT in the list above on purpose: it is audited through `_audit_device`, and a
# second write here would double-log every device event. The test below pins that it stays covered by
# something, so removing the existing helper cannot pass unnoticed.
DEVICE_ENDPOINTS = [
    ('post', "/devices/{device_id}/revoke"),
    ('delete', "/devices/{device_id}"),
    ('post', "/devices/{device_id}/grants/{vault_id}/revoke"),
    ('post', "/devices"),
    ('post', "/devices/{device_id}/grants"),
]


def _endpoint_body(src, verb, path):
    marker = f'@app.{verb}("{path}")'
    start = src.index(marker)
    nxt = re.search(r"^@app\.[a-z]+\(", src[start + len(marker):], re.M)
    return src[start:start + len(marker) + (nxt.start() if nxt else len(src))]


@pytest.mark.unit
@pytest.mark.parametrize("verb,path", ACCESS_ENDPOINTS)
def test_every_access_change_is_recorded(verb, path):
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, verb, path)
    assert "_audit_access_change(" in body, (
        f"{verb.upper()} {path} changes who can reach a vault and writes no audit row")


@pytest.mark.unit
@pytest.mark.parametrize("verb,path", DEVICE_ENDPOINTS)
def test_device_lifecycle_is_audited_exactly_once(verb, path):
    """Covered by the pre-existing helper, and not by a second write on top of it."""
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, verb, path)
    assert "_audit_device(" in body, f"{verb.upper()} {path} lost its audit write"
    assert "_audit_access_change(" not in body, (
        f"{verb.upper()} {path} would write TWO rows for one event — it already logs via "
        f"_audit_device")


@pytest.mark.unit
def test_the_audit_write_can_never_fail_the_request():
    """The change is already committed when the log is written.

    Letting an audit failure raise would report an error for work that succeeded, and the obvious
    response — retry — would apply the permission change twice.
    """
    src = API.read_text(encoding="utf-8")
    start = src.index("def _audit_access_change(")
    body = src[start:src.index("\ndef ", start + 1)]
    assert "try:" in body and "except Exception" in body, (
        "the helper must swallow its own failures")
    assert "raise" not in body, "the helper must never re-raise into the request"


@pytest.mark.unit
def test_a_revoke_is_logged_only_when_something_was_revoked():
    """The rowcount check comes first, so a 404 is not recorded as a successful revocation."""
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, 'delete', "/vaults/{vault_id}/permissions/{user_id}")
    rowcount = body.index("if result.rowcount == 0:")
    logged = body.index('_audit_access_change(db, current_user, "vault_permission_revoked"')
    assert rowcount < logged, (
        "logging before the rowcount check would record every 404 as a revoke that happened")


@pytest.mark.unit
def test_the_helper_is_the_single_shape_for_all_of_them():
    """Six call sites, one helper. Hand-rolled AuditLogger calls at each would drift."""
    src = API.read_text(encoding="utf-8")
    calls = src.count("_audit_access_change(db,")
    # 6 call sites plus the definition line itself.
    assert calls == 7, f"expected the access-control set to route through the helper, found {calls}"


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_granting_access_shows_up_in_the_audit_log(admin, temp_vault, temp_user):
    """Read the row back out of the log, rather than trusting that the call site exists."""
    before = admin.get("/audit/log?action=vault_permission_granted").json()
    n_before = len(before) if isinstance(before, list) else 0

    r = admin.post(f"/vaults/{temp_vault['id']}/permissions",
                   json={"user_id": temp_user["id"], "level": "read"})
    assert r.status_code in (200, 201), r.text

    after = admin.get("/audit/log?action=vault_permission_granted").json()
    assert isinstance(after, list), after
    assert len(after) > n_before, "granting access wrote no audit row"

    row = after[0]
    assert row.get("action") == "vault_permission_granted", row
    assert str(temp_vault["id"]) == str(row.get("resource_id")), (
        f"the row should name the vault whose access changed: {row}")
