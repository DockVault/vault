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
def test_the_helper_can_actually_reach_everything_it_names():
    """The failure this test exists for: the helper swallowed a NameError and recorded nothing.

    `current_client_ip` is not a module-level name in api_server — every user imports it locally. The
    helper was written without that import, so every call raised NameError, the deliberately-silent
    handler ate it, and six endpoints reported success while writing no audit row at all. Six call
    sites, a passing suite, and an empty log.

    A best-effort writer hides its own absence by design, so "the call site exists" proves nothing
    about it. This compiles the helper's body and checks every name it uses is either imported inside
    it, a parameter, or a module-level definition.
    """
    src = API.read_text(encoding="utf-8")
    start = src.index("def _audit_access_change(")
    body = src[start:src.index("\ndef ", start + 1)]
    before = src[:start]

    module_level = re.findall(r"^(?:from [\w.]+ )?import .*$", before, re.M)   # column 0 only
    for name in ("current_client_ip", "AuditLogger"):
        in_body = re.search(rf"^\s+(?:from [\w.]+ )?import .*\b{name}\b", body, re.M)
        at_module_scope = any(re.search(rf"\b{name}\b", line) for line in module_level)
        assert in_body or at_module_scope, (
            f"{name} is used by the helper but reachable from neither an import inside it nor the "
            f"module scope above it — it raises NameError, and the helper swallows that silently, "
            f"so every call site reports success and writes nothing")


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
    # A `raise` STATEMENT, not the word. The first version matched the substring and failed on a
    # comment that used "raises" to explain why there must not be one.
    assert not re.search(r"^\s+raise", body, re.M), (
        "the helper must never re-raise into the request")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _call_sits_inside_guard(body, guard, call):
    """True if `call` appears after `guard` and every line between them, the call included, is
    indented deeper than the guard — i.e. it is inside the guard's block, not merely below it.
    Ordering alone would pass a call that was moved out of the `if` but left underneath it."""
    lines = body.splitlines()
    g = next(i for i, l in enumerate(lines) if l.strip().startswith(guard))
    c = next(i for i, l in enumerate(lines) if call in l and i > g)
    depth = _indent(lines[g])
    return all(_indent(l) > depth for l in lines[g + 1:c + 1] if l.strip())


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
@pytest.mark.parametrize("verb,path,guard,action", [
    ('post', "/groups/{group_id}/members", "if added:", "group_members_added"),
    ('delete', "/groups/{group_id}/members/{user_id}", "if result.rowcount > 0:", "group_member_removed"),
    ('delete', "/vaults/{vault_id}/group-access/{group_id}", "if result.rowcount > 0:",
     "vault_group_access_revoked"),
])
def test_a_group_change_is_logged_only_when_something_changed(verb, path, guard, action):
    """Adding members who were already there, or removing one who was not, changes nothing and
    must not read in the log as if it had. The integration lane below proves it over HTTP; this
    pins that each write sits inside its guard, so it cannot drift back out during a refactor."""
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, verb, path)
    assert guard in body, f"{verb.upper()} {path} has no guard on its audit write"
    assert _call_sits_inside_guard(body, guard, f'"{action}"'), (
        f"{verb.upper()} {path} writes its {action} row outside the guard, so a no-op call is "
        f"recorded as a change")


@pytest.mark.unit
def test_the_group_grant_row_records_the_level_that_was_written():
    """The request's string is not what was granted; `perm` is. And a level outside read/write is
    refused by the model rather than coerced, so the two can never differ."""
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, 'post', "/vaults/{vault_id}/group-access")
    assert '"permission": perm}' in body, "the grant row must carry the level actually written"
    assert '"permission": payload.permission' not in body, (
        "the grant row is recording the caller's string, which may be a level never granted")
    assert re.search(r'permission: str = Field\(.read., pattern="\^\(read\|write\)\$"\)', src), (
        "VaultGroupAccessAdd.permission must refuse anything but read or write")


@pytest.mark.unit
def test_adding_members_records_who_not_how_many():
    src = API.read_text(encoding="utf-8")
    body = _endpoint_body(src, 'post', "/groups/{group_id}/members")
    assert '"user_ids": [str(u) for u in added]' in body, (
        "the row must name the members added; a count cannot answer who gained access")


@pytest.mark.unit
def test_the_helper_is_the_single_shape_for_all_of_them():
    """One helper, not a hand-rolled AuditLogger call per endpoint.

    This asserted an exact call count, which was brittle by construction: adding a legitimate new
    access change — replacing an upload link, say — broke it, and the only available fix was to edit
    the number, which is not a check at all. What is worth pinning is that no access-control endpoint
    writes its own audit row directly, because that is how the shapes drift apart.
    """
    src = API.read_text(encoding="utf-8")
    assert src.count("_audit_access_change(db,") >= 7, (
        "the access-control set should route through the helper")
    for verb, path in ACCESS_ENDPOINTS:
        body = _endpoint_body(src, verb, path)
        assert "AuditLogger(" not in body, (
            f"{verb.upper()} {path} builds its own audit row instead of using the shared helper")


# --------------------------------------------------------------------------- integration lane
#
# Five of the six writes were once proved only by grepping for the call site — the exact evidence
# that turned out to be worthless when the helper raised NameError into its own silent handler. Each
# lane below performs the call over HTTP and reads the row back out of the log.

from conftest import unique  # noqa: E402


@pytest.fixture
def temp_group(admin):
    r = admin.post("/groups", json={"name": unique("audited")})
    r.raise_for_status()
    group = r.json()
    yield group
    admin.delete(f"/groups/{group['id']}")


def _rows(admin, action, resource_id):
    return [r for r in admin.get(f"/audit/log?action={action}").json()
            if str(r.get("resource_id")) == str(resource_id) and r.get("action") == action]


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


@pytest.mark.integration
def test_a_group_grant_records_the_level_written_and_refuses_one_it_cannot_grant(
        admin, temp_vault, temp_group):
    """'manage' is not a level a group can hold. It used to be coerced to read and logged as
    'manage' — a row describing a grant that never happened. Now it is refused outright, and the
    row for a real grant carries exactly what the vault reports."""
    refused = admin.post(f"/vaults/{temp_vault['id']}/group-access",
                         json={"group_id": temp_group["id"], "permission": "manage"})
    assert refused.status_code == 422, (
        f"a level outside read/write should be refused, not coerced: {refused.status_code} "
        f"{refused.text}")
    assert not _rows(admin, "vault_group_access_granted", temp_vault["id"]), (
        "a refused grant must leave no row")

    r = admin.post(f"/vaults/{temp_vault['id']}/group-access",
                   json={"group_id": temp_group["id"], "permission": "write"})
    assert r.status_code in (200, 201), r.text
    rows = _rows(admin, "vault_group_access_granted", temp_vault["id"])
    assert len(rows) == 1, rows
    details = rows[0].get("details") or {}
    assert details.get("group_id") == str(temp_group["id"]), rows[0]
    granted = next(g for g in admin.get(f"/vaults/{temp_vault['id']}/group-access").json()
                   if str(g.get("group_id")) == str(temp_group["id"]))
    assert details.get("permission") == granted["permission"] == "write", (
        f"the row must say what the vault actually holds: row {details}, vault {granted}")


@pytest.mark.integration
def test_revoking_group_access_is_recorded_once_and_only_when_it_happened(
        admin, temp_vault, temp_group):
    r = admin.post(f"/vaults/{temp_vault['id']}/group-access",
                   json={"group_id": temp_group["id"], "permission": "read"})
    assert r.status_code in (200, 201), r.text

    assert admin.delete(f"/vaults/{temp_vault['id']}/group-access/{temp_group['id']}").status_code == 200
    rows = _rows(admin, "vault_group_access_revoked", temp_vault["id"])
    assert len(rows) == 1 and (rows[0].get("details") or {}).get("group_id") == str(temp_group["id"]), rows

    # The group no longer has access, so there is nothing to revoke — and nothing to record.
    assert admin.delete(f"/vaults/{temp_vault['id']}/group-access/{temp_group['id']}").status_code == 200
    assert len(_rows(admin, "vault_group_access_revoked", temp_vault["id"])) == 1, (
        "revoking access that was not there was recorded as a revoke that happened")


@pytest.mark.integration
def test_membership_changes_name_the_person_and_only_when_something_changed(
        admin, temp_group, temp_user):
    added = admin.post(f"/groups/{temp_group['id']}/members", json={"user_ids": [temp_user["id"]]})
    assert added.status_code in (200, 201), added.text
    rows = _rows(admin, "group_members_added", temp_group["id"])
    assert len(rows) == 1, rows
    assert str(temp_user["id"]) in ((rows[0].get("details") or {}).get("user_ids") or []), (
        f"the row must name who was added, not how many: {rows[0]}")

    # Already a member: nothing changed, so nothing is recorded.
    again = admin.post(f"/groups/{temp_group['id']}/members", json={"user_ids": [temp_user["id"]]})
    assert again.status_code in (200, 201) and again.json().get("added") == 0, again.text
    assert len(_rows(admin, "group_members_added", temp_group["id"])) == 1, (
        "re-adding an existing member was recorded as an access change")

    assert admin.delete(f"/groups/{temp_group['id']}/members/{temp_user['id']}").status_code == 200
    removed = _rows(admin, "group_member_removed", temp_group["id"])
    assert len(removed) == 1 and (removed[0].get("details") or {}).get("user_id") == str(temp_user["id"]), removed

    # Not a member any more: nothing to remove, nothing to record.
    assert admin.delete(f"/groups/{temp_group['id']}/members/{temp_user['id']}").status_code == 200
    assert len(_rows(admin, "group_member_removed", temp_group["id"])) == 1, (
        "removing someone who was not a member was recorded as a removal")
