"""Backend contract for the two-section temp-credentials page: the listing carries the section
split, the device DISPLAY NAME, and the lifecycle state for device-minted credentials, and never a
device id, device secret, or credential secret. The per-user interactive cap serialises under a
transaction-scoped advisory lock, never a users-row lock.

The listing runs behind get_current_user + a DB session and create_temporary_credential needs the
full app to import, so the field contract and the lock are pinned from source; the HTTP rows/scoping
and the browser render are proven in the live and UI lanes, and the two-mint race in the live lane.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"
AUTH = ROOT / "app" / "services" / "auth_service.py"


def _list_endpoint_src():
    s = API.read_text(encoding="utf-8")
    start = s.index("async def list_temp_credentials(")
    end = s.index("\n@app.", start)   # up to the next route declaration
    return s[start:end]


def test_the_listing_exposes_the_section_split_the_device_name_and_the_lifecycle():
    body = _list_endpoint_src()
    assert "'is_device_credential'" in body      # the boolean the two sections split on
    assert "'device_name'" in body               # the per-computer section names WHICH computer
    assert "'lifecycle'" in body                 # active / in-use / expired
    assert "display_lifecycle(" in body          # ...derived by the shared lifecycle helper


def test_the_device_name_is_the_display_label_never_an_identifier():
    body = _list_endpoint_src()
    assert "Device.label" in body                       # the display name is the label
    assert "_device_names.get(cred.device_id)" in body  # keyed internally, never emitted


def test_the_listing_never_renders_a_device_id_or_any_secret():
    body = _list_endpoint_src()
    assert "'device_id':" not in body            # the raw device id is never a rendered field
    for forbidden in ("credential_hash", "secret_hash", "credential_string", "prev_secret",
                      "'secret'", "device.secret", "cred.secret"):
        assert forbidden not in body, f"the listing renders a secret/identifier: {forbidden}"


def test_the_per_user_cap_serializes_with_an_advisory_lock_not_a_row_lock():
    # The cap serializes concurrent same-user mints WITHOUT locking the users ROW: a row lock there
    # deadlocked the FK KEY SHARE the audit insert takes on that row. It uses a transaction-scoped
    # advisory lock keyed by the user, and its owner read takes no row lock. (mutation: revert to a
    # with_for_update on the users query -> red)
    flat = re.sub(r"\s+", " ", AUTH.read_text(encoding="utf-8"))
    assert "pg_advisory_xact_lock(" in flat and "_TEMP_CRED_CAP_ADVISORY_CLASS" in flat
    assert "hashtext(:uid)" in flat   # keyed on the user id (per-user serialisation, not global)
    reads = re.findall(r"query\(User\)\.filter\(User\.id == user_id\)[^;]{0,120}?\.first\(\)", flat)
    assert reads, "the cap owner read was not found"
    for q in reads:
        assert "with_for_update" not in q, "the per-user cap still row-locks the users row"


def test_both_credential_cap_refusals_roll_back_before_raising():
    # A refusal raised in the offload thread with a lock still held would live until get_db closes the
    # session on the event loop; both cap 409s roll back first. (mutation: drop a rollback -> red)
    lines = AUTH.read_text(encoding="utf-8").splitlines()

    def _rollback_precedes(needle, window=12):
        for i, ln in enumerate(lines):
            if needle in ln:
                assert any("self.db.rollback()" in lines[j] for j in range(max(0, i - window), i)), (
                    f"no self.db.rollback() in the {window} lines before: {ln.strip()}")
                return
        raise AssertionError(f"marker not found: {needle}")

    _rollback_precedes("You already have the maximum")                 # per-user cap 409
    _rollback_precedes('_device_mint_refusal("device-cred-cap"')       # device cap 409
    _rollback_precedes("is password-protected — its correct")          # vault-proof failure (400)


def test_a_raise_from_a_validation_branch_rolls_back_the_locked_span():
    # Behavioural, not textual: the fix must be TOTAL -- a raise ANYWHERE inside a locked span
    # releases the lock, not only at the branches that remembered to roll back. The device mint's
    # 'no-grant' branch raises AFTER taking the device row FOR UPDATE and carries NO explicit
    # rollback of its own, so the only thing that can release that lock is the span backstop. Drive
    # it with a session spy that yields a live device then no grant, and assert the raise rolled the
    # session back. (mutation: remove @_rollback_on_error from the method -> no rollback -> red.)
    import os, sys
    sys.path.insert(0, os.path.dirname(__file__))
    import _bare_api_env; _bare_api_env.set_bare_api_env()
    from fastapi import HTTPException
    from app.services.auth_service import AuthService

    class _Dev:
        id = "dev-1"; user_id = "user-1"; is_active = True; suspended = False; expires_at = None

    class _Spy:
        # .query(...).filter(...).populate_existing().with_for_update().first() -> next queued row.
        def __init__(self, rows):
            self._rows = list(rows)
            self.rolled_back = 0
        def query(self, *a, **k): return self
        def filter(self, *a, **k): return self
        def populate_existing(self, *a, **k): return self
        def with_for_update(self, *a, **k): return self
        def first(self): return self._rows.pop(0) if self._rows else None
        def rollback(self): self.rolled_back += 1

    svc = AuthService.__new__(AuthService)
    svc.db = _Spy([_Dev()])            # device read -> live device; grant read -> None -> 'no-grant'

    with pytest.raises(HTTPException) as caught:
        svc.mint_device_sync_credential(_Dev(), "vault-1")
    assert caught.value.detail["reason"] == "no-grant"          # the validation branch we hit
    assert svc.db.rolled_back == 1, "the locked span did not roll back on a validation raise"


def test_both_mint_methods_carry_the_total_rollback_decorator():
    # The span backstop is applied to BOTH locked mints. (mutation: drop @_rollback_on_error from
    # either method -> red; the behavioural test above then proves the decorator still has teeth.)
    src = AUTH.read_text(encoding="utf-8")
    for defline in ("def create_temporary_credential(", "def mint_device_sync_credential("):
        assert re.search(r"@_rollback_on_error\s+" + re.escape(defline), src), (
            "%s is not wrapped by @_rollback_on_error" % defline)


def test_the_post_mint_audit_is_awaited_off_the_loop():
    # The synchronous audit INSERT (KEY SHARE on the users row) must not run on the event loop, where
    # it could block on a held lock and freeze every request. (mutation: make it a direct call -> red)
    src = API.read_text(encoding="utf-8")
    assert "run_offloaded(audit_logger.log_temp_credential_created" in src
    assert "\n    audit_logger.log_temp_credential_created(" not in src   # no bare on-loop call


def test_the_engine_sets_a_lock_timeout_backstop():
    src = (ROOT / "app" / "core" / "database.py").read_text(encoding="utf-8")
    assert "_LOCK_TIMEOUT_MS" in src
    assert "lock_timeout={_LOCK_TIMEOUT_MS}" in src   # applied via libpq options on every connection


def test_the_boot_ddl_disables_lock_timeout_for_its_own_statements():
    # A schema change may legitimately wait on a lock, so the DDL replay overrides the engine
    # lock_timeout to 0 per statement (SET LOCAL, resets at each commit). (mutation: drop it -> the
    # DDL could be killed mid-migration under the engine timeout; pinned so it is not removed.)
    src = API.read_text(encoding="utf-8")
    assert "SET LOCAL lock_timeout = 0" in src


def test_the_db_service_carries_an_idle_in_transaction_backstop():
    # A leaked open transaction is bounded server-side too. Both deploy composes set the timeout on
    # the postgres service.
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for compose in ("deploy/docker-compose.secure.yml", "deploy/docker-compose.yml"):
        text = (root / compose).read_text(encoding="utf-8")
        assert "idle_in_transaction_session_timeout=" in text, compose


# ---- SPA: the two sections render safely (source-pinned; the browser render is a UI-lane test) ---
def _appjs():
    return (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _js_function(js, name):
    start = js.index("function %s(" % name)
    nxt = js.index("\nfunction ", start + 1)
    return js[start:nxt]


def test_the_spa_splits_into_two_sections_on_the_device_boolean():
    js = _appjs()
    assert "Shared / handed-out" in js
    assert "Per-computer sync credentials" in js
    assert "renderPerComputerRow" in js
    assert "c.is_device_credential" in js   # the split key is the boolean, never the device id


def test_the_per_computer_row_shows_the_escaped_device_name_and_lifecycle_never_a_secret():
    body = _js_function(_appjs(), "renderPerComputerRow")
    assert "escapeHtml(cred.device_name)" in body      # the display name, HTML-escaped
    assert "tcLifecycleBadge(cred.lifecycle)" in body  # the lifecycle badge
    for forbidden in ("device_id", "secret", "device.id", "credential_string"):
        assert forbidden not in body, f"the per-computer row renders {forbidden}"


def test_the_lifecycle_badge_defaults_to_expired_never_active():
    body = _js_function(_appjs(), "tcLifecycleBadge")
    assert "'in-use'" in body and "'active'" in body   # the only two positive states
    # the fall-through (anything else, including 'expired') is Expired -- a finished credential can
    # never read Active.
    assert "data: 'expired'" in body.split("return")[-1]
