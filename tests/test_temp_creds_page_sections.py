"""Backend contract for the two-section temp-credentials page: the listing carries the section
split, the device DISPLAY NAME, and the lifecycle state for device-minted credentials, and never a
device id, device secret, or credential secret. The per-user interactive cap is taken under the owner
row lock.

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


def test_the_per_user_cap_is_taken_under_the_owner_row_lock():
    # Two concurrent interactive mints at the boundary must not both pass: the owner row is locked
    # FOR UPDATE across the cap count and the insert, like the device path. The behavioural race is
    # a live-lane test (real row locks); this pins the mechanism.
    flat = re.sub(r"\s+", " ", AUTH.read_text(encoding="utf-8"))
    owner_reads = re.findall(r"query\(User\)\.filter\(User\.id == user_id\)[^;]{0,120}?\.first\(\)", flat)
    cap_owner = [q for q in owner_reads if "populate_existing().with_for_update()" in q]
    assert cap_owner, "the per-user cap's owner read is not taken FOR UPDATE (still check-then-act)"


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
