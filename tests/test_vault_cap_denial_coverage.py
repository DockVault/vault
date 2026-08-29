"""Every vault capability that gates an endpoint must have a denial test.

Positive tests are plentiful; the security-relevant ones are negative -- does a credential WITHOUT
the capability get refused? Four destructive gates (change_info, change_password, change_expiry,
delete) shipped for several releases with no such test: enforced, but nothing watching them, so a
refactor that dropped a decorator would leave no failing test behind. This walks the
``@require_vault_cap`` decorators in the API and fails if any capability is not named in a test that
also asserts a 403 -- the same shape as the schema-divergence guard, so capability sixteen cannot
ship unguarded. It only ever asserts a door is shut, so it is safe to keep public.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]


def _gated_capabilities() -> set[str]:
    src = (_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    return set(re.findall(r"@require_vault_cap\(\s*['\"]([a-z_.]+)['\"]", src))


def test_every_gated_vault_capability_has_a_denial_test():
    gated = _gated_capabilities()
    assert gated, "premise changed: no @require_vault_cap decorators found in the API"

    # A capability is denial-tested if it is named in a test file that also asserts a 403 -- a
    # deliberately simple proxy for "someone wrote a test that a credential lacking this cap is
    # refused". A new cap added without such a test trips this.
    covered: set[str] = set()
    for test_file in (_ROOT / "tests").glob("test_*.py"):
        text = test_file.read_text(encoding="utf-8", errors="replace")
        if "403" not in text:
            continue
        for cap in gated:
            if f"'{cap}'" in text or f'"{cap}"' in text:
                covered.add(cap)

    missing = sorted(gated - covered)
    assert not missing, (
        "these vault capabilities gate an endpoint but have no denial test (a credential lacking the "
        f"capability, asserted 403): {missing}. Add one to tests/test_api_vault_cap_denial_audit.py "
        "-- an enforced-but-untested gate is one refactor away from silently opening.")
