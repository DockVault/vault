"""Every vault capability that gates an endpoint must have a denial test.

Positive tests are plentiful; the security-relevant ones are negative -- does a credential WITHOUT
the capability get refused? Four destructive gates (change_info, change_password, change_expiry,
delete) shipped for several releases with no such test: enforced, but nothing watching them, so a
refactor that dropped a decorator would leave no failing test behind.

This walks the ``@require_vault_cap`` decorators across ALL API modules (the main server and the ECC
router) and fails if a capability is not named NEAR a 403 assertion in any test. It is a FLOOR, not
a proof: a source scan cannot tell "a credential lacking cap X is refused on X's endpoint" from "cap
X is granted as input to a different endpoint's denial test", so the authoritative denials are the
explicit tests in ``test_api_vault_cap_denial_audit.py``. What this catches cheaply is the one that
bit us -- a capability that gates an endpoint with no denial test naming it anywhere -- so capability
sixteen cannot ship completely unwatched. It only ever asserts a door is shut, so it is public-safe.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
# Every API module that can carry @require_vault_cap decorators -- not just the main server.
_API_SOURCES = ("app/api/api_server.py", "app/api/ecc_router.py")
_PROXIMITY = 6  # lines: how close the cap literal must sit to a 403 to count as "in a denial"


def _gated_capabilities() -> set[str]:
    caps: set[str] = set()
    for rel in _API_SOURCES:
        src = (_ROOT / rel).read_text(encoding="utf-8")
        caps |= set(re.findall(r"@require_vault_cap\(\s*['\"]([a-z_.]+)['\"]", src))
    return caps


def test_every_gated_vault_capability_has_a_denial_test():
    gated = _gated_capabilities()
    assert gated, "premise changed: no @require_vault_cap decorators found in the API modules"

    covered: set[str] = set()
    for test_file in (_ROOT / "tests").glob("test_*.py"):
        lines = test_file.read_text(encoding="utf-8", errors="replace").splitlines()
        denial_lines = [i for i, ln in enumerate(lines)
                        if "403" in ln or "cap_denied" in ln or "_assert_cap_denied" in ln]
        if not denial_lines:
            continue
        for i, ln in enumerate(lines):
            for cap in gated - covered:
                if (f"'{cap}'" in ln or f'"{cap}"' in ln) and \
                        any(abs(i - d) <= _PROXIMITY for d in denial_lines):
                    covered.add(cap)

    missing = sorted(gated - covered)
    assert not missing, (
        "these vault capabilities gate an endpoint but are not named near any 403 denial assertion in "
        f"the tests: {missing}. Add a denial test to tests/test_api_vault_cap_denial_audit.py (a "
        "credential lacking the capability, asserted 403, with a positive control) -- an "
        "enforced-but-untested gate is one refactor away from silently opening.")
