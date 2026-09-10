"""A new vault defaults to 5 GB — and an existing one is never resized to match.

The second half is the whole risk. Changing a default is trivial; changing it in a way that also
rewrites vaults on a deployment that already exists is a data change nobody asked for. So the checks
below pin BOTH directions: the new default, and the legacy backfill still writing the 1 GiB it always
wrote for rows created before the column had a default at all.

One trap worth naming, because this file would otherwise walk into it: the web form used to send a
hard `size_limit_gb: 1` on every create, so the server's default could never apply to a vault made
through the UI. Changing the server constant alone would have looked correct in every server-side
test and changed nothing a person could see.

Lanes:
  * unit        — the model column default as a REAL value (imported, not matched in text), the API
                  constant, the create path using it rather than a literal, and the backfill left
                  alone. No server.
  * integration — create a vault over HTTP naming no size and read back what it got. This is the
                  only lane that proves the default actually reaches a vault; it needs a deployment
                  running THIS code.
"""
import re
from pathlib import Path

import pytest

from app.core.models import Vault

ROOT = Path(__file__).resolve().parent.parent
GIB = 1024 ** 3


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_the_model_column_default_is_five_gib():
    """The real default object, not its spelling — this is what SQLAlchemy applies at INSERT."""
    assert Vault.__table__.c.size_limit.default.arg == 5 * GIB


@pytest.mark.unit
def test_the_api_default_constant_is_five_gb_and_the_create_path_uses_it():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")

    # Read to the end of the line and compare as a NUMBER. Matching the text "= 5" would also be
    # satisfied by "= 50" — every correct value here is a prefix of a plausible wrong one.
    m = re.search(r"^DEFAULT_VAULT_SIZE_GB = (\d+)\s*$", src, re.M)
    assert m, "DEFAULT_VAULT_SIZE_GB is not declared on its own line"
    assert int(m.group(1)) == 5

    m = re.search(r"^DEFAULT_VAULT_SIZE_BYTES = DEFAULT_VAULT_SIZE_GB \* _GIB\s*$", src, re.M)
    assert m, "DEFAULT_VAULT_SIZE_BYTES must be derived from the GB constant, not restated"

    # The create path must fall back to the constant. A literal here is how the two drift apart.
    fallback = re.search(r"requested_size = \(?int\(vault_create\.size_limit_gb \* _GIB\)"
                         r".*?else\s+(\S+)\)?", src, re.S)
    assert fallback, "the create path's size fallback was not found"
    assert fallback.group(1).rstrip(")") == "DEFAULT_VAULT_SIZE_BYTES", (
        f"the create default must be the named constant, not {fallback.group(1)!r}")


@pytest.mark.unit
def test_the_legacy_backfill_still_writes_one_gib_and_only_to_unset_rows():
    """The guard against this change becoming a data migration.

    This statement repairs rows written before the column had a default. If it were ever pointed at
    the new default, every deployment that upgrades would silently resize those vaults — which is
    exactly what "new vaults only" forbids. It must also stay restricted to unset rows.
    """
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    stmt = re.search(r'"UPDATE vaults SET size_limit = (\d+) WHERE ([^"]+)"', src)
    assert stmt, "the legacy size_limit backfill statement was not found"
    assert int(stmt.group(1)) == 1073741824, (
        "the backfill must keep writing 1 GiB — repointing it at the new default would resize "
        "vaults on every deployment that upgrades")
    assert stmt.group(2).strip() == "size_limit IS NULL OR size_limit <= 0", (
        "the backfill must only touch rows that never had a size")

    # And nothing else may issue a blanket UPDATE of this column.
    others = [s for s in re.findall(r'"UPDATE vaults SET size_limit[^"]*"', src)]
    assert len(others) == 1, f"more than one statement rewrites size_limit: {others}"


@pytest.mark.unit
def test_the_create_form_offers_five_and_defers_to_the_server_when_blank():
    """The half that would have made a server-only change invisible."""
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

    field = re.search(r'<input[^>]*id="vault-size-gb"[^>]*>', html)
    assert field, "the vault size field was not found"
    value = re.search(r'value="([\d.]+)"', field.group(0))
    assert value and float(value.group(1)) == 5.0, (
        f"the form should offer 5 GB, not {value and value.group(1)!r}")

    sent = re.search(r"size_limit_gb: \(sizeGb && sizeGb > 0\) \? sizeGb : (\w+)", app)
    assert sent, "the create payload's size expression was not found"
    assert sent.group(1) == "null", (
        "a blank size must be sent as null so the server's default governs; sending a number here "
        "is what made the server default unreachable from the UI")


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_a_vault_created_without_a_size_gets_five_gib(admin):
    """The only check that proves the default reaches a real vault. Needs a deployment of THIS code."""
    r = admin.post("/vaults", json={"name": f"default-size-{id(admin)}", "description": ""})
    assert r.status_code in (200, 201), r.text
    vault = r.json()
    try:
        detail = admin.get(f"/vaults/{vault['id']}").json()
        assert detail["size_limit"] == 5 * GIB, (
            f"a vault created without a size should hold 5 GiB, got {detail['size_limit']}")
    finally:
        admin.delete_vault(vault["id"])
