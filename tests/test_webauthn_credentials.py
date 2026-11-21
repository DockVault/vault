"""The passkey store (`webauthn_credentials`): its shape, how the active-factors helper counts it, and that the
inventory and the recording notice describe it. Offline."""
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _the_vault_has_an_address(monkeypatch):
    """A passkey counts only at the address it was made at; these tests are not about the address, so the vault
    has one, and every key here was made at it (or says nothing, which is taken as here)."""
    set_bare_api_env()
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(
        rp_id="vault.example.test", origin="https://vault.example.test", name=name or "DockVault"))


def test_the_table_holds_what_the_authenticator_made_and_what_the_vault_must_remember():
    set_bare_api_env()
    from app.core.models import WebAuthnCredential
    t = WebAuthnCredential.__table__
    assert t.name == "webauthn_credentials"
    assert set(t.columns.keys()) == {
        "id", "user_id", "credential_id", "public_key_cose", "cose_alg", "sign_count", "transports", "aaguid",
        "attested", "backup_eligible", "backup_state", "uv_initialized", "discoverable", "label", "created_at", "last_used_at",
        "created_by_session", "provisional_until", "retired_at", "prf_slot_id", "rp_id"}
    assert t.c.rp_id.nullable                  # a row from before the address was recorded says nothing
    # The authenticator's id is unique across accounts; the key goes with the account.
    assert t.c.credential_id.unique and not t.c.credential_id.nullable
    (fk,) = t.c.user_id.foreign_keys
    assert fk.target_fullname == "users.id" and fk.ondelete == "CASCADE" and not t.c.user_id.nullable
    assert any(ix.columns.keys() == ["user_id"] for ix in t.indexes)
    # Bytes as received, never text: the id and the COSE key.
    assert t.c.credential_id.type.python_type is bytes and t.c.public_key_cose.type.python_type is bytes
    assert t.c.sign_count.type.python_type is int and not t.c.sign_count.nullable
    # The flags are pinned values, not unknowns.
    for name in ("backup_eligible", "backup_state", "uv_initialized"):
        assert not t.c[name].nullable, name
    # What may be absent: a label, a make's identifier, transports, the browser's discoverability hint, the
    # provisional window, the retirement, the future PRF slot, the last use.
    for name in ("label", "aaguid", "transports", "discoverable", "provisional_until", "retired_at", "prf_slot_id",
                 "last_used_at", "created_by_session"):
        assert t.c[name].nullable, name
    assert t.c.label.type.length == 100 and t.c.created_by_session.type.length == 64


def test_a_passkey_counts_as_a_factor_unless_it_was_retired():
    set_bare_api_env()
    from app.core import active_factors as af
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    uid, other = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(timezone.utc)
    db = MemoryDB({SecondFactorEnrollment: [], WebAuthnCredential: [
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, retired_at=None, provisional_until=now, cose_alg=-7),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, retired_at=None, provisional_until=None, cose_alg=-7),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, retired_at=now, provisional_until=None, cose_alg=-7),
        # Of an algorithm the vault does not take: refused at every use, so no factor the account could give.
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, retired_at=None, provisional_until=None, cose_alg=-65535),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=other, retired_at=None, provisional_until=None, cose_alg=-7),
    ]})
    f = af.active_factors(db, uid)
    # The provisional one counts to sign in; the retired one and the one that cannot be used do not.
    assert f.passkeys == 2 and f.any and not f.code
    assert af.active_factors(db, other).passkeys == 1
    assert af.active_factors(db, uuid.uuid4()) == af.ActiveFactors()


def test_the_inventory_and_the_notice_describe_the_store():
    set_bare_api_env()
    from app.core import recording_notice as rn
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| `webauthn_credentials`"))
    for words in ("public key", "never a private part", "sign count", "name the person gave it", "14 days",
                  "retired", "30 days", "deleted with the account"):
        assert words in row, words
    assert "\n## What 0.36.0 added\n" in text and "`webauthn_credentials`" in text.split("## What 0.36.0 added")[1]
    (store,) = [s for s in rn.STORES if s.key == "webauthn_credentials"]
    assert store.table == "webauthn_credentials" and "passkeys" in store.what.lower() and "30 days" in store.kept()
