"""Names recorded in full, sealed (app/core/audit_privacy.py seal_name), offline.

At the full level a vault, file or folder name is kept in recorded.names sealed under a key derived for its
vault and its audit row, with the detail key bound in, beside its fingerprint; no row holds it in plaintext. It
opens only for the row and key it was sealed under, and is shown only under the Activity page's name rules
(app/services/activity_names.py): to an administrator who can read the vault, and a file's or a folder's name
only in a vault with no vault password that is not zero-knowledge.
"""
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_privacy as ap  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, User, Vault  # noqa: E402
from app.core.security import _runtime_settings  # noqa: E402
from app.services import activity_names  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

_runtime_settings()          # the runtime the sealing reads its key from, set up before any test changes it


@pytest.fixture(autouse=True)
def _full_names(monkeypatch):
    _runtime_settings()      # set up again if an earlier test left it to be, before anything is set below
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    ap.use(ap.Policy(5, {**ap.POLICY_ONE, "names": "full"}))
    yield


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'names.db'}")
        for model in (User, AuditLog, Vault):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine)
        engine.dispose()


def _rename(db, vault, old="q3-layoffs.xlsx", new="q4-plan.xlsx"):
    return AuditLogger(db).build_row(action="file_renamed", status="success", resource_type="file",
                                     resource_id=str(uuid.uuid4()),
                                     details={"vault_id": str(vault), "old_name": old, "new_name": new})


def test_a_full_name_is_sealed_beside_its_fingerprint_and_never_stored_in_plaintext(factory):
    vault = uuid.uuid4()
    db = factory()
    row = _rename(db, vault)
    db.add(row)
    db.commit()
    values = row.recorded["names"]["values"]
    assert set(values) == {"old_name", "new_name"}
    assert values["old_name"]["fp"].startswith("fp1:") and values["old_name"]["sealed"]
    assert ap.open_name(vault, row.id, "old_name", values["old_name"]["sealed"]) == "q3-layoffs.xlsx"
    assert ap.open_name(vault, row.id, "new_name", values["new_name"]["sealed"]) == "q4-plan.xlsx"
    stored = " ".join(str(v) for v in db.execute(sa.text("SELECT * FROM audit_logs")).one())
    assert "q3-layoffs" not in stored and "q4-plan" not in stored
    db.close()


def test_a_sealed_name_opens_only_for_its_row_its_vault_and_its_key(factory):
    vault = uuid.uuid4()
    db = factory()
    row = _rename(db, vault)
    sealed = row.recorded["names"]["values"]["old_name"]["sealed"]
    other_row = _rename(db, vault)
    for args in ((vault, other_row.id, "old_name"), (uuid.uuid4(), row.id, "old_name"), (vault, row.id, "new_name")):
        with pytest.raises(Exception):
            ap.open_name(*args, sealed)
    # A value moved from one key to the other does not open there either.
    moved = row.recorded["names"]["values"]["new_name"]["sealed"]
    with pytest.raises(Exception):
        ap.open_name(vault, row.id, "old_name", moved)


def test_the_seal_uses_the_id_build_row_gave_the_row(factory, monkeypatch):
    seen = []
    real = ap.seal_name
    monkeypatch.setattr(ap, "seal_name", lambda v, rid, k, n: seen.append(rid) or real(v, rid, k, n))
    db = factory()
    row = _rename(db, uuid.uuid4())
    db.add(row)
    db.commit()
    assert seen == [row.id, row.id] and isinstance(row.id, uuid.UUID)
    with pytest.raises(ValueError, match="sealed under its id, and this row has none yet"):
        ap.seal_name(uuid.uuid4(), None, "old_name", "x")


def test_at_the_fingerprint_level_nothing_is_sealed(factory):
    ap.use(ap.Policy(6, {**ap.POLICY_ONE, "names": "fingerprint"}))
    row = _rename(factory(), uuid.uuid4())
    assert all(set(v) == {"fp"} for v in row.recorded["names"]["values"].values())


def _vault(db, kind="standard", password=None):
    owner = User(username=f"u-{uuid.uuid4().hex[:8]}", email=None, password_hash="x")
    db.add(owner)
    db.flush()
    v = Vault(id=uuid.uuid4(), name="Finance", owner_id=owner.id, type=kind, password_hash=password)
    db.add(v)
    db.commit()
    return v.id


@pytest.mark.parametrize("kind,password,items_shown", [
    ("standard", None, True),
    ("standard", "a-password-hash", False),
    ("zero_knowledge", None, False),
])
def test_names_are_opened_under_the_activity_pages_rules(factory, monkeypatch, kind, password, items_shown):
    db = factory()
    vault = _vault(db, kind, password)
    monkeypatch.setattr(activity_names, "readable_vault_ids", lambda db, viewer, ids: set(ids))
    renamed = _rename(db, vault)
    created = AuditLogger(db).build_row(action="vault_created", status="success", resource_type="vault",
                                        resource_id=str(vault), details={"vault_name": "Finance"})
    out = activity_names.recorded_names_for(db, object(), [renamed, created])
    assert out[1]["vault_name"]["name"] == "Finance"
    if items_shown:
        assert (out[0]["old_name"]["name"], out[0]["new_name"]["name"]) == ("q3-layoffs.xlsx", "q4-plan.xlsx")
    else:
        assert "name" not in out[0]["old_name"] and out[0]["old_name"]["fingerprint"].startswith("fp1:")
    db.close()


def test_nothing_is_opened_or_shown_outside_membership(factory, monkeypatch):
    db = factory()
    vault = _vault(db)
    monkeypatch.setattr(activity_names, "readable_vault_ids", lambda db, viewer, ids: set())
    assert activity_names.recorded_names_for(db, object(), [_rename(db, vault)]) == [None]
    db.close()


def test_a_value_that_does_not_open_says_so(factory, monkeypatch):
    db = factory()
    vault = _vault(db)
    monkeypatch.setattr(activity_names, "readable_vault_ids", lambda db, viewer, ids: set(ids))
    row = _rename(db, vault)
    row.recorded["names"]["values"]["old_name"]["sealed"] = "AAAA" + row.recorded["names"]["values"]["old_name"]["sealed"][4:]
    out = activity_names.recorded_names_for(db, object(), [row])
    assert out[0]["old_name"]["name"] == activity_names.SEALED_UNREADABLE
    assert out[0]["new_name"]["name"] == "q4-plan.xlsx"
    db.close()
