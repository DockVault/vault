"""Sealing the free text of compliance access, offline (app/core/security.py, seal_case_field).

A justification, a note to the owner, an objection, a reason or an owner's address is sealed under a key
derived from ENCRYPTION_KEY with a label of its own, bound to its row and field: it opens only for that row
and field, a changed byte refuses to open, a value without the marker is never taken as plaintext, and
another ENCRYPTION_KEY cannot open it. Written to a database, the text is not in the file.
"""
import base64
import re
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from cryptography.exceptions import InvalidTag
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import security  # noqa: E402
from app.core.models import Base, ComplianceCase  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
KEY_A = base64.urlsafe_b64encode(b"a" * 32).decode()
KEY_B = base64.urlsafe_b64encode(b"b" * 32).decode()
TEXT = "Suspected exfiltration of client files by bob; see ticket 4711. Ünïcode stays."


@pytest.fixture
def key(monkeypatch):
    current = SimpleNamespace(encryption_key=KEY_A)
    monkeypatch.setattr(security, "_runtime_settings", lambda: current)
    return current


@pytest.mark.parametrize("field", sorted(security.CASE_FIELDS))
def test_each_field_round_trips_and_is_marked(key, field):
    case = uuid.uuid4()
    token = security.seal_case_field(case, TEXT, field)
    assert token.startswith("cenc1:") and security.is_case_sealed(token)
    assert TEXT not in token
    assert security.open_case_field(case, token, field) == TEXT
    assert security.open_case_field(str(case), token, field) == TEXT
    # A fresh nonce every time.
    assert security.seal_case_field(case, TEXT, field) != token


def test_the_empty_text_round_trips(key):
    case = uuid.uuid4()
    assert security.open_case_field(case, security.seal_case_field(case, "", "objection"), "objection") == ""


def test_another_case_or_field_does_not_open_it(key):
    case, other = uuid.uuid4(), uuid.uuid4()
    token = security.seal_case_field(case, TEXT, "justification")
    with pytest.raises(InvalidTag):
        security.open_case_field(other, token, "justification")
    with pytest.raises(InvalidTag):
        security.open_case_field(case, token, "owner_note")


def test_a_second_id_binds_too(key):
    case, vault, other = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    token = security.seal_case_field(case, TEXT, "release_reason", item_id=vault)
    assert security.open_case_field(case, token, "release_reason", item_id=vault) == TEXT
    for wrong in (other, None):
        with pytest.raises(InvalidTag):
            security.open_case_field(case, token, "release_reason", item_id=wrong)
    plain = security.seal_case_field(case, TEXT, "release_reason")
    with pytest.raises(InvalidTag):
        security.open_case_field(case, plain, "release_reason", item_id=vault)


def test_a_changed_byte_does_not_open(key):
    case = uuid.uuid4()
    token = security.seal_case_field(case, TEXT, "justification")
    raw = bytearray(base64.b64decode(token[len("cenc1:"):]))
    for at in (0, 11, 12, len(raw) // 2, len(raw) - 1):          # nonce, ciphertext and tag
        changed = bytearray(raw)
        changed[at] ^= 0x01
        with pytest.raises(InvalidTag):
            security.open_case_field(case, "cenc1:" + base64.b64encode(bytes(changed)).decode(), "justification")
    with pytest.raises(InvalidTag):
        security.open_case_field(case, "cenc1:" + base64.b64encode(bytes(raw[:-1])).decode(), "justification")


def test_a_value_without_the_marker_is_never_plaintext(key):
    case = uuid.uuid4()
    token = security.seal_case_field(case, TEXT, "justification")
    for value in (TEXT, token[len("cenc1:"):], "nenc1:" + token[len("cenc1:"):], "", None):
        with pytest.raises(ValueError):
            security.open_case_field(case, value, "justification")
    with pytest.raises(ValueError):
        security.open_case_field(case, "cenc1:not base64!", "justification")
    # Stray characters inside a real seal are refused, not skipped.
    body = token[len("cenc1:"):]
    with pytest.raises(ValueError):
        security.open_case_field(case, "cenc1:" + body[:8] + "!" + body[8:], "justification")


def test_the_aad_is_the_field_and_the_row():
    case, vault = uuid.uuid4(), uuid.uuid4()
    assert security._case_field_aad("justification", case, None) == (b"dockvault-case-field:justification:"
                                                                      + case.bytes)
    assert security._case_field_aad("release_reason", case, vault) == (b"dockvault-case-field:release_reason:"
                                                                       + case.bytes + b":" + vault.bytes)


def test_only_the_known_fields_are_sealed_or_opened(key):
    case = uuid.uuid4()
    with pytest.raises(ValueError):
        security.seal_case_field(case, TEXT, "name")
    token = security.seal_case_field(case, TEXT, "objection")
    with pytest.raises(ValueError):
        security.open_case_field(case, token, "objection:")
    with pytest.raises(TypeError):
        security.seal_case_field(case, None, "objection")


def test_each_case_has_a_key_of_its_own(key):
    a, b = uuid.uuid4(), uuid.uuid4()
    assert security._case_object_key(a) == security._case_object_key(a)
    assert security._case_object_key(a) != security._case_object_key(b)
    assert len(security._case_object_key(a)) == 32


def test_another_encryption_key_does_not_open_it(key):
    case = uuid.uuid4()
    token = security.seal_case_field(case, TEXT, "owner_note")
    key.encryption_key = KEY_B
    with pytest.raises(InvalidTag):
        security.open_case_field(case, token, "owner_note")
    key.encryption_key = KEY_A
    assert security.open_case_field(case, token, "owner_note") == TEXT


def test_the_key_has_a_label_no_other_derivation_uses():
    app = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "app").rglob("*.py"))
    for label in (b"dockvault-case-enc-key-v1", b"dockvault-case-obj-v1", b"compliance-case-text"):
        assert app.count(repr(label)) == 1, label
    salts = re.findall(r"salt=(b'[^']+')", (ROOT / "app" / "core" / "security.py").read_text(encoding="utf-8"))
    assert len(salts) == len(set(salts))


def test_a_database_holding_a_sealed_case_does_not_hold_its_text(key):
    sentinel = {"justification": "SENTINEL-JUSTIFICATION-7f3a", "owner_note": "SENTINEL-NOTE-91bc",
                "objection": "SENTINEL-OBJECTION-c4d2", "reject_reason": "SENTINEL-REJECT-0aa9"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        path = Path(tmp) / "cases.db"
        engine = sa.create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(engine, tables=[Base.metadata.tables["users"],
                                                 Base.metadata.tables["auditor_grants"],
                                                 Base.metadata.tables["compliance_cases"]])
        db = sessionmaker(bind=engine)()
        case_id = uuid.uuid4()
        db.add(ComplianceCase(id=case_id, purpose="internal_investigation", legal_basis="f",
                              auditor_id=uuid.uuid4(), auditor_username="SENTINEL-CONTROL-plain",
                              **{f"{k}_enc": security.seal_case_field(case_id, v, k) for k, v in sentinel.items()}))
        db.commit()
        stored = db.query(ComplianceCase).one()
        assert security.open_case_field(case_id, stored.justification_enc, "justification") == sentinel["justification"]
        db.close()
        engine.dispose()
        raw = path.read_bytes()
    assert b"SENTINEL-CONTROL-plain" in raw          # the scan does see what is written plainly
    for value in sentinel.values():
        assert value.encode() not in raw, value
