"""Fingerprints of names recorded at the fingerprint level, offline (app/core/audit_fingerprints.py).

A fingerprint is fp1:<key id>:<hex>, a keyed HMAC. The key id follows the key, so a changed key is never a
silent mismatch. A name typed at a failed sign-in or into a filter has one key for the deployment; a vault,
file or folder name has a key derived for its vault, and its fingerprint is shown and exported only to an
administrator who can read that vault.
"""
import importlib.util
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_fingerprints as fp  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, User, Vault  # noqa: E402
from app.core.security import _runtime_settings  # noqa: E402
from app.services import activity_names  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

_runtime_settings()          # set up before any test changes a setting: a name sealed at the full level reads it

ROOT = Path(__file__).resolve().parent.parent
KEY_A = "a" * 64
KEY_B = "b" * 64


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    # The runtime first: an earlier test may have left it to be set up again, and setting it up installs every
    # setting afresh, which would undo what this test sets below.
    _runtime_settings()
    monkeypatch.setattr(settings, "audit_fingerprint_key", KEY_A)
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    yield


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'fp.db'}")
        for model in (User, AuditLog, Vault):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        engine.dispose()


def _levels(**changed):
    return {**ap.POLICY_ONE, **changed}


def test_the_form_and_the_key_id():
    value = fp.fingerprint(fp.SIGNIN, "eve")
    assert fp.is_fingerprint(value) and value.startswith(f"fp1:{fp.key_id()}:")
    assert fp.fingerprint(fp.SIGNIN, "eve") == value
    assert fp.fingerprint(fp.SIGNIN, "Eve") != value
    assert not fp.is_fingerprint("fp1:zz:00") and not fp.is_fingerprint(None)


def test_changing_the_key_changes_the_key_id_and_every_fingerprint(monkeypatch):
    first_id, first = fp.key_id(), fp.fingerprint(fp.SIGNIN, "eve")
    monkeypatch.setattr(settings, "audit_fingerprint_key", KEY_B)
    assert fp.key_id() != first_id
    assert fp.fingerprint(fp.SIGNIN, "eve").split(":")[1] == fp.key_id()
    assert fp.fingerprint(fp.SIGNIN, "eve").split(":")[2] != first.split(":")[2]


def test_without_a_key_one_is_derived_from_the_encryption_key_under_its_own_label(monkeypatch):
    monkeypatch.setattr(settings, "audit_fingerprint_key", "")
    monkeypatch.setattr(settings, "encryption_key", "an-encryption-key")
    derived_id = fp.key_id()
    assert derived_id != fp.key_id(SimpleNamespace(audit_fingerprint_key=KEY_A, encryption_key=settings.encryption_key))
    # Not the encryption key used as the fingerprint key directly.
    assert derived_id != fp.key_id(SimpleNamespace(audit_fingerprint_key=settings.encryption_key, encryption_key=""))
    monkeypatch.setattr(settings, "encryption_key", "another-encryption-key")
    assert fp.key_id() != derived_id


def test_no_key_at_all_fails_and_the_row_falls_back(db, monkeypatch):
    monkeypatch.setattr(settings, "audit_fingerprint_key", "")
    monkeypatch.setattr(settings, "encryption_key", "")
    with pytest.raises(fp.FingerprintKeyMissing):
        fp.key_id()
    ap.use(ap.Policy(2, _levels(signin_names="fingerprint")))
    row = AuditLogger(db).build_row(action="login_failure", status="failure", username="eve",
                                    ip_address="192.0.2.1")
    assert row.privacy_version == -1 and row.username is None


def test_the_same_name_in_two_vaults_gives_two_fingerprints():
    one, two = uuid.uuid4(), uuid.uuid4()
    assert fp.fingerprint(fp.NAME, "q3.xlsx", one) == fp.fingerprint(fp.NAME, "q3.xlsx", str(one))
    assert fp.fingerprint(fp.NAME, "q3.xlsx", one) != fp.fingerprint(fp.NAME, "q3.xlsx", two)
    assert fp.fingerprint(fp.NAME, "q3.xlsx", one).split(":")[2] != fp.fingerprint(fp.SIGNIN, "q3.xlsx").split(":")[2]
    assert fp.fingerprint(fp.NAME, "q3.xlsx", None) is None and fp.fingerprint(fp.SIGNIN, None) is None


def test_a_typed_name_at_the_fingerprint_level(db):
    ap.use(ap.Policy(2, _levels(signin_names="fingerprint")))
    row = AuditLogger(db).build_row(action="login_failure", status="failure", username="eve",
                                    details={"filters": {"user": "bob", "q": "salary", "category": "files"}})
    assert row.username is None
    assert row.recorded["signin_name"] == fp.fingerprint(fp.SIGNIN, "eve")
    assert row.recorded["details"] == {"filters.user": fp.fingerprint(fp.SIGNIN, "bob"),
                                       "filters.q": fp.fingerprint(fp.SIGNIN, "salary")}
    assert row.details == {"filters": {"category": "files"}}
    assert ap.for_output(ap.SIGNIN_NAME, "eve") == fp.fingerprint(fp.SIGNIN, "eve")


@pytest.mark.parametrize("level", ["fingerprint", "full"])
def test_names_at_the_fingerprint_level_or_above_keep_their_vaults_fingerprints(db, level):
    vault = uuid.uuid4()
    ap.use(ap.Policy(3, _levels(names=level)))
    row = AuditLogger(db).build_row(action="file_renamed", status="success", resource_type="file",
                                    resource_id=str(uuid.uuid4()),
                                    details={"vault_id": str(vault), "old_name": "a.txt", "new_name": "b.txt"})
    assert row.details == {"vault_id": str(vault)}
    names = row.recorded["names"]
    assert names["vault"] == str(vault)
    assert names["values"]["old_name"]["fp"] == fp.fingerprint(fp.NAME, "a.txt", vault)
    assert names["values"]["new_name"]["fp"] == fp.fingerprint(fp.NAME, "b.txt", vault)
    vault_row = AuditLogger(db).build_row(action="vault_created", status="success", resource_type="vault",
                                          resource_id=str(vault), details={"vault_name": "Finance"})
    assert vault_row.recorded["names"]["values"]["vault_name"]["fp"] == fp.fingerprint(fp.NAME, "Finance", vault)


def test_a_name_whose_vault_the_row_does_not_say_or_at_none_is_not_recorded(db):
    ap.use(ap.Policy(3, _levels(names="fingerprint")))
    row = AuditLogger(db).build_row(action="file_uploaded", status="success", details={"file_name": "a.txt"})
    assert row.recorded is None and row.details == {}
    ap.use(ap.Policy(4, _levels(names="none")))
    row = AuditLogger(db).build_row(action="file_uploaded", status="success",
                                    details={"file_name": "a.txt", "vault_id": str(uuid.uuid4())})
    assert row.recorded is None


def _row(vault, values=None, signin=None):
    recorded = {}
    if vault is not None:
        recorded["names"] = {"vault": str(vault), "values": values or {"file_name": {"fp": "fp1:x:y"}}}
    if signin:
        recorded["signin_name"] = signin
    return SimpleNamespace(recorded=recorded or None)


def test_name_fingerprints_are_given_only_for_a_vault_the_viewer_can_read(db, monkeypatch):
    mine, theirs = uuid.uuid4(), uuid.uuid4()
    asked = []

    def readable(db, viewer, vault_ids):
        asked.append(set(vault_ids))
        return {mine}

    monkeypatch.setattr(activity_names, "readable_vault_ids", readable)
    out = activity_names.recorded_names_for(db, object(), [_row(mine), _row(theirs), _row(None), SimpleNamespace(recorded=None)])
    assert out == [{"file_name": {"fingerprint": "fp1:x:y"}}, None, None, None]
    assert asked == [{mine, theirs}]


def test_the_events_the_event_and_the_export_go_through_the_gate():
    import inspect
    from app.api import api_server
    # The Events list reads its rows (from the table, or from it and the archive) in one helper, which gives the
    # names through the gate.
    events = inspect.getsource(api_server.activity_events)
    assert events.count("_activity_events_page(") == 1
    page = inspect.getsource(api_server._activity_events_page)
    assert page.count("recorded_names_for(db, current_user, rows, unlocked)") == 1
    # One event, from audit_logs or the archive, is shown by one helper, which gives the names through the gate.
    one = inspect.getsource(api_server.activity_event)
    assert one.count("_activity_event_view(") == 2 and "recorded_names_for" not in one
    view = inspect.getsource(api_server._activity_event_view)
    assert view.count("recorded_names_for(db, current_user, [row], unlocked)[0]") == 1
    # The export's batches, from the table or from an archive search, all go through views_of.
    export = inspect.getsource(api_server.activity_export)
    views = export[export.index("    def views_of(s, got):"):export.index("    def from_search(after):")]
    assert views.count("recorded_names_for(s, viewer, got, unlocked)") == 1
    fetch = export[export.index("    def from_search(after):"):export.index("    def lines():")]
    assert fetch.count("views_of(") == 2 and "recorded_names_for" not in fetch
    # The row view never carries what was recorded wholesale: only what the gate lets through is added.
    from app.services.activity_events import row_view
    assert "recorded_names" not in inspect.getsource(row_view)


def test_the_row_view_shows_a_typed_names_fingerprint_and_the_export_has_the_columns():
    from app.services import activity_events as ev
    row = SimpleNamespace(id=uuid.uuid4(), timestamp=None, username=None, temp_credential_id=None, action="login_failure",
                          details=None, status="failure", channel="web", ip_address=None, method=None, endpoint=None,
                          user_agent=None, resource_type=None, resource_id=None, error_message=None,
                          privacy_version=2, recorded={"signin_name": "fp1:abcdabcd:" + "0" * 32}, user_id=None)
    assert ev.row_view(row)["signin_fingerprint"] == "fp1:abcdabcd:" + "0" * 32
    columns = dict(ev.EXPORT_COLUMNS)
    assert columns["Typed name (fingerprint)"] == "signin_fingerprint"
    assert columns["Recorded names"] == "recorded_names"
    assert ev.EXPORT_COLUMNS[-1] == ("Temporary credential ID", "temp_credential_id")


def test_a_short_key_refuses_to_start_and_says_how_to_fix_it():
    from app.core import config
    from app.core.config import RuntimeBootstrapError, Settings
    with pytest.raises(RuntimeBootstrapError) as raised:
        config._validate_runtime_settings(Settings(audit_fingerprint_key="short"))
    assert raised.value.code == "audit-fingerprint-key-weak"
    assert "AUDIT_FINGERPRINT_KEY is shorter than 32 characters" in raised.value.safe_message
    assert "short" not in raised.value.safe_message.replace("shorter", "")
    assert fp.key_problem(SimpleNamespace(audit_fingerprint_key="")) is None
    assert fp.key_problem(SimpleNamespace(audit_fingerprint_key="x" * 32)) is None
    assert fp.key_problem(SimpleNamespace(audit_fingerprint_key="x" * 31)) is not None


def _dockvault(monkeypatch):
    spec = importlib.util.spec_from_file_location("dockvault_fp", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    return dv


def test_the_key_is_documented_generated_for_a_new_set_and_written_by_the_tool(monkeypatch):
    from app.core.config import Settings
    assert Settings.model_fields["audit_fingerprint_key"].default == ""
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\n# AUDIT_FINGERPRINT_KEY=\n") == 1
    assert "can\n# test guesses" in example or "test guesses" in example
    dv = _dockvault(monkeypatch)
    cfg = dv.new_set_config({}, "prefix-1", "dep-1")
    assert len(cfg["audit_fingerprint_key"]) == 64
    assert cfg["audit_fingerprint_key"] != dv.new_set_config({}, "prefix-1", "dep-1")["audit_fingerprint_key"]
    # A new set is new data, so it never carries the old set's key.
    carried = dv.new_set_config({"AUDIT_FINGERPRINT_KEY": "c" * 64}, "prefix-1", "dep-1")["audit_fingerprint_key"]
    assert carried != "c" * 64 and len(carried) == 64
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert f"AUDIT_FINGERPRINT_KEY='{cfg['audit_fingerprint_key']}'" in lines
    plain = dv.build_env_lines({**cfg, "server_name": "localhost", "audit_fingerprint_key": ""})
    assert not [line for line in plain if line.startswith("AUDIT_FINGERPRINT_KEY")]
    source = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    setup = source[source.index('"invite_token_pepper": gen_hex(32),\n'):]
    assert setup[:200].count('"audit_fingerprint_key": gen_hex(32),') == 1


def test_the_inventory_says_what_a_fingerprint_does_not_protect_from():
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    assert "`AUDIT_FINGERPRINT_KEY`" in text and "test guesses" in text
