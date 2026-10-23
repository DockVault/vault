"""What a rewritten audit row keeps (app/core/audit_rewrite.py reduced()), offline.

- A row recorded in full and brought down to some levels holds exactly what a row recorded at those levels holds:
  its username, address and browser description, its details and ``recorded``, for every combination of levels;
  two steps down are one step down; a row already at the levels does not change.
- A name typed at a failed sign-in is the only username it changes: never an account's, a temporary credential's,
  the server's, an erase's placeholder, nor a row with an account or a credential, nor another action's.
- What it cannot read it leaves; a name an earlier release left in the details goes below full.
- The prefilter selects every row reduced() changes, and nothing when every level is full.
"""
import itertools
import json
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_fingerprints as fp  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core import audit_rewrite as rw  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.credential_changes import HOST_OPERATOR  # noqa: E402
from app.core.models import AuditLog, AuditPrivacyPolicy, SecurityAlert, User  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

FULL = {k: ap.FULL for k in ap.POLICY_KEYS}
VAULT = str(uuid.uuid4())
DETAILS = {"vault_id": VAULT, "file_name": "plan.xlsx", "email": "x@example.com", "ip_address": "198.51.100.7",
           "user_agent": "Agent/1.0", "changes": {"email": "y@example.com", "role": "user"},
           "filters": {"ip": "198.51.100.8", "user": "bob", "q": "some text", "status": "failure"}, "reason": "r"}
COMMITTED = ("username", "ip_address", "user_agent", "recorded", "details")


def lv(**kw):
    return dict(FULL, **kw)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    ap._reset_for_tests()
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    monkeypatch.setattr(settings, "audit_fingerprint_key", "k" * 64)
    yield
    ap._reset_for_tests()


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'audit.db'}")
        for model in (User, AuditLog, AuditPrivacyPolicy, SecurityAlert):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _write(factory, levels, *, action="login_failure", username="typed name", details=DETAILS):
    """A row as the app writes it at ``levels``, read back as reduced() reads rows (JSON columns as text)."""
    ap.use(ap.Policy(9, levels))
    db = factory()
    try:
        AuditLogger(db).log_action(action=action, status="failure", username=username, ip_address="198.51.100.77",
                                   user_agent="Mozilla/5.0 test", details=dict(details), resource_type="vault",
                                   resource_id=VAULT)
        row = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
        out = {c: getattr(row, c) for c in COMMITTED + ("action", "user_id", "temp_credential_id")}
        db.delete(row)
        db.commit()
    finally:
        db.close()
    for c in ("recorded", "details"):
        out[c] = json.dumps(out[c]) if out[c] is not None else None
    return out


def _apply(row, new):
    out = dict(row)
    out.update(new or {})
    return out


def _decoded(row):
    return {c: (json.loads(row[c]) if c in ("recorded", "details") and row[c] is not None else row[c])
            for c in COMMITTED}


def _without_seals(recorded):
    """``recorded`` with each name's seal set aside: a seal is bound to its row's id, so two rows' differ."""
    if not recorded or "names" not in recorded:
        return recorded
    names = dict(recorded["names"])
    names["values"] = {k: {kk: vv for kk, vv in v.items() if kk != "sealed"} for k, v in names["values"].items()}
    return dict(recorded, names=names)


ALL_LEVELS = [dict(zip(ap.POLICY_KEYS, combo)) for combo in itertools.product(*(ap.CHOICES[k] for k in ap.POLICY_KEYS))]


def test_a_row_brought_down_holds_what_a_row_recorded_at_those_levels_holds(factory):
    # The first write starts the app's configuration from the environment (config.initialize_runtime), which sets
    # the fingerprint key again: every row compared below is written after it, under one key.
    _write(factory, FULL)
    full = _write(factory, FULL)
    assert full["username"] == "typed name" and full["ip_address"] == "198.51.100.77"
    ctx = rw.Context()
    for levels in ALL_LEVELS:
        want = _decoded(_write(factory, levels))
        got = _decoded(_apply(full, rw.reduced(full, levels, ctx)))
        if levels[ap.NAMES] == ap.FULL:
            assert ("sealed" in json.dumps(got["recorded"])) and ("sealed" in json.dumps(want["recorded"]))
            got["recorded"], want["recorded"] = _without_seals(got["recorded"]), _without_seals(want["recorded"])
        assert got == want, levels
        # Already at the levels: nothing changes, and two steps are one.
        assert rw.reduced(_apply(full, rw.reduced(full, levels, ctx)), levels, ctx) is None
    stepped = _apply(full, rw.reduced(full, lv(ip=ap.SHORTENED, names=ap.FINGERPRINT), ctx))
    once = _decoded(_apply(full, rw.reduced(full, lv(ip=ap.NONE, names=ap.NONE), ctx)))
    assert _decoded(_apply(stepped, rw.reduced(stepped, lv(ip=ap.NONE, names=ap.NONE), ctx))) == once
    assert rw.reduced(full, FULL, ctx) is None


@pytest.mark.parametrize("row", [
    {"username": "alice"},                                          # an account's username
    {"username": "tc-1"},                                           # a temporary credential's name
    {"username": HOST_OPERATOR},
    {"username": "server configuration"},
    {"username": "erased-0a1b2c3d"},                                # an erase's placeholder
    {"user_id": uuid.uuid4()},                                      # a row with an account
    {"temp_credential_id": uuid.uuid4()},                           # a failed sign-in for a credential
    {"action": "file_uploaded"},                                    # an action that never types a name
])
@pytest.mark.parametrize("level", [ap.FINGERPRINT, ap.NONE])
def test_only_a_name_typed_at_a_failed_sign_in_is_changed(row, level):
    base = {"action": "login_failure", "user_id": None, "temp_credential_id": None, "username": "typed name",
            "ip_address": None, "user_agent": None, "recorded": None, "details": None}
    ctx = rw.Context(accounts={"alice"}, credentials={"tc-1"})
    typed = rw.reduced(base, lv(signin_names=level), ctx)
    assert typed["username"] is None
    kept = json.loads(typed["recorded"]) if typed.get("recorded") else {}
    assert kept.get("signin_name") == (fp.fingerprint(fp.SIGNIN, "typed name") if level == ap.FINGERPRINT else None)
    assert rw.reduced(dict(base, **row), lv(signin_names=level), ctx) is None


def test_a_fingerprint_already_kept_goes_at_none_and_stays_at_fingerprint():
    kept = fp.fingerprint(fp.SIGNIN, "someone")
    row = {"action": "login_failure", "user_id": None, "temp_credential_id": None, "username": None,
           "ip_address": None, "user_agent": None, "recorded": json.dumps({"signin_name": kept, "ip": "198.51.100.0/24",
                                                                          "details": {"filters.q": kept}}),
           "details": None}
    assert rw.reduced(row, lv(signin_names=ap.FINGERPRINT, ip=ap.SHORTENED), rw.Context()) is None
    out = rw.reduced(row, lv(signin_names=ap.NONE), rw.Context())
    assert json.loads(out["recorded"]) == {"ip": "198.51.100.0/24"}
    out = rw.reduced(row, lv(signin_names=ap.NONE, ip=ap.NONE), rw.Context())
    assert out == {"recorded": None}


def test_what_it_cannot_read_it_leaves_and_an_old_name_in_the_details_goes():
    row = {"action": "file_uploaded", "user_id": uuid.uuid4(), "temp_credential_id": None, "username": "alice",
           "ip_address": None, "user_agent": None, "recorded": "not json", "details": json.dumps({"n": 1})}
    assert rw.reduced(row, lv(ip=ap.NONE, names=ap.NONE), rw.Context()) is None
    row = dict(row, recorded=None, details=json.dumps(["a", "list"]))
    assert rw.reduced(row, lv(ip=ap.NONE), rw.Context()) is None
    row = dict(row, details=json.dumps({"file_name": "old.txt", "vault_id": VAULT, "unknown_key": "kept"}))
    assert json.loads(rw.reduced(row, lv(names=ap.FINGERPRINT), rw.Context())["details"]) == {
        "vault_id": VAULT, "unknown_key": "kept"}
    assert rw.reduced(row, lv(ip=ap.NONE, emails=ap.NONE), rw.Context()) is None
    # A value that is not an address keeps nothing in recorded: the column goes all the same.
    assert rw.reduced(dict(row, ip_address="not an address"), lv(ip=ap.SHORTENED), rw.Context()) == {"ip_address": None}


def test_the_prefilter_selects_every_row_reduced_changes(factory):
    t = datetime(2026, 10, 1, 12, 0)
    variants = []
    for levels in (FULL, lv(ip=ap.NONE, user_agent=ap.NONE, emails=ap.NONE, signin_names=ap.NONE, names=ap.NONE),
                   lv(ip=ap.SHORTENED, signin_names=ap.FINGERPRINT, names=ap.FINGERPRINT)):
        variants.append(_write(factory, levels))
        variants.append(_write(factory, levels, action="file_uploaded", username="alice"))
        variants.append(_write(factory, levels, details={"vault_id": VAULT, "n": 1}))
    # Each kind of value alone, in one place only: the prefilter must find it there.
    alone = {"action": "file_uploaded", "user_id": None, "temp_credential_id": None, "username": None,
             "ip_address": None, "user_agent": None, "recorded": None, "details": None}
    sign_fp = fp.fingerprint(fp.SIGNIN, "someone")
    for extra in ({"details": {"client_ip": "198.51.100.1"}}, {"details": {"user_agent": "Agent/2"}},
                  {"details": {"filters": {"user": "bob"}}}, {"details": {"file_name": "old.txt"}},
                  {"details": {"to": "c@example.com"}}, {"recorded": {"ip": "198.51.100.0/24"}},
                  {"recorded": {"details": {"filters.ip": "198.51.100.0/24"}}}, {"recorded": {"signin_name": sign_fp}},
                  {"recorded": {"names": {"vault": VAULT, "values": {"file_name": {"fp": "fp1:x:y"}}}}},
                  {"ip_address": "198.51.100.9"}, {"user_agent": "Agent/3"},
                  {"action": "login_failure", "username": "typed name"}):
        v = dict(alone, **extra)
        for c in ("recorded", "details"):
            v[c] = json.dumps(v[c]) if v[c] is not None else None
        variants.append(v)
    db = factory()
    try:
        ids = []
        for i, v in enumerate(variants):
            row = AuditLog(id=uuid.uuid4(), action=v["action"], status="failure", timestamp=t + timedelta(minutes=i),
                           username=v["username"], user_id=v["user_id"], temp_credential_id=v["temp_credential_id"],
                           ip_address=v["ip_address"], user_agent=v["user_agent"],
                           recorded=json.loads(v["recorded"]) if v["recorded"] else None,
                           details=json.loads(v["details"]) if v["details"] else None)
            db.add(row)
            ids.append(row.id)
        db.commit()
        ctx = rw.Context(accounts={"alice"})
        for levels in ALL_LEVELS:
            picked = {r[0] for r in db.query(AuditLog.id).filter(*rw.prefilter(AuditLog, levels)).all()}
            changed = {i for i, v in zip(ids, variants) if rw.reduced(v, levels, ctx) is not None}
            assert changed <= picked, levels
            if levels == FULL:
                assert rw.prefilter(AuditLog, levels) == [] and changed == set()
        lowest = {k: ap.CHOICES[k][0] for k in ap.POLICY_KEYS}
        assert all(rw.reduced(v, lowest, ctx) for v in variants[-12:])     # every one alone is a value to remove
    finally:
        db.close()


def test_a_value_that_is_not_there_is_nothing_to_remove():
    row = {"action": "file_uploaded", "user_id": uuid.uuid4(), "temp_credential_id": None, "username": "alice",
           "ip_address": None, "user_agent": None, "recorded": None,
           "details": json.dumps({"email": None, "ip_address": None, "filters": {"user": None}, "n": 1})}
    assert rw.reduced(row, lv(emails=ap.NONE, ip=ap.NONE, signin_names=ap.NONE), rw.Context()) is None
