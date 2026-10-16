"""Asking for a per-person erase (app/core/person_erase.py), offline, on a throwaway SQLite database with a chain of
its own (tests/_erase_env.py):

- whose name: refused for an account's, a temporary credential's, a waiting invitation's, and a name that starts
  with "erased-" in any case or form (and no account can be named so); matched exactly;
- the name waits sealed: the token opens only for its request, the request seal's subject commits to it without
  revealing it, the placeholder is random, in its form, and drawn again on a clash;
- the request, the cancel and the audit rows never name the person; a cancel ends the request and deletes the name;
  a running or ended erase cannot be cancelled; an erase cannot be asked for while sealing is stopped;
- the preview counts every store, lists the near misses, and says what it does not reach;
- every table of the models, and every table the data inventory lists, has an entry in COVERAGE.
"""
import json
import re
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from _audit_chain_env import T0, failures
from _erase_env import EraseEnv
from app.core import audit_chain_policy_seals as ps
from app.core import audit_integrity as ai
from app.core import person_erase as pe
from app.core.models import (AccountInvitation, AuditLog, AuditSeal, Base, EraseRequest, Notification,
                             SecurityAlert, SecurityRecord, TemporaryCredential, User)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = EraseEnv(monkeypatch, tmp_path)
    yield e
    e.close()


def _seal(env, seq):
    return next(s for s in env.seals() if s.seq == seq)


# --------------------------------------------------------------------------- whose name

@pytest.mark.parametrize("name", ["erased-1234abcd", "Erased-x", "ERASED-", "ｅｒａｓｅｄ-12345678", "erased-"])
def test_a_name_that_starts_like_a_placeholder_is_reserved(name):
    assert pe.is_reserved_name(name) and pe.name_problem(name)


@pytest.mark.parametrize("name", ["erase-d", "erasedx", "my-erased-name", "eve"])
def test_other_names_are_not_reserved(name):
    assert not pe.is_reserved_name(name)


@pytest.mark.parametrize("name", ["Erased-abc", "erased-12345678"])
def test_no_account_invitation_or_signup_may_take_a_placeholder_name(name):
    from app.api.api_server import _validate_new_username
    with pytest.raises(ValueError, match="erased-"):
        _validate_new_username(name)
    assert _validate_new_username("eve") == "eve"


@pytest.mark.parametrize("name, why", [("", "Type the name"), ("x" * 256, "at most 255"), ("a\x00b", "NUL")])
def test_names_no_record_can_hold_are_refused(name, why):
    assert why in pe.name_problem(name)


@pytest.mark.parametrize("who", ["account", "credential", "invitation"])
def test_a_name_someone_has_is_refused(env, who):
    env.run_until_sealed()
    with env.session() as db:
        if who == "account":
            db.add(User(id=uuid.uuid4(), username="eve", email="e@example.com", password_hash="x", is_active=False))
        elif who == "credential":
            db.add(TemporaryCredential(id=uuid.uuid4(), user_id=uuid.uuid4(), temp_username="eve", credential_hash="x",
                                       expires_at=env.clock() - timedelta(days=1),
                                       deactivate_at=env.clock() - timedelta(days=1)))
        else:
            db.add(AccountInvitation(id=uuid.uuid4(), username="eve", role="user", token_prefix="p",
                                     token_hash=uuid.uuid4().hex, expires_at=env.clock() + timedelta(days=1)))
        db.commit()
    with pytest.raises(pe.Refused, match="cannot be erased now"):
        env.ask("eve")
    with env.session() as db:
        assert db.query(EraseRequest).count() == 0
    assert [s.kind for s in env.seals()].count("request") == 0


def test_an_invitation_that_ended_does_not_hold_the_name(env):
    env.run_until_sealed()
    with env.session() as db:
        db.add(AccountInvitation(id=uuid.uuid4(), username="eve", role="user", token_prefix="p",
                                 token_hash=uuid.uuid4().hex, expires_at=env.clock() - timedelta(days=1)))
        db.commit()
    assert env.ask("eve")["status"] == pe.PENDING


def test_an_account_name_in_another_case_does_not_hold_the_name(env):
    env.run_until_sealed()
    env.admin("Eve")
    assert env.ask("eve")["status"] == pe.PENDING


# --------------------------------------------------------------------------- the name sealed and committed to

def test_the_token_opens_only_for_its_own_request(env):
    rid, other = uuid.uuid4(), uuid.uuid4()
    r = b"\x01" * 32
    token = pe.seal_name(env.settings, rid, r, "évé ✓")
    assert pe.open_name(env.settings, rid, token) == (r, "évé ✓")
    with pytest.raises(ValueError):
        pe.open_name(env.settings, other, token)
    raw = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        pe.open_name(env.settings, rid, raw)
    with pytest.raises(ValueError):
        pe.open_name(env.settings, rid, None)


def test_the_subject_binds_the_request_r_and_the_exact_name():
    rid = uuid.uuid4()
    r = b"\x02" * 32
    s = pe.subject_of(rid, r, "eve")
    assert s != pe.subject_of(rid, r, "Eve") and s != pe.subject_of(rid, b"\x03" * 32, "eve")
    assert s != pe.subject_of(uuid.uuid4(), r, "eve") and len(s) == 32


def test_a_request_writes_its_row_its_seal_and_an_audit_row_that_never_name_the_person(env):
    env.run_until_sealed()
    name = "zelda.unique-person"
    actor = env.admin("ada")
    asked = env.ask(name, actor)
    assert re.fullmatch(r"erased-[0-9a-f]{8}", asked["placeholder"]) and asked["status"] == pe.PENDING
    seal = _seal(env, asked["request_seq"])
    d = seal.detail
    assert d["what"] == "erase" and d["placeholder"] == asked["placeholder"] and d["by"] == "admin"
    assert d["setting"] is None and d["new"] is None and d["user_id"] == str(actor.id)
    assert d["not_before"] == ai.fmt.time_text(seal.sealed_at + timedelta(days=7))
    with env.session() as db:
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        r, opened = pe.open_name(env.settings, row.id, row.name_token)
        assert opened == name and pe.subject_of(row.id, r, name).hex() == d["subject"]
        assert row.placeholder == d["placeholder"] and row.request_seq == seal.seq
        assert row.requested_by_name == "ada" and row.status == pe.PENDING
        audit = db.query(AuditLog).filter(AuditLog.action == pe.REQUESTED_ACTION).one()
        assert d["audit_row"] == str(audit.id) and audit.username == "ada"
        assert audit.details["placeholder"] == asked["placeholder"] and audit.details["request_id"] == asked["id"]
        assert "dropped" not in (audit.recorded or {})
        dumped = json.dumps({"seals": [str(s.detail) for s in env.seals()], "audit": audit.details})
        assert name not in dumped
        assert name not in str(db.execute(text("SELECT * FROM erase_requests")).fetchall())
    assert failures(env.verify()) == []


def test_the_notices_name_the_placeholder_never_the_person(env):
    title, body = pe.notice_text("asked", {"placeholder": "erased-0a1b2c3d", "effective_at": "2026-10-27T09:00:00Z"},
                                 "ada")
    assert "erased-0a1b2c3d" in body and "27 October 2026" in body
    for event in ("cancelled", "completed"):
        title, body = pe.notice_text(event, {"placeholder": "erased-0a1b2c3d", "audit_rows": 3, "other_rows": 2})
        assert "erased-0a1b2c3d" in body


def test_a_placeholder_already_taken_is_drawn_again(env, monkeypatch):
    env.run_until_sealed()
    first = env.ask("eve")
    taken = first["placeholder"][len("erased-"):]
    env.admin("erased-77777777")
    draws = iter([taken, "77777777", "0a0b0c0d"])
    monkeypatch.setattr(pe.secrets, "token_hex", lambda n: next(draws))
    second = env.ask("mallory")
    assert second["placeholder"] == "erased-0a0b0c0d"


def test_a_second_erase_of_a_name_already_waiting_is_refused(env):
    env.run_until_sealed()
    env.ask("eve")
    with pytest.raises(pe.Refused, match="already waiting"):
        env.ask("eve")
    assert env.ask("Eve")["status"] == pe.PENDING          # another name: a near miss is asked for separately


def test_an_erase_cannot_be_asked_for_before_the_chain_starts_or_while_sealing_is_stopped(env):
    with pytest.raises(ai.ChainStopped):
        env.ask("eve")
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == env.seals()[-1].seq).delete()
        db.commit()
    env.clock.advance(hours=2)
    env.seal()
    with pytest.raises(ai.ChainStopped):
        env.ask("eve")
    with env.session() as db:
        assert db.query(EraseRequest).count() == 0


# --------------------------------------------------------------------------- cancelling

def test_any_administrator_cancels_a_waiting_erase_and_its_name_is_deleted(env):
    env.run_until_sealed()
    asked = env.ask("eve", env.admin("ada"))
    bob = env.admin("bob")
    out = env.cancel(asked["id"], bob)
    assert out["status"] == pe.CANCELLED and out["decided_by"] == "bob"
    cancel = [s for s in env.seals() if s.kind == "cancel"][-1]
    assert cancel.detail["cancels"] == asked["request_seq"] and cancel.detail["by"] == "admin"
    with env.session() as db:
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        assert row.status == pe.CANCELLED and row.name_token is None and row.decided_by_name == "bob"
        audit = db.query(AuditLog).filter(AuditLog.action == pe.CANCELLED_ACTION).one()
        assert cancel.detail["audit_row"] == str(audit.id) and "eve" not in json.dumps(audit.details)
    assert asked["request_seq"] not in env.view().pending_requests()
    with pytest.raises(pe.Refused, match="no longer waiting: it was cancelled"):
        env.cancel(asked["id"], bob)
    env.passes(24 * 8)
    assert env.erase_seals() == []
    assert failures(env.verify()) == []


def test_an_erase_that_has_begun_or_completed_cannot_be_cancelled(env, monkeypatch):
    from app.core import audit_chain_erase as ae
    from app.core import retention
    env.row(T0 - timedelta(hours=30), username="eve")
    env.row(T0 - timedelta(hours=20), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 - 6)
    real = ae.step

    def one_unit(p, w, seq, findings, tried):
        out = real(p, w, seq, findings, tried)
        if out[0] == ae.ERASED:
            p.deadline = 0
        return out
    monkeypatch.setattr(ae, "step", one_unit)
    env.clock.advance(hours=6)
    retention.run_pass(env.session, now=env.clock())
    assert env.request_row(asked["id"]).status == pe.RUNNING
    with pytest.raises(pe.Refused, match="has begun"):
        env.cancel(asked["id"], env.admin("bob"))
    monkeypatch.setattr(ae, "step", real)
    env.passes(6)
    with pytest.raises(pe.Refused, match="it was completed"):
        env.cancel(asked["id"], env.admin("carol"))


def test_a_cancel_of_an_erase_the_chain_does_not_hold_is_no_erase(env):
    env.run_until_sealed()
    with pytest.raises(LookupError):
        env.cancel(uuid.uuid4(), env.admin("bob"))


def test_a_cancel_while_sealing_is_stopped_ends_it_at_once_and_is_sealed_from_the_database(env):
    env.run_until_sealed()
    asked = env.ask("eve")
    with env.session() as db:
        out = pe.cancel_while_stopped(db, asked["id"], env.admin("bob"))
        db.commit()
    assert out["status"] == pe.CANCELLED and not out["cancellable"]
    row = env.request_row(asked["id"])
    assert row.status == pe.CANCELLED and row.name_token is None
    env.passes(6)
    cancels = [s for s in env.seals() if s.kind == "cancel"]
    assert len(cancels) == 1 and cancels[0].detail["by"] == "database"
    assert asked["request_seq"] not in env.view().pending_requests()


# --------------------------------------------------------------------------- the preview and the list

def test_the_preview_counts_every_store_and_lists_near_misses(env):
    owner = env.admin("owner")
    env.row(T0 - timedelta(hours=30), username="eve")
    env.row(T0 - timedelta(hours=29), username="eve")
    env.row(T0 - timedelta(hours=29), username="EVE")
    env.row(T0 - timedelta(hours=29), username="alice", details={"target_username": "eve"})
    env.run_until_sealed()
    with env.session() as db:
        db.add(SecurityRecord(id=uuid.uuid4(), at=T0, kind="password", name="eve", address="198.51.100.4"))
        db.add(SecurityAlert(id=uuid.uuid4(), event_type="x", severity="info", message="m", username="eve",
                             timestamp=T0))
        db.add(Notification(id=uuid.uuid4(), user_id=owner.id, type="x", title="about eve", created_at=T0))
        db.commit()
    with env.session() as db:
        p = pe.preview(db, "eve", env.clock(), env.st)
    assert p["audit_rows"] == 2 and p["near_misses"] == ["EVE"] and p["refused"] is None
    counts = {s["key"]: s["count"] for s in p["stores"]}
    assert counts["security_records"] == 1 and counts["security_alerts"] == 1 and counts["notifications"] == 1
    assert set(counts) == {s.key for s in pe.STORES}
    assert p["mentioned_by_others"] == 1 and p["delay_days"] == 7
    assert any("other people's audit rows" in t for t in p["not_reached"])
    with env.session() as db:
        assert pe.preview(db, "owner", env.clock(), env.st)["refused"].startswith("an account has this name")
        with pytest.raises(pe.Refused):
            pe.preview(db, "erased-00000000", env.clock(), env.st)


def test_the_list_says_each_erase_as_the_chain_holds_it(env):
    env.run_until_sealed()
    waiting = env.ask("eve")
    cancelled = env.ask("mallory")
    env.cancel(cancelled["id"], env.admin("bob"))
    with env.session() as db:
        db.add(EraseRequest(id=uuid.uuid4(), status=pe.PENDING, placeholder="erased-feedfeed",
                            requested_at=env.clock()))
        db.commit()
    with env.session() as db:
        listed = {e["placeholder"]: e for e in pe.listing(db, env.st)}
    assert listed[waiting["placeholder"]]["status"] == pe.PENDING and listed[waiting["placeholder"]]["cancellable"]
    assert listed[cancelled["placeholder"]]["status"] == pe.CANCELLED
    assert listed["erased-feedfeed"]["status"] == "not recorded" and not listed["erased-feedfeed"]["cancellable"]
    assert "eve" not in json.dumps(list(listed.values()))


# --------------------------------------------------------------------------- what it covers

def _inventory_tables():
    text_ = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    database = text_[text_.index("## Database"):text_.index("## Cache (Redis)")]
    found = set()
    for line in database.splitlines():
        if line.startswith("| `"):
            found.update(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
        elif line.startswith("`") or " holds " in line:
            found.update(t for t in re.findall(r"`([a-z_]+)`", line) if "_" in t or t in ("vaults", "groups"))
    return found


def test_every_table_has_an_erase_handler_or_a_reason():
    assert set(Base.metadata.tables) - set(pe.COVERAGE) == set()
    for key, what in pe.COVERAGE.items():
        assert what and isinstance(what, str)
    for store in pe.STORES:
        assert pe.COVERAGE[store.key] == store.key and store.key in Base.metadata.tables


def test_every_table_the_data_inventory_lists_has_an_erase_handler_or_a_reason():
    tables = _inventory_tables()
    assert {"audit_logs", "security_records", "credential_changes", "erase_requests"} <= tables
    assert tables - set(pe.COVERAGE) == set()


def test_the_data_inventory_describes_the_built_in_erase():
    text_ = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    section = text_[text_.index("## Erasing a person"):text_.index("## Retention settings")]
    assert "There is no built-in per-person erasure" not in section
    assert "erased-" in section and "ERASE_BLOCKED_BY_PROTECTED_MINIMUM" in section


def test_deleting_an_account_leaves_its_audit_rows_to_the_database():
    assert User.audit_logs.property.passive_deletes is True
