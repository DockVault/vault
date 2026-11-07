"""The hold on an account's zero-knowledge key envelope after an administrator changed its sign-in details,
and the rule for a new passphrase.

For ZK_ENVELOPE_HOLD_DAYS (default 14, 0 turns it off, at most 14) after an administrator or the host operator
changed an account's sign-in details, GET /ecc/keys/private releases the envelope to a session only once that
session has entered a code sent by email (app/core/envelope_hold.py). Pinned here, offline: the setting and its
bounds, where it can be set, when an account is held and when that ends, what a session's release and the
host operator's release cover, the three routes, and the web app's side. test_zk_envelope_hold_live.py runs it
on a deployment with a mail sink, and without one.
"""
import importlib.util
import inspect
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import ecc_router as E  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import envelope_hold as H  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.core.models import ActiveSession, CredentialChange, User, UserKeyPair  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402
from app.services.zk_key_proof import KeyProofRefusal  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------ the setting

def test_the_hold_is_14_days_by_default_and_0_to_14_are_the_only_values():
    assert Settings.model_fields["zk_envelope_hold_days"].default == 14
    for ok in (0, 1, 7, 14, "0", "14"):
        assert Settings(zk_envelope_hold_days=ok).zk_envelope_hold_days == int(ok)
    for bad in (-1, 15, 30, 365):
        with pytest.raises(ValidationError):
            Settings(zk_envelope_hold_days=bad)


def test_a_value_the_server_cannot_use_stops_it_starting(monkeypatch, tmp_path):
    from app.core import config
    monkeypatch.setenv("ZK_ENVELOPE_HOLD_DAYS", "15")
    with pytest.raises(ValidationError):
        Settings()
    source = inspect.getsource(config.initialize_runtime)
    assert "except ValidationError:" in source and '"settings-invalid"' in source


def test_it_can_be_set_only_in_the_environment():
    for key in ("zk_envelope_hold_days", "ZK_ENVELOPE_HOLD_DAYS"):
        with pytest.raises(HTTPException) as refused:
            api._validate_settings_payload({key: 0}, db=None)
        assert refused.value.status_code == 400 and "managed by the deployment environment" in refused.value.detail
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\nZK_ENVELOPE_HOLD_DAYS=14\n") == 1


def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_hold", ROOT / "dockvault.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("env,written", [
    ({}, None), ({"ZK_ENVELOPE_HOLD_DAYS": "14"}, None), ({"ZK_ENVELOPE_HOLD_DAYS": "0"}, "0"),
    ({"ZK_ENVELOPE_HOLD_DAYS": "7"}, "7"), ({"ZK_ENVELOPE_HOLD_DAYS": "30"}, None),
    ({"ZK_ENVELOPE_HOLD_DAYS": "soon"}, None),
])
def test_the_management_tool_writes_only_a_chosen_hold_and_keeps_it_across_a_fresh_set(monkeypatch, env, written):
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config(env, "prefix-1", "dep-1")
    lines = [ln for ln in dv.build_env_lines({**cfg, "server_name": "localhost"})
             if ln.startswith("ZK_ENVELOPE_HOLD_DAYS")]
    assert lines == ([] if written is None else [f"ZK_ENVELOPE_HOLD_DAYS={written}"])
    if written is not None:
        assert Settings(zk_envelope_hold_days=written).zk_envelope_hold_days == int(written)


def test_the_web_container_says_so_at_start_only_when_it_is_off(monkeypatch):
    printed = []
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 0)
    H.report_at_startup(printed.append)
    assert len(printed) == 1 and "ZK_ENVELOPE_HOLD_DAYS=0" in printed[0]
    printed.clear()
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 14)
    H.report_at_startup(printed.append)
    assert printed == []
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    startup = src[src.index("async def lifespan("):]
    assert startup[:startup.index("\n    yield\n")].count("envelope_hold.report_at_startup()") == 1


# ------------------------------------------------------------------------------------------ the hold

NOW = datetime(2026, 11, 20, 12, 0, 0)


@pytest.fixture
def world(monkeypatch):
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None

        def process(value):
            return inner(uuid.UUID(value) if isinstance(value, str) else value)
        return process

    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 14)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'h.db'}", connect_args={"check_same_thread": False})
        for table in (User.__table__, CredentialChange.__table__, ActiveSession.__table__, UserKeyPair.__table__):
            table.create(engine)
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        db = maker()
        yield SimpleNamespace(db=db)
        db.close()
        engine.dispose()


def _account(world):
    user = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x",
                email="p@example.com")
    world.db.add(user)
    token = uuid.uuid4().hex
    world.db.add(ActiveSession(session_token=hash_session_token(token), user_id=user.id, ip_address="127.0.0.1"))
    world.db.commit()
    user._session_token = token
    return user


def _change(world, user, *, days_ago, status=cc.MADE, kind=cc.PASSWORD, payload=None):
    applied = NOW - timedelta(days=days_ago) if status in cc.APPLIED else None
    row = CredentialChange(target_user_id=user.id, kind=kind, status=status, requested_by_name="admin",
                           requested_at=NOW - timedelta(days=days_ago), applied_at=applied, payload=payload)
    world.db.add(row)
    world.db.commit()
    return row


def test_an_account_no_administrator_changed_is_not_held(world):
    user = _account(world)
    assert H.held_until(world.db, user, NOW) is None


@pytest.mark.parametrize("kind", [cc.PASSWORD, cc.RESET_LINK, cc.SECOND_FACTOR, cc.EMAIL, cc.SSH_KEY])
def test_any_change_an_administrator_made_holds_the_account(world, kind):
    user = _account(world)
    _change(world, user, days_ago=3, kind=kind)
    assert H.held_until(world.db, user, NOW) == NOW - timedelta(days=3) + timedelta(days=14)


def test_a_request_that_was_not_applied_holds_nothing(world):
    user = _account(world)
    for status in (cc.HELD, cc.DENIED, cc.WITHDRAWN, cc.EXPIRED):
        _change(world, user, days_ago=1, status=status)
    assert H.held_until(world.db, user, NOW) is None
    _change(world, user, days_ago=1, status=cc.APPROVED)
    assert H.held_until(world.db, user, NOW) is not None


def test_the_hold_ends_on_the_configured_day_and_0_turns_it_off(world, monkeypatch):
    user = _account(world)
    _change(world, user, days_ago=6)
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 7)
    assert H.held_until(world.db, user, NOW) == NOW + timedelta(days=1)
    assert H.held_until(world.db, user, NOW + timedelta(days=1, seconds=1)) is None
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 5)
    assert H.held_until(world.db, user, NOW) is None
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 0)
    assert H.held_until(world.db, user, NOW) is None


def test_at_14_days_the_hold_ends_no_later_than_the_record_is_pruned(world):
    """The hold reads the change's record, which the periodic cleanup deletes 14 days after it applied: while
    the account is held, the record is still there."""
    user = _account(world)
    _change(world, user, days_ago=0)
    for hours in range(0, 24 * 15, 7):
        now = NOW + timedelta(hours=hours)
        held = H.held_until(world.db, user, now) is not None
        pruned = world.db.query(CredentialChange).filter(
            CredentialChange.status.in_(cc.APPLIED), CredentialChange.applied_at < now - cc.WINDOW).count()
        assert not (held and pruned), hours
    assert H.MAX_DAYS == cc.WINDOW.days


def test_a_session_that_entered_the_code_is_released_until_the_next_change(world):
    user = _account(world)
    _change(world, user, days_ago=2)
    assert H.release_session(world.db, user, NOW) is True
    world.db.commit()
    assert H.held_until(world.db, user, NOW) is None
    # Another session of the same account is still held.
    mine = user._session_token
    user._session_token = "someone-else"
    assert H.held_until(world.db, user, NOW) is not None
    # A change after the release holds this session again.
    user._session_token = mine
    _change(world, user, days_ago=-0.5)
    assert H.held_until(world.db, user, NOW + timedelta(days=1)) is not None


def test_a_request_without_a_session_row_is_never_released(world):
    user = _account(world)
    _change(world, user, days_ago=1)
    user._session_token = None
    assert H.release_session(world.db, user, NOW) is False
    assert H.held_until(world.db, user, NOW) is not None


def test_the_host_operator_releases_the_account_for_the_changes_so_far(world):
    user = _account(world)
    _change(world, user, days_ago=1)
    _change(world, user, days_ago=2)
    assert H.release_by_host(world.db, user.id, NOW) == 2
    world.db.commit()
    assert H.held_until(world.db, user, NOW) is None
    assert H.release_by_host(world.db, user.id, NOW) == 0
    _change(world, user, days_ago=-1)
    assert H.held_until(world.db, user, NOW + timedelta(days=2)) is not None


# ------------------------------------------------------------------------------------------ the routes

GET_PRIVATE = inspect.unwrap(E.get_private_key)
SEND_CODE = inspect.unwrap(E.send_envelope_release_code)
RELEASE = inspect.unwrap(E.release_envelope_hold)


@pytest.fixture
def routes(world, monkeypatch):
    audit = []
    monkeypatch.setattr(E, "_audit_zk", lambda db, actor, action, **kw: audit.append((action, kw.get("details"))))
    monkeypatch.setattr(E, "_ecc_rate_limit", lambda *a, **k: None)
    monkeypatch.setattr(E, "may_release_private_envelope", lambda db, user: True)
    monkeypatch.setattr(H, "utcnow", lambda: NOW)
    sent = []
    from app.core import email_actions, otp_service
    monkeypatch.setattr(email_actions, "send_action_email",
                        lambda db, key, *, recipient, action_context=None, raise_errors=False, **k:
                        sent.append((key, recipient["email"], action_context["code"])) or True)
    codes = {}
    monkeypatch.setattr(otp_service, "issue", lambda db, *, purpose, user_id, destination, ttl_minutes, pepper=None:
                        codes.setdefault((purpose, str(user_id)), "c0de12"))
    monkeypatch.setattr(otp_service, "verify", lambda db, *, purpose, user_id, code, pepper=None:
                        otp_service.OtpResult(True) if codes.get((purpose, str(user_id))) == code
                        else otp_service.OtpResult(False, reason="invalid"))
    monkeypatch.setattr(otp_service, "invalidate", lambda db, **k: codes.clear())
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    return SimpleNamespace(audit=audit, sent=sent, codes=codes)


def _keyed(world, user):
    world.db.add(UserKeyPair(user_id=user.id, public_key="P", fingerprint="f", encrypted_private_key="ENV"))
    world.db.commit()


def test_a_held_session_gets_the_hold_refusal_and_the_rest_get_the_envelope(world, routes):
    user = _account(world)
    _keyed(world, user)
    assert run_coroutine(GET_PRIVATE(current_user=user, db=world.db))["encrypted_private_key"] == "ENV"
    _change(world, user, days_ago=1)
    with pytest.raises(KeyProofRefusal) as refused:
        run_coroutine(GET_PRIVATE(current_user=user, db=world.db))
    assert (refused.value.status_code, refused.value.reason) == (403, "zk-envelope-hold")


def test_a_key_set_up_after_the_change_is_held_until_the_hold_ends(world, routes, monkeypatch):
    """The hold reads the changes, not the key. An account whose sign-in details were changed before it had a key
    (before the upgrade too) has nothing to hold, and is held as soon as it sets one up, until the hold ends: the
    upgrade's check, which counts only accounts with a key, cannot count it."""
    user = _account(world)
    _change(world, user, days_ago=3)
    assert run_coroutine(GET_PRIVATE(current_user=user, db=world.db)) == {"has_keypair": False,
                                                                          "encrypted_private_key": None}
    # Set up two days after the change.
    world.db.add(UserKeyPair(user_id=user.id, public_key="P", fingerprint="f", encrypted_private_key="ENV",
                             created_at=NOW - timedelta(days=1)))
    world.db.commit()
    with pytest.raises(KeyProofRefusal) as refused:
        run_coroutine(GET_PRIVATE(current_user=user, db=world.db))
    assert (refused.value.status_code, refused.value.reason) == (403, "zk-envelope-hold")
    ends = H.held_until(world.db, user, NOW)
    assert ends == NOW - timedelta(days=3) + timedelta(days=14)
    monkeypatch.setattr(H, "utcnow", lambda: ends + timedelta(seconds=1))
    assert run_coroutine(GET_PRIVATE(current_user=user, db=world.db))["encrypted_private_key"] == "ENV"


def test_the_code_goes_to_the_address_before_the_change_and_releases_this_session(world, routes):
    user = _account(world)
    _keyed(world, user)
    # The account's address now (p@example.com) is not where the code goes: the change kept the one before.
    _change(world, user, days_ago=1, payload={"email_at_change": "before@example.com"})
    out = run_coroutine(SEND_CODE(current_user=user, db=world.db))
    assert out == {"held": True, "sent_to": "b***@example.com", "expires_in_minutes": H.CODE_TTL_MINUTES}
    assert routes.sent == [(H.EMAIL_ACTION, "before@example.com", "c0de12")]
    assert routes.audit[-1][0] == "zk_envelope_release_code_sent"
    # A wrong code: refused, recorded, still held.
    with pytest.raises(KeyProofRefusal) as refused:
        run_coroutine(RELEASE(request=E.EnvelopeReleaseRequest(code="nope"), current_user=user, db=world.db))
    assert (refused.value.status_code, refused.value.reason) == (403, "zk-envelope-hold-code-failed")
    assert routes.audit[-1] == ("zk_envelope_release_failed", {"reason": "invalid"})
    assert H.held_until(world.db, user, NOW) is not None
    # The right one (typed with spaces and in capitals) releases this session.
    out = run_coroutine(RELEASE(request=E.EnvelopeReleaseRequest(code=" C0DE12 "), current_user=user, db=world.db))
    assert out == {"released": True} and routes.audit[-1] == ("zk_envelope_released", {"by": "code"})
    assert run_coroutine(GET_PRIVATE(current_user=user, db=world.db))["encrypted_private_key"] == "ENV"


@pytest.mark.parametrize("case", ["no address", "an older record", "no mail", "the send fails"])
def test_without_a_way_to_send_the_code_it_says_so_and_sends_nothing(world, routes, monkeypatch, case):
    user = _account(world)
    payload = {"no address": {"email_at_change": None}, "an older record": None}.get(
        case, {"email_at_change": "p@example.com"})
    _change(world, user, days_ago=1, payload=payload)
    if case == "no mail":
        monkeypatch.setattr(api, "_smtp_configured", lambda db: False)
    if case == "the send fails":
        from app.core import email_actions, email_send

        def fail(*a, **k):
            raise email_send.EmailSendError("transport", "down")
        monkeypatch.setattr(email_actions, "send_action_email", fail)
    with pytest.raises(KeyProofRefusal) as refused:
        run_coroutine(SEND_CODE(current_user=user, db=world.db))
    assert (refused.value.status_code, refused.value.reason) == (409, "zk-envelope-hold-no-mail")
    assert routes.sent == [] and routes.codes == {}


def test_asking_for_and_entering_the_code_are_rate_limited(world, routes, monkeypatch):
    user = _account(world)
    _keyed(world, user)
    _change(world, user, days_ago=1, payload={"email_at_change": "p@example.com"})
    run_coroutine(SEND_CODE(current_user=user, db=world.db))
    buckets = []

    def limited(u, bucket):
        buckets.append(bucket)
        raise HTTPException(status_code=429, detail="Too many requests")
    monkeypatch.setattr(E, "_ecc_rate_limit", limited)
    for route, kwargs in ((SEND_CODE, {}), (RELEASE, {"request": E.EnvelopeReleaseRequest(code="c0de12")})):
        with pytest.raises(HTTPException) as refused:
            run_coroutine(route(current_user=user, db=world.db, **kwargs))
        assert refused.value.status_code == 429
    assert buckets == ["envelope_hold", "envelope_hold"]
    # The right code, refused by the limit, released nothing.
    assert H.held_until(world.db, user, NOW) is not None
    assert len(routes.sent) == 1


def test_the_right_code_releases_nothing_without_a_session_row_to_record_it_on(world, routes):
    user = _account(world)
    _keyed(world, user)
    _change(world, user, days_ago=1, payload={"email_at_change": "p@example.com"})
    run_coroutine(SEND_CODE(current_user=user, db=world.db))
    token, user._session_token = user._session_token, None
    with pytest.raises(KeyProofRefusal) as refused:
        run_coroutine(RELEASE(request=E.EnvelopeReleaseRequest(code="c0de12"), current_user=user, db=world.db))
    assert (refused.value.status_code, refused.value.reason) == (403, "zk-envelope-hold-code-failed")
    assert routes.audit[-1] == ("zk_envelope_release_failed", {"reason": "no_session"})
    user._session_token = token
    assert H.held_until(world.db, user, NOW) is not None


def test_an_account_that_is_not_held_is_sent_nothing_and_has_nothing_to_release(world, routes):
    user = _account(world)
    assert run_coroutine(SEND_CODE(current_user=user, db=world.db)) == {"held": False}
    assert run_coroutine(RELEASE(request=E.EnvelopeReleaseRequest(code="x"), current_user=user,
                                 db=world.db)) == {"released": True}
    assert routes.sent == [] and routes.audit == []


def test_the_request_names_its_session_for_the_hold():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = src[src.index("async def get_current_user("):src.index("def _audit_admin_denial(")]
    assert body.count("user._session_token = session_token or None") == 1
    assert body.index("user._session_token = ") < body.index("return user")
    # Compared hashed, as every lookup of a session row is.
    hold = (ROOT / "app" / "core" / "envelope_hold.py").read_text(encoding="utf-8")
    assert hold.count("ActiveSession.session_token == hash_session_token(token)") == 2


def test_the_host_tool_releases_the_hold_with_the_username_typed_again():
    from app.core import host_operator
    assert "release-key-hold" in host_operator.ACTIONS
    src = inspect.getsource(host_operator._run)
    branch = src[src.index('if args.action == "release-key-hold":'):src.index('if args.action == "reset-second-factor":')]
    assert "envelope_hold.release_by_host(db, user.id)" in branch
    # The confirmation is checked before any change is made (the same check as the other changes).
    assert src.index("problem = confirmation_problem(args.username, args.confirm_username)") < src.index(
        'if args.action == "release-key-hold":')
    assert "zk_notices.envelope_released_by_host(db, user)" in branch
    dv = _dockvault()
    assert "release-key-hold" in [k for k, _ in dv.ACCOUNT_ACTIONS]


# ------------------------------------------------------------------------------------------ the web app

def _function(name):
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, name
    rest = APP[decl.end():]
    nxt = re.search(r"^(async )?function |^(const|let|var) |^// =====", rest, re.M)
    return APP[decl.start():decl.end() + (nxt.start() if nxt else len(rest))]


def test_every_fetch_of_the_envelope_goes_through_the_hold():
    assert APP.count("apiRequest('/ecc/keys/private', { silent: true })") == 1
    assert "return await apiRequest('/ecc/keys/private', { silent: true });" in _function("zkFetchPrivateEnvelope")
    # Each reads it once, directly or as a step of the key operation (which a sign-out ends: _zkSteps).
    read = re.compile(r"const priv = await (zkFetchPrivateEnvelope\(\)|step\(\(\) => zkFetchPrivateEnvelope\(\)\));")
    for name in ("_zkUnlockOnce", "zkChangePassphrase", "zkExportRecoveryKey"):
        assert len(read.findall(_function(name))) == 1, name
    fetch = _function("zkFetchPrivateEnvelope")
    assert "if (!e || e.reason !== 'zk-envelope-hold' || attempt > 0) throw e;" in fetch
    release = _function("zkReleaseEnvelopeHold")
    assert release.index("'/ecc/keys/private/hold/code'") < release.index("'/ecc/keys/private/hold/release'")
    assert "if (e && e.reason === 'zk-envelope-hold-code-failed' && tries < 3) {" in release


def test_every_new_passphrase_passes_the_rule_and_an_old_one_is_only_nudged():
    for name, var in (("zkRegisterNewKeypair", "pass"), ("zkChangePassphrase", "next"),
                      ("zkExportRecoveryKey", "rec"), ("zkRestoreFromRecoveryKey", "next")):
        fn = _function(name)
        assert f"Problem = zkPassphraseProblem({var});" in fn, name
        assert f"{var}.length < 8" not in fn, name
    unlock = _function("_zkUnlockOnce")
    # After the key is in memory: the unlock has already succeeded when the person is told.
    assert "    zkNudgeWeakPassphrase(pass);\n    return zkState.privateKey;\n}\n" in unlock
    assert unlock.index("zkState.privateKey = await step(() => eccLib().importPrivateKeyPEM(pem, false));") < unlock.index(
        "zkNudgeWeakPassphrase(pass);")
    nudge = _function("zkNudgeWeakPassphrase")
    assert "throw" not in nudge and "showWarning(" in nudge
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert index.index('<script src="/static/js/zk_passphrase.js?v=') < index.index('<script src="/static/js/app.js?v=')


@pytest.fixture(scope="module")
def passphrase_rule() -> str:
    node = shutil.which("node")
    assert node, "Node is required"
    done = subprocess.run([node, str(ROOT / "tests" / "js" / "zk_passphrase.js")], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0 and done.stdout.rstrip().endswith("ALL OK"), done.stdout + done.stderr
    return done.stdout


@pytest.mark.parametrize("case", [
    "the minimum is 12 characters", "eleven characters are refused",
    "twelve or more characters of words are accepted", "the length sentence",
    "a listed passphrase is refused: P@ssw0rd1234", "a listed passphrase is refused: correct horse battery staple",
    "a common word with only digits or symbols around it is refused: password-2027-!!",
    "only digits are refused", "one character repeated is refused", "a short run repeated is refused",
    "a run of the alphabet is refused", "a run of a keyboard row is refused",
    "mostly the account name is refused", "mostly the email name is refused",
    "the account name inside a longer passphrase is accepted",
    "an ordinary passphrase is accepted: passphrase-A-123",
    "an old short passphrase is suggested for a change at unlock", "a good one is not",
])
def test_the_passphrase_rule(passphrase_rule, case):
    assert f"ok   {case}\n" in passphrase_rule, case
