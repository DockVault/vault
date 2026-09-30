"""Who is told about zero-knowledge keys, how often, and through which channel (app/services/zk_notices.py).

* A key change refused for want of the account's own encryption key tells the account's user in the app
  and by email, at most once an hour.
* An owner's reset of a vault's key tells every other manager of the vault, in the app and by email, and
  nobody else.
* An encryption key set up for an account tells its user, in the app and by email.
* A member's report of a key that does not match tells the vault's owner in the app, once a day per vault.

The notices are written through the real in-app notification writer into a throwaway SQLite database; the
emails are the automated email handed to the sender. test_zk_notices_live.py sees the same on a deployment.
"""
import contextlib
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import database  # noqa: E402
from app.core import email_actions as ea  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core.models import CredentialChange, Notification, RoleEnum, User, Vault, vault_members  # noqa: E402
from app.services import zk_notices as N  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


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
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'n.db'}", connect_args={"check_same_thread": False})
        for table in (User.__table__, Vault.__table__, vault_members, Notification.__table__,
                      CredentialChange.__table__):
            table.create(engine)
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        opened = []

        @contextlib.contextmanager
        def context():
            s = maker()
            opened.append(s)
            try:
                yield s
                s.commit()
            except Exception:
                s.rollback()
                raise
            finally:
                s.close()

        monkeypatch.setattr(database, "get_db_context", context)
        monkeypatch.setattr(S, "_fire_offloop", lambda *a, **k: None)
        mails = []
        monkeypatch.setattr(S, "_fire_action_email",
                            lambda db, key, *, email, username=None, action_context=None:
                            mails.append((key, email, (action_context or {}).get("change"))))
        clock = {"now": datetime.utcnow()}
        monkeypatch.setattr(N, "_now", lambda: clock["now"])
        db = maker()
        opened.append(db)
        yield SimpleNamespace(db=db, mails=mails, clock=clock, maker=maker)
        for s in opened:
            s.close()
        engine.dispose()


def _person(world, **kw):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x",
             email=f"{uuid.uuid4().hex[:8]}@example.com", **kw)
    world.db.add(u)
    world.db.commit()
    return u


def _notices(world, user):
    s = world.maker()
    try:
        return [(n.title, n.body, n.target) for n in s.query(Notification).filter(
            Notification.user_id == user.id, Notification.type == N.NOTICE_TYPE).order_by(Notification.created_at)]
    finally:
        s.close()


def _stamp(world, user, when):
    """Say the person's notices were written at `when` (the clock the rolling rule reads)."""
    s = world.maker()
    try:
        for n in s.query(Notification).filter(Notification.user_id == user.id).all():
            n.created_at = when
        s.commit()
    finally:
        s.close()


# ------------------------------------------------------------------------------------ failed proof

def test_a_refused_key_change_without_the_accounts_key_is_told_at_most_once_an_hour(world):
    user = _person(world)
    start = world.clock["now"]
    for _ in range(3):
        N.failed_identity_proof(world.db, user)
    assert len(_notices(world, user)) == 1
    assert world.mails == [(N.EMAIL_ACTION, user.email, N.FAILED_PROOF_TEXT)]
    title, body, target = _notices(world, user)[0]
    assert title == N.FAILED_PROOF_TITLE and body == N.FAILED_PROOF_TEXT and target == "#profile"

    # 59 minutes later: still within the hour, told nothing more.
    _stamp(world, user, start)
    world.clock["now"] = start + timedelta(minutes=59)
    N.failed_identity_proof(world.db, user)
    assert len(_notices(world, user)) == 1 and len(world.mails) == 1
    # An hour and a minute later: told again, once.
    world.clock["now"] = start + timedelta(minutes=61)
    N.failed_identity_proof(world.db, user)
    N.failed_identity_proof(world.db, user)
    assert len(_notices(world, user)) == 2 and len(world.mails) == 2


def test_the_hourly_limit_is_per_person(world):
    a, b = _person(world), _person(world)
    N.failed_identity_proof(world.db, a)
    N.failed_identity_proof(world.db, b)
    assert len(_notices(world, a)) == 1 and len(_notices(world, b)) == 1
    assert [m[1] for m in world.mails] == [a.email, b.email]


def test_the_failed_proof_text_names_no_vault_and_keeps_to_the_refusal_words():
    from app.services.zk_key_proof import FORBIDDEN_IN_REFUSALS
    low = N.FAILED_PROOF_TEXT.lower()
    for word in ("inactive", "terminated", "locked", "unauthorized", "401"):
        assert word in FORBIDDEN_IN_REFUSALS and word not in low
    assert "refused" in low and "nothing was changed" in low


# ------------------------------------------------------------------------------------ owner reset

def test_an_owner_reset_tells_every_other_manager_and_nobody_else(world):
    owner = _person(world)
    managers = [_person(world), _person(world)]
    reader, admin = _person(world), _person(world, role=RoleEnum.ADMIN)
    vid = uuid.uuid4()
    world.db.add(Vault(id=vid, owner_id=owner.id, type="zero_knowledge", key_wrapping_mode="direct"))
    world.db.flush()
    for m in managers:
        world.db.execute(vault_members.insert().values(vault_id=vid, user_id=m.id, manage_permission=True))
    world.db.execute(vault_members.insert().values(vault_id=vid, user_id=reader.id, manage_permission=False))
    world.db.commit()
    vault = world.db.get(Vault, vid)
    N.owner_reset(world.db, owner, vault)
    for m in managers:
        (title, body, target), = _notices(world, m)
        assert title == N.OWNER_RESET_TITLE and owner.username in body and target == "#vaults"
    for nobody in (owner, reader, admin):
        assert _notices(world, nobody) == []
    assert sorted(m[1] for m in world.mails) == sorted(m.email for m in managers)
    assert {m[0] for m in world.mails} == {N.EMAIL_ACTION}


def test_an_owner_reset_of_a_vault_without_other_managers_tells_no_one(world):
    owner = _person(world)
    vid = uuid.uuid4()
    world.db.add(Vault(id=vid, owner_id=owner.id, type="zero_knowledge", key_wrapping_mode="direct"))
    world.db.commit()
    N.owner_reset(world.db, owner, world.db.get(Vault, vid))
    assert _notices(world, owner) == [] and world.mails == []


# ------------------------------------------------------------------------------------ registration

def test_setting_up_a_key_tells_its_user(world):
    user = _person(world)
    N.key_registered(world.db, user)
    (title, body, target), = _notices(world, user)
    assert title == N.KEY_REGISTERED_TITLE and target == "#profile"
    assert world.mails == [(N.EMAIL_ACTION, user.email, N.KEY_REGISTERED_TEXT)]


# ------------------------------------------------------------------------------------ which address

def _changed(world, user, kind, payload, days_ago=1):
    when = cc.utcnow() - timedelta(days=days_ago)
    world.db.add(CredentialChange(target_user_id=user.id, kind=kind, status=cc.MADE, requested_by_name="admin",
                                  requested_at=when, applied_at=when, payload=payload))
    world.db.commit()


@pytest.mark.parametrize("notice", ["registered", "failed proof"])
def test_after_an_administrators_change_the_address_before_it_is_told_too(world, notice):
    """The administrator set a password, signed in with it, and moved the address through the account's own
    settings: the notice still reaches the address the account had."""
    user = _person(world)
    _changed(world, user, cc.PASSWORD, {"email_at_change": "person@example.com"})
    (N.key_registered if notice == "registered" else N.failed_identity_proof)(world.db, user)
    assert sorted(m[1] for m in world.mails) == sorted([user.email, "person@example.com"])


def test_an_administrators_email_change_tells_the_address_before_it(world):
    user = _person(world)
    _changed(world, user, cc.EMAIL, {"previous_email": "person@example.com", "new_email": user.email})
    N.key_registered(world.db, user)
    assert sorted(m[1] for m in world.mails) == sorted([user.email, "person@example.com"])


@pytest.mark.parametrize("payload,days_ago", [
    ({"email_at_change": None}, 1),                 # the account had no address
    (None, 1),                                      # a change recorded before it kept one
    ({"email_at_change": "person@example.com"}, 15),  # outside the 14 days
])
def test_without_another_known_address_only_the_account_is_told(world, payload, days_ago):
    user = _person(world)
    _changed(world, user, cc.PASSWORD, payload, days_ago=days_ago)
    N.key_registered(world.db, user)
    assert [m[1] for m in world.mails] == [user.email]


def test_the_same_address_is_told_once(world):
    user = _person(world)
    _changed(world, user, cc.PASSWORD, {"email_at_change": user.email.upper()})
    N.key_registered(world.db, user)
    assert [m[1] for m in world.mails] == [user.email]


# ------------------------------------------------------------------------------------ mismatch report

def test_a_mismatch_report_tells_the_owner_in_the_app_once_a_day_per_vault(world):
    owner = _person(world)
    vaults = []
    for _ in range(2):
        vid = uuid.uuid4()
        world.db.add(Vault(id=vid, owner_id=owner.id, type="zero_knowledge", key_wrapping_mode="direct"))
        vaults.append(vid)
    world.db.commit()
    first, second = (world.db.get(Vault, v) for v in vaults)
    N.key_check_mismatch(world.db, first, "dek_check")
    N.key_check_mismatch(world.db, first, "lineage")
    assert len(_notices(world, owner)) == 1
    N.key_check_mismatch(world.db, second, "seal")
    assert len(_notices(world, owner)) == 2
    assert world.mails == [], "a report is told in the app only"
    world.clock["now"] += timedelta(days=1)
    N.key_check_mismatch(world.db, first, "dek_check")
    assert len(_notices(world, owner)) == 3
    assert all(t == N.MISMATCH_TITLE and target == "#vaults" for t, _, target in _notices(world, owner))


def test_a_notice_that_cannot_be_written_never_raises(world, monkeypatch):
    def broken():
        raise RuntimeError("no database")
    monkeypatch.setattr(database, "get_db_context", broken)
    user = _person(world)
    N.failed_identity_proof(world.db, user)
    N.key_registered(world.db, user)
    N.key_check_mismatch(world.db, SimpleNamespace(id=uuid.uuid4(), owner_id=user.id), "seal")


# ------------------------------------------------------------------------------------ the email action

def test_the_email_is_a_system_action_that_must_say_what_happened():
    spec = ea.SPEC_BY_KEY[N.EMAIL_ACTION]
    assert spec["category"] == ea.SYSTEM
    for token in ("{{action.change}}", "{{action.when}}"):
        assert token in spec["default_body_html"]
    assert ea._fallback_body_if_missing_required_token(ea.SYSTEM, "<p>Hello</p>", spec) == spec["default_body_html"]


# ------------------------------------------------------------------------------------ where they are sent

ROUTER = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")


def _slice(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def test_only_a_failed_identity_proof_tells_the_account():
    verify = _slice(ROUTER, "def _verify_key_proof(", "\nasync def _raw_body(")
    assert verify.count("zk_notices.") == 1
    branch = verify[verify.index("if failed:"):]
    guard = branch.index('if failed == "identity":\n')
    call = branch.index("            zk_notices.failed_identity_proof(db, user)\n")
    between = branch[guard:call].splitlines()[1:]
    assert all(line.strip().startswith("#") for line in between), between   # only a comment in between
    assert branch.index("_audit_key_proof_failed(") < branch.index("zk_notices.failed_identity_proof(")
    assert branch.index("zk_notices.failed_identity_proof(") < branch.index("raise zk_key_proof.KeyProofRefusal")


def test_an_owner_reset_tells_the_managers_after_it_commits_in_both_modes():
    rekey = _slice(ROUTER, "async def rekey_vault(", "\ndef _proof_detail(")
    assert rekey.count("if owner_reset:\n") >= 2
    calls = [i for i in range(len(rekey)) if rekey.startswith("zk_notices.owner_reset(db, current_user, locked)", i)]
    assert len(calls) == 2
    for at in calls:
        assert rekey[:at].rstrip().endswith("if owner_reset:")
        # After the rotation's one commit, with no way out of the branch in between.
        commit = rekey.rindex("_commit_rotation(db)", 0, at)
        assert "return " not in rekey[commit:at] and "raise " not in rekey[commit:at]


def test_a_registration_tells_its_user_after_it_commits():
    register = _slice(ROUTER, "async def register_public_key(", "\n@router.get(\"/keys/public\"")
    assert register.count("zk_notices.key_registered(db, current_user)") == 1
    assert register.index("db.commit()") < register.index("zk_notices.key_registered(db, current_user)")


# ------------------------------------------------------------------------------------ the share dialog

APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name):
    import re
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, name
    rest = APP[decl.end():]
    nxt = re.search(r"^(async )?function |^(const|let|var) |^// =====", rest, re.M)
    return APP[decl.start():decl.end() + (nxt.start() if nxt else len(rest))]


def test_the_share_dialog_shows_a_ticked_recipients_key_for_a_zero_knowledge_vault():
    render = _function("renderVaultGrantList")
    zk = render[render.index("if (isZkVault(state.currentVault)) {"):]
    zk = zk[:zk.index("label.append(")]
    assert "if (cb.checked) { showGrantRecipientKey(u.id, keyInfo); return; }" in zk
    show = _function("showGrantRecipientKey")
    # The fingerprint is the one the person sees for their own key under "Your account".
    assert "await zkKeyFingerprint(pk.public_key)" in show
    assert "zkKeyFingerprint(pub.public_key)" in _function("refreshEncryptionKeyStatus")
    assert "pk.registered_after_admin_change === true" in show
    assert "Set up within 14 days after an administrator changed this account" in show
    # Built as text, never markup: the answer comes from the server.
    assert "innerHTML" not in show and "textContent" in show
    # An answer that arrives after the box was unticked is dropped.
    assert show.count("if (box.dataset.seq !== seq) return;") == 2


def test_the_public_key_lookup_says_when_the_key_was_set_up_and_whether_it_is_flagged():
    router = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
    lookup = _slice(router, "async def get_user_public_key(", "\nclass GrantMemberKeyRequest(")
    assert '"registered_at": kp.created_at.isoformat() if kp.created_at else None,' in lookup
    assert '"registered_after_admin_change": kp.registered_after_admin_change,' in lookup
    register = _slice(router, "async def register_public_key(", "\n@router.get(\"/keys/public\"")
    assert "registered_after_admin_change=_cc.last_applied(db, current_user.id) is not None," in register
    from app.core import credential_changes as cc
    assert cc.WINDOW == timedelta(days=14)


def test_the_web_app_still_parses():
    """The pins above read the web app as text, which a syntax error does not stop; a browser does."""
    import shutil
    import subprocess
    node = shutil.which("node")
    assert node, "Node is required"
    for name in ("app.js", "ecc_crypto.js"):
        done = subprocess.run([node, "--check", str(ROOT / "static" / "js" / name)],
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, (name, done.stderr[-600:])
