"""The passkeys each account holds, counted for the Users page's sign-in methods column
(api_server._passkey_counts): one query for the whole list, retired passkeys left out, an account with none absent,
and nothing asked of the database for an empty list. Offline, against a throwaway SQLite database."""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _the_vault_has_an_address(monkeypatch):
    """A passkey counts only at the address it was made at; these tests are not about the address, so the vault
    has one, and every key here was made at it (or says nothing, which is taken as here)."""
    set_bare_api_env()
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(
        rp_id="vault.example.test", origin="https://vault.example.test", name=name or "DockVault"))


@pytest.fixture
def S():
    set_bare_api_env()
    import app.api.api_server as S
    return S


@pytest.fixture
def db(S):
    from app.core.models import CredentialChange, User, WebAuthnCredential
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'passkeys.db'}")
        for model in (User, WebAuthnCredential, CredentialChange):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name):
    from app.core.models import RoleEnum, User
    user = User(username=name, password_hash="x", role=RoleEnum.USER, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _passkey(db, user, *, retired=False):
    from app.core.models import WebAuthnCredential
    row = WebAuthnCredential(user_id=user.id, credential_id=uuid.uuid4().bytes, public_key_cose=b"key", cose_alg=-7,
                             uv_initialized=True, retired_at=datetime(2026, 11, 1) if retired else None)
    db.add(row)
    db.commit()
    return row


def test_each_account_is_counted_on_its_own_and_a_retired_passkey_is_not_counted(S, db):
    two, one, none, only_retired = (_user(db, n) for n in ("two", "one", "none", "retired"))
    _passkey(db, two)
    _passkey(db, two)
    _passkey(db, two, retired=True)
    _passkey(db, one)
    _passkey(db, only_retired, retired=True)
    counts = S._passkey_counts(db, [u.id for u in (two, one, none, only_retired)])
    assert counts == {two.id: 2, one.id: 1}
    assert all(type(n) is int for n in counts.values())


def test_passkeys_from_before_a_reset_the_account_has_not_answered_are_retired_at_start(S, db):
    """A reset of an account's second factor retires its passkeys. A release that knew no passkeys, run for a while
    after going back to it, resets the factor and leaves them. At every start the passkeys made before a reset the
    account has not answered yet are retired, as of that reset; one made after it (the account's answer, or a key
    made while the reset is still open), the keys of an account with no reset, and a key already retired are left."""
    import inspect
    from app.core import webauthn_settings as wss
    reset_at, earlier, later = datetime(2026, 11, 10), datetime(2026, 11, 1), datetime(2026, 11, 12)
    lost, fine = _user(db, "lost-device"), _user(db, "fine")
    lost.second_factor_reset_at = reset_at
    before, after, others = _passkey(db, lost), _passkey(db, lost), _passkey(db, fine)
    already = _passkey(db, lost, retired=True)
    before.created_at, after.created_at, others.created_at, already.created_at = earlier, later, earlier, earlier
    at_once = _passkey(db, lost)                         # made at the very moment of the reset: not from before it
    at_once.created_at = reset_at
    db.commit()
    for _ in range(2):                                   # run at every start: a second run changes nothing
        db.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RESET))
        db.commit()
        for row in (before, after, others, already):
            db.refresh(row)
        assert before.retired_at == reset_at
        assert after.retired_at is None and others.retired_at is None and already.retired_at == datetime(2026, 11, 1)
        db.refresh(at_once)
        assert at_once.retired_at is None
    assert S._passkey_counts(db, [lost.id, fine.id]) == {lost.id: 2, fine.id: 1}
    # It is among the statements the server runs at start, after the table has its columns.
    source = inspect.getsource(S)
    assert source.count("_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,") == 1
    assert source.index("ADD COLUMN IF NOT EXISTS attested") < source.index("_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,")
    # And after the column it reads: a database from before that column existed gets it in the same start, and
    # the statement would fail (and the start report itself as incomplete) if it came first.
    assert source.index("ADD COLUMN IF NOT EXISTS second_factor_reset_at") < source.index(
        "_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,")


def _change(db, user, kind, applied_at, status="made"):
    """A change to ``user``'s sign-in details as another administrator's request leaves it on record."""
    from app.core.models import CredentialChange
    row = CredentialChange(target_user_id=user.id, kind=kind, status=status, requested_by_name="root",
                           requested_at=datetime(2026, 11, 9), applied_at=applied_at)
    db.add(row)
    db.commit()
    return row


def test_passkeys_from_before_a_recorded_reset_are_retired_at_start_whether_or_not_it_was_answered(S, db):
    """The earlier release clears the reset's mark on the account when the account sets a factor up again (it asks
    for that at the next sign-in), and sets none for an account whose only factor was a passkey. It records every
    reset another administrator makes among the changes to the account's sign-in details, with its time. At every
    start a passkey made before the account's latest recorded reset is retired as of it: the one of an account that
    answered its reset, and the one of an account that had no factor the earlier release knew. A passkey made after
    the reset, a request that was never applied, a change of another kind, and the keys of other accounts are left."""
    import inspect
    from app.core import webauthn_settings as wss
    earlier, reset_at, later = datetime(2026, 11, 1), datetime(2026, 11, 10), datetime(2026, 11, 12)
    answered, passkey_only = _user(db, "answered"), _user(db, "passkey-only")
    asked_only, other_change, untouched = _user(db, "asked-only"), _user(db, "new-password"), _user(db, "untouched")
    for user, how in ((answered, "made"), (passkey_only, "approved")):     # made at once; held, then approved
        assert user.second_factor_reset_at is None                # nothing on the account says a reset happened
        _change(db, user, "second_factor", reset_at, status=how)
    _change(db, answered, "second_factor", datetime(2026, 11, 4))    # an older one: the latest is what counts
    _change(db, answered, "password", datetime(2026, 11, 15))        # a later change of another kind: not a reset
    _change(db, asked_only, "second_factor", None, status="denied")  # asked for, never applied: no time
    # A row that says it was not applied counts for nothing whatever time it carries (none carries one today).
    _change(db, asked_only, "second_factor", datetime(2026, 11, 20), status="denied")
    _change(db, answered, "second_factor", datetime(2026, 11, 20), status="expired")
    _change(db, other_change, "password", reset_at)                  # not a reset of the factor
    planted, since = _passkey(db, answered), _passkey(db, answered)
    between = _passkey(db, answered)               # made after the first reset and before the latest one
    only = _passkey(db, passkey_only)
    kept = [_passkey(db, user) for user in (asked_only, other_change, untouched)]
    already = _passkey(db, answered, retired=True)
    for row in (planted, only, already, *kept):
        row.created_at = earlier
    since.created_at = later
    between.created_at = datetime(2026, 11, 7)
    # A key made at the very moment of the reset is not one from before it (the reset's own time is taken first,
    # and whatever is made in that moment is the account's answer or made beside it: left).
    at_once = _passkey(db, passkey_only)
    at_once.created_at = reset_at
    db.commit()
    for _ in range(2):                                   # run at every start: a second run changes nothing
        db.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RECORDED_RESET))
        db.commit()
        for row in (planted, since, only, already, *kept):
            db.refresh(row)
        assert planted.retired_at == reset_at and only.retired_at == reset_at
        assert since.retired_at is None and [row.retired_at for row in kept] == [None, None, None]
        assert already.retired_at == datetime(2026, 11, 1)
        db.refresh(at_once)
        assert at_once.retired_at is None
        db.refresh(between)
        assert between.retired_at == reset_at                 # from before the latest reset: that is what counts
    # The statement that reads the account's mark finds nothing here: only the record says these were reset.
    planted.retired_at = None
    db.commit()
    db.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RESET))
    db.commit()
    db.refresh(planted)
    assert planted.retired_at is None
    # Among the statements the server runs at start, once, after the one that reads the mark; the table it reads
    # is one of the models, made before that list is run.
    source = inspect.getsource(S)
    in_the_list = " " * 12 + "_RETIRE_PASSKEYS_FROM_BEFORE_A_RECORDED_RESET,"       # the entry, not the import
    assert source.count(in_the_list) == 1
    assert source.index("_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,") < source.index(in_the_list)
    from app.core.models import Base, CredentialChange
    assert CredentialChange.__tablename__ == "credential_changes" and "credential_changes" in Base.metadata.tables
    assert {"target_user_id", "kind", "applied_at"} <= set(CredentialChange.__table__.columns.keys())


def test_an_administrators_removal_of_the_only_passkey_marks_the_account_before_anything_is_written(S, db, monkeypatch):
    """On a real session that writes nothing until it is told to: when the others are looked for, the key being
    removed still reads as not retired in the database. It is left out by what it is, so the account whose only
    passkey it was is marked as after a reset; with a second key on the account nothing is marked."""
    from app.core import auditor_rights, credential_changes as cc, legal_holds
    from app.core.models import SecondFactorEnrollment
    table = SecondFactorEnrollment.__table__          # its columns, without the defaults only the server's database has
    sa.Table(table.name, sa.MetaData(), *[sa.Column(c.name, c.type, primary_key=c.primary_key)
                                          for c in table.columns]).create(db.get_bind())
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    from app.services import sign_in
    ended, spent = [], []
    monkeypatch.setattr(S, "_revoke_sessions", lambda db, **kw: ended.append(kw["user_id"]))
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db, user_id: spent.append(user_id))
    admin, carol, dave = _user(db, "root"), _user(db, "carol"), _user(db, "dave")
    only, first, _second = _passkey(db, carol), _passkey(db, dave), _passkey(db, dave)
    result = S._apply_credential_change(db, cc.PASSKEY, carol, {"passkey_id": str(only.id)}, actor_id=admin.id,
                                        actor_name="root")
    assert result["left_without_a_factor"] is True and carol.second_factor_reset_at is not None
    # As a reset does: the account's sessions end (one that key made, on the lost device, among them), and what
    # was on its way to a session with them.
    assert ended == [carol.id] and spent == [carol.id]
    result = S._apply_credential_change(db, cc.PASSKEY, dave, {"passkey_id": str(first.id)}, actor_id=admin.id,
                                        actor_name="root")
    assert result["left_without_a_factor"] is False and dave.second_factor_reset_at is None
    # A key removed beside another: the account is not reset, and its sessions end all the same. Nothing says
    # which of them that key made, on the device that was lost.
    assert ended == [carol.id, dave.id] and spent == [carol.id, dave.id]


def test_the_statement_fails_on_a_database_that_has_not_got_the_column_yet(S):
    """Why the order matters, shown: on a users table from before the reset column, the statement is an error."""
    from app.core import webauthn_settings as wss
    engine = sa.create_engine("sqlite://")
    with engine.begin() as con:
        con.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        con.execute(sa.text("CREATE TABLE webauthn_credentials (id TEXT PRIMARY KEY, user_id TEXT, created_at TEXT, "
                            "retired_at TEXT)"))
        with pytest.raises(sa.exc.OperationalError):
            con.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RESET))
    with engine.begin() as con:
        con.execute(sa.text("ALTER TABLE users ADD COLUMN second_factor_reset_at TEXT"))
        con.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RESET))
    engine.dispose()


def test_only_the_accounts_asked_about_are_counted(S, db):
    asked, other = _user(db, "asked"), _user(db, "other")
    _passkey(db, asked)
    _passkey(db, other)
    assert S._passkey_counts(db, [asked.id]) == {asked.id: 1}
    assert S._passkey_counts(db, iter([other.id])) == {other.id: 1}      # any iterable of ids


def test_an_empty_list_asks_the_database_nothing(S):
    class NoDatabase:
        def query(self, *a, **kw):
            raise AssertionError("no account was asked about")

        def get_bind(self):
            raise AssertionError("no account was asked about")

    assert S._passkey_counts(NoDatabase(), []) == {}


def test_with_passkeys_turned_off_none_is_a_way_to_sign_in(S, db, monkeypatch):
    from app.core import webauthn_settings
    user = _user(db, "one")
    _passkey(db, user)
    assert S._passkey_counts(db, [user.id]) == {user.id: 1}
    monkeypatch.setattr(webauthn_settings, "enabled", lambda: False)
    assert S._passkey_counts(db, [user.id]) == {}


def test_a_database_without_the_passkey_table_holds_none(S):
    from app.core.models import User
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'bare.db'}")
        User.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        try:
            assert S._passkey_counts(session, [uuid.uuid4()]) == {}
        finally:
            session.close()
            engine.dispose()


def test_the_user_list_gives_each_account_its_count():
    """The list route reads the counts once for the page and gives each row its own, 0 for an account with none."""
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    listing = source[source.index("async def list_users("):]
    listing = listing[:listing.index("\n@app.")]
    assert listing.count("_passkey_tally(db, [u.id for u in users])") == 1
    assert "item.passkey_count, item.passkey_unusable_count = passkey_tally.get(user.id, (0, 0))" in listing
    # Given once, and not written again further down the row (test_api_passkeys_live.py reads both numbers from
    # the running route).
    assert listing.count("passkey_unusable_count") == 1 and listing.count("item.passkey_count") == 1
    answer = source[source.index("class UserResponse("):source.index("class UserResponse(") + 4500]
    assert "passkey_count: int = 0" in answer and "passkey_unusable_count: int = 0" in answer


def _page_words(accounts: list) -> list:
    """What the Users page writes for each of ``accounts``: the page's own two functions, run by Node."""
    import json
    import shutil
    import subprocess
    app = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(encoding="utf-8")
    code = app[app.index("function signInMethods(u) {"):app.index("function renderUsersTable() {")]
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = ("const escaped = [];\nfunction escapeHtml(s) { escaped.push(s); return String(s).replace(/</g, '&lt;'); }\n"
              + code + "\nconsole.log(JSON.stringify(" + json.dumps(accounts)
              + ".map((u) => { escaped.length = 0; const badges = signInMethodBadges(u);"
              + " return { words: signInMethods(u), badges, escaped: escaped.slice() }; })));\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_page_names_the_ways_an_account_signs_in():
    rows = _page_words([{}, {"second_factor_enabled": True}, {"passkey_count": 1},
                        {"passkey_count": 3, "second_factor_enabled": True}, {"passkey_count": "2"},
                        {"passkey_count": "<img src=x>"}, {"passkey_count": 0, "second_factor_enabled": False},
                        {"passkey_count": "1"},
                        # Keys held that are no factor now (made at another address, of an algorithm no longer
                        # accepted, or never verified the person while the vault asks for that) are named apart.
                        {"passkey_unusable_count": 1}, {"passkey_count": 1, "passkey_unusable_count": 2},
                        {"passkey_unusable_count": "<img src=x>"}, {"passkey_unusable_count": 0}])
    assert [r["words"] for r in rows] == [
        ["Password"], ["Password", "Authenticator"], ["Password", "Passkey"],
        ["Password", "Authenticator", "3 passkeys"], ["Password", "2 passkeys"], ["Password"], ["Password"],
        ["Password", "Passkey"],
        ["Password", "1 passkey not usable"], ["Password", "Passkey", "2 passkeys not usable"], ["Password"],
        ["Password"]]
    # Each word is its own badge, in order, and passes through the page's escaping on its way into the markup.
    for row in rows:
        assert row["escaped"] == row["words"]
        assert row["badges"] == "".join(f'<span class="badge badge-secondary">{w}</span>' for w in row["words"])


ELSEWHERE = "old.example.test"


def _key(db, user, **extra):
    from app.core.models import WebAuthnCredential
    row = WebAuthnCredential(**{**dict(user_id=user.id, credential_id=uuid.uuid4().bytes, public_key_cose=b"key",
                                       cose_alg=-7, uv_initialized=True, rp_id="vault.example.test"), **extra})
    db.add(row)
    db.commit()
    return row


def _the_rules(monkeypatch, *, verification=True):
    from app.core import webauthn_settings as wss
    monkeypatch.setattr(wss, "require_uv", lambda: verification)
    monkeypatch.setattr(wss, "allowed_alg_codes", lambda: (-7,))
    return wss


def test_a_key_that_is_no_factor_now_is_not_counted_as_a_way_to_sign_in(S, db, monkeypatch):
    """After the vault moved to another address the list showed a passkey beside an account that is held at a
    set-up because it has none it can use. A key made at another address, of an algorithm no longer accepted, or
    one that never verified the person while the vault asks for that is counted apart: held, and no way in."""
    wss = _the_rules(monkeypatch)
    here, moved, stranded, lapsed, unverified, none = (
        _user(db, n) for n in ("here", "moved", "stranded", "lapsed", "unverified", "none"))
    _key(db, here)
    _key(db, here, rp_id=None)                         # no address on record: taken as made here
    _key(db, moved)
    _key(db, moved, rp_id=ELSEWHERE)
    _key(db, stranded, rp_id=ELSEWHERE)
    _key(db, stranded, rp_id=ELSEWHERE)
    _key(db, stranded, rp_id=ELSEWHERE, retired_at=datetime(2026, 11, 1))
    _key(db, lapsed, cose_alg=-999)
    _key(db, unverified, uv_initialized=False)
    everyone = [u.id for u in (here, moved, stranded, lapsed, unverified, none)]
    tally = S._passkey_tally(db, everyone)
    assert tally == {here.id: (2, 0), moved.id: (1, 1), stranded.id: (0, 2), lapsed.id: (0, 1), unverified.id: (0, 1)}
    assert S._passkey_counts(db, everyone) == {here.id: 2, moved.id: 1}
    # The list's number is the sign-in's: what the account can give as a factor.
    for user in (here, moved, stranded, lapsed, unverified, none):
        assert tally.get(user.id, (0, 0))[0] == wss.usable_passkeys(db, user.id), user.username
    # A key that never verified the person counts again when the vault stops asking for that.
    _the_rules(monkeypatch, verification=False)
    assert S._passkey_tally(db, [unverified.id]) == {unverified.id: (1, 0)}
    # At an address no passkey can be made at, none is a way in.
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: None)
    assert S._passkey_tally(db, [here.id, moved.id]) == {here.id: (0, 2), moved.id: (0, 2)}
    assert S._passkey_counts(db, [here.id, moved.id]) == {}


def test_the_users_list_gives_both_numbers_to_the_page(S):
    """The answer's row carries the number the page writes as the ways to sign in, and the number held in name
    only beside it; an account with no passkey has 0 and 0."""
    fields = S.UserResponse.model_fields
    assert fields["passkey_count"].default == 0 and fields["passkey_unusable_count"].default == 0
    assert fields["passkey_count"].annotation is int and fields["passkey_unusable_count"].annotation is int


def test_a_shown_passkey_says_whether_it_is_a_factor_now_and_why_not(S, db, monkeypatch):
    """The profile and the administrator's list show every key the account holds. One that cannot be used says
    so, with the reason, and never the address it was made at."""
    wss = _the_rules(monkeypatch)
    owner = _user(db, "owner")
    fine = _key(db, owner)
    elsewhere = _key(db, owner, rp_id=ELSEWHERE)
    lapsed = _key(db, owner, cose_alg=-999)
    unverified = _key(db, owner, uv_initialized=False)
    both = _key(db, owner, rp_id=ELSEWHERE, cose_alg=-999, uv_initialized=False)     # the address is said first
    alg_and_uv = _key(db, owner, cose_alg=-999, uv_initialized=False)                # then the algorithm

    def shown(row):
        public = S._passkey_public(db, row)
        assert "rp_id" not in public and ELSEWHERE not in str(public) and "vault.example.test" not in str(public)
        return public["usable"], public["not_usable_because"]

    assert shown(fine) == (True, None)
    assert shown(elsewhere) == (False, "passkeys_at_another_address") == (False, wss.PASSKEYS_AT_ANOTHER_ADDRESS)
    assert shown(lapsed) == (False, "passkeys_no_longer_accepted") == (False, wss.PASSKEYS_NO_LONGER_ACCEPTED)
    assert shown(unverified) == (False, "passkeys_without_verification") == (False, wss.PASSKEYS_WITHOUT_VERIFICATION)
    assert shown(both) == (False, "passkeys_at_another_address")
    assert shown(alg_and_uv) == (False, "passkeys_no_longer_accepted")
    # The key's reason and the account's are one rule: an account whose every key has one reason gives that one.
    for row, reason in ((elsewhere, wss.PASSKEYS_AT_ANOTHER_ADDRESS), (lapsed, wss.PASSKEYS_NO_LONGER_ACCEPTED),
                        (unverified, wss.PASSKEYS_WITHOUT_VERIFICATION)):
        alone = _user(db, "alone-" + reason)
        _key(db, alone, rp_id=row.rp_id, cose_alg=row.cose_alg, uv_initialized=row.uv_initialized)
        assert wss.why_none_can_be_used(db, alone.id) == reason == wss.why_a_key_is_no_factor(db, row)
    # A key of an algorithm removed less than 30 days ago is still a factor, and says until when.
    removed_on = datetime.utcnow() - timedelta(days=10)
    monkeypatch.setattr(wss, "_removed", lambda db: {"RS256": removed_on.isoformat()})
    leaving = _key(db, owner, cose_alg=-257)
    public = S._passkey_public(db, leaving)
    assert public["usable"] is True and public["not_usable_because"] is None
    assert public["accepted_until"] == S._passkey_time(removed_on + timedelta(days=30))
    assert S._passkey_public(db, fine)["accepted_until"] is None               # its algorithm is allowed: no end
    assert S._passkey_public(db, lapsed)["accepted_until"] is None             # refused already
    # Turned off, no passkey is a factor whatever the key is.
    monkeypatch.setattr(wss, "enabled", lambda: False)
    for row in (fine, elsewhere, lapsed, unverified):
        assert shown(row) == (False, "passkeys_turned_off") == (False, wss.PASSKEYS_TURNED_OFF)
    # Every answer that shows a key is made by the one function, with the database it reads the rules from.
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count("_passkey_public(db, ") == 7 and source.count("_passkey_public(") == 7


def test_an_algorithm_is_looked_up_once_for_a_whole_list(S, db, monkeypatch):
    wss = _the_rules(monkeypatch)
    asked = []
    real = wss.algorithm_usable
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, alg, **kw: (asked.append(alg), real(db, alg, **kw))[1])
    people = [_user(db, f"user{n}") for n in range(4)]
    for person in people:
        _key(db, person)
        _key(db, person, cose_alg=-999)
    assert S._passkey_tally(db, [p.id for p in people]) == {p.id: (1, 1) for p in people}
    assert sorted(asked) == [-999, -7]
    # A key made at another address is said so before its algorithm is looked at.
    asked.clear()
    assert wss.why_a_key_is_no_factor(db, _key(db, people[0], rp_id=ELSEWHERE, cose_alg=-8)) == wss.PASSKEYS_AT_ANOTHER_ADDRESS
    assert asked == []
