"""The passkeys each account holds, counted for the Users page's sign-in methods column
(api_server._passkey_counts): one query for the whole list, retired passkeys left out, an account with none absent,
and nothing asked of the database for an empty list. Offline, against a throwaway SQLite database."""
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


@pytest.fixture
def S():
    set_bare_api_env()
    import app.api.api_server as S
    return S


@pytest.fixture
def db(S):
    from app.core.models import User, WebAuthnCredential
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'passkeys.db'}")
        for model in (User, WebAuthnCredential):
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
                             retired_at=datetime(2026, 11, 1) if retired else None)
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
    db.commit()
    for _ in range(2):                                   # run at every start: a second run changes nothing
        db.execute(sa.text(wss.RETIRE_PASSKEYS_FROM_BEFORE_A_RESET))
        db.commit()
        for row in (before, after, others, already):
            db.refresh(row)
        assert before.retired_at == reset_at
        assert after.retired_at is None and others.retired_at is None and already.retired_at == datetime(2026, 11, 1)
    assert S._passkey_counts(db, [lost.id, fine.id]) == {lost.id: 1, fine.id: 1}
    # It is among the statements the server runs at start, after the table has its columns.
    source = inspect.getsource(S)
    assert source.count("_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,") == 1
    assert source.index("ADD COLUMN IF NOT EXISTS attested") < source.index("_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,")
    # And after the column it reads: a database from before that column existed gets it in the same start, and
    # the statement would fail (and the start report itself as incomplete) if it came first.
    assert source.index("ADD COLUMN IF NOT EXISTS second_factor_reset_at") < source.index(
        "_RETIRE_PASSKEYS_FROM_BEFORE_A_RESET,")


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
    assert listing.count("_passkey_counts(db, [u.id for u in users])") == 1
    assert "item.passkey_count = passkey_counts.get(user.id, 0)" in listing
    assert "passkey_count: int = 0" in source[source.index("class UserResponse("):source.index("class UserResponse(") + 4000]


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
                        {"passkey_count": "1"}])
    assert [r["words"] for r in rows] == [
        ["Password"], ["Password", "Authenticator"], ["Password", "Passkey"],
        ["Password", "Authenticator", "3 passkeys"], ["Password", "2 passkeys"], ["Password"], ["Password"],
        ["Password", "Passkey"]]
    # Each word is its own badge, in order, and passes through the page's escaping on its way into the markup.
    for row in rows:
        assert row["escaped"] == row["words"]
        assert row["badges"] == "".join(f'<span class="badge badge-secondary">{w}</span>' for w in row["words"])
