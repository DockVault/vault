"""The providers each account is linked to, for the Users page's sign-in methods column
(api_server._sso_provider_names and the page's signInMethods): one query for the whole list, each account its own
providers by what their button says, in the sign-in page's order; an account that signs in only through its
provider is shown as having no password. Offline: a throwaway SQLite database, and the page's own code run by
Node."""
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env
from test_passkey_counts import _page_words

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def S():
    set_bare_api_env()
    import app.api.api_server as S
    return S


@pytest.fixture
def db(S):
    from app.core.models import ExternalIdentity, SsoProvider, User
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sso.db'}")
        for model in (User, SsoProvider, ExternalIdentity):
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


def _provider(db, name, label=None, *, order=0, state="enabled"):
    from app.core.models import SsoProvider
    row = SsoProvider(kind="oidc", name=name, label=label, sort_order=order, state=state)
    db.add(row)
    db.commit()
    return row


def _link(db, user, provider):
    from app.core.models import ExternalIdentity
    db.add(ExternalIdentity(user_id=user.id, provider_id=provider.id, issuer="https://idp.example.test",
                            subject=uuid.uuid4().hex, subject_source="oidc:sub", linked_by="self"))
    db.commit()


def test_each_account_gets_its_own_providers_by_their_button_text_in_page_order(S, db):
    both, one, none = (_user(db, n) for n in ("both", "one", "none"))
    entra = _provider(db, "entra", "Company sign-in", order=2)
    okta = _provider(db, "okta", order=1)                       # no label: the button shows the name
    old = _provider(db, "old", "Old sign-in", order=1, state="disabled")
    spare = _provider(db, "spare", "Nobody is linked here")
    _link(db, both, entra)
    _link(db, both, okta)
    _link(db, both, old)
    _link(db, one, entra)
    names = S._sso_provider_names(db, [both.id, one.id, none.id])
    assert names == {both.id: ["okta", "Old sign-in", "Company sign-in"], one.id: ["Company sign-in"]}
    assert spare.label not in str(names)


def test_only_the_accounts_asked_about_are_read(S, db):
    asked, other = _user(db, "asked"), _user(db, "other")
    entra = _provider(db, "entra")
    _link(db, asked, entra)
    _link(db, other, entra)
    assert S._sso_provider_names(db, [asked.id]) == {asked.id: ["entra"]}
    assert S._sso_provider_names(db, iter([other.id])) == {other.id: ["entra"]}


def test_nothing_is_asked_for_an_empty_list_or_without_the_table(S):
    class NoDatabase:
        def query(self, *a, **kw):
            raise AssertionError("nothing to read")

    assert S._sso_provider_names(NoDatabase(), []) == {}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        from app.core.models import User
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'bare.db'}")
        User.__table__.create(engine)                           # a database built without the identity tables
        session = sessionmaker(bind=engine)()
        try:
            assert S._sso_provider_names(session, [uuid.uuid4()]) == {}
        finally:
            session.close()
            engine.dispose()


def test_the_user_list_gives_each_account_its_providers():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    listing = source[source.index("async def list_users("):]
    listing = listing[:listing.index("\n@app.")]
    assert listing.count("_sso_provider_names(db, [u.id for u in users])") == 1
    assert "item.sso_providers = provider_names.get(user.id, [])" in listing
    model = source[source.index("class UserResponse("):source.index("class UserResponse(") + 4000]
    assert "sso_providers: List[str] = Field(default_factory=list)" in model


def test_the_page_names_the_providers_and_says_when_an_account_has_no_password():
    rows = _page_words([
        {"sso_providers": ["Company sign-in"]},
        {"sso_only": True, "sso_providers": ["Company sign-in", "okta"], "second_factor_enabled": True,
         "passkey_count": 2},
        {"sso_only": True, "sso_providers": []},
        {"sso_only": False, "sso_providers": None},
        {"sso_providers": ["<img src=x onerror=alert(1)>", ""]},
        {"sso_providers": "Company sign-in"},
    ])
    assert [r["words"] for r in rows] == [
        ["Password", "Company sign-in"],
        ["No password", "Company sign-in", "okta", "Authenticator", "2 passkeys"],
        ["No password"],
        ["Password"],
        ["Password", "<img src=x onerror=alert(1)>"],
        ["Password"],
    ]
    for row in rows:
        assert row["escaped"] == row["words"]
    # A provider's name is an administrator's text: it reaches the markup escaped.
    assert "<img" not in rows[4]["badges"] and "&lt;img src=x" in rows[4]["badges"]


def test_the_list_says_what_a_password_means_for_an_account_made_at_a_first_sign_in(S, db):
    """Before an administrator sets a password on an account that a provider made at a first sign-in and that
    never had one, the page says what that does: the account keeps a password from then on. For that account
    only: not for one that linked itself, one that has or had a password, or one a password is refused for."""
    from app.core import password_origin, sso_only
    from app.core.models import ExternalIdentity
    made, own, had, held, linked, plain = (_user(db, n) for n in ("made", "own", "had", "held", "linked", "plain"))
    entra = _provider(db, "entra", "Company sign-in")
    for user in (made, own, had, held):
        db.add(ExternalIdentity(user_id=user.id, provider_id=entra.id, issuer="https://idp.example.test",
                                subject=uuid.uuid4().hex, subject_source="oidc:sub", linked_by="jit"))
    _link(db, linked, entra)
    for user in (made, had, held, linked):
        user.password_hash = "random-bytes"
        password_origin.mark_nobody_knows(user)
    had.had_a_password_at = entra.created_at or __import__("datetime").datetime(2026, 11, 1)
    held.sso_only = True
    db.commit()
    notes = sso_only.password_set_notes(db, [made, own, had, held, linked, plain])
    assert notes == {made.id: (
        "made was made at its first sign-in through Company sign-in and has never had a password. With one, this "
        "account keeps a password from now on, also if Company sign-in later stops letting the accounts it makes "
        "set one.")}
    # The list's rows carry it, and nothing for anybody else.
    assert S.UserResponse.model_fields["password_set_note"].default is None
    import inspect
    listing = inspect.getsource(inspect.unwrap(S.list_users))
    assert "sso_only.password_set_notes(db, users)" in listing
    assert "item.password_set_note = password_notes.get(user.id)" in listing
    assert sso_only.password_set_notes(db, [own, plain]) == {} and sso_only.password_set_notes(db, []) == {}
