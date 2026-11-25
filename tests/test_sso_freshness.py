"""Single sign-on freshness (app/services/sso_freshness.py): an account linked to a provider keeps its SSH keys,
temporary credentials and devices only while it keeps signing in there; the provider's verified refusal pauses them
at once; the daily sweep warns five days before and tells when they pause; the administrators' user list shows the
due date. Offline: an in-memory store, the clock the test's."""
import types
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

set_bare_api_env()

from app.core.models import ExternalIdentity, SsoProvider, User  # noqa: E402
from app.services import sso_freshness as F  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 9, 12, 0, 0)
DAY = timedelta(days=1)


@pytest.fixture(autouse=True)
def _an_address_single_sign_on_can_use(monkeypatch):
    """The vault's address can carry single sign-on, so the sign-in page shows the providers' buttons, and the
    sentences here name them. A test of an address that cannot sets its own."""
    from app.services import sso_sign_in
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: None)


def _user(name="alice", **extra):
    fields = dict(id=uuid.uuid4(), username=name, email=f"{name}@example.test", is_active=True)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def _provider(days=30, *, name="contoso", label=None, state="enabled", **policy):
    """A provider whose button shows its name unless ``label`` gives the button its own text."""
    stored = {"sso_freshness_days": days, **policy} if days is not None else dict(policy)
    return types.SimpleNamespace(id=uuid.uuid4(), name=name, label=label, state=state, kind="oidc", policy=stored)


def _identity(user, provider, *, signed_in=None, linked=None, refused=None):
    return types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, provider_id=provider.id,
                                 last_sign_in_at=signed_in, linked_at=linked or NOW - 100 * DAY, refused_at=refused)


def _db(users=(), providers=(), identities=()):
    return MemoryDB({User: list(users), SsoProvider: list(providers), ExternalIdentity: list(identities)})


# --------------------------------------------------------------------------- the rule

def test_an_account_is_fresh_while_its_last_provider_sign_in_is_younger_than_the_window():
    alice, p = _user(), _provider(30)
    i = _identity(alice, p, signed_in=NOW - 30 * DAY + timedelta(seconds=1))
    db = _db([alice], [p], [i])
    assert F.lapsed(db, alice.id, now=NOW) is None
    found, = F.deadlines(db, alice.id)
    assert found.due == i.last_sign_in_at + 30 * DAY and found.provider_name == "contoso" and not found.refused
    assert found.identity_id == str(i.id) and found.user_id == str(alice.id) and found.provider_id == str(p.id)
    assert F.due_date(db, alice.id) == found.due
    i.last_sign_in_at = NOW - 30 * DAY
    assert F.lapsed(db, alice.id, now=NOW).identity_id == str(i.id)
    # Never signed in since the link: the link is when the window starts.
    i.last_sign_in_at, i.linked_at = None, NOW - 10 * DAY
    assert F.lapsed(db, alice.id, now=NOW) is None
    i.linked_at = NOW - 31 * DAY
    assert F.lapsed(db, alice.id, now=NOW) is not None
    # The default window is 30 days.
    p.policy = {}
    assert F.deadlines(db, alice.id)[0].due == i.linked_at + 30 * DAY


def test_the_days_go_on_counting_while_a_provider_is_off_and_others_are_untouched():
    """A provider with no days set asks nothing. One that is turned off goes on counting: nobody can sign in through
    it then, so a person's keys pause on the day they would have. Otherwise someone who stopped signing in (a
    leaver whose days end tomorrow) would keep their keys for as long as the provider stayed off."""
    alice, bob, p = _user(), _user("bob"), _provider(30)
    i = _identity(alice, p, signed_in=NOW - 90 * DAY)
    db = _db([alice, bob], [p], [i])
    assert F.lapsed(db, alice.id, now=NOW) is not None
    assert F.lapsed(db, bob.id, now=NOW) is None and F.due_date(db, bob.id) is None
    p.policy = {"sso_freshness_days": 0}
    assert F.lapsed(db, alice.id, now=NOW) is None and F.deadlines(db, alice.id) == []
    p.policy = {"sso_freshness_days": 30}
    for state in ("disabled", "draft"):
        p.state = state
        assert F.lapsed(db, alice.id, now=NOW) is not None, state
        # Still inside the days when the provider went off: nothing yet, and the pause comes on its day.
        i.last_sign_in_at = NOW - 29 * DAY
        assert F.lapsed(db, alice.id, now=NOW) is None, state
        assert F.due_date(db, alice.id) == NOW + DAY, state
        assert F.lapsed(db, alice.id, now=NOW + 2 * DAY) is not None, state
        i.last_sign_in_at = NOW - 90 * DAY
        p.policy = {"sso_freshness_days": 0}                 # the rule is ended by its days, on or off
        assert F.lapsed(db, alice.id, now=NOW) is None, state
        p.policy = {"sso_freshness_days": 30}
    assert F.lapsed(_db(), alice.id, now=NOW) is None and F.lapsed(db, None, now=NOW) is None


def test_a_refusal_pauses_at_once_whatever_the_window_and_a_later_admitted_sign_in_answers_it():
    alice, p = _user(), _provider(30)
    i = _identity(alice, p, signed_in=NOW - DAY, refused=NOW - timedelta(hours=1))
    db = _db([alice], [p], [i])
    found = F.lapsed(db, alice.id, now=NOW)
    assert found is not None and found.refused
    # With the window off the refusal still counts.
    p.policy = {"sso_freshness_days": 0}
    found = F.lapsed(db, alice.id, now=NOW)
    assert found is not None and found.refused and found.due == i.refused_at
    # A sign-in the provider admitted after the refusal answers it.
    i.last_sign_in_at = NOW - timedelta(minutes=5)
    assert F.lapsed(db, alice.id, now=NOW) is None
    p.policy = {"sso_freshness_days": 30}
    assert F.lapsed(db, alice.id, now=NOW) is None
    # A refusal with no sign-in since the link counts.
    i.last_sign_in_at = None
    assert F.lapsed(db, alice.id, now=NOW).refused


def test_each_provider_asks_on_its_own():
    alice, a, b = _user(), _provider(30, name="contoso"), _provider(7, name="fabrikam")
    ia = _identity(alice, a, signed_in=NOW - DAY)
    ib = _identity(alice, b, signed_in=NOW - 8 * DAY)
    db = _db([alice], [a, b], [ia, ib])
    found = F.lapsed(db, alice.id, now=NOW)
    assert found is not None and found.provider_name == "fabrikam"
    assert [d.provider_name for d in F.deadlines(db, alice.id)] == ["fabrikam", "contoso"]
    assert F.refusal_text(found).startswith("Sign in through fabrikam again")
    ib.last_sign_in_at = NOW - DAY
    assert F.lapsed(db, alice.id, now=NOW) is None


def test_the_user_list_shows_the_deadline_that_matters_most():
    alice, bob, carol, dave = _user(), _user("bob"), _user("carol"), _user("dave")
    a, b = _provider(30, name="contoso"), _provider(10, name="fabrikam")
    db = _db([alice, bob, carol, dave], [a, b], [
        _identity(alice, a, signed_in=NOW - DAY), _identity(alice, b, signed_in=NOW - 2 * DAY),
        _identity(bob, a, signed_in=NOW - 40 * DAY), _identity(bob, b, signed_in=NOW - DAY),
        _identity(carol, a, signed_in=NOW - 40 * DAY), _identity(carol, b, signed_in=NOW, refused=NOW + DAY)])
    standing = F.standing_of(db, now=NOW)
    assert standing[str(alice.id)] == {"due": (NOW + 8 * DAY).isoformat() + "Z", "provider": "fabrikam",
                                       "lapsed": False, "refused": False}
    assert standing[str(bob.id)]["provider"] == "contoso" and standing[str(bob.id)]["lapsed"] is True
    assert standing[str(carol.id)]["provider"] == "fabrikam" and standing[str(carol.id)]["refused"] is True
    assert str(dave.id) not in standing


# --------------------------------------------------------------------------- the sweep

@pytest.fixture
def told(monkeypatch):
    """The notices (deduplicated as the real ones are), the emails and the audit rows the sweep writes."""
    import app.api.api_server as S
    import app.services.audit_logger as al
    out = types.SimpleNamespace(notices=[], emails=[], audits=[], seen=set(), admins=[])

    def notify(ids, ntype, title=None, body=None, target=None, dedup_prefix=None):
        sent = []
        for uid in ids:
            key = f"{dedup_prefix}:{uid}"
            if key in out.seen:
                continue
            out.seen.add(key)
            out.notices.append((str(uid), ntype, title, body, target))
            sent.append(str(uid))
        return sent

    class _Audit:
        def __init__(self, db):
            pass

        def build_row(self, **kw):
            out.audits.append((kw["action"], kw["user"].username, dict(kw["details"])))
            return types.SimpleNamespace(**kw)
    monkeypatch.setattr(S, "_notify_users", notify)
    monkeypatch.setattr(S, "_fire_action_email", lambda db, key, *, email, username=None, action_context=None:
                        out.emails.append((key, email, dict(action_context or {}))))
    monkeypatch.setattr(S, "_active_admins", lambda db: out.admins)
    monkeypatch.setattr(al, "AuditLogger", _Audit)
    return out


def test_the_sweep_warns_five_days_before_once_and_tells_once_when_keys_pause(told):
    admin = _user("root")
    told.admins.append(admin)
    alice, bob, carol, dave, erin, frank = (_user(n) for n in ("alice", "bob", "carol", "dave", "erin", "frank"))
    erin.is_active = False
    # A provider that pauses the keys and leaves the password as it is (the other state has its own test).
    p, off = _provider(30, sso_lapse_ends_sign_in=False), _provider(0, name="fabrikam")
    ia = _identity(alice, p, signed_in=NOW - 27 * DAY)                 # due in 3 days: warned
    ib = _identity(bob, p, signed_in=NOW - 20 * DAY)                   # due in 10 days: nothing yet
    ic = _identity(carol, p, signed_in=NOW - 31 * DAY)                 # lapsed a day ago
    idd = _identity(dave, p, signed_in=NOW - 31 * DAY, refused=NOW - 2 * DAY)   # refused: told when it happened
    ie = _identity(erin, p, signed_in=NOW - 31 * DAY)                  # inactive: nothing
    i_off = _identity(frank, off, signed_in=NOW - 300 * DAY)           # the provider asks nothing
    db = _db([admin, alice, bob, carol, dave, erin, frank], [p, off], [ia, ib, ic, idd, ie, i_off])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 1}
    due_a = (NOW + 3 * DAY).strftime("%d %B %Y, %H:%M UTC")
    assert (str(alice.id), F.WARNED, f"Sign in through contoso by {due_a}") == told.notices[0][:3]
    assert told.emails == [("sso_freshness_warning", "alice@example.test",
                            {"change": F.warning_text(F.deadlines(db, alice.id)[0], due_a), "when": due_a})]
    assert told.emails[0][2]["change"].startswith(f"Sign in through contoso by {due_a}.")
    # How: the button, and to sign out first, since only a sign-in through the provider counts.
    how = " Use the “contoso” button on the sign-in page (sign out first if you are signed in)."
    assert told.emails[0][2]["change"].endswith(how) and told.notices[0][3].endswith(how)
    assert (str(carol.id), F.EXPIRED, "Your SSH keys and temporary credentials are paused") == told.notices[1][:3]
    assert told.notices[1][3].startswith("Sign in through contoso again")
    assert told.notices[1][3] == F.refusal_text(F.deadlines(db, carol.id)[0]) + how
    wave = told.notices[2]
    assert wave[0] == str(admin.id) and wave[2].startswith("1 account") and "carol" in wave[3] and wave[4] == "#users"
    assert len(told.notices) == 3
    assert [(a, u) for a, u, _ in told.audits] == [(F.WARNED, "alice"), (F.EXPIRED, "carol")]
    assert told.audits[0][2] == {"provider_id": str(p.id), "identity_id": str(ia.id),
                                 "expires_at": (NOW + 3 * DAY).isoformat() + "Z", "ends_sign_in": False}
    # The next pass, an hour later: nothing new to tell, nothing recorded again.
    assert F.sweep(db, NOW + timedelta(hours=1)) == {"warned": 0, "lapsed": 0}
    assert len(told.notices) == 3 and len(told.emails) == 1 and len(told.audits) == 2
    # Alice signs in through the provider: a new deadline, warned about again when it comes near.
    ia.last_sign_in_at = NOW + DAY
    assert F.sweep(db, NOW + 27 * DAY) == {"warned": 1, "lapsed": 1}     # bob lapses meanwhile
    assert told.emails[-1][2]["when"] == (NOW + 31 * DAY).strftime("%d %B %Y, %H:%M UTC")


def test_the_person_reads_the_providers_button_text_and_the_administrators_its_name(told):
    """An administrator names a provider "entra-prod" and gives its button the text "Contoso". The person knows it
    only by the button: every sentence they read of their deadline, in the app, by email, at the door and when a
    hold is lifted, says "Contoso". The administrators' list and records keep the name."""
    admin = _user("root")
    told.admins.append(admin)
    alice, bob = _user(), _user("bob")
    p = _provider(30, name="entra-prod", label="Contoso")
    ia = _identity(alice, p, signed_in=NOW - 27 * DAY)                 # due in 3 days: warned
    ib = _identity(bob, p, signed_in=NOW - 31 * DAY)                   # lapsed a day ago
    db = _db([admin, alice, bob], [p], [ia, ib])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 1}
    due_a = (NOW + 3 * DAY).strftime("%d %B %Y, %H:%M UTC")
    warned, expired, to_the_administrators = told.notices
    assert warned[2] == f"Sign in through Contoso by {due_a}"
    assert expired[2].startswith("Sign in through Contoso")
    change = told.emails[0][2]["change"]
    found_a, found_b = F.deadlines(db, alice.id)[0], F.deadlines(db, bob.id)[0]
    to_the_person = [warned[2], warned[3], expired[2], expired[3], change,
                     F.warning_text(found_a, due_a), F.warning_text(found_a, due_a, sign_in_too=True),
                     F.refusal_text(found_b), F.refusal_text(found_b, sign_in_too=True), F.way_in_text(db, found_b),
                     F.after_a_hold_is_lifted(db, bob, ib, p, whose="your", now=NOW)]
    for text in to_the_person:
        assert "Contoso" in text and "entra-prod" not in text, text
    # The administrators: their list, their notice of the lifted hold, and the records, by the provider's name.
    assert F.standing_of(db, now=NOW)[str(alice.id)]["provider"] == "entra-prod"
    assert "entra-prod" in F.after_a_hold_is_lifted(db, bob, ib, p, whose="its", now=NOW)
    assert found_a.provider_name == "entra-prod" and found_a.provider_label == "Contoso"
    assert to_the_administrators[0] == str(admin.id) and "bob" in to_the_administrators[3]
    # A provider with no button text of its own: its button shows its name, and so does every sentence.
    p.label = None
    assert F.deadlines(db, alice.id)[0].provider_label == "entra-prod"


def test_a_vault_address_single_sign_on_cannot_use_sends_nobody_to_a_button(monkeypatch):
    """The vault's address cannot carry single sign-on (plain http on a public name, say): the sign-in page shows
    no provider's button and no sign-in through a provider starts. A person held to a provider is told it is not
    available on this vault right now, never to use a button that is not there, nor another provider of theirs,
    which cannot start either."""
    from app.services import sso_sign_in
    alice = _user()
    p, q = _provider(30, name="entra-prod", label="Contoso"), _provider(30, name="fabrikam")
    held = _identity(alice, p, signed_in=NOW - 31 * DAY)               # its days ran out a day ago
    other = _identity(alice, q, signed_in=NOW - DAY)
    db = _db([alice], [p, q], [held, other])
    lapsed = F.lapsed(db, alice.id, now=NOW)
    held.refused_at = NOW - DAY + timedelta(hours=1)
    refused = F.lapsed(db, alice.id, now=NOW)
    assert not lapsed.refused and refused.refused and lapsed.provider_id == refused.provider_id == str(p.id)
    # An address single sign-on can use: the button, and for a refusal the person's other provider.
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: None)
    assert F.way_in_text(db, lapsed).endswith("Use the “Contoso” button on the sign-in page.")
    assert F.way_in_text(db, refused).endswith("You can sign in through fabrikam instead: Use the “fabrikam” button "
                                               "on the sign-in page.")
    # One it cannot use.
    monkeypatch.setattr(sso_sign_in, "address_refusal",
                        lambda: "Single sign-on needs the vault's public address. It is not set.")
    for found in (lapsed, refused):
        said = F.way_in_text(db, found)
        assert said == ("Your account signs in only through Contoso until it has signed in there again, and Contoso "
                        "is not available on this vault right now. Ask your administrator."), said
        assert "button" not in said
    assert F.another_way_in(db, refused) is None


def test_the_warning_says_how_to_sign_in_through_the_provider(told, monkeypatch):
    """Only a sign-in through the provider counts, and a person signed in with a password must sign out to make one:
    the warning, in the app and by email, and the notice of the pause say how. Where the provider is not on the
    sign-in page, the link the organisation hands out. The door's own answer says nothing of signing out: nobody
    is signed in there."""
    alice, bob = _user(), _user("bob")
    p = _provider(30, name="entra-prod", label="Contoso", sso_lapse_ends_sign_in=False)
    p.show_on_sign_in = False
    ia = _identity(alice, p, signed_in=NOW - 27 * DAY)                 # due in 3 days: warned
    ib = _identity(bob, p, signed_in=NOW - 31 * DAY)                   # lapsed a day ago
    db = _db([alice, bob], [p], [ia, ib])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 1}
    link = " Use the sign-in link your organisation gave you (sign out first if you are signed in)."
    warned, expired = told.notices
    assert told.emails[0][2]["change"].endswith(link) and warned[3].endswith(link) and expired[3].endswith(link)
    for found in F.deadlines(db, alice.id) + F.deadlines(db, bob.id):
        assert "sign out" not in F.refusal_text(found) and "sign out" not in F.refusal_text(found, sign_in_too=True)
    # On the sign-in page: its button, as it says it.
    p.show_on_sign_in = True
    found = F.deadlines(db, alice.id)[0]
    assert F.how_to_sign_in(found) == ("Use the “Contoso” button on the sign-in page (sign out first if you are "
                                       "signed in).")
    assert F.warning_text(found, "x", sign_in_too=True).endswith(" " + F.how_to_sign_in(found))
    # An address single sign-on cannot use: no button, no link that would work; the administrator.
    from app.services import sso_sign_in
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: "Single sign-on needs the vault's public address.")
    said = F.how_to_sign_in(found)
    assert "button" not in said and "link" not in said and "administrator" in said


def test_the_sweep_sends_no_email_to_an_account_without_an_address(told):
    alice, p = _user(email=None), _provider(30)
    db = _db([alice], [p], [_identity(alice, p, signed_in=NOW - 26 * DAY)])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 0}
    assert told.emails == [] and len(told.notices) == 1


def test_the_sweep_is_a_job_of_the_pruner():
    from app.core import retention
    job, = [j for j in retention.JOBS if j.name == "sso_freshness"]
    assert job.run is retention.run_sso_freshness and not job.held


# --------------------------------------------------------------------------- where it is enforced

def _lapsed_for(user_id):
    return F.Deadline(identity_id="i", user_id=str(user_id), provider_id="p", provider_name="contoso",
                      due=NOW, refused=False)


def test_a_temporary_credential_of_a_lapsed_account_is_refused_and_not_spent(monkeypatch):
    from app.services import auth_service as A
    later = datetime.now(timezone.utc) + timedelta(hours=1)
    owner = types.SimpleNamespace(id=uuid.uuid4(), is_active=True, is_locked=False, locked_until=None, role=None)
    cred = types.SimpleNamespace(id=uuid.uuid4(), device_id=None, credential_hash="h", is_active=True, is_used=False,
                                 expires_at=later, deactivate_at=None, user=owner)
    claims = []

    from app.core.models import TemporaryCredential

    class _Q:
        def __init__(self, entity):
            self.entity = entity

        def filter(self, *a, **k):
            return self

        def first(self):
            return cred if self.entity is TemporaryCredential else None

        def update(self, *a, **k):
            claims.append(1)
            return 1

    svc = A.AuthService.__new__(A.AuthService)
    svc.db = types.SimpleNamespace(query=lambda entity, *a: _Q(entity), commit=lambda: None, add=lambda row: None)
    svc._check_rate_limit = svc._check_username_rate_limit = lambda *a, **k: None
    failures = []
    svc._record_failed_login = lambda name, ip: failures.append(name)
    svc._create_session = lambda *a, **k: "session-token"
    monkeypatch.setattr(A, "verify_temporary_credential", lambda *a, **k: True)
    monkeypatch.setattr("app.core.temp_scope.attach_scope", lambda *a, **k: None)
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: _lapsed_for(user_id))
    for door in (True, False):
        with pytest.raises(A.FreshnessLapsedError):
            svc.authenticate_temporary_credential("temp_x", "cred", "203.0.113.9", allow_device_credential=door)
    assert issubclass(A.FreshnessLapsedError, A.InvalidCredentialsError)      # answered like a wrong credential
    assert claims == [] and failures == ["temp_x", "temp_x"]
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: None)
    user, token = svc.authenticate_temporary_credential("temp_x", "cred", "203.0.113.9")
    assert user is owner and claims == [1]


def test_no_temporary_credential_is_minted_for_a_lapsed_account(monkeypatch):
    from fastapi import HTTPException
    from app.services import auth_service as A
    svc = A.AuthService.__new__(A.AuthService)
    svc.db = object()
    seen = []
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: seen.append(user_id) or _lapsed_for(user_id))
    uid = uuid.uuid4()
    with pytest.raises(HTTPException) as e:
        svc.create_temporary_credential(uid)
    assert e.value.status_code == 403 and e.value.detail["reason"] == "sso_freshness_lapsed"
    assert e.value.detail["message"].startswith("Sign in through contoso again") and seen == [uid]


def test_ssh_keys_of_a_lapsed_account_are_refused_at_authentication_and_at_the_channel(monkeypatch):
    import paramiko
    from app.sftp import sftp_server as S
    key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIFreshnessKeyFreshnessKeyFreshnessKey0"
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice", sftp_enabled=True, is_active=True,
                                  is_locked=False, locked_until=None)
    stored = types.SimpleNamespace(id=uuid.uuid4(), public_key=f"ssh-ed25519 {key_b64} laptop", last_used=None)

    class _Q:
        def __init__(self, entity):
            self.entity = entity

        def filter(self, *a, **k):
            return self

        def first(self):
            return alice if self.entity is User else stored

        def all(self):
            return [stored]

    db = types.SimpleNamespace(query=lambda entity, *a: _Q(entity), commit=lambda: None)

    @contextmanager
    def ctx():
        yield db
    monkeypatch.setattr(S, "get_db_context", ctx)
    monkeypatch.setattr(S, "_sftp_key_throttled", lambda ip, username: False)
    monkeypatch.setattr(S, "_sftp_key_clear", lambda ip, username: None)
    monkeypatch.setattr(S, "_user_requires_temp_cred_for_sftp", lambda db, user, fail_closed=True: False)
    import app.core.sign_in_lockout as lockout
    monkeypatch.setattr(lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
    key = types.SimpleNamespace(get_base64=lambda: key_b64)
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: _lapsed_for(user_id))
    assert S.SFTPServer("203.0.113.9").check_auth_publickey("alice", key) == paramiko.AUTH_FAILED
    server = S.SFTPServer("203.0.113.9")
    server.user_id, server.session_token = alice.id, None
    assert server.check_channel_request("session", 1) == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    assert server.session_token is None
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: None)
    assert S.SFTPServer("203.0.113.9").check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL


def test_no_device_sync_credential_is_minted_for_a_lapsed_account(monkeypatch):
    from fastapi import HTTPException
    from app.core.models import Device, DeviceGrant, Vault
    from app.services import auth_service as A
    owner = types.SimpleNamespace(id=uuid.uuid4(), is_active=True, is_locked=False, locked_until=None, role=None)
    device = types.SimpleNamespace(id=uuid.uuid4(), user_id=owner.id, is_active=True, suspended=False, expires_at=None)
    vault_id = uuid.uuid4()
    rows = {Device: device, DeviceGrant: types.SimpleNamespace(vault_password_fingerprint=None),
            Vault: types.SimpleNamespace(id=vault_id, type="standard", password_hash=None), User: owner}

    class _Q:
        def __init__(self, entity):
            self.entity = entity

        def filter(self, *a, **k):
            return self

        def populate_existing(self):
            return self

        def with_for_update(self, **k):
            return self

        def first(self):
            return rows.get(self.entity)

    svc = A.AuthService.__new__(A.AuthService)
    svc.db = types.SimpleNamespace(query=lambda entity, *a: _Q(entity))
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: _lapsed_for(user_id))
    with pytest.raises(HTTPException) as e:
        svc.mint_device_sync_credential(device, vault_id)
    assert e.value.status_code == 403 and e.value.detail["reason"] == "sso-freshness-lapsed"
    assert e.value.detail["message"].startswith("Sign in through contoso again")
    # Fresh: the mint goes past the check (here to the next predicate, which this stand-in does not satisfy).
    monkeypatch.setattr(F, "lapsed", lambda db, user_id, now=None: None)
    with pytest.raises(Exception) as e:
        svc.mint_device_sync_credential(device, vault_id)
    assert getattr(e.value, "detail", {}) == {} or e.value.detail.get("reason") != "sso-freshness-lapsed"



# --------------------------------------------------------------------------- a refusal outlives the provider's state

def test_a_refusal_stays_in_force_when_the_provider_is_disabled_or_removed():
    alice, p = _user(), _provider(0)
    i = _identity(alice, p, signed_in=NOW - DAY, refused=NOW - timedelta(hours=1))
    db = _db([alice], [p], [i])
    for state in ("disabled", "draft"):
        p.state = state
        found = F.lapsed(db, alice.id, now=NOW)
        assert found is not None and found.refused and found.provider_id == str(p.id), state
    # The provider removed altogether (its row gone, the identity left behind): still refused.
    gone = _db([alice], [], [i])
    assert F.lapsed(gone, alice.id, now=NOW).refused
    assert F.standing_of(gone, now=NOW)[str(alice.id)]["refused"] is True
    # Without a refusal, a provider that is not enabled asks nothing.
    i.refused_at = None
    assert F.lapsed(db, alice.id, now=NOW) is None


class _Store:
    """The in-memory store for the identities and providers, and fixed answers for everything else a door reads."""

    def __init__(self, memory, fixed):
        self.memory, self.fixed = memory, fixed
        self.claims = []

    def query(self, entity, *a):
        if entity in (ExternalIdentity, SsoProvider):
            return self.memory.query(entity)
        return _Fixed(self, self.fixed.get(entity))

    def commit(self):
        pass

    def add(self, row):
        pass


class _Fixed:
    def __init__(self, store, value):
        self.store, self.value = store, value

    def filter(self, *a, **k):
        return self

    def first(self):
        return self.value[0] if isinstance(self.value, list) else self.value

    def all(self):
        return list(self.value or [])

    def update(self, *a, **k):
        self.store.claims.append(1)
        return 1


def test_refused_then_the_provider_disabled_the_ssh_key_and_the_temporary_credential_are_still_refused(monkeypatch):
    """The real rule, not a stand-in: the provider refuses alice, an administrator disables the provider, and alice's
    SSH key and temporary credential are still refused; nothing is spent."""
    import paramiko
    from app.core.models import TemporaryCredential, UserSSHKey
    from app.services import auth_service as A
    from app.sftp import sftp_server as S
    alice = _user(sftp_enabled=True, is_locked=False, locked_until=None, role=None)
    p = _provider(30)
    i = _identity(alice, p, signed_in=NOW - DAY, refused=datetime.utcnow())
    memory = _db([alice], [p], [i])
    p.state = "disabled"
    key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIRefusalKeyRefusalKeyRefusalKeyRefusal0"
    stored = types.SimpleNamespace(id=uuid.uuid4(), public_key=f"ssh-ed25519 {key_b64} laptop", last_used=None)
    later = datetime.now(timezone.utc) + timedelta(hours=1)
    cred = types.SimpleNamespace(id=uuid.uuid4(), device_id=None, credential_hash="h", is_active=True, is_used=False,
                                 expires_at=later, deactivate_at=None, user=alice)
    store = _Store(memory, {User: alice, UserSSHKey: [stored], TemporaryCredential: cred})

    @contextmanager
    def ctx():
        yield store
    monkeypatch.setattr(S, "get_db_context", ctx)
    monkeypatch.setattr(S, "_sftp_key_throttled", lambda ip, username: False)
    monkeypatch.setattr(S, "_sftp_key_clear", lambda ip, username: None)
    monkeypatch.setattr(S, "_user_requires_temp_cred_for_sftp", lambda db, user, fail_closed=True: False)
    import app.core.sign_in_lockout as lockout
    monkeypatch.setattr(lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
    key = types.SimpleNamespace(get_base64=lambda: key_b64)
    assert S.SFTPServer("203.0.113.9").check_auth_publickey("alice", key) == paramiko.AUTH_FAILED
    svc = A.AuthService.__new__(A.AuthService)
    svc.db = store
    svc._check_rate_limit = svc._check_username_rate_limit = lambda *a, **k: None
    svc._record_failed_login = lambda name, ip: None
    svc._create_session = lambda *a, **k: "session-token"
    monkeypatch.setattr(A, "verify_temporary_credential", lambda *a, **k: True)
    monkeypatch.setattr("app.core.temp_scope.attach_scope", lambda *a, **k: None)
    with pytest.raises(A.FreshnessLapsedError):
        svc.authenticate_temporary_credential("temp_x", "cred", "203.0.113.9")
    assert store.claims == []
    # A sign-in the provider admits (only possible once it is enabled again) lifts the refusal.
    p.state = "enabled"
    i.last_sign_in_at = datetime.utcnow() + timedelta(seconds=1)
    assert S.SFTPServer("203.0.113.9").check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL


def test_a_short_window_warns_within_half_of_it_and_a_window_of_a_day_not_at_all(told):
    assert F.warning_lead(1) == timedelta(0) and F.warning_lead(4) == 2 * DAY and F.warning_lead(30) == 5 * DAY
    assert F.warning_lead(0) == timedelta(0)
    alice, bob = _user(), _user("bob")
    daily, short = _provider(1, name="daily"), _provider(4, name="short")
    ia = _identity(alice, daily, signed_in=NOW - timedelta(hours=12))      # due in 12 hours: never warned
    ib = _identity(bob, short, signed_in=NOW - DAY)                        # due in 3 days, warned 2 days before
    db = _db([alice, bob], [daily, short], [ia, ib])
    assert F.sweep(db, NOW) == {"warned": 0, "lapsed": 0} and told.emails == []
    assert F.sweep(db, NOW + DAY + timedelta(hours=1)) == {"warned": 1, "lapsed": 1}
    assert [e[1] for e in told.emails] == ["bob@example.test"]


def test_told_once_is_kept_on_the_identity_whatever_becomes_of_the_notices(told):
    alice, p = _user(), _provider(30)
    i = _identity(alice, p, signed_in=NOW - 27 * DAY)
    db = _db([alice], [p], [i])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 0} and len(told.emails) == 1
    assert i.freshness_warned_for == NOW + 3 * DAY
    # The person deleted the notice (or it was pruned): not told again.
    told.seen.clear()
    assert F.sweep(db, NOW + DAY) == {"warned": 0, "lapsed": 0} and len(told.emails) == 1
    # A pass whose transaction rolled back: the row's mark is lost, its notice was kept. Recorded again, with no
    # second notice and no second email.
    i.freshness_warned_for = None
    told.seen.add(f"{F.WARNED}:{i.id}:{(NOW + 3 * DAY):%Y-%m-%d}:{alice.id}")
    shown = len(told.notices)
    assert F.sweep(db, NOW + DAY) == {"warned": 1, "lapsed": 0}
    assert len(told.emails) == 1 and len(told.notices) == shown
    assert [a for a, _, _ in told.audits].count(F.WARNED) == 2
    # The pause is told once, and not again once its notice is gone.
    assert F.sweep(db, NOW + 4 * DAY) == {"warned": 0, "lapsed": 1} and i.freshness_paused_for == NOW + 3 * DAY
    told.seen.clear()
    assert F.sweep(db, NOW + 5 * DAY) == {"warned": 0, "lapsed": 0}


def test_the_sweep_sends_nobody_to_a_provider_that_is_turned_off_and_tells_them_once_it_is_on(told):
    """An administrator turns a provider off for a while. The days go on counting. Told to sign in through it by
    a date, or again, the person would be sent where nothing answers: the sign-in page has no way to a provider
    that is off. Nothing is told and nothing is kept as told; the first pass after it is on again tells what
    holds then."""
    admin = _user("root")
    told.admins.append(admin)
    alice, bob = _user("alice"), _user("bob")
    p = _provider(30, sso_lapse_ends_sign_in=False)
    ia = _identity(alice, p, signed_in=NOW - 27 * DAY)                 # due in 3 days
    ib = _identity(bob, p, signed_in=NOW - 31 * DAY)                   # lapsed a day ago
    db = _db([admin, alice, bob], [p], [ia, ib])
    p.state = "disabled"
    assert [d.provider_on for d in F.deadlines(db, alice.id)] == [False]
    assert F.sweep(db, NOW) == {"warned": 0, "lapsed": 0}
    assert told.notices == [] and told.emails == [] and told.audits == []
    assert not hasattr(ia, "freshness_warned_for") and not hasattr(ib, "freshness_paused_for")     # nothing kept as told
    # A draft that never was on is the same.
    p.state = "draft"
    assert F.sweep(db, NOW) == {"warned": 0, "lapsed": 0} and told.notices == []
    # Turned on again: each is told what holds now, once.
    p.state = "enabled"
    assert F.sweep(db, NOW + DAY) == {"warned": 1, "lapsed": 1}
    assert [(n[0], n[1]) for n in told.notices] == [(str(alice.id), F.WARNED), (str(bob.id), F.EXPIRED),
                                                    (str(admin.id), F.EXPIRED)]
    assert [(a, u) for a, u, _ in told.audits] == [(F.WARNED, "alice"), (F.EXPIRED, "bob")]
    assert F.sweep(db, NOW + DAY + timedelta(hours=1)) == {"warned": 0, "lapsed": 0}
    # A refusal by the provider was told when it happened, whatever the provider's state: still not told here.
    ia.refused_at = NOW + DAY
    p.state = "disabled"
    assert F.sweep(db, NOW + 2 * DAY) == {"warned": 0, "lapsed": 0} and len(told.notices) == 3


def test_an_accounts_deadlines_are_read_in_two_queries_however_many_providers_it_is_linked_to():
    """The deadlines are asked at every door and on every SFTP operation. One read for the account's identities,
    which is the only one for an account linked to nothing, and one for their providers together: a read per
    identity made an operation cost more with every provider the account was linked to."""
    alice, bob = _user(), _user("bob")
    providers = [_provider(30, name=f"p{n}") for n in range(4)]
    links = [_identity(alice, p, signed_in=NOW - (n + 1) * DAY) for n, p in enumerate(providers)]
    db = _db([alice, bob], providers, links)
    asked, through = [], db.query

    def query(*entities):
        asked.append(getattr(entities[0], "__tablename__", None))
        return through(*entities)
    db.query = query
    found = F.deadlines(db, alice.id)
    assert asked == ["external_identities", "sso_providers"]
    assert [d.provider_name for d in found] == ["p3", "p2", "p1", "p0"]          # earliest first, each with its own
    del asked[:]
    assert F.deadlines(db, bob.id) == [] and asked == ["external_identities"]     # linked to nothing: one read
    # An identity whose provider is gone asks nothing of anybody.
    db.tables[SsoProvider].remove(providers[0])
    assert [d.provider_name for d in F.deadlines(db, alice.id)] == ["p3", "p2", "p1"]
