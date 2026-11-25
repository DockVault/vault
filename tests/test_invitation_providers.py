"""An invitation may be accepted through the organisation's sign-in: the invitation page offers the providers the
server lists for it (GET /invites/{token} ``providers``), offline on a real database.

They are the sign-in page's buttons (a provider that is on and shown there, while the vault has an address a provider
can send the browser back to), and none for an administrator's invitation, which the start refuses before anyone is
sent to a provider (app/api/sso_router.py _invitation_for_start) because it is accepted with the form. The start and
the page read the same rule (app/services/sso_sign_in.py invitation_takes_a_provider). The page itself is driven in
Node: its buttons start the sign-in with the invitation's token, and a start the server refuses is said in the
server's words, as the sign-in page says it.
"""
import json
import os
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
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import invitations  # noqa: E402
from app.core.models import AccountInvitation, RoleEnum, SsoProvider, SystemSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

PEPPER = "p" * 48
BASE = "https://vault.example.test"
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def db(monkeypatch):
    from app.core import public_url
    from app.core import rate_limiter
    monkeypatch.setattr(api, "_invite_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_account_policy", lambda db: {"invite_enabled": True, "email_requirement": "optional"})
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(public_url, "public_base_url", lambda: BASE)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'invitation-providers.db'}")
        for model in (User, AccountInvitation, SystemSetting, SsoProvider):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _admin(db):
    u = User(username="root", email=None, password_hash="x", role=RoleEnum.ADMIN, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def _invite(db, by, role):
    token, prefix = invitations.mint_invite()
    db.add(AccountInvitation(username=f"new-{role}", email=None, role=role, token_prefix=prefix,
                             token_hash=invitations.hash_invite_token(token, PEPPER),
                             expires_at=datetime.utcnow() + timedelta(days=1), created_by=by.id))
    db.commit()
    return token


def _provider(db, name, *, state="enabled", shown=True, order=0, label=None):
    row = SsoProvider(id=uuid.uuid4(), kind="oidc", state=state, name=name, label=label, icon="microsoft",
                      sort_order=order, show_on_sign_in=shown, issuer="https://login.example.test", client_id="client",
                      client_secret_enc="enc", token_auth="client_secret_basic", scopes="openid")
    db.add(row)
    db.commit()
    return row


def _info(db, token):
    return run_coroutine(api.get_invite(token=token, request=SimpleNamespace(headers={}, client=None), db=db))


def test_a_users_invitation_lists_the_sign_in_pages_providers_and_an_administrators_none(db):
    root = _admin(db)
    second = _provider(db, "fabrikam", order=2, label="Fabrikam")
    first = _provider(db, "contoso", order=1, label="Sign in with Contoso")
    _provider(db, "off", state="disabled")
    _provider(db, "draft", state="draft")
    _provider(db, "hidden", shown=False)                 # handed out by its link only
    user_info = _info(db, _invite(db, root, "user"))
    assert [p["id"] for p in user_info["providers"]] == [str(first.id), str(second.id)]
    assert user_info["providers"][0] == {"id": str(first.id), "label": "Sign in with Contoso", "kind": "oidc",
                                         "icon": "microsoft", "order": 1}
    assert user_info["providers"] == api._sign_in_providers(db)        # the sign-in page's own list
    assert user_info["origin"] == BASE
    assert _info(db, _invite(db, root, "external"))["providers"] == user_info["providers"]
    # An administrator types the account's password at every sign-in: that invitation is accepted with the form.
    admin_info = _info(db, _invite(db, root, "admin"))
    assert admin_info["providers"] == [] and admin_info["username"] == "new-admin"


def test_without_an_address_a_provider_can_send_the_browser_back_to_there_is_no_provider_to_offer(db, monkeypatch):
    from app.core import public_url
    root = _admin(db)
    _provider(db, "contoso")
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    info = _info(db, _invite(db, root, "user"))
    assert info["providers"] == [] and info["origin"] is None


def test_the_start_and_the_page_hold_an_invitation_to_one_rule():
    from app.api import sso_router
    from app.services import sso_sign_in as sso
    assert sso.invitation_takes_a_provider(SimpleNamespace(role="user")) is True
    assert sso.invitation_takes_a_provider(SimpleNamespace(role="external")) is True
    assert sso.invitation_takes_a_provider(SimpleNamespace(role="admin")) is False
    import inspect
    assert "invitation_takes_a_provider(inv)" in inspect.getsource(sso_router._invitation_for_start)
    assert "invitation_takes_a_provider(inv)" in inspect.getsource(api.get_invite)


# --------------------------------------------------------------------------- the page

APP_JS = ROOT / "static" / "js" / "app.js"
_SHIPPED = ("_el", "_inviteCard", "_signInOriginElsewhere", "_inviteProviders", "_renderInviteForm")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const card = document.createElement('div'); card.id = 'invite-card-body'; document.body.appendChild(card);
global.location = { origin: 'https://vault.example.test' };
var API_BASE = 'https://vault.example.test';
const started = [];
let refuse = null;
window.Sso = { startSignIn: async (id, options) => { started.push([id, options]); if (refuse) throw new Error(refuse); } };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = (id) => document.getElementById(id);
const out = (value) => console.log(JSON.stringify(value));
const INFO = { username: 'new-user', email: null, email_required: false, password_policy: {},
               expires_at: '2026-12-01T00:00:00', origin: 'https://vault.example.test',
               providers: [{ id: 'p-1', label: 'Sign in with Contoso', kind: 'oidc', icon: 'microsoft', order: 1 },
                           { id: 'p-2', label: 'Fabrikam', kind: 'oidc', icon: 'generic', order: 2 }] };
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_function(js, n) for n in _SHIPPED) + "(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_invitation_page_offers_the_listed_providers_and_starts_one_with_the_invitation():
    got = _node(r"""
_renderInviteForm('the-invite-token', INFO);
const box = byId('invite-sso');
const buttons = box.querySelectorAll('button');
const seen = { sub: card.children[1].textContent, say: box.children[0].textContent,
               buttons: buttons.map((b) => [b.textContent, b.dataset.provider, b.dataset.icon, b.type]),
               password: card.querySelectorAll('input').length };
buttons[0].click();
await tick();
out({ seen, started, disabled: buttons.map((b) => b.disabled) });
""")
    seen = got["seen"]
    assert seen["sub"] == ("You are claiming the username new-user. Set a password to finish, or accept it through "
                           "your organisation's sign-in below.")
    assert seen["say"] == ("Or accept it through your organisation's sign-in: you sign in there, and your account "
                           "is made when you come back.")
    assert seen["buttons"] == [["Sign in with Contoso", "p-1", "microsoft", "button"],
                               ["Fabrikam", "p-2", "generic", "button"]]
    assert seen["password"] == 1                          # the form is still there
    assert got["started"] == [["p-1", {"invitation": "the-invite-token"}]]
    assert got["disabled"] == [True, True]                # leaving: no second start


def test_a_start_the_server_refuses_is_said_in_its_words_and_the_buttons_come_back():
    got = _node(r"""
refuse = "An administrator's invitation is accepted with a password: an administrator types it at every sign-in.";
_renderInviteForm('the-invite-token', INFO);
const box = byId('invite-sso');
box.querySelectorAll('button')[1].click();
await tick(); await tick();
const said = byId('invite-sso-error');
out({ said: said.textContent, shown: said.style.display, role: said.getAttribute('role'),
      disabled: box.querySelectorAll('button').map((b) => b.disabled), started });
""")
    assert got["said"].startswith("An administrator's invitation is accepted with a password")
    assert got["shown"] == "block" and got["role"] == "alert" and got["disabled"] == [False, False]
    assert got["started"] == [["p-2", {"invitation": "the-invite-token"}]]


def test_an_invitation_with_no_provider_to_offer_shows_the_form_alone():
    got = _node(r"""
_renderInviteForm('the-invite-token', Object.assign({}, INFO, { providers: [] }));
const none = { box: byId('invite-sso') === null, sub: card.children[1].textContent };
card.replaceChildren();
_renderInviteForm('the-invite-token', Object.assign({}, INFO, { providers: undefined }));
out({ none, older: byId('invite-sso') === null, started });
""")
    assert got["none"] == {"box": True, "sub": "You are claiming the username new-user. Set a password to finish."}
    assert got["older"] is True and got["started"] == []


def test_a_page_opened_at_another_address_says_where_the_providers_work_and_offers_none():
    got = _node(r"""
_renderInviteForm('the-invite-token', Object.assign({}, INFO, { origin: 'https://vault.example.org' }));
const box = byId('invite-sso');
out({ buttons: box.querySelectorAll('button').length, said: box.textContent,
      href: box.querySelector('a') ? box.querySelector('a').href : null });
""")
    assert got["buttons"] == 0
    assert got["said"] == ("This invitation can also be accepted through your organisation's sign-in at "
                           "https://vault.example.org. Open your invitation link there to do that.")
    assert got["href"] is None                            # the invitation's token goes into no link on the page
