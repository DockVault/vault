"""The Users page says where each account stands with a provider that asks it to sign in again.

GET /users gives each such account its standing (``sso_freshness``: when its SSH keys, temporary credentials and
devices pause or paused, through which provider, whether the provider refused it, and, once it has lapsed, whether
its password and passkeys are held too). The row's status shows a badge for an account whose keys are paused, and
its details say what paused them, since when or until when, and what restores them. Only the lapsed rows ask the
database whether the account is held.

The page's own functions are run by Node on the small document of tests/js/mini_dom.js; the route is driven offline
against an in-memory database.
"""
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from _async_run import run_coroutine
from test_sso_sign_in import Harness, _identity, _provider, _user

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"
_SHIPPED = ("parseServerTime", "formatDayMonth", "formatServerTime", "_el", "credentialChangeNoteText",
            "_ssoStanding", "_ssoStandingNote", "fillCredentialChangeNotes", "fillSsoStandingBadges",
            "signInMethods", "signInMethodBadges", "_holdsAFactor", "_passkeysCounted", "_passkeysHeld",
            "_passkeysShownFor", "renderUserDetail", "renderUserRow")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


def _const(js, name):
    start = js.index(f"\nconst {name} = {{") + 1
    return js[start:js.index("\n};\n", start) + 4]


PRELUDE = r"""
const _RealDate = Date, _FIXED_NOW = _RealDate.parse('2026-06-15T12:00:00Z');
globalThis.Date = class extends _RealDate {
  constructor(...a) { super(...(a.length ? a : [_FIXED_NOW])); }
  static now() { return _FIXED_NOW; }
};
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
var currentUser = { id: 'me', username: 'alice', role: 'admin' };
var currentSettings = {};
var isScopedTemp = false;
const iconSvg = () => '';
const escapeHtml = (s) => String(s);
const groupChip = () => '';
const People = { placeholder: () => '', whenPlaceholder: () => '' };
const okta = (extra) => Object.assign({ provider: 'Okta' }, extra);
const row = (id, freshness) => ({ id, username: id, role: 'user', groups: [], is_active: true, sso_freshness: freshness });
var usersView = { groups: [], expanded: new Set(), users: [
    row('ann', okta({ due: '2026-06-01T00:00:00Z', lapsed: true, refused: true, held: true })),
    row('fay', okta({ due: '2026-07-01T00:00:00Z', lapsed: true, refused: true, held: false })),
    row('ben', okta({ due: '2026-06-05T00:00:00Z', lapsed: true, refused: false, held: false })),
    row('eve', okta({ due: '2026-06-03T00:00:00Z', lapsed: true, refused: false, held: true })),
    row('cat', okta({ due: '2026-06-30T00:00:00Z', lapsed: false, refused: false, held: false })),
    row('dan', null),
    Object.assign(row('me', okta({ due: '2026-06-01T00:00:00Z', lapsed: true, refused: true, held: false })),
                  { username: 'alice', role: 'admin' }),
] };
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + _const(js, "_CHANGE_MADE") + "".join(_function(js, n) for n in _SHIPPED)
              + "(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_paused_account_shows_a_badge_and_its_details_say_what_paused_it_and_what_restores_it():
    got = _node(r"""
const day = (v) => new Date(v).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
const placed = {}, badges = {}, notes = {};
usersView.users.forEach((u) => {
    placed[u.id] = renderUserRow(u).includes('class="badge badge-warning sso-standing-badge" data-user-id="' + u.id + '"');
    const badge = document.createElement('span');
    badge.className = 'badge badge-warning sso-standing-badge';
    badge.setAttribute('data-user-id', u.id);
    document.body.appendChild(badge);
    const note = document.createElement('div');
    note.className = 'credential-change-note';
    note.setAttribute('data-user-id', u.id);
    document.body.appendChild(note);
});
fillSsoStandingBadges();
fillCredentialChangeNotes();
document.querySelectorAll('.sso-standing-badge').forEach((b) => { badges[b.getAttribute('data-user-id')] = b.textContent; });
document.querySelectorAll('.credential-change-note').forEach((n) => {
    notes[n.getAttribute('data-user-id')] = n.hidden ? null : n.children.map((c) => c.textContent); });
out({ placed, badges, notes, days: { ben: day('2026-06-05T00:00:00Z'), eve: day('2026-06-03T00:00:00Z'),
                                     cat: day('2026-06-30T00:00:00Z') } });
""")
    days = got["days"]
    # The badge is put in the row only for an account whose keys are paused, and says by which provider.
    assert got["placed"] == {"ann": True, "fay": True, "ben": True, "eve": True, "cat": False, "dan": False, "me": True}
    assert got["badges"] == {"ann": "Refused or held (Okta)", "fay": "Refused or held (Okta)",
                             "ben": "Keys paused (Okta)", "eve": "Keys paused (Okta)", "cat": "", "dan": "",
                             "me": "Refused or held (Okta)"}
    refused = ("Okta refused this person at a sign-in, or the vault held them after their days without a sign-in "
               "there had run out. Their SSH keys, temporary credentials and devices are paused")
    lift = ("until they sign in through Okta again. {who} lift it with Lift refusal on Okta’s Identities page "
            "(Settings, Sign-in methods), which says what lifting it gives.")
    assert got["notes"]["ann"] == [refused + ", and their password and passkeys do not sign them in, "
                                   + lift.format(who="You can also")]
    assert got["notes"]["fay"] == [refused + " " + lift.format(who="You can also")]
    assert got["notes"]["me"] == [refused + " " + lift.format(who="Another administrator can also")]
    assert got["notes"]["ben"] == [f"Their SSH keys, temporary credentials and devices paused on {days['ben']}: they "
                                   "have not signed in through Okta within its days. A sign-in through Okta restores "
                                   "them."]
    assert got["notes"]["eve"] == [f"Their SSH keys, temporary credentials and devices paused on {days['eve']}: they "
                                   "have not signed in through Okta within its days. Their password and passkeys do "
                                   "not sign them in either. A sign-in through Okta restores all of it."]
    assert got["notes"]["cat"] == [f"Their SSH keys, temporary credentials and devices pause on {days['cat']} unless "
                                   "they sign in through Okta before then."]
    assert got["notes"]["dan"] is None


def test_the_users_list_asks_whether_an_account_is_held_only_for_a_lapsed_one(monkeypatch):
    from app.services import sso_freshness
    root, ann, ben, cat, dan = (_user(n, **({"role": "admin"} if n == "root" else {}), password_set_by=None,
                                      password_set_by_other_at=None)
                                for n in ("root", "ann", "ben", "cat", "dan"))
    p = _provider(policy={"sso_freshness_days": 30})
    signed_in = datetime.utcnow() - timedelta(days=10)
    h = Harness(monkeypatch, [root, ann, ben, cat, dan], [p],
                identities=[_identity(u, p, subject=u.username, last_sign_in_at=signed_in) for u in (ann, ben, cat)])
    import app.core.endpoint_permissions as ep
    monkeypatch.setattr(ep, "check_endpoint_permission", lambda *a, **k: None)
    due = "2026-06-01T00:00:00Z"
    standing = {str(ann.id): {"due": due, "provider": "contoso", "lapsed": True, "refused": True},
                str(ben.id): {"due": due, "provider": "contoso", "lapsed": True, "refused": False},
                str(cat.id): {"due": due, "provider": "contoso", "lapsed": False, "refused": False}}
    monkeypatch.setattr(sso_freshness, "standing_of", lambda db, now=None: standing)
    asked = []

    def held(db, user, *, now=None):
        asked.append(user.username)
        return sso_freshness.Deadline(identity_id="i", user_id=str(user.id), provider_id=str(p.id),
                                      provider_name="contoso", due=datetime.utcnow(), refused=True) \
            if user.username == "ann" else None
    monkeypatch.setattr(sso_freshness, "held_to_a_provider", held)
    rows = {r.username: r.sso_freshness for r in run_coroutine(h.S.list_users(current_user=root, db=h.db))}
    assert sorted(asked) == ["ann", "ben"]
    assert rows["ann"] == {"due": due, "provider": "contoso", "lapsed": True, "refused": True, "held": True}
    assert rows["ben"] == {"due": due, "provider": "contoso", "lapsed": True, "refused": False, "held": False}
    assert rows["cat"] == {"due": due, "provider": "contoso", "lapsed": False, "refused": False, "held": False}
    assert rows["dan"] is None and rows["root"] is None


def test_an_account_held_by_another_provider_than_the_one_shown_is_not_said_to_be_held_by_it(monkeypatch):
    """The row shows the provider whose standing matters most; a hold by a second provider would be lifted there,
    so the row does not say this one holds the password."""
    from app.services import sso_freshness
    root, ann = (_user(n, **({"role": "admin"} if n == "root" else {}), password_set_by=None,
                       password_set_by_other_at=None) for n in ("root", "ann"))
    p = _provider(policy={"sso_freshness_days": 30})
    h = Harness(monkeypatch, [root, ann], [p])
    import app.core.endpoint_permissions as ep
    monkeypatch.setattr(ep, "check_endpoint_permission", lambda *a, **k: None)
    monkeypatch.setattr(sso_freshness, "standing_of", lambda db, now=None: {
        str(ann.id): {"due": "2026-06-01T00:00:00Z", "provider": "contoso", "lapsed": True, "refused": True}})
    monkeypatch.setattr(sso_freshness, "held_to_a_provider", lambda db, user, *, now=None: sso_freshness.Deadline(
        identity_id="i", user_id=str(user.id), provider_id="other", provider_name="fabrikam", due=datetime.utcnow(),
        refused=False))
    rows = {r.username: r.sso_freshness for r in run_coroutine(h.S.list_users(current_user=root, db=h.db))}
    assert rows["ann"]["held"] is False
