"""What a tab takes from another tab's renewal, what it sends again after one, and the reasons it can hand to the page
that replaces it, offline (static/js/app.js run in Node with static/js/session-watch.js and the stand-ins of
test_session_watch_refusals).

A tab told that another tab renewed the session it holds takes the token the message names, and only when that
token renews its own sign-in: a tab the browser froze gets its messages when it wakes, when the token stored for the
browser may be another account's, the same person's new sign-in, or a temporary credential's. A request refused while
the tab's own renewal is on its way is sent again with the renewed token, and never with the token of a sign-in made
on the page once its session ended. The reasons the warning signs out with travel to the next page as codes, which
cannot name anything but the app's own sentences. Without the warning's module, a refusal signs out with the same
sentences as before it.
"""
import json
import shutil
import subprocess

import pytest

from test_session_watch_refusals import PRELUDE, ROOT

pytestmark = pytest.mark.unit

APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _slice(start: str, end: str) -> str:
    i = APP.index(start)
    return APP[i:APP.index(end, i)]


# The sign-out channel: from its declaration to the sign-in policy that follows it.
CHANNEL = _slice("let _signOutChannel = null;", "// The sign-in screen's policy")
# _signOutRefused, the session-ended counter, apiRequest and _apiRequestNow (to the end of its body).
_REQ_START = APP.index("async function _signOutRefused(")
REQUESTS = APP[_REQ_START:APP.index("\n}\n", APP.index("async function _apiRequestNow(")) + 3]
# The reasons a sign-out hands to the next page, and how the page reads a code back.
REASONS = _slice("const SIGNED_OUT_REASONS = {", "let _endedReason = '';")


def _node(body: str, *chunks: str, without_watch: bool = False) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    load = "".join(f"vm.runInThisContext({json.dumps(c)}, {{ filename: 'app-slice.js' }});\n" for c in chunks)
    drop = "delete globalThis.SessionWatch;\n" if without_watch else ""
    script = PRELUDE + "(async () => {\n" + drop + load + body + "\n})();"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


# The tab the browser froze holds `mine`; it is told late that `mine` was renewed, and finds `stored` stored.
TOLD = r"""
let listener = null;
globalThis.BroadcastChannel = function () {
    this.addEventListener = (t, fn) => { listener = fn; };
    this.postMessage = () => {};
};
globalThis.SIGN_OUT_TOLD = 'told';
"""


@pytest.mark.parametrize("stored", [
    "token({ sub: '9', username: 'quinn', is_temporary: false, iat: NOW, exp: NOW + 3600 }, 'quinn')",  # another account
    "token({ ...person, iat: NOW, exp: NOW + 3600 }, 'again')",                       # the same person's new sign-in
    "token({ ...person, username: 'tmp-ana-1', is_temporary: true, iat: NOW, exp: NOW + 600 }, 'tmp')",  # temporary
    "token({ ...person, iat: NOW, exp: NOW - 5, auth_time: NOW - 600 }, 'ranout')",   # a renewal that has run out
])
def test_a_tab_told_of_a_renewal_takes_no_token_but_a_renewal_of_its_own_sign_in(stored):
    out = _node(TOLD + f"""
vm.runInThisContext({json.dumps(CHANNEL)}, {{ filename: 'app-channel.js' }});
const theirs = {stored};
store.set('authToken', theirs);
listener({{ data: {{ type: 'renewed', token: _tokenTail(mine), next: _tokenTail(theirs) }} }});
out({{ held: authToken === mine ? 'mine' : authToken === theirs ? 'theirs' : String(authToken) }});
""")
    assert out == {"held": "mine"}


def test_a_tab_told_of_a_renewal_takes_only_the_token_the_message_names():
    out = _node(TOLD + f"""
vm.runInThisContext({json.dumps(CHANNEL)}, {{ filename: 'app-channel.js' }});
store.set('authToken', renewed);
const results = {{}};
// The message names another token than the one stored (stored since by another renewal or sign-in): nothing taken.
listener({{ data: {{ type: 'renewed', token: _tokenTail(mine), next: 'x'.repeat(24) }} }});
results.other_name = authToken === mine;
// A message without a name (an older page's): nothing taken.
listener({{ data: {{ type: 'renewed', token: _tokenTail(mine) }} }});
results.no_name = authToken === mine;
// The renewal of this tab's own sign-in, named: taken.
listener({{ data: {{ type: 'renewed', token: _tokenTail(mine), next: _tokenTail(renewed) }} }});
results.its_own = authToken === renewed;
out(results);
""")
    assert out == {"other_name": True, "no_name": True, "its_own": True}


# A request refused while this tab's renewal hangs; then, before the renewal settles, `between` happens on the page.
RETRY = r"""
globalThis.SIGNED_OUT_REASONS = { ended: 'Your session has ended. Sign in again.' };
const quinn = token({ sub: '9', username: 'quinn', iat: NOW, exp: NOW + 3600 }, 'quinn');
const json = (status, body) => ({ ...answer(status, body),
    headers: { get: (h) => (h.toLowerCase() === 'content-type' ? 'application/json' : null) } });
let releaseExtend;
let deletes = 0;
route = (url) => {
    if (url.endsWith('/auth/session/extend'))
        return new Promise((r) => { releaseExtend = () => r(answer(200, { access_token: renewed })); });
    if (url.endsWith('/files/f1')) {
        deletes += 1;
        return Promise.resolve(deletes === 1
            ? json(401, { detail: 'Session has been terminated. Please login again.' }) : json(200, { ok: true }));
    }
    return Promise.resolve(answer(200, {}));
};
console.error = () => {};
SessionWatch.armAt(Date.now() + 30000);
SessionWatch.show();
const pressed = listeners['session-stay:click']();
let settled = 'pending';
apiRequest('/vaults/v1/files/f1', { method: 'DELETE' }).then(() => { settled = 'resolved'; }, () => { settled = 'rejected'; });
await settle();
BETWEEN
releaseExtend();
await pressed;
await settle();
out({ sent: sent.filter((s) => s.url.endsWith('/files/f1')).map((s) => s.bearer.slice(-6)), settled });
"""


def test_a_refused_request_is_not_sent_again_with_a_sign_in_made_on_the_page_since():
    # The session ends on the page (logout: the count of ended sessions goes up, the token goes), and another
    # person signs in on the ended page, which holds their token until it is replaced.
    out = _node(RETRY.replace("BETWEEN", "_sessionsEnded += 1; authToken = null; authToken = quinn;"), REQUESTS)
    assert out["sent"] == ["--mine"], out


def test_a_refused_request_is_sent_again_with_the_renewal_of_this_tab():
    # The control: nothing happens between, the renewal settles, and the request goes again with its token.
    out = _node(RETRY.replace("BETWEEN", ""), REQUESTS)
    assert out == {"sent": ["--mine", "enewed"], "settled": "resolved"}


def test_the_reasons_travel_as_codes_that_name_only_the_apps_own_sentences():
    out = _node(r"""
globalThis._nameNote = null;
vm.runInThisContext(""" + json.dumps(REASONS) + r""" + '\nglobalThis.__r = { SIGNED_OUT_REASONS, _knownReasons, _reasonCode, _nameNoteReason };',
                    { filename: 'app-reasons.js' });
const R = globalThis.__r;
const watch = SessionWatch.REASONS;
const back = {};
for (const [code, said] of Object.entries(R._knownReasons())) {
    globalThis._nameNote = { code: R._reasonCode(said), told: false };
    back[code] = R._nameNoteReason() === said;
}
const strange = [];
for (const c of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', '', 'RAN_OUT']) {
    globalThis._nameNote = { code: c, told: false };
    strange.push([c, R._nameNoteReason()]);
}
out({ watch: Object.keys(watch).sort(), back, strange,
      collide: Object.keys(watch).filter((k) => Object.prototype.hasOwnProperty.call(R.SIGNED_OUT_REASONS, k)),
      sentences: { ran_out: R._reasonCode('Your session ended because nobody chose to stay signed in. Sign in again.'),
                   temporary_ran_out: R._reasonCode(watch.temporary_ran_out),
                   uncoded: R._reasonCode('This sign-in has reached its renewal limit. Sign in again.') } });
""")
    assert out["watch"] == ["ran_out", "temporary_ran_out"]
    assert out["back"] and all(out["back"].values()), out["back"]
    assert {"ended", "told", "inactive", "locked", "ran_out", "temporary_ran_out"} <= set(out["back"])
    assert out["collide"] == []
    assert out["strange"] == [[c, None] for c in ["__proto__", "constructor", "toString", "hasOwnProperty", "", "RAN_OUT"]]
    assert out["sentences"] == {"ran_out": "ran_out", "temporary_ran_out": "temporary_ran_out", "uncoded": ""}


def test_without_the_warnings_module_a_refusal_signs_out_with_the_same_sentences():
    out = _node(r"""
globalThis.SIGNED_OUT_REASONS = { ended: 'Your session has ended. Sign in again.' };
const said = [];
globalThis.logout = (how, reason) => { said.push([how === undefined ? null : how, reason]); authToken = null; };
const a = await _signOutRefused(mine, 401, 'Session has been terminated. Please login again.');
authToken = mine;
const b = await _signOutRefused(mine, 403, 'User account is locked');
authToken = mine;
const c = await _signOutRefused(mine, 403, '');
out({ said, carriedOn: [a, b, c] });
""", REQUESTS, without_watch=True)
    assert out == {"said": [[None, "Your session has ended. Sign in again."], [None, "User account is locked"],
                            [None, "Your session has ended. Sign in again."]],
                   "carriedOn": [False, False, False]}


def test_a_refusal_carries_on_only_with_a_renewal_of_its_own_sign_in():
    # What the page is told by the warning when one of its requests is refused (SessionWatch.refusedSession): true
    # only when the tab now holds a renewal of the sign-in the refused token belongs to.
    out = _node(r"""
const quinn = token({ sub: '9', username: 'quinn', iat: NOW, exp: NOW + 3600 }, 'quinn');
const ended = 'Session has been terminated. Please login again.';
const results = {};
// Another person's token held since, with no renewal of this tab's on its way.
authToken = quinn;
results.someone_else_held = await SessionWatch.refusedSession(mine, 401, ended);
// This tab's renewal on its way when the refusal comes; another person's token is held by the time it settles.
authToken = mine;
store.set('authToken', mine);
let release;
route = () => new Promise((r) => { release = () => r(answer(200, { access_token: renewed })); });
SessionWatch.armAt(Date.now() + 30000);
SessionWatch.show();
const pressed = listeners['session-stay:click']();
await settle();
const asked = SessionWatch.refusedSession(mine, 401, ended);
await settle();
authToken = quinn;
release();
await pressed;
results.someone_else_after_the_renewal = await asked;
// The control: the renewal settles for this tab, and the refusal carries on with its token.
authToken = mine;
store.set('authToken', mine);
const pressedAgain = listeners['session-stay:click']();
await settle();
const askedAgain = SessionWatch.refusedSession(mine, 401, ended);
await settle();
release();
await pressedAgain;
results.its_own_renewal = await askedAgain;
results.holds_the_renewal = authToken === renewed;
out(results);
""")
    assert out == {"someone_else_held": False, "someone_else_after_the_renewal": False,
                   "its_own_renewal": True, "holds_the_renewal": True}
